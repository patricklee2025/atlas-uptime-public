"""Public CI boundary: authenticated encrypted reports, no site details in logs."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import zlib

from cryptography.fernet import Fernet
import monitor

FILES = {"state.json", "STATUS.md", "status.html"}
MAX_BUNDLE = 16 * 1024 * 1024


def cipher():
    key = os.environ.get("STATE_ENCRYPTION_KEY", "").strip()
    if not key:
        raise ValueError("Missing encryption key")
    return Fernet(key.encode("ascii"))


def unpack(path, fernet):
    raw = fernet.decrypt(Path(path).read_bytes())
    decoder = zlib.decompressobj()
    plain = decoder.decompress(raw, MAX_BUNDLE + 1)
    if len(plain) > MAX_BUNDLE or not decoder.eof or decoder.unused_data:
        raise ValueError("Invalid encrypted bundle")
    bundle = json.loads(plain)
    if bundle.get("version") != 1 or not isinstance(bundle.get("files"), dict):
        raise ValueError("Unknown bundle format")
    files = bundle["files"]
    if "state.json" not in files or not set(files).issubset(FILES):
        raise ValueError("Invalid report names")
    if not all(isinstance(value, str) for value in files.values()):
        raise ValueError("Invalid report content")
    state = json.loads(files["state.json"])
    if state.get("version") != 1 or not isinstance(state.get("sites"), dict):
        raise ValueError("Invalid state")
    if not isinstance(state.get("samples"), list) or not isinstance(state.get("events"), list):
        raise ValueError("Invalid state")
    return files


def pack(path, files, fernet):
    plain = json.dumps({"version": 1, "files": files}, separators=(",", ":")).encode()
    if len(plain) > MAX_BUNDLE:
        raise ValueError("State too large")
    payload = fernet.encrypt(zlib.compress(plain, level=9))
    path = Path(path)
    temp = path.with_suffix(".tmp")
    temp.write_bytes(payload)
    temp.replace(path)


def readiness():
    entries = monitor.alert_readiness()
    if not entries or any(e["status"] != "READY TO TEST" for e in entries.values()):
        raise ValueError("Selected alert channels are not ready")


def test_diagnostics(folder):
    """Expose only fixed delivery-test labels, never report content or secrets."""
    path = Path(folder, "alert-test.json")
    if not path.exists():
        print("Alert test: no delivery report available.")
        return
    report = json.loads(path.read_text(encoding="utf-8"))
    reasons = {
        "SMTP authentication rejected; check approved SMTP credentials": "SMTP authentication rejected",
        "SMTP rejected recipients; check EMAIL_TO and relay permissions": "SMTP recipients rejected",
        "Network/TLS request failed or timed out": "Network or TLS failure",
        "HTTP 400; verify alert credentials, provider quota, and service availability": "Provider rejected request (HTTP 400)",
        "HTTP 401; verify alert credentials, provider quota, and service availability": "Provider rejected credentials (HTTP 401)",
        "HTTP 403; verify alert credentials, provider quota, and service availability": "Provider denied request (HTTP 403)",
        "HTTP 429; verify alert credentials, provider quota, and service availability": "Provider rate limit (HTTP 429)",
    }
    for channel in ("email", "pushover", "chat"):
        entry = report.get("channels", {}).get(channel)
        if not isinstance(entry, dict):
            continue
        status = entry.get("status")
        if status == "ACCEPTED":
            print(f"Alert test {channel}: provider accepted.")
        elif status == "NOT CONFIGURED":
            print(f"Alert test {channel}: not selected.")
        else:
            reason = reasons.get(entry.get("detail"), "Check channel configuration privately")
            print(f"Alert test {channel}: failed. {reason}.")


def run(mode, state_path):
    fernet = cipher()  # Fail before probes or delivery when encryption is unavailable.
    if mode == "initialize":
        if Path(state_path).exists():
            raise ValueError("Refusing to overwrite state")
        readiness()
        empty = {"version": 1, "sites": {}, "samples": [], "events": []}
        pack(state_path, {"state.json": json.dumps(empty)}, fernet)
        return 0
    readiness()
    files = unpack(state_path, fernet)  # Never silently reset missing/corrupt state.
    with tempfile.TemporaryDirectory(prefix="atlas-private-") as folder:
        os.chmod(folder, 0o700)
        for name, data in files.items():
            Path(folder, name).write_text(data, encoding="utf-8")
        env = dict(os.environ)
        env.pop("GITHUB_STEP_SUMMARY", None)
        env.pop("GITHUB_OUTPUT", None)
        command = [sys.executable, str(Path(__file__).with_name("monitor.py")), "--data-dir", folder]
        if mode == "test":
            command.append("--test-alert")
        # Neither child output nor exception text can reach public CI logs.
        result = subprocess.run(command, env=env, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=480)
        if mode == "test":
            test_diagnostics(folder)
            return 0 if result.returncode == 0 else 2
        if result.returncode not in (0, 1, 2):
            raise ValueError("Unexpected monitor exit")
        updated = {name: Path(folder, name).read_text(encoding="utf-8")
                   for name in FILES if Path(folder, name).exists()}
        pack(state_path, updated, fernet)  # Keep queued notifications even on delivery failure.
        return 0 if result.returncode in (0, 1) else 2


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["initialize", "check", "test", "decrypt"])
    parser.add_argument("--state", default="state-work/state.enc")
    parser.add_argument("--output", default="private-reports")
    args = parser.parse_args()
    try:
        if args.mode == "decrypt":
            files = unpack(args.state, cipher())
            target = Path(args.output)
            target.mkdir(mode=0o700, parents=True, exist_ok=False)
            for name, data in files.items():
                Path(target, name).write_text(data, encoding="utf-8")
            print("Reports decrypted locally. Do not upload or commit this folder.")
            return 0
        code = run(args.mode, args.state)
        print("Monitor operation completed." if code == 0 else
              "Monitor operation failed; check configuration and alert delivery privately.")
        return code
    except Exception:
        print("Monitor operation failed; check secrets, encrypted state, and runtime privately.")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
