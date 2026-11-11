#!/usr/bin/env python3
"""Read-only external HTTP monitoring. Python standard library + curl."""
import argparse
import concurrent.futures
from datetime import datetime, timezone
from email.message import EmailMessage
import html
import json
import os
from pathlib import Path
import re
import smtplib
import ssl
import subprocess
import tempfile
import time
from urllib.parse import urlsplit, parse_qs, urlencode
import urllib.error
import urllib.request
import uuid


def utc(ts):
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="seconds")


def atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(value, separators=(",", ":")), encoding="utf-8")
    tmp.replace(path)


def validate(cfg):
    ids = set()
    for site in cfg["sites"]:
        u = urlsplit(site["url"])
        if u.scheme != "https" or not u.hostname or u.username or u.password or u.query or u.fragment:
            raise ValueError("Monitor URLs must be public HTTPS URLs without credentials, query, or fragment")
        if site["id"] in ids or not re.fullmatch(r"[a-z0-9-]+", site["id"]):
            raise ValueError("Site IDs must be unique lowercase slugs")
        ids.add(site["id"])
        if u.hostname not in site["allowed_hosts"]:
            raise ValueError("Initial hostname must be allowed")
    for key in ("timeout_seconds", "attempts", "retry_seconds", "slow_seconds", "history_days", "stale_seconds"):
        if not isinstance(cfg[key], int) or cfg[key] < 1:
            raise ValueError("Configuration intervals and limits must be positive integers")
    if not isinstance(cfg["reminder_seconds"], int) or cfg["reminder_seconds"] < 0:
        raise ValueError("Reminder interval must be a nonnegative integer; zero disables reminders")
    if not cfg["sites"] or cfg["attempts"] > 5 or cfg["timeout_seconds"] > 60:
        raise ValueError("Require sites, at most 5 attempts, and at most a 60-second request timeout")


def probe(site, cfg):
    """curl enforces a total timeout (including redirects and response body)."""
    start = time.monotonic()
    status, reason, ok = None, "request failed", False
    with tempfile.TemporaryDirectory() as folder:
        body_path = Path(folder) / "body"
        args = ["curl", "--silent", "--location", "--max-redirs", "5",
                "--proto", "=https", "--proto-redir", "=https", "--compressed",
                "--connect-timeout", "8", "--max-time", str(cfg["timeout_seconds"]),
                "--max-filesize", "2097152", "--user-agent", "AtlasUptime/1.0",
                "--output", str(body_path), "--write-out", "%{json}", site["url"]]
        try:
            p = subprocess.run(args, capture_output=True, text=True, timeout=cfg["timeout_seconds"] + 5)
            meta = json.loads(p.stdout or "{}")
            status = meta.get("http_code") or None
            final = urlsplit(meta.get("url_effective", ""))
            if p.returncode:
                reason = {6: "DNS lookup failed", 7: "connection failed", 28: "request timed out",
                          35: "TLS handshake failed", 47: "too many redirects", 60: "TLS certificate invalid",
                          63: "response exceeds 2 MiB limit"}.get(p.returncode, f"network error (curl {p.returncode})")
            elif final.scheme != "https" or final.hostname not in site["allowed_hosts"]:
                reason = "unexpected redirect destination"
            elif status is None or not 200 <= status < 300:
                reason = f"HTTP {status}"
            else:
                body = body_path.read_text(encoding="utf-8", errors="replace")
                if not body.strip():
                    reason = "empty response"
                elif any(text.casefold() not in html.unescape(body).casefold() for text in site["expected_text"]):
                    reason = "expected page text missing"
                else:
                    ok, reason = True, "OK"
        except subprocess.TimeoutExpired:
            reason = "request process timed out"
        except (ValueError, OSError):
            # Missing curl is an internal monitor failure, not a site outage.
            raise RuntimeError("Could not execute or parse curl probe") from None
    return {"ok": ok, "http": status, "seconds": round(time.monotonic() - start, 3), "reason": reason}


def check(site, cfg):
    started = time.time()
    for attempt in range(1, cfg["attempts"] + 1):
        result = probe(site, cfg)
        if result["ok"]:
            break
        if attempt < cfg["attempts"]:
            time.sleep(cfg["retry_seconds"])
    return dict(result, attempts=attempt, started=started, checked=time.time(),
                slow=result["ok"] and result["seconds"] > cfg["slow_seconds"])


def selected_channels():
    channels = [c.strip() for c in os.getenv("ALERT_CHANNELS", "chat,email,pushover").split(",") if c.strip()]
    if not channels or any(c not in ("chat", "email", "pushover") for c in channels):
        raise AlertConfigurationError("ALERT_CHANNELS must list chat, email, or pushover")
    return set(channels)


def configured_channels():
    channels = []
    if os.getenv("GOOGLE_CHAT_WEBHOOK"):
        channels.append("chat")
    if os.getenv("SMTP_HOST"):
        channels.append("email")
    if os.getenv("PUSHOVER_APP_TOKEN") or os.getenv("PUSHOVER_USER_KEY"):
        channels.append("pushover")
    return [c for c in channels if c in selected_channels()]


class AlertConfigurationError(ValueError):
    """Contains only fixed diagnostics or secret names, never secret values."""


def validate_channel(channel):
    if channel == "chat":
        if not os.getenv("GOOGLE_CHAT_WEBHOOK", "").strip():
            raise AlertConfigurationError("Missing repository secret: GOOGLE_CHAT_WEBHOOK")
        parsed = urlsplit(os.getenv("GOOGLE_CHAT_WEBHOOK", ""))
        query = parse_qs(parsed.query)
        if (parsed.scheme != "https" or parsed.netloc != "chat.googleapis.com"
                or not re.fullmatch(r"/v1/spaces/[^/]+/messages", parsed.path)
                or not query.get("key") or not query.get("token") or parsed.fragment):
            raise AlertConfigurationError("GOOGLE_CHAT_WEBHOOK must contain the complete Google Chat webhook URL, including key and token")
        try:
            chat_payload("", "")
        except ValueError:
            raise AlertConfigurationError("GOOGLE_CHAT_MENTIONS must be all or comma-separated numeric user IDs") from None
    elif channel == "pushover":
        for name in ("PUSHOVER_APP_TOKEN", "PUSHOVER_USER_KEY"):
            if not os.getenv(name, "").strip():
                raise AlertConfigurationError("Missing repository secret: " + name)
            if not re.fullmatch(r"[A-Za-z0-9]{30}", os.environ[name].strip()):
                raise AlertConfigurationError(name + " must be the complete 30-character Pushover key")
    elif channel == "email":
        missing = [name for name in ("SMTP_HOST", "EMAIL_FROM", "EMAIL_TO") if not os.getenv(name, "").strip()]
        if os.getenv("SMTP_USERNAME") and not os.getenv("SMTP_PASSWORD"):
            missing.append("SMTP_PASSWORD")
        if missing:
            raise AlertConfigurationError("Missing secrets: " + ", ".join(missing))
        if os.getenv("SMTP_PASSWORD") and not os.getenv("SMTP_USERNAME"):
            raise AlertConfigurationError("SMTP_USERNAME is required when SMTP_PASSWORD is provided")
        try:
            port = int(os.getenv("SMTP_PORT") or "587")
            if not 1 <= port <= 65535:
                raise ValueError
        except ValueError:
            raise AlertConfigurationError("SMTP_PORT must be an integer from 1 to 65535") from None
        if not any(x.strip() for x in os.environ["EMAIL_TO"].split(",")):
            raise AlertConfigurationError("EMAIL_TO must contain a recipient")


def alert_readiness():
    result = {}
    selected = selected_channels()
    for channel, names in {
        "chat": ("GOOGLE_CHAT_WEBHOOK", "GOOGLE_CHAT_MENTIONS"),
        "email": ("SMTP_HOST", "SMTP_PORT", "SMTP_USERNAME", "SMTP_PASSWORD", "EMAIL_FROM", "EMAIL_TO"),
        "pushover": ("PUSHOVER_APP_TOKEN", "PUSHOVER_USER_KEY"),
    }.items():
        if channel not in selected:
            continue
        if not any(os.getenv(name, "").strip() for name in names):
            details = {"chat": "Add GOOGLE_CHAT_WEBHOOK", "email": "Add SMTP_HOST, EMAIL_FROM, EMAIL_TO and approved SMTP authentication", "pushover": "Add PUSHOVER_APP_TOKEN and PUSHOVER_USER_KEY"}
            result[channel] = {"status": "NOT CONFIGURED", "detail": details[channel]}
            continue
        try:
            validate_channel(channel)
            result[channel] = {"status": "READY TO TEST", "detail": "Configuration looks complete; run a delivery test to verify"}
        except (ValueError, KeyError) as exc:
            # Fixed diagnostics from our validator only; parsing errors may contain input.
            detail = str(exc) if isinstance(exc, AlertConfigurationError) else "Invalid alert configuration"
            result[channel] = {"status": "CONFIGURATION ERROR", "detail": detail}
    return result


def delivery_error(exc):
    if isinstance(exc, AlertConfigurationError):
        return str(exc)
    if isinstance(exc, urllib.error.HTTPError):
        return f"HTTP {exc.code}; verify alert credentials, provider quota, and service availability"
    if isinstance(exc, smtplib.SMTPAuthenticationError):
        return "SMTP authentication rejected; check approved SMTP credentials"
    if isinstance(exc, smtplib.SMTPRecipientsRefused):
        return "SMTP rejected recipients; check EMAIL_TO and relay permissions"
    if isinstance(exc, (TimeoutError, urllib.error.URLError)):
        return "Network/TLS request failed or timed out"
    return type(exc).__name__ + "; check channel configuration and provider availability"


def write_summary(text):
    if os.getenv("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
            f.write(text + "\n")


def test_alerts(folder, send_test=True):
    """Test real transports without reading or changing production incident state."""
    result = {"checked": utc(time.time()), "commit": os.getenv("GITHUB_SHA", ""),
              "mode": "delivery test" if send_test else "configuration only",
              "channels": alert_readiness()}
    test_id = str(uuid.uuid4())
    for channel, entry in result["channels"].items():
        if entry["status"] != "READY TO TEST" or not send_test:
            continue
        try:
            send(channel, "[Atlas Uptime] TEST — no outage",
                 f"Alert delivery test at {result['checked']}.\nNo production site status has changed.\nTest ID: {test_id}")
            entry.update(status="ACCEPTED", detail="Provider accepted the test; confirm receipt on your phone, in Chat, or in your inbox")
        except Exception as exc:
            entry.update(status="DELIVERY FAILED", detail=delivery_error(exc))
    enabled = [e for e in result["channels"].values() if e["status"] != "NOT CONFIGURED"]
    if os.getenv("ALERT_CHANNELS"):
        enabled = list(result["channels"].values())  # Explicit selections must all pass.
    good = "ACCEPTED" if send_test else "READY TO TEST"
    result["passed"] = bool(enabled) and all(e["status"] == good for e in enabled)
    lines = ["## Atlas alert test", "", f"Checked: {result['checked']}", "",
             "| Channel | Result | Details |", "|---|---|---|"]
    for channel, entry in result["channels"].items():
        lines.append(f"| {channel} | {entry['status']} | {entry['detail']} |")
    lines += ["", "This test does not check sites or change outage history.",
              "A provider acceptance is not confirmation that a person received the notification."]
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    atomic_json(folder / "alert-test.json", result)
    markdown = "\n".join(lines) + "\n"
    (folder / "ALERT-TEST.md").write_text(markdown, encoding="utf-8")
    print(markdown)
    write_summary(markdown)
    return 0 if result["passed"] else 2


def queue_event(state, channels, subject, message, now):
    event = {"id": str(uuid.uuid4()), "at": now, "subject": subject, "message": message,
             "pending": list(channels)}
    state["events"].append(event)


def transition(state, site, result, cfg, channels):
    now, key = result["checked"], site["id"]
    previous = state["sites"].get(key, {})
    was_down = previous.get("status") == "DOWN"
    down = not result["ok"]
    since = previous.get("down_since") if was_down else result["started"]
    last_event = previous.get("last_event", 0)
    kind = None
    if down and not was_down:
        kind = "DOWN"
    elif not down and was_down:
        kind = "RECOVERED"
    elif down and cfg["reminder_seconds"] > 0 and now - last_event >= cfg["reminder_seconds"]:
        kind = "STILL DOWN"
    if kind:
        duration = max(0, round(now - since))
        subject = f"[Atlas Uptime] {kind}: {site['name']}"
        message = (f"{site['url']}\nObserved: {utc(now)}\nResult: {result['reason']}\n"
                   f"Attempts this run: {result['attempts']}\n"
                   f"Time since first failed observation: {duration} seconds\n"
                   "This checks the public page, not login or payment completion.")
        queue_event(state, channels, subject, message, now)
        last_event = now
    state["sites"][key] = dict(result, status="DOWN" if down else "UP",
                               down_since=since if down else None, last_event=last_event)
    state["samples"].append({"at": now, "site": key, "ok": result["ok"], "seconds": result["seconds"]})


def chat_payload(subject, message):
    mentions = []
    for item in os.getenv("GOOGLE_CHAT_MENTIONS", "").split(","):
        item = item.strip()
        if not item:
            continue
        if item != "all" and not re.fullmatch(r"[0-9]+", item):
            raise ValueError("Use numeric Google Chat IDs or all; webhook email aliases are unsupported")
        mentions.append(f"<users/{item}>")
    return {"text": f"{' '.join(mentions)}\n{subject}\n{message}".strip()}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def send(channel, subject, message):
    validate_channel(channel)
    if channel == "chat":
        url = os.environ["GOOGLE_CHAT_WEBHOOK"]
        parsed = urlsplit(url)
        if parsed.scheme != "https" or parsed.netloc != "chat.googleapis.com" or not parsed.path.startswith("/v1/spaces/"):
            raise ValueError("Invalid Google Chat webhook")
        request = urllib.request.Request(url, data=json.dumps(chat_payload(subject, message)).encode(),
                                         headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.build_opener(NoRedirect).open(request, timeout=20) as response:
            if not 200 <= response.status < 300:
                raise RuntimeError("Chat delivery failed")
    elif channel == "pushover":
        payload = {"token": os.environ["PUSHOVER_APP_TOKEN"].strip(),
                   "user": os.environ["PUSHOVER_USER_KEY"].strip(),
                   "title": subject[:250], "message": message[:1024], "priority": 0}
        request = urllib.request.Request("https://api.pushover.net/1/messages.json",
                                         data=urlencode(payload).encode(),
                                         headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST")
        with urllib.request.build_opener(NoRedirect).open(request, timeout=20) as response:
            if not 200 <= response.status < 300:
                raise RuntimeError("Pushover delivery failed")
            body = json.loads(response.read(65536))
            if not isinstance(body, dict) or body.get("status") != 1:
                raise AlertConfigurationError("Pushover rejected the message; verify app token, user key, active device, and quota")
    elif channel == "email":
        recipients = [x.strip() for x in os.environ["EMAIL_TO"].split(",") if x.strip()]
        if not recipients:
            raise ValueError("EMAIL_TO required")
        email = EmailMessage()
        email["From"], email["To"], email["Subject"] = os.environ["EMAIL_FROM"], ", ".join(recipients), subject
        email.set_content(message)
        port = int(os.getenv("SMTP_PORT") or "587")
        context = ssl.create_default_context()
        if port == 465:
            smtp = smtplib.SMTP_SSL(os.environ["SMTP_HOST"], port, timeout=20, context=context)
        else:
            smtp = smtplib.SMTP(os.environ["SMTP_HOST"], port, timeout=20)
        with smtp:
            if port != 465:
                smtp.starttls(context=context)
            if os.getenv("SMTP_USERNAME"):
                smtp.login(os.environ["SMTP_USERNAME"], os.environ["SMTP_PASSWORD"])
            refused = smtp.send_message(email)
            if refused:
                raise RuntimeError("One or more email recipients were refused")
    else:
        raise ValueError("Unsupported notification channel")


def deliver(state, channels):
    """Independent per-channel ordered queues. Failed deliveries stay pending."""
    failed = set()
    count = {channel: 0 for channel in channels}
    for event in state["events"]:
        for channel in list(event["pending"]):
            if channel not in channels or channel in failed or count[channel] >= 8:
                continue
            try:
                send(channel, event["subject"], event["message"] + f"\nEvent ID: {event['id']}")
                event["pending"].remove(channel)
                count[channel] += 1
                if channel == "chat":
                    time.sleep(1.1)  # Respect the per-space write rate.
            except Exception as exc:
                # No response bodies, URLs, addresses, or credentials in logs.
                print(f"Notification failed: {channel}: {delivery_error(exc)}; retained for retry")
                failed.add(channel)
    return bool(failed)


def report(state, cfg, folder):
    esc = html.escape
    counts = {}
    for sample in state["samples"]:
        total, good = counts.get(sample["site"], (0, 0))
        counts[sample["site"]] = (total + 1, good + int(sample["ok"]))
    rows, summary = [], ["## Atlas uptime", "", f"Last checked: {utc(state['checked'])}", "",
                         f"| Site | Result | HTTP | Response | Attempts | Reason | Successful samples ({cfg['history_days']}d) |", "|---|---|---|---|---|---|---|"]
    for site in cfg["sites"]:
        result = state["sites"][site["id"]]
        total, good = counts.get(site["id"], (0, 0))
        ratio = (f"{100 * good / total:.2f}% ({total} samples)"
                 if total else "No samples in this window")
        status = result["status"] + (" / SLOW" if result["slow"] else "")
        scope = "HTTP + page text" if site["expected_text"] else "HTTP only; content baseline needed"
        rows.append(f'<article><div class="heading"><h2>{esc(site["name"])}</h2><b class="{result["status"]}">{status}</b></div>'
                    f'<a href="{esc(site["url"], quote=True)}">{esc(site["url"])}</a>'
                    f'<p>{esc(result["reason"])} · {result["seconds"]:.2f}s · {result["attempts"]} attempt(s)</p>'
                    f'<p>Successful checks: {ratio}</p><small>{scope}</small></article>')
        summary.append(f"| {site['name']} | {status} | {result['http'] or '—'} | {result['seconds']:.2f}s | {result['attempts']} | {result['reason']} | {ratio} |")
    pending = sum(len(e["pending"]) for e in state["events"])
    events = "".join(f'<li><strong>{esc(e["subject"])}</strong><br><small>{utc(e["at"])} · '
                     f'{"pending delivery" if e["pending"] else "delivery complete or alerts unconfigured"}</small></li>'
                     for e in state["events"][-20:][::-1]) or "<li>No recorded incidents.</li>"
    page = '''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Atlas uptime report</title><style>
*{box-sizing:border-box}body{background:#eef3f8;color:#172c42;font:16px system-ui;margin:0;padding:36px 20px}
main{max-width:1050px;margin:auto}h1{font-size:38px;letter-spacing:-1px;margin-bottom:8px}h2{font-size:19px;margin:0}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(310px,1fr));gap:18px;margin:26px 0}article{padding:24px;background:white;border:1px solid #dce4ee;border-radius:16px}
.heading{display:flex;gap:12px;justify-content:space-between;margin-bottom:14px}b{font-size:13px;white-space:nowrap}.UP{color:#07794a}.DOWN{color:#be293e}
a{font-size:13px;color:#2867aa;overflow-wrap:anywhere}small{color:#526478}#fresh{padding:12px 16px;background:#fff3cf;border-radius:8px}li{padding:12px 0}
</style><main><small>ATLAS / OPERATIONS</small><h1>Production availability</h1>'''
    page += f'<p>Snapshot taken {utc(state["checked"])}</p><div id="fresh">Checking snapshot age…</div>'
    page += f'<div class="grid">{"".join(rows)}</div><p>{pending} pending notification delivery(s).</p>'
    readiness = alert_readiness()
    page += '<h2>Alert setup</h2><ul>' + ''.join(
        f'<li>{channel}: <strong>{esc(entry["status"])}</strong> — {esc(entry["detail"])}</li>'
        for channel, entry in readiness.items()) + '</ul>'
    page += '<p>Public-page checks only. Successful sample percentage is not time-weighted uptime. Gaps between runs are unobserved.</p>'
    page += f'<h2>Recent incidents</h2><ul>{events}</ul><p>This is a saved report. Download a newer report to update the results.</p></main>'
    page += f'''<script>const checked={state['checked']};function age(){{const seconds=Date.now()/1000-checked;document.getElementById('fresh').textContent=seconds>{cfg['stale_seconds']}?'STALE — these results are over {cfg['stale_seconds']/60:g} minutes old. Current availability is unknown.':'Snapshot age: '+Math.max(0,Math.floor(seconds/60))+' minute(s).';}}age();setInterval(age,10000);</script></html>'''
    Path(folder, "status.html").write_text(page, encoding="utf-8")
    summary += ["", f"Pending deliveries: {pending}. Alert channels: {', '.join(configured_channels()) or 'NONE CONFIGURED'}.",
                "", "HTTP checks only. Sample success is not time-weighted uptime; missed runs are unobserved."]
    summary += ["", "### Alert setup", ""] + [f"- {channel}: **{entry['status']}** — {entry['detail']}"
                                                  for channel, entry in readiness.items()]
    Path(folder, "STATUS.md").write_text("\n".join(summary) + "\n", encoding="utf-8")
    write_summary("\n".join(summary))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="monitors.json")
    parser.add_argument("--data-dir", default="runtime")
    parser.add_argument("--test-alert", action="store_true", help="Send an explicitly labeled test to all configured channels")
    parser.add_argument("--check-alert-config", action="store_true", help="Validate alert settings without sending messages")
    args = parser.parse_args()
    if args.test_alert or args.check_alert_config:
        return test_alerts(args.data_dir, send_test=args.test_alert)
    cfg = json.loads(Path(args.config).read_text())
    validate(cfg)
    channels = configured_channels()
    folder = Path(args.data_dir)
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / "state.json"
    state = json.loads(path.read_text()) if path.exists() else {"version": 1, "sites": {}, "samples": [], "events": []}
    if state.get("version") != 1:
        raise ValueError("Unknown state version; refusing to reset incident history")
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda s: check(s, cfg), cfg["sites"]))
    for site, result in zip(cfg["sites"], results):
        transition(state, site, result, cfg, channels)
        print(f"{site['id']}: {'UP' if result['ok'] else 'DOWN'} ({result['reason']})")
    state["checked"] = time.time()
    cutoff = state["checked"] - cfg["history_days"] * 86400
    state["samples"] = [s for s in state["samples"] if s["at"] >= cutoff]
    state["events"] = [e for e in state["events"] if e["at"] >= cutoff or e["pending"]]
    atomic_json(path, state)  # Preserve pending events before attempting delivery.
    delivery_failed = deliver(state, channels)
    atomic_json(path, state)
    report(state, cfg, folder)
    if not channels:
        print("Alerts are not configured; this run records status only.")
    return 2 if delivery_failed else (1 if any(not r["ok"] for r in results) else 0)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"Monitor internal error: {type(exc).__name__}. Check configuration/runtime; this is not a confirmed site outage.")
        raise SystemExit(2)
