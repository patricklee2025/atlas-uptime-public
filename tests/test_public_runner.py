import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from cryptography.fernet import Fernet, InvalidToken
import monitor
import public_runner as runner
from test_monitor import CFG, SITE, observation, state


class PublicRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name, "state.enc")
        self.key = Fernet.generate_key()
        self.env = patch.dict(os.environ, {
            "STATE_ENCRYPTION_KEY": self.key.decode(), "ALERT_CHANNELS": "email",
            "SMTP_HOST": "mail.example.invalid", "EMAIL_FROM": "sender@example.invalid",
            "EMAIL_TO": "recipient@example.invalid",
            "GITHUB_STEP_SUMMARY": str(Path(self.temp.name, "public-summary")),
        }, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)

    def initialize(self):
        self.assertEqual(runner.run("initialize", self.path), 0)

    def test_encryption_roundtrip_and_tamper_rejection(self):
        secret = "PRIVATE INCIDENT DETAILS"
        files = {"state.json": json.dumps(state()), "STATUS.md": secret}
        runner.pack(self.path, files, Fernet(self.key))
        self.assertNotIn(secret.encode(), self.path.read_bytes())
        self.assertEqual(runner.unpack(self.path, Fernet(self.key)), files)
        with self.assertRaises(InvalidToken):
            runner.unpack(self.path, Fernet(Fernet.generate_key()))
        data = bytearray(self.path.read_bytes())
        data[len(data) // 2] ^= 1
        self.path.write_bytes(data)
        with self.assertRaises(InvalidToken):
            runner.unpack(self.path, Fernet(self.key))

    def test_missing_key_stops_before_network(self):
        os.environ.pop("STATE_ENCRYPTION_KEY")
        with patch("public_runner.subprocess.run") as child:
            with self.assertRaises(ValueError):
                runner.run("check", self.path)
            child.assert_not_called()

    def test_missing_state_never_silently_initializes(self):
        with patch("public_runner.subprocess.run") as child:
            with self.assertRaises(FileNotFoundError):
                runner.run("check", self.path)
            child.assert_not_called()

    def test_reinitialization_refused(self):
        self.initialize()
        before = self.path.read_bytes()
        with self.assertRaises(ValueError):
            runner.run("initialize", self.path)
        self.assertEqual(before, self.path.read_bytes())

    def test_unconfigured_alert_channel_blocks_probes(self):
        os.environ["ALERT_CHANNELS"] = "email,pushover"
        with patch("public_runner.subprocess.run") as child:
            with self.assertRaises(ValueError):
                runner.run("initialize", self.path)
            child.assert_not_called()

    def test_down_is_not_public_failure_and_child_output_is_suppressed(self):
        self.initialize()
        def child(args, **kwargs):
            self.assertIs(kwargs["stdout"], subprocess.DEVNULL)
            self.assertIs(kwargs["stderr"], subprocess.DEVNULL)
            self.assertNotIn("GITHUB_STEP_SUMMARY", kwargs["env"])
            folder = Path(args[args.index("--data-dir") + 1])
            folder.joinpath("STATUS.md").write_text("private incident")
            return subprocess.CompletedProcess(args, 1)
        with patch("public_runner.subprocess.run", side_effect=child):
            self.assertEqual(runner.run("check", self.path), 0)
        self.assertEqual(runner.unpack(self.path, Fernet(self.key))["STATUS.md"], "private incident")
        self.assertFalse(Path(os.environ["GITHUB_STEP_SUMMARY"]).exists())

    def test_delivery_failure_keeps_queue_encrypted(self):
        self.initialize()
        def child(args, **kwargs):
            folder = Path(args[args.index("--data-dir") + 1])
            data = state()
            monitor.queue_event(data, ["email"], "DOWN", "private details", 1)
            folder.joinpath("state.json").write_text(json.dumps(data))
            return subprocess.CompletedProcess(args, 2)
        with patch("public_runner.subprocess.run", side_effect=child):
            self.assertEqual(runner.run("check", self.path), 2)
        data = json.loads(runner.unpack(self.path, Fernet(self.key))["state.json"])
        self.assertEqual(data["events"][0]["pending"], ["email"])
        self.assertNotIn(b"private details", self.path.read_bytes())

    def test_alert_test_preserves_incident_state(self):
        self.initialize()
        before = self.path.read_bytes()
        with patch("public_runner.subprocess.run", return_value=subprocess.CompletedProcess([], 0)):
            self.assertEqual(runner.run("test", self.path), 0)
        self.assertEqual(before, self.path.read_bytes())

    def test_failure_log_contains_no_exception_details(self):
        with patch("sys.argv", ["public_runner.py", "check"]), \
             patch("public_runner.run", side_effect=RuntimeError("PRIVATE SECRET")), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(runner.main(), 2)
        self.assertNotIn("PRIVATE SECRET", output.getvalue())

    def test_no_repeated_down_alert_with_default_configuration(self):
        data = state()
        monitor.transition(data, SITE, observation(False, 1000), CFG, ["email"])
        monitor.transition(data, SITE, observation(False, 100000), CFG, ["email"])
        self.assertEqual(len(data["events"]), 1)
        monitor.transition(data, SITE, observation(True, 100100), CFG, ["email"])
        self.assertEqual(len(data["events"]), 2)
        self.assertIn("RECOVERED", data["events"][-1]["subject"])


if __name__ == "__main__":
    unittest.main()
