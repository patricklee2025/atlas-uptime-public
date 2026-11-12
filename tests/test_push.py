import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs
import urllib.error

import monitor as m

PUSH = {"PUSHOVER_APP_TOKEN": "A" * 30, "PUSHOVER_USER_KEY": "B" * 30}
EMAIL = {"SMTP_HOST": "smtp.gmail.com", "SMTP_PORT": "587", "SMTP_USERNAME": "sender@example.invalid",
         "SMTP_PASSWORD": "private-password", "EMAIL_FROM": "sender@example.invalid", "EMAIL_TO": "recipient@example.invalid"}


class PushTests(unittest.TestCase):
    def test_transport_requires_provider_acceptance(self):
        response = MagicMock()
        response.__enter__.return_value = response
        response.status = 200
        response.read.return_value = b'{"status":1}'
        with patch.dict(os.environ, PUSH, clear=True), patch("monitor.urllib.request.build_opener") as opener:
            opener.return_value.open.return_value = response
            m.send("pushover", "DOWN", "Example")
            request = opener.return_value.open.call_args.args[0]
            self.assertEqual(request.full_url, "https://api.pushover.net/1/messages.json")
            self.assertEqual(request.method, "POST")
            data = parse_qs(request.data.decode())
            self.assertEqual(data["user"], [PUSH["PUSHOVER_USER_KEY"]])
            self.assertEqual(data["message"], ["Example"])
            self.assertEqual(data["priority"], ["0"])
            response.read.return_value = b'{"status":0,"errors":["private-password"]}'
            with self.assertRaises(m.AlertConfigurationError) as error:
                m.send("pushover", "TEST", "Example")
            self.assertNotIn("private-password", str(error.exception))
            response.read.return_value = b'not json'
            with self.assertRaises(ValueError):
                m.send("pushover", "TEST", "Example")

    def test_missing_and_malformed_keys_never_sent(self):
        for env in ({"PUSHOVER_APP_TOKEN": "A" * 30}, {**PUSH, "PUSHOVER_USER_KEY": "bad"}):
            with self.subTest(env=list(env)), patch.dict(os.environ, env, clear=True), patch("monitor.urllib.request.build_opener") as opener:
                with self.assertRaises(m.AlertConfigurationError):
                    m.send("pushover", "TEST", "Example")
                opener.assert_not_called()

    def test_push_failure_keeps_queue_and_email_succeeds(self):
        state = {"events": []}
        m.queue_event(state, ["pushover", "email"], "DOWN", "Example", 1000)
        def sender(channel, *args):
            if channel == "pushover":
                raise urllib.error.HTTPError("https://api.pushover.net/", 429, "private-password", {}, None)
        with patch("monitor.send", side_effect=sender), patch("builtins.print") as output:
            self.assertTrue(m.deliver(state, ["pushover", "email"]))
            self.assertNotIn("private-password", str(output.call_args_list))
        self.assertEqual(state["events"][0]["pending"], ["pushover"])
        with patch("monitor.send") as sender:
            self.assertFalse(m.deliver(state, ["pushover", "email"]))
            self.assertEqual(sender.call_args.args[0], "pushover")
            self.assertEqual(sender.call_count, 1)

    def test_explicit_channels_ignore_stale_chat_and_require_both(self):
        base = {**PUSH, "ALERT_CHANNELS": "pushover,email", "GOOGLE_CHAT_MENTIONS": "bad-legacy-value"}
        for email, expected in (({}, 2), (EMAIL, 0)):
            with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, {**base, **email}, clear=True), patch("monitor.send") as sender, contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(m.test_alerts(folder), expected)
                report = json.loads(Path(folder, "alert-test.json").read_text())
                self.assertNotIn("chat", report["channels"])
                self.assertEqual(report["channels"]["pushover"]["status"], "ACCEPTED")
                self.assertEqual(set(m.configured_channels()), {"pushover", "email"} if email else {"pushover"})
                self.assertEqual(sender.call_count, 2 if email else 1)
                for secret in PUSH.values():
                    self.assertNotIn(secret, json.dumps(report))

    def test_unknown_channel_rejected(self):
        with patch.dict(os.environ, {"ALERT_CHANNELS": "typo"}, clear=True):
            with self.assertRaises(m.AlertConfigurationError):
                m.alert_readiness()


if __name__ == "__main__":
    unittest.main()
