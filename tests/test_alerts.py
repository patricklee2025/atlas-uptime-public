import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, MagicMock
import urllib.error

import monitor as m

CHAT = {"GOOGLE_CHAT_WEBHOOK": "https://chat.googleapis.com/v1/spaces/TEST/messages?key=private-key&token=private-token",
        "GOOGLE_CHAT_MENTIONS": "all"}
EMAIL = {"SMTP_HOST": "mail.example.invalid", "EMAIL_FROM": "sender@example.invalid",
         "EMAIL_TO": "recipient@example.invalid", "SMTP_USERNAME": "test", "SMTP_PASSWORD": "private-password"}


class AlertTests(unittest.TestCase):
    def run_test(self, environment, effect=None, send_test=True):
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, environment, clear=True), \
                patch("monitor.send", side_effect=effect) as sender, contextlib.redirect_stdout(io.StringIO()) as output:
            marker = Path(folder, "state.json")
            marker.write_text('{"production":"untouched"}')
            code = m.test_alerts(folder, send_test=send_test)
            report = json.loads(Path(folder, "alert-test.json").read_text())
            markdown = Path(folder, "ALERT-TEST.md").read_text()
            self.assertEqual(marker.read_text(), '{"production":"untouched"}')
            for secret in ("private-key", "private-token", "private-password"):
                self.assertNotIn(secret, markdown + output.getvalue() + json.dumps(report))
            return code, report, sender.call_args_list

    def test_missing_channels_is_actionable_failure(self):
        code, report, calls = self.run_test({})
        self.assertEqual(code, 2)
        self.assertEqual(calls, [])
        self.assertEqual(report["channels"]["chat"]["status"], "NOT CONFIGURED")
        self.assertIn("GOOGLE_CHAT_WEBHOOK", report["channels"]["chat"]["detail"])

    def test_one_configured_channel_can_pass(self):
        code, report, calls = self.run_test(CHAT)
        self.assertEqual(code, 0)
        self.assertEqual(len(calls), 1)
        self.assertIn("TEST", calls[0].args[1])
        self.assertEqual(report["channels"]["chat"]["status"], "ACCEPTED")
        self.assertEqual(report["channels"]["email"]["status"], "NOT CONFIGURED")

    def test_partial_email_config_prevents_false_pass(self):
        code, report, calls = self.run_test({**CHAT, "EMAIL_TO": "recipient@example.invalid"})
        self.assertEqual(code, 2)
        self.assertEqual(len(calls), 1)
        self.assertEqual(report["channels"]["email"]["status"], "CONFIGURATION ERROR")

    def test_invalid_webhook_never_sent(self):
        code, report, calls = self.run_test({"GOOGLE_CHAT_WEBHOOK": "https://example.invalid/private-token"})
        self.assertEqual(code, 2)
        self.assertEqual(calls, [])

    def test_webhook_without_token_is_rejected(self):
        code, report, calls = self.run_test({"GOOGLE_CHAT_WEBHOOK": "https://chat.googleapis.com/v1/spaces/TEST/messages?key=private-key"})
        self.assertEqual(code, 2)
        self.assertEqual(calls, [])

    def test_invalid_mention_diagnostic(self):
        code, report, calls = self.run_test({**CHAT, "GOOGLE_CHAT_MENTIONS": "person@example.invalid"})
        self.assertEqual(code, 2)
        self.assertEqual(calls, [])
        self.assertIn("GOOGLE_CHAT_MENTIONS", report["channels"]["chat"]["detail"])

    def test_provider_failure_redacted_and_other_channel_continues(self):
        def send(channel, *args):
            if channel == "chat":
                raise urllib.error.HTTPError(CHAT["GOOGLE_CHAT_WEBHOOK"], 403, "private-token", {}, None)
        code, report, calls = self.run_test({**CHAT, **EMAIL}, send)
        self.assertEqual(code, 2)
        self.assertEqual(len(calls), 2)
        self.assertIn("HTTP 403", report["channels"]["chat"]["detail"])
        self.assertEqual(report["channels"]["email"]["status"], "ACCEPTED")

    def test_config_only_never_sends(self):
        code, report, calls = self.run_test(CHAT, send_test=False)
        self.assertEqual(code, 0)
        self.assertEqual(calls, [])
        self.assertEqual(report["channels"]["chat"]["status"], "READY TO TEST")

    def test_chat_transport_posts_mention_and_body(self):
        response = MagicMock()
        response.__enter__.return_value.status = 200
        with patch.dict(os.environ, CHAT, clear=True), patch("monitor.urllib.request.build_opener") as opener:
            opener.return_value.open.return_value = response
            m.send("chat", "TEST", "Example")
            request = opener.return_value.open.call_args.args[0]
            self.assertEqual(request.method, "POST")
            self.assertIn("<users/all>", json.loads(request.data)["text"])

    def test_email_transport_uses_tls_and_sends(self):
        with patch.dict(os.environ, EMAIL, clear=True), patch("monitor.smtplib.SMTP") as smtp:
            smtp.return_value.__enter__.return_value = smtp.return_value
            smtp.return_value.send_message.return_value = {}
            m.send("email", "TEST", "Example")
            smtp.return_value.starttls.assert_called_once()
            smtp.return_value.login.assert_called_once_with("test", "private-password")
            smtp.return_value.send_message.assert_called_once()

if __name__ == "__main__":
    unittest.main()
