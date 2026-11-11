import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import monitor as m

CFG = json.loads(Path("monitors.json").read_text())
SITE = CFG["sites"][1]


def state():
    return {"version": 1, "sites": {}, "samples": [], "events": []}


def observation(ok, at=1000):
    return {"ok": ok, "http": 200 if ok else 503, "seconds": 0.2, "reason": "OK" if ok else "HTTP 503",
            "attempts": 1 if ok else 3, "started": at - 20, "checked": at, "slow": False}


class MonitorTests(unittest.TestCase):
    def test_config(self):
        m.validate(CFG)
        bad = copy.deepcopy(CFG)
        bad["sites"][0]["url"] += "?secret=example"
        with self.assertRaises(ValueError):
            m.validate(bad)

    def test_duplicate_id_rejected(self):
        cfg = copy.deepcopy(CFG)
        cfg["sites"].append(cfg["sites"][0])
        with self.assertRaises(ValueError):
            m.validate(cfg)

    def test_first_up_no_alert_then_outage_reminder_and_recovery(self):
        cfg = dict(CFG, reminder_seconds=3600)
        s = state()
        m.transition(s, SITE, observation(True), CFG, ["chat", "email"])
        self.assertEqual(s["events"], [])
        m.transition(s, SITE, observation(False, 1300), CFG, ["chat", "email"])
        m.transition(s, SITE, observation(False, 1600), CFG, ["chat", "email"])
        self.assertEqual(len(s["events"]), 1)
        m.transition(s, SITE, observation(False, 4900), cfg, ["chat", "email"])
        self.assertIn("STILL DOWN", s["events"][-1]["subject"])
        m.transition(s, SITE, observation(True, 5200), CFG, ["chat", "email"])
        self.assertIn("RECOVERED", s["events"][-1]["subject"])
        self.assertIn("3920 seconds", s["events"][-1]["message"])
        self.assertIsNone(s["sites"][SITE["id"]]["down_since"])

    def test_initial_down_alerts(self):
        s = state()
        m.transition(s, SITE, observation(False), CFG, ["email"])
        self.assertEqual(s["events"][0]["pending"], ["email"])

    @patch("monitor.time.sleep")
    @patch("monitor.probe")
    def test_transient_failure_recovers_without_incident(self, probe, sleep):
        probe.side_effect = [observation(False), observation(True)]
        result = m.check(SITE, CFG)
        self.assertTrue(result["ok"])
        self.assertEqual(result["attempts"], 2)
        self.assertEqual(sleep.call_count, 1)

    @patch("monitor.time.sleep")
    @patch("monitor.probe", return_value=observation(False))
    def test_persistent_failure_retries_three_times(self, probe, sleep):
        result = m.check(SITE, CFG)
        self.assertFalse(result["ok"])
        self.assertEqual(probe.call_count, 3)
        self.assertEqual(sleep.call_count, 2)

    @patch("monitor.time.sleep")
    def test_failed_channel_retried_without_resending_successful_channel(self, sleep):
        s = state()
        m.queue_event(s, ["chat", "email"], "DOWN", "example", 1000)
        def fail_chat(channel, *args):
            if channel == "chat":
                raise RuntimeError("secret must never be logged")
        with patch("monitor.send", side_effect=fail_chat), patch("builtins.print") as log:
            self.assertTrue(m.deliver(s, ["chat", "email"]))
            self.assertNotIn("secret", str(log.call_args_list))
        self.assertEqual(s["events"][0]["pending"], ["chat"])
        with patch("monitor.send") as send:
            self.assertFalse(m.deliver(s, ["chat", "email"]))
            self.assertEqual(send.call_count, 1)
            self.assertEqual(send.call_args.args[0], "chat")
        self.assertEqual(s["events"][0]["pending"], [])

    @patch("monitor.time.sleep")
    def test_queue_preserves_outage_before_recovery(self, sleep):
        s = state()
        m.queue_event(s, ["email"], "DOWN", "example", 1000)
        m.queue_event(s, ["email"], "RECOVERED", "example", 1300)
        with patch("monitor.send", side_effect=RuntimeError) as send:
            self.assertTrue(m.deliver(s, ["email"]))
            self.assertEqual(send.call_count, 1)
        self.assertTrue(all(e["pending"] for e in s["events"]))

    def test_mentions(self):
        with patch.dict(os.environ, {"GOOGLE_CHAT_MENTIONS": "all,123456"}):
            self.assertIn("<users/all> <users/123456>", m.chat_payload("test", "body")["text"])
        with patch.dict(os.environ, {"GOOGLE_CHAT_MENTIONS": "person@example.com"}):
            with self.assertRaises(ValueError):
                m.chat_payload("test", "body")

    def fake_curl(self, body="Account Number", status=200, final=None, code=0):
        def run(args, **kwargs):
            Path(args[args.index("--output") + 1]).write_text(body)
            self.assertIn("--max-time", args)
            self.assertNotIn("--insecure", args)
            return subprocess.CompletedProcess(args, code, json.dumps({"http_code": status, "url_effective": final or SITE["url"]}), "")
        return run

    def test_healthy_page(self):
        with patch("monitor.subprocess.run", side_effect=self.fake_curl()):
            self.assertTrue(m.probe(SITE, CFG)["ok"])

    def test_200_error_page_not_healthy(self):
        with patch("monitor.subprocess.run", side_effect=self.fake_curl(body="Something went wrong")):
            self.assertEqual(m.probe(SITE, CFG)["reason"], "expected page text missing")

    def test_unexpected_redirect_not_healthy(self):
        with patch("monitor.subprocess.run", side_effect=self.fake_curl(final="https://unrelated.example/")):
            self.assertFalse(m.probe(SITE, CFG)["ok"])

    def test_http_error_not_healthy(self):
        with patch("monitor.subprocess.run", side_effect=self.fake_curl(status=503)):
            self.assertEqual(m.probe(SITE, CFG)["reason"], "HTTP 503")

    def test_tls_error_not_healthy(self):
        with patch("monitor.subprocess.run", side_effect=self.fake_curl(code=60)):
            self.assertEqual(m.probe(SITE, CFG)["reason"], "TLS certificate invalid")

    def test_empty_page_not_healthy(self):
        with patch("monitor.subprocess.run", side_effect=self.fake_curl(body="")):
            self.assertFalse(m.probe(SITE, CFG)["ok"])

    def test_report_and_state_round_trip(self):
        s = state()
        for site in CFG["sites"]:
            m.transition(s, site, observation(True), CFG, [])
        s["checked"] = 1000
        with tempfile.TemporaryDirectory() as folder:
            m.atomic_json(Path(folder) / "state.json", s)
            self.assertEqual(json.loads(Path(folder, "state.json").read_text()), s)
            m.report(s, CFG, folder)
            page = Path(folder, "status.html").read_text()
            self.assertIn("STALE", page)
            self.assertIn("not time-weighted uptime", page)
            self.assertIn("100.00% (1 samples)", page)

    def test_report_with_expired_samples(self):
        s = state()
        for site in CFG["sites"]:
            m.transition(s, site, observation(True), CFG, [])
        s["checked"], s["samples"] = 1000, []
        with tempfile.TemporaryDirectory() as folder:
            m.report(s, CFG, folder)
            self.assertIn("No samples in this window", Path(folder, "status.html").read_text())


if __name__ == "__main__":
    unittest.main()
