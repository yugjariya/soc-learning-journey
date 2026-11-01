"""End-to-end checks against the reproducible synthetic evidence fixture."""
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "data" / "auth.log"


class CliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.output = Path(self.temp.name) / "reports"

    def run_cli(self, *extra, source=FIXTURE):
        return subprocess.run(
            [sys.executable, "-m", "bruteforce", "--input", str(source),
             "--output", str(self.output), *extra],
            cwd=ROOT, text=True, capture_output=True, timeout=20,
        )

    def report(self):
        return json.loads((self.output / "alerts.json").read_text(encoding="utf-8"))

    def test_demo_findings_and_evidence_outputs(self):
        completed = self.run_cli("--label", "Synthetic SSH lab")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result = self.report()
        expected = {"parsed_events": 27, "failures": 22, "successes": 5,
                    "total_lines": 28, "skipped_lines": 1, "malformed_lines": 0,
                    "alerts": 4, "unique_sources": 6}
        for key, value in expected.items():
            self.assertEqual(result["summary"][key], value, key)
        self.assertEqual({a["type"] for a in result["alerts"]},
                         {"brute_force", "password_spray", "distributed_attack", "suspicious_success"})
        self.assertEqual(result["source"]["sha256"], hashlib.sha256(FIXTURE.read_bytes()).hexdigest())
        records = [json.loads(row) for row in (self.output / "events.jsonl").read_text().splitlines()]
        original = FIXTURE.read_text().splitlines()
        self.assertEqual(len(records), 27)
        for record in records:
            self.assertEqual(record["raw"], original[record["line_number"] - 1])
        for alert in result["alerts"]:
            self.assertTrue(all(1 <= line <= len(original) for line in alert["evidence_lines"]))
        self.assertIn("Synthetic SSH lab", (self.output / "dashboard.html").read_text())
        self.assertIn("## Findings", (self.output / "investigation.md").read_text())

    def test_allowlist_serializes_and_excludes_detection_only(self):
        completed = self.run_cli("--allow", "203.0.113.10/32")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result = self.report()
        self.assertEqual(result["summary"]["parsed_events"], 27)
        self.assertEqual(result["config"]["allowlist"], ["203.0.113.10/32"])
        self.assertNotIn("_networks", result["config"])
        self.assertEqual({a["type"] for a in result["alerts"]}, {"password_spray", "distributed_attack"})

    def test_fail_on_alert_exit_code(self):
        completed = self.run_cli("--fail-on-alert")
        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertEqual(len(self.report()["alerts"]), 4)

    def test_empty_input_succeeds_without_alerts(self):
        source = Path(self.temp.name) / "empty.log"
        source.write_text("")
        completed = self.run_cli("--fail-on-alert", source=source)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(self.report()["summary"]["parsed_events"], 0)
        self.assertEqual(self.report()["alerts"], [])

    def test_missing_input_returns_actionable_error(self):
        completed = self.run_cli(source=Path(self.temp.name) / "missing.log")
        self.assertEqual(completed.returncode, 2)
        self.assertIn("error:", completed.stderr)
        self.assertNotIn("Traceback", completed.stderr)

    def test_invalid_configuration_returns_usage_error(self):
        for extra in [("--threshold", "0"), ("--allow", "invalid-ip"), ("--timezone", "+24:00")]:
            with self.subTest(extra=extra):
                completed = self.run_cli(*extra)
                self.assertEqual(completed.returncode, 2)
                self.assertNotIn("Traceback", completed.stderr)

    def test_html_escapes_untrusted_label_username_and_host(self):
        source = Path(self.temp.name) / "untrusted.log"
        payload = "<script>alert(1)</script>"
        source.write_text("\n".join(
            f"2026-10-20T09:00:0{i}Z {payload} sshd[1]: Failed password for {payload} from 192.0.2.1 port 22 ssh2"
            for i in range(5)
        ) + "\n", encoding="utf-8")
        completed = self.run_cli("--label", payload, source=source)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        output = (self.output / "dashboard.html").read_text()
        self.assertNotIn(payload, output)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", output)
        self.assertEqual(self.report()["label"], payload)


if __name__ == "__main__":
    unittest.main()
