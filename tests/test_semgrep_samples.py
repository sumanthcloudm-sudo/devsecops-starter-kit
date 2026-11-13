import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from verify_semgrep_samples import EXPECTED


class SemgrepSampleVerificationTests(unittest.TestCase):
    def setUp(self):
        self.report = {
            "paths": {"scanned": list(EXPECTED)},
            "results": [
                {"path": path, "check_id": "configs.semgrep." + rule}
                for path, rule in EXPECTED.items()
            ],
            "errors": [],
        }

    def run_verifier(self, content):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_text(content, encoding="utf-8")
            return subprocess.run(
                [sys.executable, str(Path(__file__).with_name("verify_semgrep_samples.py")), str(path)],
                capture_output=True,
                text=True,
                check=False,
            )

    def test_scanned_samples_with_findings_pass(self):
        self.assertEqual(self.run_verifier(json.dumps(self.report)).returncode, 0)

    def test_missing_scanned_sample_fails(self):
        self.report["paths"]["scanned"].pop()
        result = self.run_verifier(json.dumps(self.report))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("sample was not scanned", result.stderr)

    def test_missing_expected_finding_fails(self):
        self.report["results"].pop()
        result = self.run_verifier(json.dumps(self.report))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("did not match", result.stderr)

    def test_findings_outside_vulnerable_samples_fail(self):
        self.report["results"].append({"path": "scripts/security-scan.sh", "check_id": "unexpected.rule"})
        result = self.run_verifier(json.dumps(self.report))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("outside vulnerable samples", result.stderr)

    def test_scan_errors_and_invalid_json_fail(self):
        self.report["errors"].append({"message": "scan failed"})
        self.assertNotEqual(self.run_verifier(json.dumps(self.report)).returncode, 0)
        self.assertNotEqual(self.run_verifier("{").returncode, 0)


if __name__ == "__main__":
    unittest.main()
