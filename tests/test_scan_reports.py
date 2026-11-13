import os
import subprocess
import textwrap
import unittest
from pathlib import Path

from verify_scan_reports import verify_leaks


class GitleaksSampleVerificationTests(unittest.TestCase):
    def test_expected_fixture_passes(self):
        verify_leaks([{"RuleID": "test-only-synthetic-secret",
                       "File": "samples/vulnerable-code/secrets-example.txt"}])

    def test_missing_or_unexpected_findings_fail(self):
        fixture = {"RuleID": "test-only-synthetic-secret",
                   "File": "samples/vulnerable-code/secrets-example.txt"}
        for findings in ([], [fixture, {"RuleID": "other", "File": "src/app.py"}],
                         [fixture, fixture], [{**fixture, "File": None}],
                         [{**fixture, "File": "other/" + fixture["File"]}],
                         [{**fixture, "RuleID": "other"}]):
            with self.subTest(findings=findings), self.assertRaises(ValueError):
                verify_leaks(findings)


class SecurityWorkflowTests(unittest.TestCase):
    def test_scan_exit_handling(self):
        workflow = (Path(__file__).resolve().parent.parent / ".github/workflows/security-scan.yml").read_text()
        block = workflow.split("      - name: Run all security checks\n", 1)[1]
        block = block.split("        run: |\n", 1)[1].split("\n      - name:", 1)[0]
        command = "bash() { return \"$SCAN_EXIT\"; }\n" + textwrap.dedent(block)
        for status, expected in ((0, 0), (1, 0), (2, 1), (127, 1)):
            with self.subTest(status=status):
                result = subprocess.run(
                    ["bash", "-e", "-c", command],
                    env={**os.environ, "SCAN_EXIT": str(status)},
                    check=False,
                )
                self.assertEqual(result.returncode, expected)
