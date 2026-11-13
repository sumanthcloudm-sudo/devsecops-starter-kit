import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import DEFAULT, patch

import verify_scan_reports


TEST_DIR = Path(__file__).resolve().parent
EXPECTED_REPORTS = (
    "gitleaks/gitleaks-report.json", "gitleaks/gitleaks-report.txt",
    "semgrep/semgrep-report.json", "semgrep/semgrep-report.txt",
    "trivy/dependency-report.json", "trivy/dependency-report.txt",
    "trivy/dependency-summary.csv", "trivy/dependency-summary.txt",
    "syft/sbom-cyclonedx.json", "syft/sbom-spdx.json", "syft/sbom-summary.txt",
    "grype/grype-report.json", "grype/grype-report.txt",
    "grype/grype-image-report.json", "grype/grype-image-report.txt",
    "checkov/iac-report.json", "checkov/iac-report.txt", "checkov/summary.txt",
)


class RequiredReportTests(unittest.TestCase):
    def run_verifier(self, omitted=(), states=None, empty=(), expect_all=False):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            scanner_states = {
                "gitleaks": "PASS", "semgrep": "PASS", "trivy": "PASS",
                "syft": "PASS", "grype": "PASS", "checkov": "PASS",
            }
            scanner_states.update(states or {})
            exit_code = 2 if "ERROR" in scanner_states.values() else (
                1 if "FAIL" in scanner_states.values() else 0
            )
            (root / "summary.txt").write_text(
                "Security scan summary\n" +
                "".join(f"{name} {state}\n" for name, state in scanner_states.items()) +
                f"Exit code: {exit_code}\n", encoding="utf-8",
            )
            for name in EXPECTED_REPORTS:
                if name in omitted:
                    continue
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("" if name in empty else "report\n", encoding="utf-8")
            command = [sys.executable, str(TEST_DIR / "verify_required_reports.py"), str(root)]
            if expect_all:
                command.append("--expect-all")
            return subprocess.run(
                command,
                capture_output=True, text=True, check=False,
            )

    def test_all_reports_present_with_security_gate_failure(self):
        self.assertEqual(self.run_verifier().returncode, 0)
        result = self.run_verifier(states={"checkov": "FAIL"})
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_and_empty_reports_are_listed(self):
        for path in EXPECTED_REPORTS:
            with self.subTest(path=path):
                result = self.run_verifier(omitted=(path,))
                self.assertEqual(result.returncode, 1)
                self.assertIn(path, result.stderr.replace("\\", "/"))
        result = self.run_verifier(empty=("syft/sbom-summary.txt",))
        self.assertEqual(result.returncode, 1)
        self.assertIn("sbom-summary.txt", result.stderr)

    def test_all_missing_reports_are_reported(self):
        result = self.run_verifier(omitted=("semgrep/semgrep-report.txt", "syft/sbom-summary.txt"))
        self.assertEqual(result.returncode, 1)
        self.assertIn("semgrep-report.txt", result.stderr)
        self.assertIn("sbom-summary.txt", result.stderr)

    def test_intentionally_skipped_scanner_does_not_require_reports(self):
        result = self.run_verifier(
            omitted=("syft/sbom-cyclonedx.json", "syft/sbom-spdx.json", "syft/sbom-summary.txt"),
            states={"syft": "SKIPPED"},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("syft: SKIPPED", result.stdout)

    def test_sample_verification_skips_only_the_unselected_scanner(self):
        states = dict.fromkeys(("gitleaks", "trivy", "syft", "grype", "checkov"), "PASS")
        states["syft"] = "SKIPPED"
        with patch.multiple(
            verify_scan_reports, verify_gitleaks=DEFAULT, verify_trivy=DEFAULT,
            verify_syft=DEFAULT, verify_grype=DEFAULT, verify_checkov=DEFAULT,
        ) as checks:
            verify_scan_reports.verify(states)
        checks["verify_syft"].assert_not_called()
        for name in ("gitleaks", "trivy", "grype", "checkov"):
            checks[f"verify_{name}"].assert_called_once_with()

    def test_all_scanner_job_rejects_unexpected_skip(self):
        result = self.run_verifier(states={"syft": "SKIPPED"}, expect_all=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("syft: unexpectedly SKIPPED", result.stderr)

    def test_scanner_error_does_not_pass_with_stale_reports(self):
        result = self.run_verifier(states={"checkov": "ERROR"})
        self.assertEqual(result.returncode, 1)
        self.assertIn("checkov: scanner execution", result.stderr)

    def test_invalid_scanner_status_fails(self):
        result = self.run_verifier(states={"checkov": "UNKNOWN"})
        self.assertEqual(result.returncode, 1)
        self.assertIn("invalid or duplicate status for checkov", result.stderr)

    def test_explicit_report_paths_are_checked_individually(self):
        names = ("scan.json", "scan.txt", "summary.txt")
        for missing in (None, *names):
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as temporary:
                paths = [Path(temporary) / name for name in names]
                for path in paths:
                    if path.name != missing:
                        path.write_text("report\n", encoding="utf-8")
                result = subprocess.run(
                    [sys.executable, str(TEST_DIR / "check_report_files.py"), *map(str, paths)],
                    capture_output=True, text=True, check=False,
                )
                self.assertEqual(result.returncode, 0 if missing is None else 1, result.stderr)
                if missing:
                    self.assertIn(missing, result.stderr)
        with tempfile.TemporaryDirectory() as temporary:
            empty = Path(temporary) / "empty.txt"
            empty.write_text("", encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(TEST_DIR / "check_report_files.py"), str(empty)],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("empty.txt", result.stderr)

    def test_dedicated_workflows_check_each_report_and_always_upload(self):
        workflows = {
            "semgrep.yml": (
                "Verify required Semgrep reports", "Upload Semgrep reports",
                ("semgrep-reports/semgrep-report.json", "semgrep-reports/semgrep-report.txt",
                 "semgrep-reports/summary.txt"),
            ),
            "syft-sbom.yml": (
                "Verify required Syft reports", "Upload SBOM reports",
                ("syft-reports/sbom-cyclonedx.json", "syft-reports/sbom-spdx.json",
                 "syft-reports/sbom-summary.txt", "syft-reports/summary.txt",
                 "syft-reports/provenance.json"),
            ),
            "grype.yml": (
                "Verify required Grype reports", "Upload reports",
                ("reports/grype/grype-report.json", "reports/grype/grype-report.txt",
                 "reports/grype/grype-image-report.json", "reports/grype/grype-image-report.txt",
                 "reports/grype/summary.txt"),
            ),
        }
        for filename, (verify_name, upload_name, reports) in workflows.items():
            with self.subTest(workflow=filename):
                workflow = (TEST_DIR.parent / ".github" / "workflows" / filename).read_text(
                    encoding="utf-8"
                )
                verify = workflow.split(f"      - name: {verify_name}\n", 1)[1]
                verify = verify.split("      - name:", 1)[0]
                upload = workflow.split(f"      - name: {upload_name}\n", 1)[1]
                self.assertIn("if: always() &&", verify)
                self.assertIn("steps.scan.outcome != 'skipped'", verify)
                self.assertIn("python3 tests/check_report_files.py", verify)
                for report in reports:
                    self.assertIn(report, verify)
                self.assertIn("if: always()", upload)
                self.assertIn("if-no-files-found: error", upload)
        self.assertIn(
            'if [[ "${{ steps.provenance.outcome }}" == "success" ]]; then',
            (TEST_DIR.parent / ".github" / "workflows" / "syft-sbom.yml").read_text(
                encoding="utf-8"
            ),
        )

    def test_upload_and_verification_run_after_failed_scan(self):
        workflow = (TEST_DIR.parent / ".github" / "workflows" / "security-scan.yml").read_text(
            encoding="utf-8"
        )
        verify = workflow.split("      - name: Verify real sample and dependency reports\n", 1)[1]
        verify, upload = verify.split("      - name: Upload reports\n", 1)
        self.assertIn("if: always() && steps.scan.outcome != 'skipped'", verify)
        self.assertIn("python3 tests/verify_required_reports.py --expect-all", verify)
        self.assertIn("python3 tests/verify_scan_reports.py reports/summary.txt", verify)
        self.assertIn("^semgrep[[:space:]]+SKIPPED$", verify)
        self.assertIn("if: always()", upload)
        self.assertIn("path: reports/", upload)
        self.assertIn("if-no-files-found: error", upload)


if __name__ == "__main__":
    unittest.main()
