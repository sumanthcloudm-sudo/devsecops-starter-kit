import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("grype_scan", ROOT / "scripts" / "grype-scan.py")
scanner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner)


def finding(severity):
    return {
        "vulnerability": {"id": "CVE-test", "severity": severity, "fix": {"versions": ["2.0"]}},
        "artifact": {"name": "sample", "version": "1.0"},
    }


class GrypeScanTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        (self.root / "sbom.json").write_text(json.dumps({
            "bomFormat": "CycloneDX",
            "components": [{"type": "library", "name": "sample", "version": "1.0"}],
        }), encoding="utf-8")
        self.config = self.root / "config.json"
        self.config.write_text(json.dumps({"sbom": "sbom.json", "fail_on": "high"}), encoding="utf-8")
        self.output = self.root / "reports"
        environment = mock.patch.dict(os.environ, {"GRYPE_REPORT_DIR": str(self.output)}, clear=True)
        environment.start()
        self.addCleanup(environment.stop)
        for attribute, value in (("ROOT", self.root), ("CONFIG", self.config)):
            patcher = mock.patch.object(scanner, attribute, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        executable = mock.patch.object(scanner.shutil, "which", return_value="grype")
        executable.start()
        self.addCleanup(executable.stop)

    def run_with(self, report, scan_status=0):
        def execute(command, **kwargs):
            if command[-1] == "version":
                return subprocess.CompletedProcess(command, 0)
            self.assertEqual(kwargs["env"]["GRYPE_INCLUDE_MATCHER_SUPPRESSIONS"], "true")
            if report is not None:
                json.dump(report, kwargs["stdout"])
            return subprocess.CompletedProcess(command, scan_status)
        with mock.patch.object(scanner.subprocess, "run", side_effect=execute):
            return scanner.main()

    def test_threshold_and_ignored_findings_are_reported(self):
        report = {"matches": [finding("Medium")], "ignoredMatches": [finding("High")],
                  "source": {"type": "sbom"}, "descriptor": {"name": "grype"}}
        self.assertEqual(self.run_with(report), 1)
        data = (self.output / "grype-report.json").read_text(encoding="utf-8")
        text = (self.output / "grype-report.txt").read_text(encoding="utf-8")
        self.assertEqual(json.loads(data), report)
        self.assertEqual(data, json.dumps(report, ensure_ascii=False, indent=2) + "\n")
        self.assertIn("Findings: 2 (active: 1, ignored by Grype: 1)", text)
        self.assertIn("HIGH: 1", text)
        self.assertIn("MEDIUM: 1", text)
        self.assertIn("Fixed versions: 2.0", text)
        with mock.patch.dict(os.environ, {"GRYPE_FAIL_ON": "critical"}):
            self.assertEqual(self.run_with(report), 0)

    def test_failure_does_not_replace_reports(self):
        self.output.mkdir()
        for name in ("grype-report.json", "grype-report.txt"):
            (self.output / name).write_text("previous", encoding="utf-8")
        for report, status in ((None, 1), ({"matches": []}, 0)):
            with self.subTest(status=status):
                self.assertEqual(self.run_with(report, status), 2)
                self.assertEqual((self.output / "grype-report.json").read_text(), "previous")
                self.assertEqual((self.output / "grype-report.txt").read_text(), "previous")

    def test_missing_empty_sbom_and_invalid_threshold_fail(self):
        (self.root / "sbom.json").unlink()
        self.assertEqual(scanner.main(), 2)
        (self.root / "sbom.json").write_text('{"bomFormat":"CycloneDX","components":[]}', encoding="utf-8")
        self.assertEqual(scanner.main(), 2)
        with mock.patch.dict(os.environ, {"GRYPE_FAIL_ON": "severe"}):
            self.assertEqual(scanner.main(), 2)


if __name__ == "__main__":
    unittest.main()
