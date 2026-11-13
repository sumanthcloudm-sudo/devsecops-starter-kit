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
        self.directory = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.config = self.root / "config.json"
        self.config.write_text(json.dumps({"fail_on": "high"}), encoding="utf-8")
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

    def run_with(self, report, scan_status=0, image=None):
        def execute(command, **kwargs):
            self.assertIs(kwargs["shell"], False)
            self.assertIsInstance(command, list)
            self.assertEqual(command[0], os.environ.get("GRYPE_BIN", "grype"))
            if command[1] == "version":
                return subprocess.CompletedProcess(command, 0)
            expected_image = image or "docker.io/library/alpine:3.10"
            self.assertEqual(command[1:], [f"registry:{expected_image}", "-o", "json"])
            self.assertTrue(kwargs["capture_output"])
            self.assertTrue(kwargs["text"])
            self.assertEqual(kwargs["env"]["GRYPE_INCLUDE_MATCHER_SUPPRESSIONS"], "true")
            self.assertNotIn("GRYPE_FAIL_ON", kwargs["env"])
            return subprocess.CompletedProcess(
                command, scan_status,
                stdout=json.dumps(report) if report is not None else "",
                stderr="scanner error" if scan_status else "",
            )
        with mock.patch.object(scanner.subprocess, "run", side_effect=execute):
            return scanner.main()

    def test_windows_batch_executables_are_rejected(self):
        for executable in ("grype.cmd", "grype.BAT"):
            with self.subTest(executable=executable), \
                 mock.patch.object(scanner.sys, "platform", "win32"), \
                 mock.patch.dict(os.environ, {"GRYPE_BIN": executable}), \
                 mock.patch.object(scanner.subprocess, "run") as run:
                self.assertEqual(scanner.main(), 2)
                run.assert_not_called()

    def test_registry_image_is_scanned_as_one_shell_free_argument(self):
        image = "docker.io/library/alpine:3.10"
        report = {"matches": [], "source": {"type": "image"}, "descriptor": {"name": "grype"}}
        self.assertEqual(self.run_with(report, image=image), 0)

    def test_configured_image_is_used_and_reported(self):
        image = "registry.example/test/image:tag"
        report = {"matches": [], "source": {"type": "image"}, "descriptor": {"name": "grype"}}
        with mock.patch.dict(os.environ, {"GRYPE_IMAGE": image}):
            self.assertEqual(self.run_with(report, image=image), 0)
        text = (self.output / "grype-report.txt").read_text(encoding="utf-8")
        self.assertIn(f"Image: {image}", text)

    def test_grype_binary_override_is_used(self):
        report = {"matches": [], "source": {"type": "image"}, "descriptor": {"name": "grype"}}
        with mock.patch.dict(os.environ, {"GRYPE_BIN": "custom-grype"}):
            self.assertEqual(self.run_with(report), 0)

    def test_threshold_and_ignored_findings_are_reported(self):
        report = {"matches": [finding("Medium")], "ignoredMatches": [finding("High")],
                  "source": {"type": "image"}, "descriptor": {"name": "grype"}}
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

    def test_default_and_configured_severity_boundaries(self):
        for severity, fails in (("Critical", True), ("High", True), ("Medium", False),
                                ("Low", False), ("Negligible", False)):
            with self.subTest(severity=severity):
                report = {"matches": [finding(severity)], "source": {"type": "image"},
                          "descriptor": {"name": "grype"}}
                text, gate = scanner.summarize(report, "high", "docker.io/library/alpine:3.10")
                self.assertEqual(gate, fails)
                self.assertIn(f"{severity.upper()}: 1", text)
                self.assertTrue(scanner.summarize(report, severity.lower(), "image:tag")[1])
                self.assertFalse(scanner.summarize(report, "none", "image:tag")[1])

    def test_failure_does_not_replace_reports(self):
        self.output.mkdir()
        for name in ("grype-report.json", "grype-report.txt"):
            (self.output / name).write_text("previous", encoding="utf-8")
        for report, status in ((None, 1), ({"matches": []}, 0)):
            with self.subTest(status=status):
                self.assertEqual(self.run_with(report, status), 2)
                self.assertEqual((self.output / "grype-report.json").read_text(), "previous")
                self.assertEqual((self.output / "grype-report.txt").read_text(), "previous")

    def test_invalid_image_and_non_image_report_fail(self):
        for image in ("", " image:tag", "image: tag"):
            with self.subTest(image=image), mock.patch.dict(os.environ, {"GRYPE_IMAGE": image}):
                self.assertEqual(scanner.main(), 2)
        with mock.patch.dict(os.environ, {"GRYPE_IMAGE": "image:tag"}):
            self.assertEqual(self.run_with({
                "matches": [], "source": {"type": "sbom"}, "descriptor": {"name": "grype"},
            }, image="image:tag"), 2)

    def test_invalid_threshold_fails(self):
        with mock.patch.dict(os.environ, {"GRYPE_FAIL_ON": "severe"}):
            self.assertEqual(scanner.main(), 2)


if __name__ == "__main__":
    unittest.main()
