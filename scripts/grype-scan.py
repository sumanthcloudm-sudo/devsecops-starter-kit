#!/usr/bin/env python3
"""Scan a registry container image with Grype and publish JSON and text reports."""

from collections import Counter
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parent.parent
CONFIG = ROOT / "configs" / "grype" / "config.json"
SEVERITIES = ("negligible", "low", "medium", "high", "critical")


def summarize(report, threshold, image):
    if not isinstance(report, dict) or not isinstance(report.get("matches"), list):
        raise ValueError("Grype report has no matches array")
    if not isinstance(report.get("descriptor"), dict) or report["descriptor"].get("name") != "grype":
        raise ValueError("Grype report descriptor is missing")
    source = report.get("source")
    if not isinstance(source, dict) or source.get("type") != "image":
        raise ValueError("Grype report source is not a container image")
    ignored = report.get("ignoredMatches", [])
    if ignored is None:
        ignored = []
    if not isinstance(ignored, list):
        raise ValueError("Grype ignored matches are invalid")
    findings = [(item, "active") for item in report["matches"]] + [(item, "ignored by Grype") for item in ignored]
    counts = Counter()
    details = []
    for item, status in findings:
        if not isinstance(item, dict) or not isinstance(item.get("vulnerability"), dict) or not isinstance(item.get("artifact"), dict):
            raise ValueError("Grype report contains an invalid match")
        vulnerability, artifact = item["vulnerability"], item["artifact"]
        if not all(isinstance(value, str) and value for value in (vulnerability.get("id"), artifact.get("name"), artifact.get("version"))):
            raise ValueError("Grype match is missing a vulnerability ID, package name or version")
        severity = str(vulnerability.get("severity") or "unknown").lower()
        if severity not in SEVERITIES:
            severity = "unknown"
        counts[severity] += 1
        fix = vulnerability.get("fix") or {}
        if not isinstance(fix, dict) or not isinstance(fix.get("versions", []), list):
            raise ValueError("Grype match has invalid fix information")
        versions = ", ".join(str(version) for version in fix.get("versions", [])) or "not available"
        details.extend([
            f"Vulnerability: {vulnerability['id']}",
            f"Package: {artifact['name']}",
            f"Installed version: {artifact['version']}",
            f"Severity: {severity.upper()}",
            f"Fixed versions: {versions}",
            f"Status: {status}",
            "",
        ])
    gate = threshold != "none" and any(
        counts[level] for level in SEVERITIES[SEVERITIES.index(threshold):]
    )
    text = [
        "Grype container image vulnerability scan",
        f"Image: {image}",
        f"Findings: {len(findings)} (active: {len(report['matches'])}, ignored by Grype: {len(ignored)})",
        f"Failure threshold: {threshold.upper()}",
    ]
    text.extend(f"{severity.upper()}: {counts[severity]}" for severity in reversed(SEVERITIES))
    text.extend([f"UNKNOWN: {counts['unknown']}", ""])
    text.extend(details if details else ["No vulnerabilities found.", ""])
    return "\n".join(text) + "\n", gate


def main():
    try:
        with CONFIG.open(encoding="utf-8") as source:
            config = json.load(source)
        if not isinstance(config, dict):
            raise ValueError("Grype configuration must be a JSON object")
        threshold = os.environ.get("GRYPE_FAIL_ON", config.get("fail_on", "high"))
        if not isinstance(threshold, str):
            raise ValueError("Grype failure threshold must be a string")
        threshold = threshold.lower()
        if threshold not in (*SEVERITIES, "none"):
            raise ValueError("GRYPE_FAIL_ON must be negligible, low, medium, high, critical or none")
        image = os.environ.get("GRYPE_IMAGE", "docker.io/library/alpine:3.10")
        if not image or image != image.strip() or any(character.isspace() for character in image):
            raise ValueError("GRYPE_IMAGE must be a non-empty image reference without whitespace")

        executable = os.environ.get("GRYPE_BIN") or shutil.which("grype")
        if not executable:
            raise ValueError("Grype was not found; install an approved release or set GRYPE_BIN")
        if sys.platform == "win32" and Path(executable).suffix.lower() in (".bat", ".cmd"):
            raise ValueError("Grype must be a native executable, not a Windows batch file")
        report_dir = (ROOT / os.environ.get("GRYPE_REPORT_DIR", "reports/grype")).resolve()
        report_dir.mkdir(parents=True, exist_ok=True)
        json_path, text_path = report_dir / "grype-report.json", report_dir / "grype-report.txt"
        if json_path.is_dir() or text_path.is_dir():
            raise ValueError("Grype report destinations must be files")

        version = subprocess.run([executable, "version"], cwd=ROOT, check=False, shell=False)  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-tainted-env-args.dangerous-subprocess-use-tainted-env-args
        if version.returncode:
            raise ValueError(f"Grype version command failed with exit code {version.returncode}")
        scan_environment = os.environ.copy()
        scan_environment.pop("GRYPE_FAIL_ON", None)
        scan_environment["GRYPE_INCLUDE_MATCHER_SUPPRESSIONS"] = "true"
        scan = subprocess.run(
            [executable, f"registry:{image}", "-o", "json"],  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-tainted-env-args.dangerous-subprocess-use-tainted-env-args
            cwd=ROOT, capture_output=True, text=True, encoding="utf-8",
            env=scan_environment, check=False, shell=False,
        )
        if scan.returncode:
            raise ValueError(f"Grype scan failed with exit code {scan.returncode}")
        report = json.loads(scan.stdout)
        text, gate = summarize(report, threshold, image)
        pending = []
        try:
            for destination, content in (
                (json_path, json.dumps(report, ensure_ascii=False, indent=2) + "\n"),
                (text_path, text),
            ):
                with tempfile.NamedTemporaryFile(
                    mode="w", encoding="utf-8", newline="\n", dir=report_dir,
                    prefix=f".{destination.name}.", delete=False,
                ) as target:
                    pending.append(Path(target.name))
                    target.write(content)
            for temporary, destination in zip(pending, (json_path, text_path)):
                os.replace(temporary, destination)
        finally:
            for temporary in pending:
                temporary.unlink(missing_ok=True)
        print(f"Grype reports: {json_path} and {text_path}")
        if gate:
            print(f"Grype security gate failed at {threshold.upper()}.", file=sys.stderr)
            return 1
        return 0
    except (OSError, ValueError, TypeError, KeyError) as error:
        print(f"Grype scan or report generation failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
