#!/usr/bin/env python3
"""Verify that real scans detected the intentionally vulnerable fixtures."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPORTS = ROOT / "reports"


def load(path):
    with (REPORTS / path).open(encoding="utf-8") as source:
        return json.load(source)


def verify():
    leaks = load("gitleaks/gitleaks-report.json")
    if not any(item.get("RuleID") == "test-only-synthetic-secret" and
               item.get("File", "").replace("\\", "/").endswith("samples/vulnerable-code/secrets-example.txt")
               for item in leaks):
        raise ValueError("Gitleaks did not detect the synthetic secret")
    value = (ROOT / "samples/vulnerable-code/secrets-example.txt").read_text().split('"')[1]
    for path in ("gitleaks/gitleaks-report.json", "gitleaks/gitleaks-report.txt"):
        if value in (REPORTS / path).read_text(encoding="utf-8"):
            raise ValueError("Gitleaks report contains the synthetic secret")

    trivy = load("trivy/dependency-report.json")
    vulnerabilities = [item for result in trivy["Results"] for item in result.get("Vulnerabilities") or []]
    if not any(v.get("PkgName", "").endswith("log4j-core") and
               v.get("VulnerabilityID") == "CVE-2021-44228" for v in vulnerabilities):
        raise ValueError("Trivy did not detect the Log4Shell sample")
    cdx, spdx = load("syft/sbom-cyclonedx.json"), load("syft/sbom-spdx.json")
    for packages, version_field in ((cdx["components"], "version"), (spdx["packages"], "versionInfo")):
        if not any(p.get("name", "").endswith("log4j-core") and p.get(version_field) == "2.14.1" for p in packages):
            raise ValueError("SBOM is missing the sample dependency")
    grype = load("grype/grype-report.json")
    if grype.get("source", {}).get("type") != "image" or not grype.get("matches"):
        raise ValueError("Grype did not report vulnerabilities from an image scan")
    checkov = load("checkov/checkov-report.json")
    ids = {item["check_id"] for item in checkov["results"]["failed_checks"]}
    missing = {"CKV_AWS_19", "CKV_AWS_24", "CKV_AWS_53"} - ids
    if missing:
        raise ValueError(f"Checkov did not detect expected checks: {', '.join(sorted(missing))}")
    print("Gitleaks, Trivy, Syft, Grype image and Checkov sample reports verified.")


if __name__ == "__main__":
    try:
        verify()
    except (OSError, ValueError, TypeError, KeyError) as error:
        print(f"Sample verification failed: {error}", file=sys.stderr)
        sys.exit(1)
