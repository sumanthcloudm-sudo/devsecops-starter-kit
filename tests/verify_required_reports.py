#!/usr/bin/env python3
"""Verify reports for scanners selected in the unified scan summary."""

import argparse
import sys
from pathlib import Path

from check_report_files import missing_report_errors


REPORTS = {
    "gitleaks": ("gitleaks/gitleaks-report.json", "gitleaks/gitleaks-report.txt"),
    "semgrep": ("semgrep/semgrep-report.json", "semgrep/semgrep-report.txt"),
    "trivy": (
        "trivy/dependency-report.json", "trivy/dependency-report.txt",
        "trivy/dependency-summary.csv", "trivy/dependency-summary.txt",
    ),
    "syft": ("syft/sbom-cyclonedx.json", "syft/sbom-spdx.json", "syft/sbom-summary.txt"),
    "grype": (
        "grype/grype-report.json", "grype/grype-report.txt",
        "grype/grype-image-report.json", "grype/grype-image-report.txt",
    ),
    "checkov": ("checkov/iac-report.json", "checkov/iac-report.txt", "checkov/summary.txt"),
}
STATES = {"PASS", "PASS (findings; gate passed)", "FAIL", "ERROR", "SKIPPED"}


def read_states(summary):
    states = {}
    for line in summary.read_text(encoding="utf-8").splitlines():
        parts = line.split(maxsplit=1)
        if not parts or parts[0] not in REPORTS:
            continue
        name = parts[0]
        if name in states or len(parts) != 2 or parts[1] not in STATES:
            raise ValueError(f"invalid or duplicate status for {name}")
        states[name] = parts[1]
    missing_states = REPORTS.keys() - states.keys()
    if missing_states:
        raise ValueError(f"missing scanner statuses: {', '.join(sorted(missing_states))}")
    return states


def verify(directory, expect_all=False):
    try:
        states = read_states(directory / "summary.txt")
        errors = []
        for name, paths in REPORTS.items():
            if states[name] == "SKIPPED":
                if expect_all:
                    errors.append(f"{name}: unexpectedly SKIPPED in an all-scanner run")
                    continue
                print(f"{name}: SKIPPED; reports not required")
                continue
            if states[name] == "ERROR":
                errors.append(f"{name}: scanner execution or report generation failed")
            errors.extend(missing_report_errors(directory / path for path in paths))
        if errors:
            for error in errors:
                print(error, file=sys.stderr)
            return 1
        print("All required reports for selected scanners are present and nonempty.")
        return 0
    except (OSError, UnicodeError, ValueError) as error:
        print(f"Report verification failed: {error}", file=sys.stderr)
        return 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", nargs="?", type=Path, default=Path("reports"))
    parser.add_argument("--expect-all", action="store_true", help="fail if any scanner is skipped")
    args = parser.parse_args()
    return verify(args.directory, args.expect_all)


if __name__ == "__main__":
    sys.exit(main())
