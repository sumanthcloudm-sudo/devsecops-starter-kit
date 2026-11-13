#!/usr/bin/env python3
import json
import sys
from pathlib import Path


EXPECTED = {
    "samples/vulnerable-code/sql-injection.py": "devsecops-starter.python.sql-injection-concatenation",
    "samples/vulnerable-code/hardcoded-credentials.py": "devsecops-starter.python.hardcoded-credential",
    "samples/vulnerable-code/insecure-cryptography.py": "devsecops-starter.python.insecure-hash",
    "samples/vulnerable-code/command-injection.py": "devsecops-starter.python.shell-command-injection",
}


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: verify_semgrep_samples.py REPORT.json", file=sys.stderr)
        return 2
    try:
        with Path(sys.argv[1]).open(encoding="utf-8") as source:
            report = json.load(source)
        if not isinstance(report, dict):
            raise ValueError("report is not an object")
        paths = report.get("paths")
        results = report.get("results")
        errors = report.get("errors")
        if not isinstance(paths, dict) or not isinstance(paths.get("scanned"), list):
            raise ValueError("report has no scanned-file list")
        if not isinstance(results, list) or not isinstance(errors, list) or errors:
            raise ValueError("report is incomplete or contains scan errors")
        if any(not isinstance(result, dict) or not isinstance(result.get("path"), str) for result in results):
            raise ValueError("report contains an invalid result")
        scanned = set(paths["scanned"])
        for path, rule in EXPECTED.items():
            if path not in scanned:
                raise ValueError(f"sample was not scanned: {path}")
            if not any(
                isinstance(result, dict)
                and result.get("path") == path
                and isinstance(result.get("check_id"), str)
                and (result["check_id"] == rule or result["check_id"].endswith("." + rule))
                for result in results
            ):
                raise ValueError(f"expected rule {rule} did not match {path}")
        unexpected = next((result["path"] for result in results if result["path"] not in EXPECTED), None)
        if unexpected is not None:
            raise ValueError(f"unexpected finding outside vulnerable samples: {unexpected}")
    except (OSError, ValueError, TypeError) as error:
        print(f"Semgrep sample verification failed: {error}", file=sys.stderr)
        return 1
    print("All four vulnerable Python samples were scanned and matched their custom rules.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
