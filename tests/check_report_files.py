#!/usr/bin/env python3
"""Check that each explicitly listed report exists and is nonempty."""

import argparse
import sys
from pathlib import Path


def missing_report_errors(paths):
    return [
        f"missing or empty report: {path}"
        for path in paths
        if not path.is_file() or path.stat().st_size == 0
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", type=Path)
    args = parser.parse_args()
    try:
        errors = missing_report_errors(args.paths)
    except OSError as error:
        print(f"Report verification failed: {error}", file=sys.stderr)
        return 1
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print("All specified reports are present and nonempty.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
