#!/usr/bin/env bash

set -uo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

scanner="${1:-all}"
if [[ "$scanner" != "all" && "$scanner" != "gitleaks" && "$scanner" != "semgrep" ]]; then
  echo "Usage: $0 [all|gitleaks|semgrep]" >&2
  exit 2
fi

gitleaks_config="configs/gitleaks/.gitleaks.toml"
gitleaks_report="${GITLEAKS_REPORT_PATH:-reports/gitleaks/gitleaks-report.json}"
semgrep_report="${SEMGREP_REPORT_PATH:-reports/semgrep/semgrep-report.json}"
semgrep_text_report="${SEMGREP_TEXT_REPORT_PATH:-reports/semgrep/semgrep-report.txt}"

mkdir -p "$(dirname "$gitleaks_report")" "$(dirname "$semgrep_report")" "$(dirname "$semgrep_text_report")"

overall_status=0

record_status() {
  local status="$1"
  if [[ "$status" -eq 2 ]]; then
    overall_status=2
  elif [[ "$status" -eq 1 && "$overall_status" -eq 0 ]]; then
    overall_status=1
  fi
}

run_gitleaks() {
  if ! command -v gitleaks >/dev/null 2>&1; then
    echo "Gitleaks was not found. Install an organization-approved Gitleaks release and retry." >&2
    return 2
  fi

  echo "Running Gitleaks..."
  gitleaks dir . \
    --config "$gitleaks_config" \
    --report-format json \
    --report-path "$gitleaks_report"
  local status=$?
  if [[ "$status" -eq 1 ]]; then
    echo "Gitleaks found one or more secrets. Report: $gitleaks_report" >&2
  elif [[ "$status" -ne 0 ]]; then
    echo "Gitleaks failed with exit code $status." >&2
    return 2
  else
    echo "Gitleaks completed without findings. Report: $gitleaks_report"
  fi
  return "$status"
}

run_semgrep() {
  if ! command -v semgrep >/dev/null 2>&1; then
    echo "Semgrep was not found. Install an organization-approved Semgrep CLI or use the GitHub Actions workflow." >&2
    return 2
  fi

  local python=""
  if [[ ( "${OSTYPE:-}" == msys* || "${OSTYPE:-}" == cygwin* ) ]] && command -v python >/dev/null 2>&1; then
    python="$(command -v python)"
  elif command -v python3 >/dev/null 2>&1; then
    python="$(command -v python3)"
  elif command -v python >/dev/null 2>&1; then
    python="$(command -v python)"
  fi
  if [[ -z "$python" ]]; then
    echo "Python 3 is required to validate the Semgrep JSON report." >&2
    return 2
  fi

  local json_temp text_temp status
  json_temp="$(mktemp "${semgrep_report}.tmp.XXXXXX")" || return 2
  text_temp="$(mktemp "${semgrep_text_report}.tmp.XXXXXX")" || {
    rm -f "$json_temp"
    return 2
  }
  echo "Running Semgrep..."
  local -a semgrep_args=(scan
    --config p/owasp-top-ten
    --config p/python
    --config configs/semgrep/semgrep.yml
    --metrics=off
    --strict
    --json-output "$json_temp"
    --error)
  if [[ -n "${SEMGREP_EXCLUDE:-}" ]]; then
    semgrep_args+=(--exclude "$SEMGREP_EXCLUDE")
  fi
  semgrep "${semgrep_args[@]}" . 2>&1 | tee "$text_temp"
  local -a pipeline_status=("${PIPESTATUS[@]}")
  status="${pipeline_status[0]}"
  if [[ "${pipeline_status[1]}" -ne 0 || ( "$status" -ne 0 && "$status" -ne 1 ) ]]; then
    echo "Semgrep or report capture failed (scanner exit $status); existing reports were not replaced." >&2
    if [[ ( "${OSTYPE:-}" == msys* || "${OSTYPE:-}" == cygwin* ) && ( "$status" -eq 126 || "$status" -eq 127 ) ]]; then
      echo "If Windows Application Control blocked Semgrep, request IT approval; do not bypass security policy." >&2
    fi
    rm -f "$json_temp" "$text_temp"
    return 2
  fi
  if ! "$python" - "$json_temp" "$status" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as source:
        report = json.load(source)
    if not isinstance(report, dict):
        raise ValueError("report is not an object")
    results = report.get("results")
    errors = report.get("errors")
    paths = report.get("paths")
    if not isinstance(results, list) or not isinstance(errors, list) or errors:
        raise ValueError("missing results or incomplete scan")
    if not isinstance(paths, dict) or not isinstance(paths.get("scanned"), list) or not paths["scanned"]:
        raise ValueError("no scanned files recorded")
    if bool(results) != (sys.argv[2] == "1"):
        raise ValueError("findings do not match scanner exit code")
except (OSError, ValueError) as error:
    print(f"Invalid Semgrep report: {error}", file=sys.stderr)
    sys.exit(1)
PY
  then
    echo "Semgrep did not produce a valid, complete report; existing reports were not replaced." >&2
    rm -f "$json_temp" "$text_temp"
    return 2
  fi
  if ! mv -f "$json_temp" "$semgrep_report" || ! mv -f "$text_temp" "$semgrep_text_report"; then
    echo "Could not publish both Semgrep reports; check the report paths." >&2
    rm -f "$json_temp" "$text_temp"
    return 2
  fi
  if [[ "$status" -eq 0 ]]; then
    echo "Semgrep completed without findings. Reports: $semgrep_report and $semgrep_text_report"
  elif [[ "$status" -eq 1 ]]; then
    echo "Semgrep found one or more issues. Reports: $semgrep_report and $semgrep_text_report" >&2
  fi
  return "$status"
}

if [[ "$scanner" == "all" || "$scanner" == "gitleaks" ]]; then
  run_gitleaks
  record_status "$?"
fi

if [[ "$scanner" == "all" || "$scanner" == "semgrep" ]]; then
  run_semgrep
  record_status "$?"
fi

exit "$overall_status"
