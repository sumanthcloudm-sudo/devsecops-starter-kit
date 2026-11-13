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
  case "${OSTYPE:-}" in
    msys*|cygwin*|win32*)
      echo "Do not run the Windows semgrep.exe from this shell; Windows Application Control may block it." >&2
      echo "Use the documented interactive Docker command with an IT-approved installation, or run this script inside WSL with Semgrep installed there." >&2
      return 2
      ;;
  esac

  if ! command -v semgrep >/dev/null 2>&1; then
    echo "Semgrep was not found in this Linux/WSL environment." >&2
    echo "Install it through an organization-approved package source, or use the official semgrep/semgrep container through approved Docker." >&2
    return 2
  fi

  echo "Running Semgrep..."
  semgrep scan \
    --config p/owasp-top-ten \
    --config p/python \
    --config configs/semgrep/semgrep.yml \
    --metrics=off \
    --json-output "$semgrep_report" \
    --error \
    . 2>&1 | tee "$semgrep_text_report"
  local status="${PIPESTATUS[0]}"
  if [[ "$status" -eq 0 ]]; then
    echo "Semgrep completed without findings. Reports: $semgrep_report and $semgrep_text_report"
  elif [[ "$status" -eq 1 ]]; then
    echo "Semgrep found one or more issues. Reports: $semgrep_report and $semgrep_text_report" >&2
  else
    echo "Semgrep failed with exit code $status. Check the text report and runtime configuration." >&2
    return 2
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
