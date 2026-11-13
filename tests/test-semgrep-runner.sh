#!/usr/bin/env bash
set -uo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
temp_dir="$(mktemp -d)" || exit 1
mkdir -p "$temp_dir/bin" "$temp_dir/reports" "$temp_dir/diagnostics"
trap 'for dir in "$temp_dir"/diagnostics/semgrep-diagnostics.*; do if [[ -d "$dir" ]]; then rm -f "$dir/stderr.txt" "$dir/rejected.json"; rmdir "$dir"; fi; done; rm -f "$temp_dir/bin/semgrep" "$temp_dir/reports/report.json" "$temp_dir/reports/report.txt" "$temp_dir/reports/summary.txt" "$temp_dir/reports/log"; rmdir "$temp_dir/bin" "$temp_dir/reports" "$temp_dir/diagnostics" "$temp_dir"' EXIT

cat > "$temp_dir/bin/semgrep" <<'STUB'
#!/usr/bin/env bash
if [[ -n "${SCAN_EXPECT_EXCLUDE:-}" ]]; then
  found=0
  for ((i = 1; i < $#; i++)); do
    if [[ "${!i}" == "--exclude" ]]; then
      j=$((i + 1))
      if [[ "${!j}" == "$SCAN_EXPECT_EXCLUDE" ]]; then found=1; fi
    fi
  done
  if [[ "$found" -ne 1 ]]; then exit 2; fi
fi
while [[ $# -gt 0 ]]; do
  if [[ "$1" == "--json-output" ]]; then
    output="$2"
    break
  fi
  shift
done
case "$SCAN_CASE" in
  clean) printf '%s' '{"results":[],"errors":[],"paths":{"scanned":["file.py"]}}' > "$output"; echo 'warning test-sensitive-value' >&2; exit 0 ;;
  finding) printf '%s' '{"results":[{"check_id":"test","path":"scripts/grype-scan.py"}],"errors":[],"paths":{"scanned":["scripts/grype-scan.py"]}}' > "$output"; exit 1 ;;
  sample-finding) printf '%s' '{"results":[{"check_id":"test","path":"samples/vulnerable-code/command-injection.py"}],"errors":[],"paths":{"scanned":["samples/vulnerable-code/command-injection.py"]}}' > "$output"; exit 1 ;;
  mixed-findings) printf '%s' '{"results":[{"check_id":"test","path":"samples/vulnerable-code/command-injection.py"},{"check_id":"test","path":"scripts/source.py"}],"errors":[],"paths":{"scanned":["samples/vulnerable-code/command-injection.py","scripts/source.py"]}}' > "$output"; exit 1 ;;
  malformed) printf '%s' '{"results":' > "$output"; exit 0 ;;
  unreadable) rm -f "$output"; exit 0 ;;
  missing-results) printf '%s' '{"errors":[]}' > "$output"; exit 0 ;;
  invalid-results) printf '%s' '{"results":{},"errors":[]}' > "$output"; exit 0 ;;
  missing-errors) printf '%s' '{"results":[]}' > "$output"; exit 0 ;;
  invalid-errors) printf '%s' '{"results":[],"errors":{}}' > "$output"; exit 0 ;;
  errors) printf '%s' '{"results":[],"errors":[{"type":"Syntax error","message":"test-sensitive-value"}],"paths":{"scanned":["file.py"]}}' > "$output"; echo 'syntax test-sensitive-value' >&2; exit 0 ;;
  no-files) printf '%s' '{"results":[],"errors":[],"paths":{"scanned":[]}}' > "$output"; exit 0 ;;
  mismatch) printf '%s' '{"results":[],"errors":[],"paths":{"scanned":["file.py"]}}' > "$output"; exit 1 ;;
  mismatch-findings) printf '%s' '{"results":[{"check_id":"test"}],"errors":[],"paths":{"scanned":["file.py"]}}' > "$output"; exit 0 ;;
  scanner-error) printf '%s' '{"results":[],"errors":[{"type":"SemgrepError"}]}' > "$output"; exit 7 ;;
  blocked) exit 1 ;;
  failed) exit 2 ;;
esac
STUB
chmod +x "$temp_dir/bin/semgrep"

export PATH="$temp_dir/bin:$PATH"
export SEMGREP_REPORT_PATH="$temp_dir/reports/report.json"
export SEMGREP_TEXT_REPORT_PATH="$temp_dir/reports/report.txt"
export SCAN_SUMMARY_PATH="$temp_dir/reports/summary.txt"
export RUNNER_TEMP="$temp_dir/diagnostics"
for case_name in clean finding sample-finding mixed-findings malformed unreadable missing-results invalid-results missing-errors invalid-errors errors no-files mismatch mismatch-findings scanner-error blocked failed; do
  printf 'previous JSON' > "$SEMGREP_REPORT_PATH"
  printf 'previous text' > "$SEMGREP_TEXT_REPORT_PATH"
  export SCAN_CASE="$case_name"
  bash "$repo_root/scripts/security-scan.sh" semgrep >"$temp_dir/reports/log" 2>&1
  status=$?
  if [[ ! -s "$SCAN_SUMMARY_PATH" ]]; then
    echo "$case_name: isolated scan summary was not generated" >&2
    exit 1
  fi
  expected=2
  if [[ "$case_name" == clean ]]; then expected=0; fi
  if [[ "$case_name" == finding ]]; then expected=1; fi
  if [[ "$case_name" == sample-finding ]]; then expected=1; fi
  if [[ "$case_name" == mixed-findings ]]; then expected=1; fi
  if [[ "$status" -ne "$expected" ]]; then
    echo "$case_name: expected exit $expected, got $status" >&2
    exit 1
  fi
  if [[ "$expected" -eq 2 ]]; then
    if [[ "$(cat "$SEMGREP_REPORT_PATH")" != 'previous JSON' || "$(cat "$SEMGREP_TEXT_REPORT_PATH")" != 'previous text' ]]; then
      echo "$case_name: previous reports were changed" >&2
      exit 1
    fi
    if ! grep -q '^semgrep  ERROR$' "$SCAN_SUMMARY_PATH"; then
      echo "$case_name: scanner error was not recorded" >&2
      exit 1
    fi
    diagnostic_dirs=("$RUNNER_TEMP"/semgrep-diagnostics.*)
    if [[ "${OSTYPE:-}" == msys* || "${OSTYPE:-}" == cygwin* ]]; then
      if [[ -d "${diagnostic_dirs[0]}" ]] ||
         ! grep -Fq 'Raw Semgrep diagnostics were not retained' "$temp_dir/reports/log"; then
        echo "$case_name: unsafe Windows diagnostic retention" >&2
        exit 1
      fi
    else
      if [[ ${#diagnostic_dirs[@]} -ne 1 || ! -d "${diagnostic_dirs[0]}" ]]; then
        echo "$case_name: private diagnostics were not retained" >&2
        exit 1
      fi
      permissions="$(stat -c '%a' "${diagnostic_dirs[0]}" 2>/dev/null || stat -f '%Lp' "${diagnostic_dirs[0]}")"
      if [[ "$permissions" != 700 ]]; then
        echo "$case_name: diagnostics directory is not private" >&2
        exit 1
      fi
      if [[ "$case_name" != unreadable && "$case_name" != blocked && "$case_name" != failed && ! -s "${diagnostic_dirs[0]}/rejected.json" ]]; then
        echo "$case_name: rejected JSON was not retained" >&2
        exit 1
      fi
    fi
    case "$case_name" in
      malformed|unreadable) message="unreadable or invalid JSON" ;;
      missing-results|invalid-results) message="missing or invalid results array" ;;
      missing-errors|invalid-errors) message="missing or invalid errors array" ;;
      errors) message="non-empty errors array" ;;
      *) message="" ;;
    esac
    if [[ -n "$message" ]] && ! grep -Fq "$message" "$temp_dir/reports/log"; then
      echo "$case_name: expected diagnostic was not logged" >&2
      exit 1
    fi
    if [[ "$case_name" == errors ]]; then
      if ! grep -Fq 'recognized types: Syntax error' "$temp_dir/reports/log" ||
         ! grep -Fq 'possible categories: parsing' "$temp_dir/reports/log" ||
         grep -Fq 'test-sensitive-value' "$temp_dir/reports/log"; then
        echo "$case_name: unsafe or incomplete diagnostics" >&2
        exit 1
      fi
      if [[ "${OSTYPE:-}" != msys* && "${OSTYPE:-}" != cygwin* ]] &&
         { ! grep -Fq 'test-sensitive-value' "${diagnostic_dirs[0]}/stderr.txt" ||
           ! grep -Fq 'test-sensitive-value' "${diagnostic_dirs[0]}/rejected.json"; }; then
        echo "$case_name: raw diagnostics were not retained" >&2
        exit 1
      fi
    fi
    if [[ "${OSTYPE:-}" != msys* && "${OSTYPE:-}" != cygwin* ]]; then
      rm -f "${diagnostic_dirs[0]}/stderr.txt" "${diagnostic_dirs[0]}/rejected.json"
      rmdir "${diagnostic_dirs[0]}"
    fi
  elif [[ "$(cat "$SEMGREP_REPORT_PATH")" == 'previous JSON' || "$(cat "$SEMGREP_TEXT_REPORT_PATH")" == 'previous text' || ! -s "$SEMGREP_TEXT_REPORT_PATH" ]]; then
    echo "$case_name: fresh reports were not published" >&2
    exit 1
  fi
  if [[ "$case_name" == clean ]] &&
     { ! grep -Fq 'Semgrep stderr captured; possible categories: other' "$temp_dir/reports/log" ||
       grep -Fq 'test-sensitive-value' "$temp_dir/reports/log"; }; then
    echo "$case_name: scanner stderr was not safely reported" >&2
    exit 1
  fi
  scanner_exit=0
  case "$case_name" in
    finding|sample-finding|mixed-findings|mismatch|blocked) scanner_exit=1 ;;
    failed) scanner_exit=2 ;;
    scanner-error) scanner_exit=7 ;;
  esac
  if ! grep -Fq "Semgrep scanner exit code: $scanner_exit" "$temp_dir/reports/log"; then
    echo "$case_name: scanner exit code was not logged" >&2
    exit 1
  fi
  echo "$case_name: passed"
done

export RUNNER_TEMP="$temp_dir/diagnostics/test-sensitive-value/missing" SCAN_CASE=clean
bash "$repo_root/scripts/security-scan.sh" semgrep >/dev/null 2>"$temp_dir/reports/log"
status=$?
if [[ "$status" -ne 2 ]] ||
   ! grep -Fxq 'Could not create a private Semgrep diagnostic directory.' "$temp_dir/reports/log" ||
   grep -Fq 'test-sensitive-value' "$temp_dir/reports/log" ||
   grep -Fq "$temp_dir" "$temp_dir/reports/log" ||
   ! grep -q '^semgrep  ERROR$' "$SCAN_SUMMARY_PATH"; then
  echo "diagnostic directory creation failure leaked a path or was not reported safely" >&2
  exit 1
fi

export RUNNER_TEMP="$temp_dir/reports" SCAN_CASE=clean
bash "$repo_root/scripts/security-scan.sh" semgrep >"$temp_dir/reports/log" 2>&1
if [[ "$?" -ne 2 ]] || ! grep -Fq 'diagnostic directory must be outside report directories' "$temp_dir/reports/log"; then
  echo "diagnostic directory inside reports was not rejected" >&2
  exit 1
fi

export RUNNER_TEMP="$temp_dir/diagnostics"
export SCAN_CASE=clean SEMGREP_EXCLUDE=samples/vulnerable-code SCAN_EXPECT_EXCLUDE=samples/vulnerable-code
bash "$repo_root/scripts/security-scan.sh" semgrep >/dev/null 2>&1
if [[ "$?" -ne 0 ]]; then
  echo "configured exclusion was not passed to Semgrep" >&2
  exit 1
fi
echo "configured exclusion: passed"
