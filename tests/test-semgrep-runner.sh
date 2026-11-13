#!/usr/bin/env bash
set -uo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
temp_dir="$(mktemp -d)" || exit 1
mkdir -p "$temp_dir/bin" "$temp_dir/reports"
trap 'rm -f "$temp_dir/bin/semgrep" "$temp_dir/reports/report.json" "$temp_dir/reports/report.txt"; rmdir "$temp_dir/bin" "$temp_dir/reports" "$temp_dir"' EXIT

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
  clean) printf '%s' '{"results":[],"errors":[],"paths":{"scanned":["file.py"]}}' > "$output"; exit 0 ;;
  finding) printf '%s' '{"results":[{"check_id":"test","path":"scripts/grype-scan.py"}],"errors":[],"paths":{"scanned":["scripts/grype-scan.py"]}}' > "$output"; exit 1 ;;
  sample-finding) printf '%s' '{"results":[{"check_id":"test","path":"samples/vulnerable-code/command-injection.py"}],"errors":[],"paths":{"scanned":["samples/vulnerable-code/command-injection.py"]}}' > "$output"; exit 1 ;;
  mixed-findings) printf '%s' '{"results":[{"check_id":"test","path":"samples/vulnerable-code/command-injection.py"},{"check_id":"test","path":"scripts/source.py"}],"errors":[],"paths":{"scanned":["samples/vulnerable-code/command-injection.py","scripts/source.py"]}}' > "$output"; exit 1 ;;
  malformed) printf '%s' '{"results":' > "$output"; exit 0 ;;
  errors) printf '%s' '{"results":[],"errors":[{"message":"scan failed"}],"paths":{"scanned":["file.py"]}}' > "$output"; exit 0 ;;
  no-files) printf '%s' '{"results":[],"errors":[],"paths":{"scanned":[]}}' > "$output"; exit 0 ;;
  mismatch) printf '%s' '{"results":[],"errors":[],"paths":{"scanned":["file.py"]}}' > "$output"; exit 1 ;;
  mismatch-findings) printf '%s' '{"results":[{"check_id":"test"}],"errors":[],"paths":{"scanned":["file.py"]}}' > "$output"; exit 0 ;;
  blocked) exit 1 ;;
  failed) exit 2 ;;
esac
STUB
chmod +x "$temp_dir/bin/semgrep"

export PATH="$temp_dir/bin:$PATH"
export SEMGREP_REPORT_PATH="$temp_dir/reports/report.json"
export SEMGREP_TEXT_REPORT_PATH="$temp_dir/reports/report.txt"
for case_name in clean finding sample-finding mixed-findings malformed errors no-files mismatch mismatch-findings blocked failed; do
  printf 'previous JSON' > "$SEMGREP_REPORT_PATH"
  printf 'previous text' > "$SEMGREP_TEXT_REPORT_PATH"
  export SCAN_CASE="$case_name"
  bash "$repo_root/scripts/security-scan.sh" semgrep >/dev/null 2>&1
  status=$?
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
  elif [[ "$(cat "$SEMGREP_REPORT_PATH")" == 'previous JSON' ]]; then
    echo "$case_name: fresh report was not published" >&2
    exit 1
  fi
  echo "$case_name: passed"
done

export SCAN_CASE=clean SEMGREP_EXCLUDE=samples/vulnerable-code SCAN_EXPECT_EXCLUDE=samples/vulnerable-code
bash "$repo_root/scripts/security-scan.sh" semgrep >/dev/null 2>&1
if [[ "$?" -ne 0 ]]; then
  echo "configured exclusion was not passed to Semgrep" >&2
  exit 1
fi
echo "configured exclusion: passed"
