#!/usr/bin/env bash
set -uo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)" || exit 1
mkdir -p "$tmp/bin" "$tmp/gitleaks" "$tmp/semgrep" "$tmp/trivy" "$tmp/syft" "$tmp/checkov"
trap 'rm -f "$tmp/summary.txt" "$tmp/bin/gitleaks" "$tmp/bin/semgrep" "$tmp/bin/trivy" "$tmp/bin/syft" "$tmp/bin/checkov" "$tmp/gitleaks/gitleaks-report.json" "$tmp/gitleaks/gitleaks-report.txt" "$tmp/semgrep/report.json" "$tmp/semgrep/report.txt" "$tmp/trivy/dependency-report.json" "$tmp/trivy/dependency-report.txt" "$tmp/trivy/dependency-summary.csv" "$tmp/trivy/dependency-summary.txt" "$tmp/checkov/iac-report.json" "$tmp/checkov/iac-report.txt" "$tmp/checkov/summary.txt"; rmdir "$tmp/bin" "$tmp/gitleaks" "$tmp/semgrep" "$tmp/trivy" "$tmp/syft" "$tmp/checkov" "$tmp" 2>/dev/null || true' EXIT
cat > "$tmp/bin/gitleaks" <<'STUB'
#!/usr/bin/env bash
if [[ "${GITLEAKS_TEST_NO_REPORT:-0}" == 1 ]]; then exit 0; fi
while [[ $# -gt 0 ]]; do
  if [[ "$1" == --report-path ]]; then printf '%s' '[{"RuleID":"test","File":"sample","StartLine":1}]' > "$2"; break; fi
  shift
done
exit 10
STUB
cat > "$tmp/bin/semgrep" <<'STUB'
#!/usr/bin/env bash
while [[ $# -gt 0 ]]; do
  if [[ "$1" == --json-output ]]; then printf '%s' '{"results":[{"path":"sample.py"}],"errors":[],"paths":{"scanned":["sample.py"]}}' > "$2"; break; fi
  shift
done
exit 1
STUB
cat > "$tmp/bin/trivy" <<'STUB'
#!/usr/bin/env bash
while [[ $# -gt 0 ]]; do
  if [[ "$1" == --output ]]; then printf '%s' '{"Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-TEST","PkgName":"test-package","InstalledVersion":"1.0","Severity":"MEDIUM"}]}]}' > "$2"; break; fi
  shift
done
STUB
cat > "$tmp/bin/syft" <<'STUB'
#!/usr/bin/env bash
exit 2
STUB
cat > "$tmp/bin/checkov" <<'STUB'
#!/usr/bin/env bash
if [[ "${CHECKOV_TEST_FAILURE:-0}" == 1 ]]; then exit 2; fi
if [[ "${CHECKOV_TEST_NO_VERSION:-0}" == 1 ]]; then
  printf '%s' '{"summary":{"parsing_errors":0},"results":{"passed_checks":[{"check_id":"test"}],"failed_checks":[]}}'
  exit 0
fi
if [[ "${CHECKOV_TEST_PASS:-0}" == 1 ]]; then
  printf '%s' '{"summary":{"parsing_errors":0,"checkov_version":"3.2.495"},"results":{"passed_checks":[{"check_id":"test"}],"failed_checks":[]}}'
  exit 0
fi
printf '%s' '{"summary":{"parsing_errors":0,"checkov_version":"3.2.495"},"results":{"passed_checks":[],"failed_checks":[{"check_id":"test"}]}}'
STUB
chmod +x "$tmp/bin/"*
export PATH="$tmp/bin:$PATH"
export GITLEAKS_REPORT_PATH="$tmp/gitleaks/gitleaks-report.json"
export SEMGREP_REPORT_PATH="$tmp/semgrep/report.json" SEMGREP_TEXT_REPORT_PATH="$tmp/semgrep/report.txt"
export TRIVY_BIN="$tmp/bin/trivy" TRIVY_REPORT_DIR="$tmp/trivy"
export SYFT_BIN="$tmp/bin/syft" SYFT_CYCLONEDX_REPORT_PATH="$tmp/syft/cdx.json" SYFT_SPDX_REPORT_PATH="$tmp/syft/spdx.json"
export GRYPE_BIN="$tmp/bin/nonexistent" GRYPE_REPORT_DIR="$tmp/grype"
export CHECKOV_REPORT_DIR="$tmp/checkov"
export SCAN_SUMMARY_PATH="$tmp/summary.txt"
bash "$root/scripts/security-scan.sh" > /dev/null 2>&1
status=$?
if [[ "$status" -ne 2 ]] || ! grep -q '^gitleaks FINDINGS' "$SCAN_SUMMARY_PATH" ||
   ! grep -q '^semgrep  FINDINGS' "$SCAN_SUMMARY_PATH" ||
   ! grep -q '^trivy    FINDINGS' "$SCAN_SUMMARY_PATH" ||
   ! grep -q '^syft     ERROR' "$SCAN_SUMMARY_PATH" ||
   ! grep -q '^grype    ERROR' "$SCAN_SUMMARY_PATH" ||
   ! grep -q '^checkov  FINDINGS' "$SCAN_SUMMARY_PATH"; then
  echo "all: failed to continue after findings and errors (exit $status)" >&2
  cat "$SCAN_SUMMARY_PATH" >&2
  exit 1
fi
if [[ ! -s "$tmp/checkov/iac-report.json" ]] ||
   ! grep -q '^test ' "$tmp/checkov/iac-report.txt" ||
   ! grep -q '^Checkov version: 3\.2\.495$' "$tmp/checkov/summary.txt" ||
   ! grep -q '^Status: FAIL$' "$tmp/checkov/summary.txt"; then
  echo "Checkov reports are missing or do not show the failed check" >&2; exit 1
fi
export TRIVY_FAIL_ON=high
bash "$root/scripts/security-scan.sh" trivy > /dev/null 2>&1
if [[ "$?" -ne 0 ]] || ! grep -q '^trivy    FINDINGS' "$SCAN_SUMMARY_PATH"; then
  echo "Trivy below-threshold finding was not reported" >&2; exit 1
fi
if ! cmp -s "$tmp/trivy/dependency-report.txt" "$tmp/trivy/dependency-summary.txt" ||
   ! grep -q '^VulnerabilityID: CVE-TEST$' "$tmp/trivy/dependency-report.txt" ||
   ! grep -q '^PkgName: test-package$' "$tmp/trivy/dependency-report.txt" ||
   ! grep -q '^InstalledVersion: 1.0$' "$tmp/trivy/dependency-report.txt" ||
   ! grep -q '^Severity: MEDIUM$' "$tmp/trivy/dependency-report.txt"; then
  echo "Trivy dependency text report is missing or incomplete" >&2; exit 1
fi
export TRIVY_FAIL_ON=medium
bash "$root/scripts/security-scan.sh" trivy > /dev/null 2>&1
if [[ "$?" -ne 1 ]]; then echo "Trivy threshold did not fail" >&2; exit 1; fi
export CHECKOV_TEST_PASS=1
bash "$root/scripts/security-scan.sh" checkov > /dev/null 2>&1
if [[ "$?" -ne 0 ]] || ! grep -q '^checkov  PASS' "$SCAN_SUMMARY_PATH" ||
   ! grep -q '^gitleaks SKIPPED' "$SCAN_SUMMARY_PATH" ||
   ! grep -q '^Status: PASS$' "$tmp/checkov/summary.txt"; then
  echo "Checkov pass or skipped status was not reported" >&2; exit 1
fi
unset CHECKOV_TEST_PASS
export CHECKOV_TEST_NO_VERSION=1
bash "$root/scripts/security-scan.sh" checkov > /dev/null 2>&1
if [[ "$?" -ne 2 ]] || ! grep -q '^checkov  ERROR' "$SCAN_SUMMARY_PATH"; then
  echo "Missing Checkov version was not rejected" >&2; exit 1
fi
unset CHECKOV_TEST_NO_VERSION
export CHECKOV_TEST_FAILURE=1
bash "$root/scripts/security-scan.sh" checkov > /dev/null 2>&1
if [[ "$?" -ne 2 ]] || ! grep -q '^checkov  ERROR' "$SCAN_SUMMARY_PATH"; then
  echo "Checkov scanner error was not reported" >&2; exit 1
fi
export GITLEAKS_TEST_NO_REPORT=1
bash "$root/scripts/security-scan.sh" gitleaks > /dev/null 2>&1
if [[ "$?" -ne 2 ]] || ! grep -q '^gitleaks ERROR' "$SCAN_SUMMARY_PATH"; then
  echo "Missing Gitleaks report was not rejected" >&2; exit 1
fi
echo "Orchestration, missing tool, scanner error, findings and severity gates: passed"
