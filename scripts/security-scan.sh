#!/usr/bin/env bash
# Run available DevSecOps scanners and write reports under reports/.
# Findings are recorded; scanner findings do not stop the remaining checks.
# Non-zero exit means a scanner could not execute or produce a valid report.

set -uo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
REPORT_DIR="$ROOT_DIR/reports"
mkdir -p "$REPORT_DIR"

FAILED=0
SKIPPED=0
PASSED=0

log() { printf '\n[%s] %s\n' "$1" "$2"; }
skip_check() { SKIPPED=$((SKIPPED + 1)); log "SKIP" "$1"; }
has() { command -v "$1" >/dev/null 2>&1; }

# Gitleaks: report-only mode for deliberately fake test credentials.
if has gitleaks; then
  log "RUN" "Gitleaks secret scan"
  gitleaks dir samples/code --config config/gitleaks/gitleaks.toml --report-format json --report-path "$REPORT_DIR/gitleaks-local.json" --exit-code 0
  rc=$?
  if [[ -s "$REPORT_DIR/gitleaks-local.json" ]] && python -m json.tool "$REPORT_DIR/gitleaks-local.json" >/dev/null; then PASSED=$((PASSED + 1)); else FAILED=$((FAILED + 1)); log "ERROR" "Gitleaks failed to create valid JSON (exit $rc)"; fi
else skip_check "Gitleaks (install gitleaks)"; fi

# Semgrep: findings are saved as JSON and the other checks continue.
if has semgrep; then
  log "RUN" "Semgrep static analysis"
  semgrep scan --config p/python --config config/semgrep/rules.yml --json --output "$REPORT_DIR/semgrep-local.json" samples/code
  rc=$?
  if [[ -s "$REPORT_DIR/semgrep-local.json" ]] && python -m json.tool "$REPORT_DIR/semgrep-local.json" >/dev/null; then PASSED=$((PASSED + 1)); else FAILED=$((FAILED + 1)); log "ERROR" "Semgrep failed to create valid JSON (exit $rc)"; fi
else skip_check "Semgrep (install semgrep)"; fi

# pip-audit uses a non-zero status when it finds vulnerabilities; report that separately.
if has pip-audit; then
  log "RUN" "pip-audit dependency scan"
  pip-audit -r samples/code/requirements.txt --format json --output "$REPORT_DIR/pip-audit-local.json"
  rc=$?
  if [[ -s "$REPORT_DIR/pip-audit-local.json" ]] && python -m json.tool "$REPORT_DIR/pip-audit-local.json" >/dev/null; then
    PASSED=$((PASSED + 1))
    log "OK" "pip-audit report generated (exit $rc; inspect report for findings)"
  else FAILED=$((FAILED + 1)); log "ERROR" "pip-audit failed to create valid JSON (exit $rc)"; fi
else skip_check "pip-audit (install pip-audit)"; fi

if has syft; then
  log "RUN" "Syft SBOM generation"
  syft dir:. -o spdx-json="$REPORT_DIR/syft-local.spdx.json"
  rc=$?
  if [[ -s "$REPORT_DIR/syft-local.spdx.json" ]] && python -m json.tool "$REPORT_DIR/syft-local.spdx.json" >/dev/null; then PASSED=$((PASSED + 1)); else FAILED=$((FAILED + 1)); log "ERROR" "Syft failed to create valid SPDX JSON (exit $rc)"; fi
else skip_check "Syft (install syft)"; fi

if has docker && has grype; then
  log "RUN" "Build sample Docker image"
  if docker build -t devsecops-sample:local -f samples/docker/Dockerfile samples/docker; then
    log "RUN" "Grype container scan"
    grype devsecops-sample:local -o json > "$REPORT_DIR/grype-local.json"
    rc=$?
    if [[ -s "$REPORT_DIR/grype-local.json" ]] && python -m json.tool "$REPORT_DIR/grype-local.json" >/dev/null; then PASSED=$((PASSED + 1)); log "OK" "Grype report generated (exit $rc; findings are recorded)"; else FAILED=$((FAILED + 1)); log "ERROR" "Grype failed to create valid JSON (exit $rc)"; fi
  else FAILED=$((FAILED + 1)); log "ERROR" "Docker image build failed; Grype was not run"; fi
else skip_check "Container scan (requires Docker and Grype)"; fi

if has checkov; then
  log "RUN" "Checkov IaC scan"
  checkov -d samples/terraform --framework terraform -o json --soft-fail > "$REPORT_DIR/checkov-local.json"
  rc=$?
  if [[ -s "$REPORT_DIR/checkov-local.json" ]] && python -m json.tool "$REPORT_DIR/checkov-local.json" >/dev/null; then PASSED=$((PASSED + 1)); else FAILED=$((FAILED + 1)); log "ERROR" "Checkov failed to create valid JSON (exit $rc)"; fi
else skip_check "Checkov (install checkov)"; fi

printf '\n========================================\nDevSecOps Starter Kit scan summary\nCompleted: %s\nSkipped: %s\nErrors: %s\nReports: %s\n========================================\n' "$PASSED" "$SKIPPED" "$FAILED" "$REPORT_DIR"
(( FAILED == 0 )) || exit 1
exit 0
