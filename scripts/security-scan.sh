
#!/usr/bin/env bash

# ==========================================================
# LOCAL DEVSECOPS STARTER KIT
# Security scanning automation
# ==========================================================

set -u
set -o pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR" || exit 2

REPORT_DIR="reports"
mkdir -p "$REPORT_DIR"

SUMMARY="$REPORT_DIR/security-summary.md"

SUCCESS=0
FINDINGS=0
ERRORS=0
SKIPPED=0

# ----------------------------------------------------------
# Initialize summary
# ----------------------------------------------------------

cat > "$SUMMARY" <<EOF
# Local DevSecOps Security Scan Report

Generated: $(date -u '+%Y-%m-%d %H:%M UTC')

Repository: $(basename "$ROOT_DIR")

## Scanner Results

| Scanner | Status | Report |
|---|---|---|
EOF

record() {
    local name="$1"
    local status="$2"
    local details="$3"

    printf '| %s | %s | %s |\n' \
        "$name" "$status" "$details" >> "$SUMMARY"

    printf '%-14s %-12s %s\n' \
        "$name" "$status" "$details"
}

has_tool() {
    command -v "$1" >/dev/null 2>&1
}

# ----------------------------------------------------------
# Generic JSON scanner runner
# ----------------------------------------------------------

run_json_scan() {
    local name="$1"
    local tool="$2"
    local report="$3"
    shift 3

    echo
    echo "===== $name ====="

    if ! has_tool "$tool"; then
        record "$name" "SKIPPED" "$tool not installed"
        SKIPPED=$((SKIPPED + 1))
        return
    fi

    "$@" > "reports/${name,,}.log" 2>&1
    local rc=$?

    if [[ ! -s "$report" ]]; then
        record "$name" "ERROR" \
            "No report generated; see reports/${name,,}.log"
        ERRORS=$((ERRORS + 1))
        return
    fi

    if ! python -m json.tool "$report" >/dev/null 2>&1; then
        record "$name" "ERROR" \
            "Invalid JSON report; see reports/${name,,}.log"
        ERRORS=$((ERRORS + 1))
        return
    fi

    if [[ "$rc" -eq 0 ]]; then
        record "$name" "PASS" "$report"
        SUCCESS=$((SUCCESS + 1))
    else
        record "$name" "FINDINGS" \
            "$report (scanner exit code $rc)"
        FINDINGS=$((FINDINGS + 1))
    fi
}

# ----------------------------------------------------------
# 1. GITLEAKS - SECRET SCANNING
# ----------------------------------------------------------

run_json_scan \
    "Gitleaks" \
    "gitleaks" \
    "$REPORT_DIR/gitleaks-local.json" \
    gitleaks dir samples/code \
    --config config/gitleaks/gitleaks.toml \
    --report-format json \
    --report-path "$REPORT_DIR/gitleaks-local.json"

# ----------------------------------------------------------
# 2. SEMGREP - STATIC CODE ANALYSIS
# ----------------------------------------------------------

run_json_scan \
    "Semgrep" \
    "semgrep" \
    "$REPORT_DIR/semgrep-local.json" \
    semgrep scan \
    --metrics=off \
    --config config/semgrep/rules.yml \
    --json \
    --output "$REPORT_DIR/semgrep-local.json" \
    samples/code

# ----------------------------------------------------------
# 3. PIP-AUDIT - DEPENDENCY SCANNING
# ----------------------------------------------------------

run_json_scan \
    "Dependency" \
    "pip-audit" \
    "$REPORT_DIR/pip-audit-local.json" \
    pip-audit \
    -r samples/code/requirements.txt \
    --format json \
    --output "$REPORT_DIR/pip-audit-local.json"

# ----------------------------------------------------------
# 4. SYFT - SBOM GENERATION
# ----------------------------------------------------------

run_json_scan \
    "Syft" \
    "syft" \
    "$REPORT_DIR/syft-local.spdx.json" \
    syft dir:samples \
    -o spdx-json="$REPORT_DIR/syft-local.spdx.json"

# ----------------------------------------------------------
# 5. CHECKOV - INFRASTRUCTURE SECURITY
# ----------------------------------------------------------

run_json_scan \
    "Checkov" \
    "checkov" \
    "$REPORT_DIR/checkov-local.json" \
    checkov \
    -d samples/terraform \
    --framework terraform \
    -o json

# ----------------------------------------------------------
# 6. GRYPE - CONTAINER / FILESYSTEM SCANNING
# ----------------------------------------------------------

echo
echo "===== Grype ====="

if ! has_tool grype; then

    record "Grype" "SKIPPED" "Grype not installed"
    SKIPPED=$((SKIPPED + 1))

elif has_tool docker && docker info >/dev/null 2>&1; then

    echo "Docker Engine available."
    echo "Building sample Docker image..."

    if docker build \
        -t devsecops-starter-local:scan \
        -f samples/docker/Dockerfile \
        samples/docker \
        > "$REPORT_DIR/docker-build.log" 2>&1; then

        grype docker:devsecops-starter-local:scan \
            -o json \
            > "$REPORT_DIR/grype-local.json" \
            2> "$REPORT_DIR/grype.log"

        rc=$?

    else
        rc=1
    fi

    if [[ -s "$REPORT_DIR/grype-local.json" ]] &&
       python -m json.tool "$REPORT_DIR/grype-local.json" >/dev/null 2>&1; then

        if [[ "$rc" -eq 0 ]]; then
            record "Grype" "COMPLETE" \
                "Docker image report generated"
        else
            record "Grype" "FINDINGS" \
                "Docker image report generated; review findings"
        fi

        SUCCESS=$((SUCCESS + 1))

    else
        record "Grype" "ERROR" \
            "Docker scan failed; see reports/docker-build.log or grype.log"
        ERRORS=$((ERRORS + 1))
    fi

else

    echo "Docker Engine unavailable."
    echo "Using Grype filesystem scanning instead."

    grype dir:samples/docker \
        -o json \
        > "$REPORT_DIR/grype-local.json" \
        2> "$REPORT_DIR/grype.log"

    rc=$?

    if [[ -s "$REPORT_DIR/grype-local.json" ]] &&
       python -m json.tool "$REPORT_DIR/grype-local.json" >/dev/null 2>&1; then

        if [[ "$rc" -eq 0 ]]; then
            record "Grype" "COMPLETE" \
                "Filesystem scan; reports/grype-local.json"
        else
            record "Grype" "FINDINGS" \
                "Filesystem report generated; review findings"
        fi

        SUCCESS=$((SUCCESS + 1))

    else
        record "Grype" "ERROR" \
            "Filesystem scan failed; see reports/grype.log"
        ERRORS=$((ERRORS + 1))
    fi

fi

# ----------------------------------------------------------
# EXECUTION SUMMARY
# ----------------------------------------------------------

cat >> "$SUMMARY" <<EOF

## Execution Summary

| Result | Count |
|---|---:|
| Successful scans | $SUCCESS |
| Scans reporting findings | $FINDINGS |
| Execution errors | $ERRORS |
| Skipped scans | $SKIPPED |

## Report Locations

- Gitleaks: reports/gitleaks-local.json
- Semgrep: reports/semgrep-local.json
- Dependency: reports/pip-audit-local.json
- Syft: reports/syft-local.spdx.json
- Checkov: reports/checkov-local.json
- Grype: reports/grype-local.json

## Interpretation

PASS:
Scanner completed successfully.

FINDINGS:
Scanner produced a report but returned a non-zero exit code.
Review the report to determine the reason.

COMPLETE:
Grype generated a valid scan report. Review it for vulnerabilities.

ERROR:
Scanner failed or did not produce a valid report.

SKIPPED:
Required scanner was unavailable.

IMPORTANT:
A successful scan does not mean that the application
or container has zero vulnerabilities.

Filesystem scanning is not equivalent to scanning
a built Docker image.

## Recommended Actions

1. Review Critical and High vulnerabilities.
2. Investigate exposed credentials.
3. Upgrade vulnerable dependencies where fixes exist.
4. Review Semgrep insecure coding patterns.
5. Remediate Checkov infrastructure findings.
6. Review the generated SBOM.
7. Validate container images in CI/CD before release.

Do not deploy intentionally vulnerable demonstration samples.
EOF

# ----------------------------------------------------------
# FINAL CONSOLE OUTPUT
# ----------------------------------------------------------

echo
echo "======================================"
echo "       DEVSECOPS SCAN SUMMARY"
echo "======================================"

echo "Successful: $SUCCESS"
echo "Findings:   $FINDINGS"
echo "Errors:     $ERRORS"
echo "Skipped:    $SKIPPED"

echo "--------------------------------------"
echo "Report: $SUMMARY"
echo "======================================"

if [[ "$ERRORS" -gt 0 ]]; then
    exit 2
fi

exit 0
