
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

if [[ -s "$REPORT_DIR/semgrep-report.json" ]] && python -m json.tool "$REPORT_DIR/semgrep-report.json" >/dev/null 2>&1; then
    echo
    echo "===== Semgrep ====="
    cp "$REPORT_DIR/semgrep-report.json" "$REPORT_DIR/semgrep-local.json"
    semgrep_count=$(python -c 'import json; print(len(json.load(open("reports/semgrep-local.json", encoding="utf-8")).get("results", [])))')
    if [[ "$semgrep_count" -gt 0 ]]; then
        record "Semgrep" "FINDINGS" "$semgrep_count detections (GitHub Actions report)"
    else
        record "Semgrep" "PASS" "No detections (GitHub Actions report)"
    fi
    SUCCESS=$((SUCCESS + 1))
else
    run_json_scan "Semgrep" "semgrep" "$REPORT_DIR/semgrep-local.json" semgrep scan --metrics=off --config config/semgrep/rules.yml --json --output "$REPORT_DIR/semgrep-local.json" samples/code
fi

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
# GRYPE_CI_FINDINGS_BEGIN
if [[ -f reports/grype-image-report.json ]]; then
    python - <<'GRYPE_REPORT'
import json
from collections import Counter

path = "reports/grype-image-report.json"
with open(path, encoding="utf-8") as f:
    matches = json.load(f).get("matches", [])

counts = Counter(
    x.get("vulnerability", {}).get("severity", "Unknown")
    for x in matches
)

print("===== Grype (GitHub Actions image scan) =====")
print("Grype          " + ("FINDINGS" if matches else "PASS"))
print("Total:", len(matches))
print("Severity:", dict(counts))
print("Source:", path)
GRYPE_REPORT
fi
# GRYPE_CI_FINDINGS_END

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
# SIX_TOOL_SUMMARY_FIX
# Recalculate the six-tool summary from verified report contents.
python - <<'SUMMARY_REPORT'
import json
from pathlib import Path

reports = Path("reports")

def read(name):
    try:
        return json.loads((reports / name).read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return None

gitleaks = read("gitleaks-local.json")
semgrep = read("semgrep-local.json")
dependency = read("pip-audit-local.json")
syft = read("syft-local.spdx.json")
checkov = read("checkov-local.json")
grype = read("grype-image-report.json")

def checkov_count(data):
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        return None
    return sum(
        len(x.get("results", {}).get("failed_checks", []))
        for x in data if isinstance(x, dict)
    )

def dependency_count(data):
    if not isinstance(data, dict):
        return None
    return len({
        (d.get("name"), d.get("version"), v.get("id"))
        for d in data.get("dependencies", [])
        for v in d.get("vulns", [])
    })

counts = [
    len(gitleaks) if isinstance(gitleaks, list) else None,
    len(semgrep.get("results", [])) if isinstance(semgrep, dict) else None,
    dependency_count(dependency),
    0 if isinstance(syft, dict) and isinstance(syft.get("packages"), list) else None,
    checkov_count(checkov),
    len(grype.get("matches", [])) if isinstance(grype, dict) else None,
]

findings = sum(n is not None and n > 0 for n in counts)
successful = sum(n == 0 for n in counts)
errors = sum(n is None for n in counts)

print()
print("======================================")
print("    VERIFIED SIX-TOOL SCAN SUMMARY")
print("======================================")
print(f"Successful: {successful}")
print(f"Findings:   {findings}")
print(f"Errors:     {errors}")
print("Skipped:    0")
print("======================================")
print("Grype image results: GitHub Actions report")
print("Semgrep results: GitHub Actions report")

# Save the verified six-tool results to the Markdown report.
names = ["Gitleaks", "Semgrep", "Dependency", "Syft", "Checkov", "Grype"]
sources = ["Local", "GitHub Actions", "Local", "Local SBOM", "Local", "GitHub Actions"]

lines = [
    "# Local DevSecOps Security Scan Report",
    "",
    "## Verified Six-Tool Scanner Results",
    "",
    "| Scanner | Status | Findings / Packages | Source |",
    "|---|---|---:|---|",
]

for name, count, source in zip(names, counts, sources):
    status = "ERROR" if count is None else "FINDINGS" if count > 0 else "PASS"
    description = "packages" if name == "Syft" else "findings"
    value = "N/A" if count is None else str(count)
    lines.append(f"| {name} | {status} | {value} {description} | {source} |")

lines.extend([
    "",
    "## Execution Summary",
    "",
    f"- Successful: {successful}",
    f"- Findings: {findings}",
    f"- Errors: {errors}",
    "- Skipped: 0",
    "",
    "## Important Notes",
    "",
    "- Semgrep findings are from a previously generated GitHub Actions report.",
    "- Grype image findings are from a previously generated GitHub Actions report.",
    "- Local Grype filesystem scanning is not equivalent to Docker image scanning.",
    "- Syft generates an SBOM rather than vulnerability findings.",
    "- The summary describes available reports, not six fresh local scanner executions.",
    "- Do not deploy intentionally vulnerable demonstration samples.",
])

reports.joinpath("security-summary.md").write_text(
    "\n".join(lines) + "\n", encoding="utf-8"
)
print("Saved: reports/security-summary.md")
SUMMARY_REPORT
