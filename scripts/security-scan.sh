#!/usr/bin/env bash

set -uo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

scanner="${1:-all}"
if [[ "$scanner" != "all" && "$scanner" != "gitleaks" && "$scanner" != "semgrep" && "$scanner" != "trivy" && "$scanner" != "syft" && "$scanner" != "grype" && "$scanner" != "checkov" ]] || [[ $# -gt 1 ]]; then
  echo "Usage: $0 [all|gitleaks|semgrep|trivy|syft|grype|checkov]" >&2
  exit 2
fi

gitleaks_config="configs/gitleaks/.gitleaks.toml"
gitleaks_report="${GITLEAKS_REPORT_PATH:-reports/gitleaks/gitleaks-report.json}"
semgrep_report="${SEMGREP_REPORT_PATH:-reports/semgrep/semgrep-report.json}"
semgrep_text_report="${SEMGREP_TEXT_REPORT_PATH:-reports/semgrep/semgrep-report.txt}"
trivy_target="${TRIVY_TARGET:-samples/vulnerable-dependencies}"
trivy_report_dir="${TRIVY_REPORT_DIR:-reports/trivy}"
trivy_report="$trivy_report_dir/dependency-report.json"
trivy_csv="$trivy_report_dir/dependency-summary.csv"
trivy_text="$trivy_report_dir/dependency-summary.txt"
trivy_report_text="$trivy_report_dir/dependency-report.txt"
syft_target="${SYFT_TARGET:-samples/vulnerable-dependencies}"
syft_cyclonedx="${SYFT_CYCLONEDX_REPORT_PATH:-reports/syft/sbom-cyclonedx.json}"
syft_spdx="${SYFT_SPDX_REPORT_PATH:-reports/syft/sbom-spdx.json}"

mkdir -p "$(dirname "$gitleaks_report")" "$(dirname "$semgrep_report")" "$(dirname "$semgrep_text_report")" "$(dirname "$trivy_report")"

overall_status=0
scan_findings=0
python_cmd=""
if [[ ( "${OSTYPE:-}" == msys* || "${OSTYPE:-}" == cygwin* ) ]] && command -v python >/dev/null 2>&1; then
  python_cmd="$(command -v python)"
elif command -v python3 >/dev/null 2>&1; then
  python_cmd="$(command -v python3)"
elif command -v python >/dev/null 2>&1; then
  python_cmd="$(command -v python)"
fi

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
  if [[ -z "$python_cmd" ]]; then echo "Python 3 is required for Gitleaks report validation." >&2; return 2; fi

  local json_temp text_temp status
  json_temp="$(mktemp "${gitleaks_report}.tmp.XXXXXX")" || return 2
  text_temp="$(mktemp "${gitleaks_report}.txt.tmp.XXXXXX")" || { rm -f "$json_temp"; return 2; }
  echo "Running Gitleaks..."
  gitleaks dir . \
    --config "$gitleaks_config" \
    --redact=100 --exit-code 10 \
    --report-format json \
    --report-path "$json_temp"
  status=$?
  if [[ "$status" -ne 0 && "$status" -ne 10 ]]; then
    echo "Gitleaks failed with exit code $status." >&2
    rm -f "$json_temp" "$text_temp"; return 2
  fi
  if ! "$python_cmd" - "$json_temp" "$text_temp" "$status" <<'PY'
import json
import sys
try:
    with open(sys.argv[1], encoding="utf-8") as source:
        findings = json.load(source)
    if not isinstance(findings, list) or bool(findings) != (sys.argv[3] == "10"):
        raise ValueError("invalid or inconsistent findings")
    with open(sys.argv[2], "w", encoding="utf-8") as output:
        output.write(f"Gitleaks findings: {len(findings)} (secret values redacted)\n")
        for finding in findings:
            if not isinstance(finding, dict):
                raise ValueError("invalid finding")
            output.write(f"{finding.get('RuleID', 'unknown')} {finding.get('File', 'unknown')}:{finding.get('StartLine', '?')}\n")
except (OSError, ValueError, TypeError) as error:
    print(f"Invalid Gitleaks report: {error}", file=sys.stderr)
    sys.exit(1)
PY
  then rm -f "$json_temp" "$text_temp"; return 2; fi
  if ! mv -f "$json_temp" "$gitleaks_report" || ! mv -f "$text_temp" "${gitleaks_report%.json}.txt"; then
    rm -f "$json_temp" "$text_temp"; return 2
  fi
  if [[ "$status" -eq 10 ]]; then scan_findings=1; return 1; fi
  return 0
}

run_grype() {
  local python=""
  if [[ ( "${OSTYPE:-}" == msys* || "${OSTYPE:-}" == cygwin* ) ]] && command -v python >/dev/null 2>&1; then
    python="$(command -v python)"
  elif command -v python3 >/dev/null 2>&1; then
    python="$(command -v python3)"
  elif command -v python >/dev/null 2>&1; then
    python="$(command -v python)"
  fi
  if [[ -z "$python" ]]; then
    echo "Python 3 is required to run Grype and generate reports." >&2
    return 2
  fi
  "$python" scripts/grype-scan.py
  local status=$?
  if [[ "$status" -eq 0 || "$status" -eq 1 ]]; then return "$status"; fi
  return 2
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
  semgrep "${semgrep_args[@]}" . > /dev/null 2>&1
  status=$?
  if [[ "$status" -ne 0 && "$status" -ne 1 ]]; then
    echo "Semgrep failed (scanner exit $status); check its configuration and network access. Existing reports were not replaced." >&2
    if [[ ( "${OSTYPE:-}" == msys* || "${OSTYPE:-}" == cygwin* ) && ( "$status" -eq 126 || "$status" -eq 127 ) ]]; then
      echo "If Windows Application Control blocked Semgrep, request IT approval; do not bypass security policy." >&2
    fi
    rm -f "$json_temp" "$text_temp"
    return 2
  fi
  "$python" - "$json_temp" "$status" "$text_temp" <<'PY'
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
    if not all(isinstance(result, dict) and isinstance(result.get("path"), str) for result in results):
        raise ValueError("invalid result entry")
    with open(sys.argv[3], "w", encoding="utf-8") as output:
        output.write(f"Semgrep findings: {len(results)}\n")
        for result in results:
            output.write(f"{result.get('check_id', '?')} {result['path']}:{result.get('start', {}).get('line', '?')} "
                         f"{result.get('extra', {}).get('severity', '?')}\n")
except (OSError, ValueError) as error:
    print(f"Invalid Semgrep report: {error}", file=sys.stderr)
    sys.exit(2)
sys.exit(1 if results else 0)
PY
  local validation_status=$?
  if [[ "$validation_status" -gt 1 ]]; then
    echo "Semgrep did not produce a valid, complete report; existing reports were not replaced." >&2
    rm -f "$json_temp" "$text_temp"
    return 2
  fi
  if ! mv -f "$json_temp" "$semgrep_report" || ! mv -f "$text_temp" "$semgrep_text_report"; then
    echo "Could not publish both Semgrep reports; check the report paths." >&2
    rm -f "$json_temp" "$text_temp"
    return 2
  fi
  if [[ "$validation_status" -eq 1 ]]; then
    scan_findings=1
    echo "Semgrep found issues. Reports: $semgrep_report and $semgrep_text_report" >&2
    return 1
  elif [[ "$status" -eq 0 ]]; then
    echo "Semgrep completed without findings. Reports: $semgrep_report and $semgrep_text_report"
  fi
  return 0
}

run_trivy() {
  local trivy="${TRIVY_BIN:-}"
  local python=""
  local json_temp csv_temp text_temp report_text_temp count

  case "${TRIVY_FAIL_ON:-high}" in
    none|low|medium|high|critical) ;;
    *) echo "TRIVY_FAIL_ON must be none, low, medium, high or critical." >&2; return 2 ;;
  esac
  if [[ -z "$trivy" ]]; then
    trivy="$(command -v trivy || true)"
    if [[ -z "$trivy" && ( "${OSTYPE:-}" == msys* || "${OSTYPE:-}" == cygwin* ) && -n "${LOCALAPPDATA:-}" ]]; then
      trivy="$(cygpath -u "$LOCALAPPDATA")/Microsoft/WinGet/Packages/AquaSecurity.Trivy_Microsoft.Winget.Source_8wekyb3d8bbwe/trivy.exe"
    fi
  elif [[ ( "${OSTYPE:-}" == msys* || "${OSTYPE:-}" == cygwin* ) && "$trivy" =~ ^[A-Za-z]: ]]; then
    trivy="$(cygpath -u "$trivy")"
  fi

  if [[ -z "$trivy" || ! -x "$trivy" ]]; then
    echo "Trivy was not found. Install an approved release or set TRIVY_BIN to its executable." >&2
    return 2
  fi
  if [[ ! -e "$trivy_target" ]]; then
    echo "Trivy target does not exist: $trivy_target" >&2
    return 2
  fi
  if [[ ( "${OSTYPE:-}" == msys* || "${OSTYPE:-}" == cygwin* ) ]] && command -v python >/dev/null 2>&1; then
    python="$(command -v python)"
  elif command -v python3 >/dev/null 2>&1; then
    python="$(command -v python3)"
  fi
  if [[ -z "$python" ]]; then
    echo "Python 3 is required to generate the Trivy CSV summary." >&2
    return 2
  fi

  json_temp="$(mktemp "${trivy_report}.tmp.XXXXXX")" || return 2
  csv_temp="$(mktemp "${trivy_csv}.tmp.XXXXXX")" || {
    rm -f "$json_temp"
    return 2
  }
  text_temp="$(mktemp "${trivy_text}.tmp.XXXXXX")" || {
    rm -f "$json_temp" "$csv_temp"
    return 2
  }
  report_text_temp="$(mktemp "${trivy_report_text}.tmp.XXXXXX")" || {
    rm -f "$json_temp" "$csv_temp" "$text_temp"
    return 2
  }
  echo "Running Trivy on $trivy_target..."
  if ! "$trivy" fs --scanners vuln --format json --output "$json_temp" --exit-code 0 "$trivy_target"; then
    echo "Trivy scan failed; existing reports were not replaced." >&2
    rm -f "$json_temp" "$csv_temp" "$text_temp" "$report_text_temp"
    return 2
  fi
  if ! count="$("$python" - "$json_temp" "$csv_temp" "$text_temp" <<'PY'
import csv
import json
import sys
from collections import Counter

with open(sys.argv[1], encoding="utf-8") as source:
    report = json.load(source)
results = report.get("Results")
if not isinstance(results, list) or not results:
    raise SystemExit("Trivy reported no dependency results; check the target and scan output.")
findings = [v for result in results for v in (result.get("Vulnerabilities") or [])]
with open(sys.argv[2], "w", encoding="utf-8", newline="") as output:
    writer = csv.DictWriter(output, fieldnames=["PkgName", "InstalledVersion", "VulnerabilityID", "Severity"], quoting=csv.QUOTE_ALL)
    writer.writeheader()
    for finding in findings:
        writer.writerow({name: finding.get(name, "") for name in writer.fieldnames})
counts = Counter(finding.get("Severity") or "UNKNOWN" for finding in findings)
with open(sys.argv[3], "w", encoding="utf-8") as output:
    output.write("Trivy dependency vulnerability summary\n")
    output.write(f"Target: {report.get('ArtifactName', 'unknown')}\n")
    output.write(f"Findings: {len(findings)}\n")
    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"):
        output.write(f"{severity}: {counts.pop(severity, 0)}\n")
    for severity, total in sorted(counts.items()):
        output.write(f"{severity}: {total}\n")
    for finding in findings:
        output.write("\n")
        for field in ("VulnerabilityID", "PkgName", "InstalledVersion", "FixedVersion", "Severity"):
            output.write(f"{field}: {finding.get(field) or 'Not available'}\n")
    if not findings:
        output.write("\nNo vulnerabilities found.\n")
print(len(findings))
PY
)"; then
    echo "Could not generate the Trivy summary; existing reports were not replaced." >&2
    rm -f "$json_temp" "$csv_temp" "$text_temp" "$report_text_temp"
    return 2
  fi
  if ! cp "$text_temp" "$report_text_temp"; then
    echo "Could not prepare the Trivy text report; existing reports were not replaced." >&2
    rm -f "$json_temp" "$csv_temp" "$text_temp" "$report_text_temp"
    return 2
  fi
  if ! mv -f "$json_temp" "$trivy_report" || ! mv -f "$csv_temp" "$trivy_csv" || ! mv -f "$text_temp" "$trivy_text" || ! mv -f "$report_text_temp" "$trivy_report_text"; then
    echo "Could not publish all Trivy reports; check the report directory." >&2
    rm -f "$json_temp" "$csv_temp" "$text_temp" "$report_text_temp"
    return 2
  fi
  echo "Trivy found $count vulnerabilities. Reports: $trivy_report, $trivy_report_text, $trivy_csv and $trivy_text"
  if [[ "$count" -gt 0 ]]; then scan_findings=1; fi
  "$python" - "$trivy_report" "${TRIVY_FAIL_ON:-high}" <<'PY'
import json
import sys
try:
    levels = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    with open(sys.argv[1], encoding="utf-8") as source:
        report = json.load(source)
    threshold = levels.get(sys.argv[2].upper(), 99)
    findings = [v for result in report["Results"] for v in (result.get("Vulnerabilities") or [])]
    sys.exit(int(any(levels.get((v.get("Severity") or "UNKNOWN").upper(), 0) >= threshold
                     for v in findings)))
except (OSError, ValueError, TypeError, KeyError, AttributeError) as error:
    print(f"Invalid Trivy report for severity gate: {error}", file=sys.stderr)
    sys.exit(2)
PY
  return $?
}

run_syft() {
  local syft="${SYFT_BIN:-}" python="" target="$syft_target"
  local cdx_report="$syft_cyclonedx" spdx_report="$syft_spdx"
  local cdx_temp spdx_temp target_arg cdx_arg spdx_arg

  if [[ -z "$syft" ]]; then
    syft="$(command -v syft || true)"
  elif [[ ( "${OSTYPE:-}" == msys* || "${OSTYPE:-}" == cygwin* ) && "$syft" =~ ^[A-Za-z]: ]]; then
    syft="$(cygpath -u "$syft")"
  fi
  if [[ -z "$syft" || ! -x "$syft" ]]; then
    echo "Syft was not found. Install an approved official release or set SYFT_BIN to its executable: https://github.com/anchore/syft" >&2
    return 2
  fi
  if [[ ( "${OSTYPE:-}" == msys* || "${OSTYPE:-}" == cygwin* ) && "$target" =~ ^[A-Za-z]: ]]; then
    target="$(cygpath -u "$target")"
  fi
  if [[ "${OSTYPE:-}" == msys* || "${OSTYPE:-}" == cygwin* ]]; then
    if [[ "$cdx_report" =~ ^[A-Za-z]: ]]; then cdx_report="$(cygpath -u "$cdx_report")"; fi
    if [[ "$spdx_report" =~ ^[A-Za-z]: ]]; then spdx_report="$(cygpath -u "$spdx_report")"; fi
  fi
  if [[ ! -d "$target" ]]; then
    echo "Syft target is not a directory: $syft_target" >&2
    return 2
  fi
  if [[ -d "$cdx_report" || -d "$spdx_report" ]]; then
    echo "Syft report paths must be files, not directories." >&2
    return 2
  fi
  if [[ "$cdx_report" == "$spdx_report" ]] || \
     [[ -e "$cdx_report" && -e "$spdx_report" && "$cdx_report" -ef "$spdx_report" ]]; then
    echo "Syft CycloneDX and SPDX report paths must be different." >&2
    return 2
  fi
  if [[ ( "${OSTYPE:-}" == msys* || "${OSTYPE:-}" == cygwin* ) ]] && command -v python >/dev/null 2>&1; then
    python="$(command -v python)"
  elif command -v python3 >/dev/null 2>&1; then
    python="$(command -v python3)"
  elif command -v python >/dev/null 2>&1; then
    python="$(command -v python)"
  fi
  if [[ -z "$python" ]]; then
    echo "Python 3 is required to validate Syft reports." >&2
    return 2
  fi
  if [[ "${SYFT_REQUIRE_PACKAGES:-1}" != 0 && "${SYFT_REQUIRE_PACKAGES:-1}" != 1 ]]; then
    echo "SYFT_REQUIRE_PACKAGES must be 0 or 1." >&2
    return 2
  fi
  if ! "$syft" version; then
    echo "Syft could not execute. Check installation and organizational application-control policy." >&2
    return 2
  fi
  if ! mkdir -p "$(dirname "$cdx_report")" "$(dirname "$spdx_report")"; then
    echo "Could not create Syft report directories." >&2
    return 2
  fi
  if [[ "$(cd -P -- "$(dirname "$cdx_report")" && pwd)/$(basename "$cdx_report")" == \
        "$(cd -P -- "$(dirname "$spdx_report")" && pwd)/$(basename "$spdx_report")" ]]; then
    echo "Syft CycloneDX and SPDX report paths must be different." >&2
    return 2
  fi
  cdx_temp="$(mktemp "${cdx_report}.tmp.XXXXXX")" || return 2
  spdx_temp="$(mktemp "${spdx_report}.tmp.XXXXXX")" || {
    rm -f "$cdx_temp"
    return 2
  }
  target_arg="$target"
  cdx_arg="$cdx_temp"
  spdx_arg="$spdx_temp"
  if [[ "${OSTYPE:-}" == msys* || "${OSTYPE:-}" == cygwin* ]]; then
    target_arg="$(cygpath -w "$target")"
    cdx_arg="$(cygpath -w "$cdx_temp")"
    spdx_arg="$(cygpath -w "$spdx_temp")"
  fi
  echo "Generating Syft SBOMs for $syft_target..."
  if ! "$syft" scan "dir:$target_arg" -o "cyclonedx-json=$cdx_arg" -o "spdx-json=$spdx_arg"; then
    echo "Syft scan failed; existing reports were not replaced." >&2
    rm -f "$cdx_temp" "$spdx_temp"
    return 2
  fi
  if ! "$python" - "$cdx_temp" "$spdx_temp" "${SYFT_REQUIRE_PACKAGES:-1}" > "${cdx_temp}.txt" <<'PY'
import json
import re
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as source:
        cdx = json.load(source)
    with open(sys.argv[2], encoding="utf-8") as source:
        spdx = json.load(source)
    if not isinstance(cdx, dict) or cdx.get("bomFormat") != "CycloneDX" or not re.fullmatch(r"1\.\d+", str(cdx.get("specVersion", ""))):
        raise ValueError("invalid CycloneDX format or version")
    if not isinstance(cdx.get("metadata"), dict) or not isinstance(cdx.get("components", []), list):
        raise ValueError("invalid CycloneDX metadata or components")
    if not isinstance(spdx, dict) or not re.fullmatch(r"SPDX-2\.\d+", str(spdx.get("spdxVersion", ""))):
        raise ValueError("invalid SPDX format or version")
    if spdx.get("SPDXID") != "SPDXRef-DOCUMENT" or not isinstance(spdx.get("creationInfo"), dict):
        raise ValueError("invalid SPDX document metadata")
    packages = spdx.get("packages", [])
    relationships = spdx.get("relationships", [])
    if not isinstance(packages, list) or not isinstance(relationships, list):
        raise ValueError("invalid SPDX packages or relationships")
    if any(not isinstance(p, dict) for p in packages):
        raise ValueError("invalid SPDX package")
    root_ids = {
        r.get("relatedSpdxElement") for r in relationships
        if isinstance(r, dict) and r.get("spdxElementId") == "SPDXRef-DOCUMENT"
        and r.get("relationshipType") == "DESCRIBES"
    }
    packages = [p for p in packages if p.get("SPDXID") not in root_ids]
    components = cdx.get("components", [])
    for package in components + packages:
        if not isinstance(package, dict) or not isinstance(package.get("name"), str) or not package["name"].strip():
            raise ValueError("a package has no readable name")
        version = package.get("version", package.get("versionInfo"))
        if version is not None and not isinstance(version, str):
            raise ValueError("a package has an invalid version")
    non_file_components = [component for component in components if component.get("type") != "file"]
    if sys.argv[3] == "1" and (not non_file_components or not packages):
        raise ValueError("no packages discovered in one or both SBOMs")
    print(f"CycloneDX {cdx['specVersion']}: {len(components)} components ({len(non_file_components)} non-file)")
    print(f"SPDX {spdx['spdxVersion']}: {len(packages)} packages (excluding document root)")
    if not non_file_components or not packages:
        print("Warning: no packages discovered in one or both SBOMs.", file=sys.stderr)
except (OSError, ValueError, TypeError) as error:
    print(f"Syft report validation failed: {error}", file=sys.stderr)
    sys.exit(1)
PY
  then
    echo "Syft reports were not valid; existing reports were not replaced." >&2
    rm -f "$cdx_temp" "$spdx_temp" "${cdx_temp}.txt"
    return 2
  fi
  if ! mv -f "$cdx_temp" "$cdx_report" || ! mv -f "$spdx_temp" "$spdx_report" || ! mv -f "${cdx_temp}.txt" "$(dirname "$cdx_report")/sbom-summary.txt"; then
    echo "Could not publish both Syft reports; check the report paths." >&2
    rm -f "$cdx_temp" "$spdx_temp" "${cdx_temp}.txt"
    return 2
  fi
  echo "Syft reports: $syft_cyclonedx and $syft_spdx"
  return 0
}

run_checkov() {
  local target="${CHECKOV_TARGET:-samples/vulnerable-iac}"
  local directory="${CHECKOV_REPORT_DIR:-reports/checkov}"
  local json_temp text_temp summary_temp status
  if ! command -v checkov >/dev/null 2>&1; then
    echo "Checkov was not found. Install an approved Checkov release." >&2; return 2
  fi
  if [[ -z "$python_cmd" || ! -d "$target" ]]; then
    echo "Checkov requires Python 3 and an existing target directory: $target" >&2; return 2
  fi
  mkdir -p "$directory" || return 2
  json_temp="$(mktemp "$directory/checkov.json.tmp.XXXXXX")" || return 2
  text_temp="$(mktemp "$directory/checkov.txt.tmp.XXXXXX")" || { rm -f "$json_temp"; return 2; }
  summary_temp="$(mktemp "$directory/checkov-summary.tmp.XXXXXX")" || { rm -f "$json_temp" "$text_temp"; return 2; }
  echo "Running Checkov on $target..."
  if ! checkov --directory "$target" --framework terraform --output json --soft-fail > "$json_temp"; then
    echo "Checkov scan failed." >&2; rm -f "$json_temp" "$text_temp" "$summary_temp"; return 2
  fi
  "$python_cmd" - "$json_temp" "$text_temp" "$summary_temp" "$target" <<'PY'
import json
import os
import sys
try:
    with open(sys.argv[1], encoding="utf-8") as source:
        report = json.load(source)
    if not isinstance(report, dict) or not isinstance(report.get("results"), dict):
        raise ValueError("missing Checkov results")
    summary, results = report.get("summary"), report["results"]
    if not isinstance(summary, dict) or summary.get("parsing_errors", 0):
        raise ValueError("missing summary or parsing errors")
    version = summary.get("checkov_version")
    if not isinstance(version, str) or not version.strip():
        raise ValueError("missing Checkov version")
    passed, failed = results.get("passed_checks"), results.get("failed_checks")
    if not isinstance(passed, list) or not isinstance(failed, list) or not (passed or failed):
        raise ValueError("no checks executed or malformed results")
    with open(sys.argv[2], "w", encoding="utf-8") as output:
        output.write(f"Checkov: {len(passed)} passed, {len(failed)} failed\n")
        for finding in failed:
            output.write(f"{finding.get('check_id', '?')} {finding.get('check_name', '?')} "
                         f"{finding.get('file_path', '?')} "
                         f"severity: {finding.get('severity') or 'not provided'}\n")
    with open(sys.argv[3], "w", encoding="utf-8") as output:
        output.write(f"Checkov target: {sys.argv[4]}\n")
        output.write(f"Source: {'GitHub Actions' if os.environ.get('GITHUB_ACTIONS') == 'true' else 'local scan'}\n")
        output.write(f"Checkov version: {version}\n")
        output.write(f"Status: {'FAIL' if failed else 'PASS'}\n")
        output.write(f"Checks: {len(passed)} passed, {len(failed)} failed\n")
    sys.exit(1 if failed else 0)
except (OSError, ValueError, TypeError, AttributeError) as error:
    print(f"Invalid Checkov report: {error}", file=sys.stderr)
    sys.exit(2)
PY
  status=$?
  if [[ "$status" -gt 1 ]]; then rm -f "$json_temp" "$text_temp" "$summary_temp"; return 2; fi
  if ! mv -f "$json_temp" "$directory/iac-report.json" || ! mv -f "$text_temp" "$directory/iac-report.txt" ||
     ! mv -f "$summary_temp" "$directory/summary.txt"; then
    rm -f "$json_temp" "$text_temp" "$summary_temp"; return 2
  fi
  if [[ "$status" -eq 1 ]]; then scan_findings=1; fi
  return "$status"
}

summary_report="${SCAN_SUMMARY_PATH:-reports/summary.txt}"
if ! mkdir -p "$(dirname "$summary_report")"; then echo "Cannot create summary directory." >&2; exit 2; fi
summary="$(mktemp "${summary_report}.tmp.XXXXXX")" || exit 2
printf 'Security scan summary\n' > "$summary"
for name in gitleaks semgrep trivy syft grype checkov; do
  scan_findings=0
  if [[ "$scanner" != all && "$scanner" != "$name" ]]; then
    state=SKIPPED
  else
    "run_$name"
    status=$?
    if [[ "$status" -ne 0 && "$status" -ne 1 ]]; then
      status=2
      state=ERROR
    else
      if [[ "$name" == grype && -n "$python_cmd" ]]; then
        "$python_cmd" - "${GRYPE_REPORT_DIR:-reports/grype}/grype-report.json" "${GRYPE_REPORT_DIR:-reports/grype}/grype-image-report.json" <<'PY'
import json
import sys
try:
    findings = False
    for path, expected_type in zip(sys.argv[1:], ("directory", "image")):
        with open(path, encoding="utf-8") as source:
            report = json.load(source)
        if (not isinstance(report, dict) or not isinstance(report.get("matches"), list) or
                not isinstance(report.get("source"), dict) or report["source"].get("type") != expected_type):
            raise ValueError(f"invalid Grype {expected_type} report")
        findings = findings or bool(report["matches"] or report.get("ignoredMatches"))
    sys.exit(1 if findings else 0)
except (OSError, ValueError, TypeError) as error:
    print(f"Invalid Grype report: {error}", file=sys.stderr)
    sys.exit(2)
PY
        grype_findings=$?
        if [[ "$grype_findings" -eq 1 ]]; then scan_findings=1
        elif [[ "$grype_findings" -ne 0 ]]; then status=2; state=ERROR
        fi
      fi
      if [[ "$status" -ne 2 ]]; then
        if [[ "$status" -eq 1 || "$scan_findings" -eq 1 ]]; then state=FINDINGS; else state=PASS; fi
      fi
    fi
    record_status "$status"
  fi
  printf '%-8s %s\n' "$name" "$state" >> "$summary"
done
printf 'Exit code: %s\n' "$overall_status" >> "$summary"
cat "$summary"
if ! mv -f "$summary" "$summary_report"; then echo "Cannot publish summary." >&2; exit 2; fi
exit "$overall_status"
