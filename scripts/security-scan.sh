#!/usr/bin/env bash

set -uo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

scanner="${1:-all}"
if [[ "$scanner" != "all" && "$scanner" != "gitleaks" && "$scanner" != "semgrep" && "$scanner" != "trivy" && "$scanner" != "syft" ]]; then
  echo "Usage: $0 [all|gitleaks|semgrep|trivy|syft]" >&2
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
syft_target="${SYFT_TARGET:-samples/vulnerable-dependencies}"
syft_cyclonedx="${SYFT_CYCLONEDX_REPORT_PATH:-reports/syft/sbom-cyclonedx.json}"
syft_spdx="${SYFT_SPDX_REPORT_PATH:-reports/syft/sbom-spdx.json}"

mkdir -p "$(dirname "$gitleaks_report")" "$(dirname "$semgrep_report")" "$(dirname "$semgrep_text_report")" "$(dirname "$trivy_report")"

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

run_trivy() {
  local trivy="${TRIVY_BIN:-}"
  local python=""
  local json_temp csv_temp text_temp count

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
  echo "Running Trivy on $trivy_target..."
  if ! "$trivy" fs --scanners vuln --format json --output "$json_temp" --exit-code 0 "$trivy_target"; then
    echo "Trivy scan failed; existing reports were not replaced." >&2
    rm -f "$json_temp" "$csv_temp" "$text_temp"
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
    rm -f "$json_temp" "$csv_temp" "$text_temp"
    return 2
  fi
  if ! mv -f "$json_temp" "$trivy_report" || ! mv -f "$csv_temp" "$trivy_csv" || ! mv -f "$text_temp" "$trivy_text"; then
    echo "Could not publish all Trivy reports; check the report directory." >&2
    rm -f "$json_temp" "$csv_temp" "$text_temp"
    return 2
  fi
  echo "Trivy found $count vulnerabilities. Reports: $trivy_report, $trivy_csv and $trivy_text"
  if [[ "$count" -gt 0 ]]; then
    return 1
  fi
  return 0
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
  if [[ "${SYFT_REQUIRE_PACKAGES:-0}" != 0 && "${SYFT_REQUIRE_PACKAGES:-0}" != 1 ]]; then
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
  if ! "$python" - "$cdx_temp" "$spdx_temp" "${SYFT_REQUIRE_PACKAGES:-0}" <<'PY'
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
    rm -f "$cdx_temp" "$spdx_temp"
    return 2
  fi
  if ! mv -f "$cdx_temp" "$cdx_report" || ! mv -f "$spdx_temp" "$spdx_report"; then
    echo "Could not publish both Syft reports; check the report paths." >&2
    rm -f "$cdx_temp" "$spdx_temp"
    return 2
  fi
  echo "Syft reports: $syft_cyclonedx and $syft_spdx"
  return 0
}

if [[ "$scanner" == "all" || "$scanner" == "gitleaks" ]]; then
  run_gitleaks
  record_status "$?"
fi

if [[ "$scanner" == "all" || "$scanner" == "semgrep" ]]; then
  run_semgrep
  record_status "$?"
fi

if [[ "$scanner" == "all" || "$scanner" == "trivy" ]]; then
  run_trivy
  record_status "$?"
fi

if [[ "$scanner" == "all" || "$scanner" == "syft" ]]; then
  run_syft
  record_status "$?"
fi

exit "$overall_status"
