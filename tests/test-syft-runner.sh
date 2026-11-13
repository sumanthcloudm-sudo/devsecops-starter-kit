#!/usr/bin/env bash
set -uo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
temp_dir="$(mktemp -d)" || exit 1
mkdir -p "$temp_dir/bin" "$temp_dir/target"
trap 'rm -f "$temp_dir/bin/syft" "$temp_dir/output/cdx.json" "$temp_dir/output/spdx.json" "$temp_dir/output/sbom-summary.txt" "$temp_dir/output/alias.json" "$temp_dir/summary.txt" "$temp_dir/block"; rmdir "$temp_dir/output/directory" "$temp_dir/bin" "$temp_dir/target" "$temp_dir/output" "$temp_dir" 2>/dev/null || true' EXIT

cat > "$temp_dir/bin/syft" <<'STUB'
#!/usr/bin/env bash
if [[ "$1" == version ]]; then
  echo "Syft test double"
  exit 0
fi
shift
cdx=""
spdx=""
while [[ $# -gt 0 ]]; do
  if [[ "$1" == -o ]]; then
    case "$2" in
      cyclonedx-json=*) cdx="${2#*=}" ;;
      spdx-json=*) spdx="${2#*=}" ;;
    esac
    shift
  fi
  shift
done
if [[ "${OSTYPE:-}" == msys* || "${OSTYPE:-}" == cygwin* ]]; then
  cdx="$(cygpath -u "$cdx")"
  spdx="$(cygpath -u "$spdx")"
fi
if [[ "$SYFT_TEST_CASE" == failed ]]; then exit 1; fi
if [[ "$SYFT_TEST_CASE" == malformed ]]; then
  printf '{' > "$cdx"
else
  case "$SYFT_TEST_CASE" in
    empty) components='[]' ;;
    file-only) components='[{"type":"file","name":"pom.xml"}]' ;;
    *) components='[{"type":"library","name":"example","version":"1"}]' ;;
  esac
  printf '{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{},"components":%s}' "$components" > "$cdx"
fi
if [[ "$SYFT_TEST_CASE" == missing-output ]]; then exit 0; fi
case "$SYFT_TEST_CASE" in
  invalid-version) version='invalid' ;;
  *) version='SPDX-2.3' ;;
esac
case "$SYFT_TEST_CASE" in
  empty) packages='[]' ;;
  *) packages='[{"SPDXID":"SPDXRef-Example","name":"example","versionInfo":"1"}]' ;;
esac
printf '{"spdxVersion":"%s","SPDXID":"SPDXRef-DOCUMENT","creationInfo":{},"packages":%s,"relationships":[]}' "$version" "$packages" > "$spdx"
STUB
chmod +x "$temp_dir/bin/syft"

export SYFT_BIN="$temp_dir/bin/syft"
export SYFT_TARGET="$temp_dir/target"
export SYFT_CYCLONEDX_REPORT_PATH="$temp_dir/output/cdx.json"
export SYFT_SPDX_REPORT_PATH="$temp_dir/output/spdx.json"
export SCAN_SUMMARY_PATH="$temp_dir/summary.txt"
export SYFT_REQUIRE_PACKAGES=1
export SYFT_TEST_CASE=valid
export GITHUB_ACTIONS=false
bash "$repo_root/scripts/security-scan.sh" syft >/dev/null 2>&1 || { echo "valid scan or directory creation failed" >&2; exit 1; }
summary_target="$SYFT_TARGET"
if [[ "${OSTYPE:-}" == msys* || "${OSTYPE:-}" == cygwin* ]]; then
  summary_target="$(cygpath -m "$summary_target")"
fi
if ! grep -Fxq "Target: $summary_target" "$temp_dir/output/sbom-summary.txt" ||
   ! grep -Fxq "Generation status: PASS" "$temp_dir/output/sbom-summary.txt" ||
   ! grep -Fxq "Generation source: Local execution" "$temp_dir/output/sbom-summary.txt"; then
  echo "Expected target: $summary_target" >&2
  cat "$temp_dir/output/sbom-summary.txt" >&2
  echo "SBOM summary is missing the target or generation status" >&2; exit 1
fi
echo "valid scan and directory creation: passed"

export GITHUB_ACTIONS=true
bash "$repo_root/scripts/security-scan.sh" syft >/dev/null 2>&1 || { echo "CI scan failed" >&2; exit 1; }
if ! grep -Fxq "Generation source: GitHub Actions" "$temp_dir/output/sbom-summary.txt"; then
  echo "CI generation source was not recorded" >&2; exit 1
fi
export GITHUB_ACTIONS=false

for case_name in malformed invalid-version missing-output failed empty file-only; do
  printf 'previous CycloneDX' > "$SYFT_CYCLONEDX_REPORT_PATH"
  printf 'previous SPDX' > "$SYFT_SPDX_REPORT_PATH"
  export SYFT_TEST_CASE="$case_name"
  bash "$repo_root/scripts/security-scan.sh" syft >/dev/null 2>&1
  status=$?
  if [[ "$status" -ne 2 || "$(cat "$SYFT_CYCLONEDX_REPORT_PATH")" != 'previous CycloneDX' || "$(cat "$SYFT_SPDX_REPORT_PATH")" != 'previous SPDX' ]]; then
    echo "$case_name: expected exit 2 with previous reports preserved" >&2
    exit 1
  fi
  echo "$case_name: passed"
done

export SYFT_REQUIRE_PACKAGES=0 SYFT_TEST_CASE=empty
bash "$repo_root/scripts/security-scan.sh" syft >/dev/null 2>&1 || { echo "empty inventory should be allowed" >&2; exit 1; }
echo "empty inventory: passed"

export SYFT_BIN="$temp_dir/bin/missing"
bash "$repo_root/scripts/security-scan.sh" syft >/dev/null 2>&1
if [[ "$?" -ne 2 ]]; then echo "missing scanner was not rejected" >&2; exit 1; fi
export SYFT_BIN="$temp_dir/bin/syft" SYFT_TARGET="$temp_dir/missing"
bash "$repo_root/scripts/security-scan.sh" syft >/dev/null 2>&1
if [[ "$?" -ne 2 ]]; then echo "invalid target was not rejected" >&2; exit 1; fi
export SYFT_TARGET="$temp_dir/target"
printf 'file' > "$temp_dir/block"
export SYFT_CYCLONEDX_REPORT_PATH="$temp_dir/block/cdx.json"
bash "$repo_root/scripts/security-scan.sh" syft >/dev/null 2>&1
if [[ "$?" -ne 2 ]]; then echo "invalid output path was not rejected" >&2; exit 1; fi
echo "missing scanner, invalid target and invalid output: passed"

export SYFT_TEST_CASE=valid SYFT_REQUIRE_PACKAGES=1
mkdir "$temp_dir/output/directory"
export SYFT_CYCLONEDX_REPORT_PATH="$temp_dir/output/directory"
bash "$repo_root/scripts/security-scan.sh" syft >/dev/null 2>&1
if [[ "$?" -ne 2 || -n "$(ls -A "$temp_dir/output/directory")" ]]; then
  echo "directory report destination was not rejected" >&2
  exit 1
fi
export SYFT_CYCLONEDX_REPORT_PATH="$temp_dir/output/alias.json"
export SYFT_SPDX_REPORT_PATH="$temp_dir/output/../output/alias.json"
bash "$repo_root/scripts/security-scan.sh" syft >/dev/null 2>&1
if [[ "$?" -ne 2 || -e "$temp_dir/output/alias.json" ]]; then
  echo "aliased report destinations were not rejected" >&2
  exit 1
fi
echo "directory and aliased report destinations: passed"
