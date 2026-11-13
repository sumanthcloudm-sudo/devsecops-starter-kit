# DevSecOps Starter Kit

A lightweight starter kit for local and CI security scanning. It includes Gitleaks for secrets, Semgrep Community Edition (CE) for SAST, Trivy for dependency vulnerabilities, Syft for SBOM generation, and Grype for SBOM vulnerability scanning.

## Prerequisites

- Git.
- Gitleaks 8.x for secret scanning.
- Semgrep CE, provided by one of the approved execution methods below.
- Python 3 for Semgrep JSON validation.
- Trivy, Syft, and Grype for dependency scanning, SBOM generation, and SBOM vulnerability scanning.
- Internet access when Semgrep must download its configured rulesets.

The sample files in `samples/vulnerable-code/` intentionally contain insecure patterns and test-only placeholder values. They are not production code and must not be copied into an application.

## Semgrep installation and Windows restrictions

### Windows

On this workstation, Windows Application Control blocks the installed Semgrep launcher/engine. Do not disable or work around Application Control, Smart App Control, AppLocker, WDAC, execution policies, or other security controls. Ask IT to approve the native CLI and its engine before using them.

Use one of these alternatives only after the organization approves the software and its source:

1. **Docker Desktop and the official Semgrep image**: Ask IT to approve/install Docker Desktop and permit pulling/running `semgrep/semgrep`. In an interactive PowerShell session, run:

   ```powershell
   docker run --rm --volume "$((Get-Location).Path):/src" --workdir /src --entrypoint bash semgrep/semgrep scripts/security-scan.sh semgrep
   ```

   The wrapper validates a fresh JSON report and writes readable output. Installation, container policy approval, or registry access may require IT approval.

2. **WSL**: Ask IT to approve/install WSL 2 and a supported Linux distribution if they are not already available. Install Semgrep inside that Linux distribution using an organization-approved package source (for example `pipx install semgrep`), then run:

   ```powershell
   wsl.exe -- bash -lc 'cd /mnt/c/path/to/devsecops-starter-kit && bash scripts/security-scan.sh semgrep'
   ```

   Replace the example WSL path with the mounted location of this repository. Do not invoke the blocked Windows `semgrep.exe` from Git Bash or PowerShell.

**Verified on this workstation:** Windows Application Control blocks the currently installed Python Semgrep launcher/engine. No WSL distribution or Docker CLI is currently available. The approved Docker and WSL alternatives have not been executed locally and require IT approval or setup. GitHub-hosted Semgrep has run independently of the local Windows policy.

The PowerShell execution policy on this workstation also prevents direct execution of `.ps1` files. Do not relax or bypass that policy. The checked-in `scripts/security-scan.ps1` is available only in environments where its execution is already authorized (for example, through an IT-approved signing/policy process); otherwise use the documented interactive Docker command or the Linux/WSL shell script.

### Linux and WSL

Install Semgrep within the approved Linux environment using the organization's package source. Semgrep's documented standalone CLI options include `pipx install semgrep` and `uv tool install semgrep`; obtain any required approval before installing. Verify the installation with `semgrep --version`, then run:

```bash
bash scripts/security-scan.sh semgrep
```

On Windows the Bash wrapper can invoke a native CLI only when the executable and its engine are permitted by organizational policy; it does not bypass Application Control.

## Running scans

From the repository root, the PowerShell convenience script can be used only when its execution is already authorized:

```powershell
# Windows PowerShell; requires an authorized script-execution policy and approved Docker for Semgrep
.\scripts\security-scan.ps1 all
.\scripts\security-scan.ps1 gitleaks
.\scripts\security-scan.ps1 semgrep
.\scripts\security-scan.ps1 trivy
.\scripts\security-scan.ps1 grype
```

If policy blocks the script, do not change the policy. Run the approved commands interactively instead:

```powershell
gitleaks dir . --config configs\gitleaks\.gitleaks.toml --report-format json --report-path reports\gitleaks\gitleaks-report.json
docker run --rm --volume "$((Get-Location).Path):/src" --workdir /src --entrypoint bash semgrep/semgrep scripts/security-scan.sh semgrep
$LASTEXITCODE
```

The wrapper returns `1` for findings, `0` for a clean scan, and `2` for a runtime/configuration failure.

```bash
# Linux or WSL; requires Gitleaks and Semgrep installed in that environment
bash scripts/security-scan.sh all
bash scripts/security-scan.sh gitleaks
bash scripts/security-scan.sh semgrep
bash scripts/security-scan.sh trivy
bash scripts/security-scan.sh syft
bash scripts/security-scan.sh grype
```

The Bash `all` option runs the scanners even if one reports findings; Grype uses the newly generated Syft SBOM and is skipped if Syft fails. Exit code `0` means all requested security gates passed, `1` means a gate failed, and `2` means a scanner could not run or encountered a configuration/runtime error. The PowerShell wrapper does not invoke Syft and uses an existing SBOM for Grype.

The report path environment variables can be set to direct output to a temporary or alternate location:

- `GITLEAKS_REPORT_PATH` (default `reports/gitleaks/gitleaks-report.json`)
- `SEMGREP_REPORT_PATH` (default `reports/semgrep/semgrep-report.json`)
- `SEMGREP_TEXT_REPORT_PATH` (default `reports/semgrep/semgrep-report.txt`)
- `SEMGREP_EXCLUDE` (optional single Semgrep exclusion pattern; unset by default)
- `TRIVY_TARGET`, `TRIVY_BIN`, and `TRIVY_REPORT_DIR` configure the Trivy scan.
- `SYFT_TARGET`, `SYFT_BIN`, `SYFT_CYCLONEDX_REPORT_PATH`, `SYFT_SPDX_REPORT_PATH`, and `SYFT_REQUIRE_PACKAGES` configure Syft.

## Semgrep configuration

`configs/semgrep/semgrep.yml` contains repository-specific Python rules for SQL query concatenation, credential-like string assignments, weak MD5/SHA-1 hashing, and shell-based command execution. The scan also combines:

- `p/owasp-top-ten` for OWASP Top 10 security coverage.
- `p/python` for Python-specific security checks, appropriate to the repository's current vulnerable-code samples.

Add repository-specific rules to the `rules` list in `configs/semgrep/semgrep.yml`. Review rule overlap and test new rules against representative source before enabling them broadly. The Semgrep CLI resolves these remote rulesets when scanning, so network/registry access may be required.

## Reports and severity

- Semgrep JSON: `reports/semgrep/semgrep-report.json`
- Semgrep readable output: `reports/semgrep/semgrep-report.txt`
- Gitleaks JSON: `reports/gitleaks/gitleaks-report.json`

Semgrep JSON results include the rule ID (`check_id`), severity, file path, and start/end line locations. The configuration uses Semgrep's `ERROR`, `WARNING`, and `INFO` severity levels. Treat `ERROR` as high priority, `WARNING` as requiring review/remediation, and `INFO` as an advisory. The scanners return a findings exit code when findings are present; review the full output rather than interpreting a nonzero exit as a scanner crash.

The Bash wrapper publishes reports only after a fresh scan produces valid JSON, no scan errors, scanned files, and findings consistent with its exit code. On failure, an existing report is not evidence of the latest scan.

Gitleaks JSON can include matched secret values. Protect the report as sensitive data, and do not commit or share it unredacted.

## GitHub Actions

`.github/workflows/semgrep.yml` runs Semgrep CE on pushes, pull requests, and manual dispatch using Semgrep's maintained `semgrep/semgrep` container image. CI includes `samples/vulnerable-code/` and verifies that all four vulnerable Python fixtures were scanned and matched their custom rules. Findings limited to those designated fixtures are expected and do not fail the security gate; findings elsewhere do. The workflow requests only `contents: read` and uploads fresh validated JSON/text reports as a 14-day artifact, including when unexpected findings cause the scan step to fail. No Semgrep account token or other secret is required. Semgrep normally scans files tracked by Git.

To run it on GitHub:

1. Commit and push the workflow, wrapper, tests, and source files to a branch. A push or pull request triggers the scan automatically.
2. For a manual run, ensure the workflow with `workflow_dispatch` exists on the default branch. In the repository's **Actions** tab, select **Semgrep SAST**, choose **Run workflow**, select the branch, and choose **Run workflow** again. Manual dispatch requires repository write access and Actions to be enabled.
3. Open the run, expand **Run Semgrep**, and check the scanned-file count, findings, and exit status. Findings outside the designated vulnerable samples fail the gate; scanner or report-validation errors also fail it and are not clean results. Expected findings in the samples remain visible in the report.
4. On the run's summary page, download **semgrep-reports** under **Artifacts**. Open `semgrep-report.json` with a JSON parser and review `results`, `errors`, and `paths.scanned`. If no artifact was produced, inspect the job log; do not use an older report as evidence of that run. To repeat the sample coverage check locally, run `python tests/verify_semgrep_samples.py path/to/semgrep-report.json`.

The intentionally vulnerable fixtures are an explicit exception to the Semgrep gate so the workflow can validate their custom rules without treating teaching examples as production findings. Review unexpected findings outside those fixtures and do not treat scanner or report-validation errors as clean scans.

## Troubleshooting

- **Windows Application Control blocks `semgrep.exe`:** Do not change security policy. Use an IT-approved Docker Desktop installation with the documented interactive command or an already authorized `security-scan.ps1`, or use an IT-approved WSL environment and install/run Semgrep inside Linux.
- **PowerShell blocks `security-scan.ps1`:** Do not change or bypass execution policy. Obtain IT approval for an authorized script-signing/policy route, or run the documented Docker command interactively.
- **PowerShell reports Docker is missing:** Request IT approval for Docker Desktop and the official `semgrep/semgrep` image, or use WSL. The PowerShell Semgrep option does not fall back to the blocked Windows executable.
- **WSL reports Semgrep is missing:** Install the CLI inside the approved WSL distribution from an organization-approved source; the Windows Python installation is not shared with WSL.
- **Registry/network or configuration error:** Confirm the runner can reach Semgrep's registry and that the configured rulesets and local YAML rules are valid. Such errors return a scanner-error exit code and must not be treated as clean results.
- **Semgrep exits `1`:** Findings were produced. Review the report and remediate or document the accepted risk; the JSON report is still uploaded in CI.
- **Gitleaks exits `1`:** Findings were produced. Review the Gitleaks report and follow your secret-rotation process if a real credential was exposed.

## Syft SBOM generation

A software bill of materials (SBOM) inventories components and versions for supply-chain review and incident response. [Anchore Syft](https://github.com/anchore/syft) generates SBOMs; it does not determine whether those components are vulnerable.

### Installation

Obtain organizational approval before installing or running Syft. The workflow uses the official [Syft 1.57.1 release](https://github.com/anchore/syft/releases/tag/v1.57.1) and verifies its archive SHA-256. For Windows 11 x64:

```powershell
$zip = Join-Path $env:TEMP 'syft_1.57.1_windows_amd64.zip'
Invoke-WebRequest -Uri 'https://github.com/anchore/syft/releases/download/v1.57.1/syft_1.57.1_windows_amd64.zip' -OutFile $zip
if ((Get-FileHash $zip -Algorithm SHA256).Hash -ne '3A01FE865076BB548352195B77E88FA4649277861EA458EFE165C3A810B6DCC7') { throw 'Checksum mismatch' }
Expand-Archive -Path $zip -DestinationPath "$env:USERPROFILE\tools\syft-1.57.1"
$env:SYFT_BIN = "$env:USERPROFILE\tools\syft-1.57.1\syft.exe"
& $env:SYFT_BIN version
```

Anchore also documents `winget install Anchore.syft` in its [installation guide](https://oss.anchore.com/docs/installation/syft/). The checksum-verified Windows executable was blocked by Application Control on this workstation. Request IT approval; do not bypass or disable security controls. Docker and WSL are not required.

### Run the scan

With an approved Syft executable on `PATH` or in `SYFT_BIN`, from the repository root:

```powershell
& 'C:\Program Files\Git\bin\bash.exe' scripts/security-scan.sh syft
& 'C:\Program Files\Git\bin\bash.exe' scripts/security-scan.sh all
```

In Git Bash or Linux use `bash scripts/security-scan.sh syft` or `bash scripts/security-scan.sh all`. `SYFT_TARGET` selects a directory (default `samples/vulnerable-dependencies`). Set `SYFT_REQUIRE_PACKAGES=1` to fail on an empty inventory. The wrapper scans once and writes validated `reports/syft/sbom-cyclonedx.json` and `reports/syft/sbom-spdx.json`; override them using `SYFT_CYCLONEDX_REPORT_PATH` and `SYFT_SPDX_REPORT_PATH`. The paths must differ. Exit `0` indicates successful inventory, not absence of vulnerabilities; exit `2` means an unavailable scanner, invalid target, scan failure, or invalid output.

To print either format directly in PowerShell, once Syft is approved:

```powershell
& $env:SYFT_BIN scan 'dir:samples/vulnerable-dependencies' -o cyclonedx-json
& $env:SYFT_BIN scan 'dir:samples/vulnerable-dependencies' -o spdx-json
```

The wrapper validates both files before publishing. For syntax-only checks use `Get-Content -Raw reports\syft\sbom-cyclonedx.json | ConvertFrom-Json` or the corresponding SPDX path. Basic structure checks do not prove full standards-schema compliance. A Maven POM may describe declared rather than resolved dependencies; scan resolved artifacts when needed.

### GitHub Actions and troubleshooting

`.github/workflows/syft-sbom.yml` scans the same sample on pushes, pull requests, and manual dispatch using the verified official Linux release, `contents: read`, and SHA-pinned actions. It checks both formats for the sample dependency and uploads `syft-sbom-reports`, including if the later sample check fails. Open **Actions → Syft SBOM → a run → Artifacts** to download it. Manual dispatch requires the workflow on the default branch and repository write access.

- If Syft is missing or blocked, set `SYFT_BIN` to an approved executable and request IT authorization. Do not change security policy.
- For invalid targets or outputs, choose an existing directory and two distinct writable report paths.
- If no packages are found, verify supported manifests or resolved artifacts are present.
- On scanner or JSON-validation failure, existing reports are not evidence of the current run.
- Local Windows validation is blocked by Application Control. [GitHub Actions run 43387970726](https://github.com/sumanthcloudm-sudo/devsecops-starter-kit/actions/runs/43387970726) succeeded at commit `141668c`: the generated reports include Log4j Core 2.14.1 and passed official CycloneDX 1.7 and SPDX 2.3 JSON schemas. Trivy read both reports, with a third-party SBOM warning for CycloneDX.

## Grype SBOM vulnerability scanning

[Grype](https://github.com/anchore/grype) matches packages in an existing Syft SBOM against a vulnerability database; it does not generate another SBOM. The default input is `reports/syft/sbom-cyclonedx.json`. Results depend on the completeness and freshness of that inventory.

Obtain organizational approval for the [official Grype release](https://github.com/anchore/grype/releases/tag/v0.121.3) before installing or running it. The checksum-verified Windows executable was blocked by Application Control on this workstation; do not bypass security controls or PowerShell execution policy. The GitHub workflow verifies the official Linux archive checksum.

Treat `GRYPE_BIN` and `PATH` as trusted execution configuration: selecting an executable runs it with the caller's privileges. On Windows the wrapper rejects `.bat` and `.cmd` launchers, which may be interpreted by a shell even when Python does not request one; use an approved native executable.

With an approved binary on `PATH` (or `GRYPE_BIN` set to its path), generate a Syft SBOM first and run:

```powershell
& 'C:\Program Files\Git\bin\bash.exe' scripts/security-scan.sh grype
# Or, when PowerShell script execution is already authorized:
.\scripts\security-scan.ps1 grype
```

In Linux, use `bash scripts/security-scan.sh grype`. Set `GRYPE_SBOM_PATH` to an existing CycloneDX or SPDX JSON SBOM and `GRYPE_REPORT_DIR` to change the output directory. Reports are `reports/grype/grype-report.json` and `reports/grype/grype-report.txt` by default; they may contain sensitive package metadata.

`configs/grype/config.json` defaults `GRYPE_FAIL_ON` to `high`. The gate fails for High or Critical matches; Medium, Low, Negligible and Unknown remain visible. Set `GRYPE_FAIL_ON` to `critical`, `high`, `medium`, `low`, `negligible`, or `none` to select a different threshold without suppressing findings. Unknown severity has no rank. Internally ignored matches remain visible and are counted in the gate; review their reasons. Exit `0` means the threshold passed, `1` means the scan completed but the security gate failed, and `2` means a scanner, SBOM, or report error. Existing reports are not proof of a later successful scan.

The Grype workflow runs on push, pull request, and manual dispatch with `contents: read` and `actions: read`. It downloads a successful Syft artifact for the same commit and event (and pull request, if applicable), checks the SBOM checksum and checkout provenance, scans it with the gate disabled, and uploads `grype-sbom-reports`. The Syft workflow deliberately scans vulnerable teaching samples, so CI reports their findings without failing the job; local scans retain the configured High threshold by default. It never reruns Syft. For manual dispatch, both workflows must exist on the default branch; first manually run Syft for the selected commit, then run Grype from the Actions tab. Missing, expired, failed, or mismatched Syft artifacts cause an error.

[Run 43393890342](https://github.com/sumanthcloudm-sudo/devsecops-starter-kit/actions/runs/43393890342) used the SBOM from Syft run `43393890252` and found 8 vulnerabilities: 2 Critical, 1 High, and 5 Medium. The scan completed, the High gate failed as intended, and both reports were uploaded. Download the artifact to inspect those historical results; they are not a local Windows scan.
