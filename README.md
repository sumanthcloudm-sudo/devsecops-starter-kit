# DevSecOps Starter Kit

A lightweight starter kit for local and CI security scanning. The current scanners are Gitleaks for secret detection and Semgrep Community Edition (CE) for static application security testing (SAST).

## Prerequisites

- Git.
- Gitleaks 8.x for secret scanning.
- Semgrep CE, provided by one of the approved execution methods below.
- Python 3 for Semgrep JSON validation.
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
```

`all` runs both tools even if one reports findings. Exit code `0` means both requested scans completed without findings, `1` means one or more findings were reported, and `2` means a scanner could not run or encountered a configuration/runtime error. Findings are not silently treated as a clean scan. A missing approved Semgrep runtime returns `2`.

The report path environment variables can be set to direct output to a temporary or alternate location:

- `GITLEAKS_REPORT_PATH` (default `reports/gitleaks/gitleaks-report.json`)
- `SEMGREP_REPORT_PATH` (default `reports/semgrep/semgrep-report.json`)
- `SEMGREP_TEXT_REPORT_PATH` (default `reports/semgrep/semgrep-report.txt`)
- `SEMGREP_EXCLUDE` (optional single Semgrep exclusion pattern; unset by default)

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

`.github/workflows/semgrep.yml` runs Semgrep CE on pushes, pull requests, and manual dispatch using Semgrep's maintained `semgrep/semgrep` container image. CI includes `samples/vulnerable-code/` and verifies that all four vulnerable Python fixtures were scanned and matched their custom rules. Their intentional findings cause the security gate to fail; that is expected and is not a scanner execution error. The workflow requests only `contents: read` and uploads fresh validated JSON/text reports as a 14-day artifact, including when findings cause the scan step to fail. No Semgrep account token or other secret is required. Semgrep normally scans files tracked by Git.

To run it on GitHub:

1. Commit and push the workflow, wrapper, tests, and source files to a branch. A push or pull request triggers the scan automatically.
2. For a manual run, ensure the workflow with `workflow_dispatch` exists on the default branch. In the repository's **Actions** tab, select **Semgrep SAST**, choose **Run workflow**, select the branch, and choose **Run workflow** again. Manual dispatch requires repository write access and Actions to be enabled.
3. Open the run, expand **Run Semgrep**, and check the scanned-file count, findings, and exit status. A findings exit of `1` fails the gate; scanner or report-validation errors also fail it and are not clean results.
4. On the run's summary page, download **semgrep-reports** under **Artifacts**. Open `semgrep-report.json` with a JSON parser and review `results`, `errors`, and `paths.scanned`. If no artifact was produced, inspect the job log; do not use an older report as evidence of that run. To repeat the sample coverage check locally, run `python tests/verify_semgrep_samples.py path/to/semgrep-report.json`.

The intentionally vulnerable fixtures mean this workflow is expected to fail the gate until the fixtures are removed or a different policy is chosen; do not treat that expected failure as a clean scan.

## Troubleshooting

- **Windows Application Control blocks `semgrep.exe`:** Do not change security policy. Use an IT-approved Docker Desktop installation with the documented interactive command or an already authorized `security-scan.ps1`, or use an IT-approved WSL environment and install/run Semgrep inside Linux.
- **PowerShell blocks `security-scan.ps1`:** Do not change or bypass execution policy. Obtain IT approval for an authorized script-signing/policy route, or run the documented Docker command interactively.
- **PowerShell reports Docker is missing:** Request IT approval for Docker Desktop and the official `semgrep/semgrep` image, or use WSL. The PowerShell Semgrep option does not fall back to the blocked Windows executable.
- **WSL reports Semgrep is missing:** Install the CLI inside the approved WSL distribution from an organization-approved source; the Windows Python installation is not shared with WSL.
- **Registry/network or configuration error:** Confirm the runner can reach Semgrep's registry and that the configured rulesets and local YAML rules are valid. Such errors return a scanner-error exit code and must not be treated as clean results.
- **Semgrep exits `1`:** Findings were produced. Review the report and remediate or document the accepted risk; the JSON report is still uploaded in CI.
- **Gitleaks exits `1`:** Findings were produced. Review the Gitleaks report and follow your secret-rotation process if a real credential was exposed.
