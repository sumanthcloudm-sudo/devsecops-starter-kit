# Local DevSecOps starter kit

This reusable starter kit runs six security checks locally and in proposed GitHub Actions workflows for later integration into AccIDion; it does not modify that repository. All samples are intentionally insecure, test-only, and must never be deployed or used as credentials.

| Tool | Purpose and default target | Individual command | Reports |
| --- | --- | --- | --- |
| Gitleaks | Find and redact secrets in the working tree | `./scripts/security-scan.sh gitleaks` | `reports/gitleaks/gitleaks-report.json`, `gitleaks-report.txt` |
| Semgrep | OWASP/Python SAST and custom rules on the repository | `./scripts/security-scan.sh semgrep` | `reports/semgrep/semgrep-report.json`, `semgrep-report.txt` |
| Trivy | Find vulnerable dependencies in the sample Maven project | `./scripts/security-scan.sh trivy` | `reports/trivy/dependency-report.json`, `dependency-report.txt`, summaries |
| Syft | Inventory sample Maven components as CycloneDX and SPDX SBOMs | `./scripts/security-scan.sh syft` | `reports/syft/sbom-cyclonedx.json`, `sbom-spdx.json`, `sbom-summary.txt` |
| Grype | Scan sample Maven dependencies and a container image independently | `./scripts/security-scan.sh grype` | `reports/grype/grype-report.json`, `grype-report.txt`, `grype-image-report.json`, `grype-image-report.txt` |
| Checkov | Check the sample Terraform-compatible IaC for insecure settings | `./scripts/security-scan.sh checkov` | `reports/checkov/iac-report.json`, `iac-report.txt`, `summary.txt` |

## Prerequisites and installation

Install Git, Bash, Python 3, and approved versions of all six executables on `PATH`. The proposed Ubuntu CI uses Gitleaks 8.30.1, Semgrep 1.184.0, Trivy 0.69.3, Syft 1.57.1, Grype 0.121.3 and Checkov 3.2.495. Obtain organizational approval before installing software.

**Linux and macOS:** Install Bash, Git, Python 3 and approved scanner binaries. On systems with [Homebrew](https://brew.sh/), for example:

```bash
brew install gitleaks trivy syft grype
```

Homebrew versions may differ from CI. Alternatively, use the official [Gitleaks](https://github.com/gitleaks/gitleaks#installing), [Trivy](https://trivy.dev/latest/getting-started/installation/), [Syft](https://oss.anchore.com/docs/installation/syft/) and [Grype](https://oss.anchore.com/docs/installation/grype/) releases for your platform and verify their checksums. The CI workflow shows pinned Linux AMD64 downloads and checksum verification.

Install [Semgrep](https://semgrep.dev/docs/getting-started/) and [Checkov](https://www.checkov.io/2.Basics/Installing%20Checkov.html) in separate approved environments; with `pipx` installed:

  ```bash
  pipx install 'semgrep==1.184.0'
  pipx install 'checkov==3.2.495'
  ```

**Windows 11:** Install approved Git for Windows and Python, then open **Git Bash** in the repository. Install approved Windows binaries for Gitleaks, Trivy, Syft and Grype using their official instructions; confirm they are on Git Bash's `PATH`. For Checkov, an isolated environment can be created from PowerShell:

```powershell
python -m venv .venv\checkov
.\.venv\checkov\Scripts\python.exe -m pip install checkov==3.2.495
```

In Git Bash, add it to the current shell with `export PATH="$PWD/.venv/checkov/Scripts:$PATH"`. The workstation's earlier Checkov installation was isolated, not global. Semgrep may require a supported Linux/macOS environment or CI; a Windows executable on `PATH` is not proof that it can run.

Internet access is needed for Semgrep rules, vulnerability databases and registry downloads. Docker is optional for the default registry-based Grype scan, but is required to build and scan the supplied local image. Windows Application Control previously blocked Grype and Semgrep on this workstation; Docker was unavailable. Syft and Checkov have run locally in separate verified runs. Do not disable or bypass security controls; request IT approval or use GitHub-hosted Ubuntu. Availability on `PATH` does not prove execution is permitted.

## Run

From the repository root in Git Bash or Linux:

```bash
./scripts/security-scan.sh
```

In PowerShell, invoke the Git Bash executable directly (without changing execution policy):

```powershell
& 'C:\Program Files\Git\bin\bash.exe' scripts/security-scan.sh
```

Individual checks use the same implementation:

```bash
./scripts/security-scan.sh gitleaks
./scripts/security-scan.sh semgrep
./scripts/security-scan.sh trivy
./scripts/security-scan.sh syft
./scripts/security-scan.sh grype
./scripts/security-scan.sh checkov
```

The script continues after findings or errors. `PASS` means the scan completed and its gate passed; `PASS (findings; gate passed)` additionally indicates findings below the threshold or a disabled threshold. `FAIL` means the scan completed but its security gate failed. `SKIPPED` means it was not selected; `ERROR` means execution, configuration or report validation failed. A gate failure is not a scanner execution failure. Exit `0` means all selected gates passed, `1` means at least one gate failed, and `2` means an execution, configuration or report error (which takes precedence). Intentional sample findings are **not suppressed** and normally make a full run exit nonzero.

Set `TRIVY_FAIL_ON` to `low`, `medium`, `high` (default), `critical`, or `none`; set `GRYPE_FAIL_ON` to `negligible`, `low`, `medium`, `high` (default), `critical`, or `none`. Lower-severity and unknown findings remain in reports; unknown has no threshold rank. `none` disables that scanner's severity gate, not its findings. Gitleaks, Semgrep and Checkov fail on any finding. This sample has known vulnerabilities and is expected to fail gates.

Set `GRYPE_IMAGE` to a registry image reference (without `registry:`); the default is an intentionally old public image, whose tag can change. Pin a digest for reproducible use. `TRIVY_TARGET`, `SYFT_TARGET`, `GRYPE_TARGET`, `CHECKOV_TARGET` select existing targets; `GRYPE_TARGET` defaults to `samples/vulnerable-dependencies`. Grype scans that directory and the image independently, applying `GRYPE_FAIL_ON` to both. `TRIVY_BIN`, `SYFT_BIN`, and `GRYPE_BIN` may select approved executables. `TRIVY_REPORT_DIR`, `GRYPE_REPORT_DIR`, `CHECKOV_REPORT_DIR`, `GITLEAKS_REPORT_PATH`, `SEMGREP_REPORT_PATH`, `SEMGREP_TEXT_REPORT_PATH`, `SYFT_CYCLONEDX_REPORT_PATH`, `SYFT_SPDX_REPORT_PATH` and `SCAN_SUMMARY_PATH` override report destinations. Syft requires components by default; `SYFT_REQUIRE_PACKAGES=0` permits an empty inventory. `SEMGREP_EXCLUDE` passes one optional exclusion pattern; exclusions can hide real findings and should be reviewed.

### Build and scan the sample image

With an approved Docker installation and approved access to the pinned official Alpine base image:

```bash
docker build -t devsecops-starter-sample:1.0 -f samples/container-scan/Dockerfile samples/container-scan
GRYPE_IMAGE=devsecops-starter-sample:1.0 GRYPE_IMAGE_SOURCE=docker \
  GRYPE_REPORT_DIR=reports/grype-sample SCAN_SUMMARY_PATH=reports/grype-sample/summary.txt \
  ./scripts/security-scan.sh grype
```

The `docker` source scans the image just built in the local daemon; the default `registry` source remains unchanged. The command also scans the sample dependency directory and applies the High gate to both scans. Reports go to `reports/grype-sample/`, separate from the existing reports; back up any existing reports at that location before rerunning. The dedicated Grype workflow builds and verifies the sample image, while the combined workflow retains the registry scan. Docker and locally approved Grype are required for the local example.

## Reports and interpretation

`reports/summary.txt` contains the last run's statuses. Generated reports are ignored by Git:

- `reports/gitleaks/gitleaks-report.json` and `gitleaks-report.txt` (matched secrets redacted).
- `reports/semgrep/semgrep-report.json` and `semgrep-report.txt` (rule, path, line and severity).
- `reports/trivy/dependency-report.json` and `dependency-report.txt` (dependency findings), plus the identical `dependency-summary.txt` and CSV.
- `reports/syft/sbom-cyclonedx.json`, `sbom-spdx.json`, and `sbom-summary.txt` (target, successful generation status, local or GitHub Actions source, and component counts).
- `reports/grype/grype-report.json` and `grype-report.txt` (application directory dependencies).
- `reports/grype/grype-image-report.json` and `grype-image-report.txt` (container image).
- `reports/checkov/iac-report.json`, `iac-report.txt`, and `summary.txt` (Checkov target, source and PASS/FAIL result).

The Checkov summary describes the last completed Checkov scan. The overall summary reports `FAIL` for Checkov findings, or `SKIPPED`/`ERROR` when it did not complete.

Completed scans replace their configured report files and the overall summary. Back up reports or choose different report destinations before running if previous evidence must be preserved. Old reports can remain after a failed run; use the current summary and timestamps, not file existence, as evidence. Gitleaks redacts matched values, but other reports may contain source snippets, paths, package metadata or configuration: restrict access, review before sharing, and never commit sensitive reports. A working-tree scan does not inspect Git history; separately run approved `gitleaks git . --config configs/gitleaks/.gitleaks.toml --redact=100` for history. Findings require triage, and a clean report does not guarantee security.

## Test-only samples

- `samples/vulnerable-code/` contains a synthetic secret and Python examples for hardcoded credentials, SQL injection, weak hashes and unsafe shell execution. Gitleaks uses `configs/gitleaks/.gitleaks.toml`; Semgrep combines `configs/semgrep/semgrep.yml` with OWASP and Python rules.
- `samples/vulnerable-dependencies/pom.xml` declares `log4j-core` 2.14.1; Trivy and Grype should report vulnerabilities and Syft should inventory the component.
- `samples/vulnerable-iac/main.tf` contains public S3 settings, an unencrypted EBS volume and open SSH ingress. Checkov should report these issues without deploying anything.
- `samples/container-scan/Dockerfile` is the separately built sample image. Its findings depend on the base-image and vulnerability database versions.

## GitHub Actions and tests

`.github/workflows/security-scan.yml` runs on pushes, pull requests and manual dispatch using GitHub-hosted Ubuntu, the same Bash runner, pinned actions, read-only repository permission, verified binary downloads, and separate Python environments. It runs tests, scans the registry image and sample projects, verifies sample reports, and uploads `security-reports` even on gate failure. `.github/workflows/grype.yml` separately builds the sample Dockerfile, scans the actual daemon image, verifies its image ID and uploads its reports; the other dedicated workflows cover Semgrep and Syft. The intentional samples normally make a job fail; inspect its summary and artifact rather than calling that a scanner error. Reports are artifacts, not commits. Rules, databases, registries and PyPI remain network dependencies.

The combined workflow checks every expected report with `python3 tests/verify_required_reports.py --expect-all`. This summary-driven verifier expects the default report directory layout and filenames listed above (under `reports/`, or another root supplied as its positional argument). It does not resolve arbitrary customized destinations or filenames set through the runner's report-path environment variables; use the default layout for this verification. Missing or empty files, scanner `ERROR` statuses, and unexpected skips fail verification; findings that fail a security gate do not mean a report is missing. Without `--expect-all`, the verifier does not require reports for scanners marked `SKIPPED` in the current summary.

The dedicated single-scanner workflows use `python3 tests/check_report_files.py FILE...` to check their explicitly configured report paths individually. Their artifacts also include the runner's scan summary. The Syft workflow checks provenance when that optional step succeeds. Report verification and artifact upload run after security-gate failures.

For local automated checks:

```bash
bash -n scripts/security-scan.sh
bash tests/test-semgrep-runner.sh
bash tests/test-syft-runner.sh
bash tests/test-security-scan.sh
python -m unittest discover -s tests -p 'test_*.py'
```

After an actual complete scan, `python tests/verify_semgrep_samples.py reports/semgrep/semgrep-report.json` and `python tests/verify_scan_reports.py` verify the required sample findings, image scan and SBOM components. These are integration checks, not substitutes for running the scanners.

## Limitations

The recorded local evidence includes Gitleaks, Syft and Checkov scans; the full six-scanner run was verified in [GitHub Actions](https://github.com/sumanthcloudm-sudo/devsecops-starter-kit/actions/runs/43448185570), and the built sample image was scanned in a [separate run](https://github.com/sumanthcloudm-sudo/devsecops-starter-kit/actions/runs/43436081812). Both jobs failed security gates despite producing reports. These runs precede the current uncommitted changes. macOS and a complete local Windows run have not been verified here.

Trivy and Grype default to the sample Maven project, not an external application. Point their targets at an application's supported manifests or lockfiles to scan that application. The Maven sample inventories declared dependencies; resolved artifacts are preferable for complete transitive coverage. Grype scans the directory independently of the image and Syft reports. Database contents and findings change over time, network failures are errors, and component/JSON shape validation is not full SBOM schema validation. Terraform versus OpenTofu remains **Dilip's decision**; the sample uses common Terraform-compatible syntax and no tool choice is implied. Workflow changes must be pushed and run on GitHub before their end-to-end execution can be claimed.
