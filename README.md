# Local DevSecOps starter kit

This repository demonstrates six local and CI checks for later integration into AccIDion; it does not modify that repository. All samples are intentionally insecure, test-only, and must never be deployed or used as credentials.

| Tool | Purpose | Default target |
| --- | --- | --- |
| Gitleaks | Find secrets in the working tree; redact matched values | Repository |
| Semgrep | OWASP and Python SAST plus four custom Python rules | Repository |
| Trivy | Dependency vulnerabilities and severity | Sample Maven POM |
| Syft | CycloneDX and SPDX component inventories | Sample Maven POM |
| Grype | Vulnerabilities in a real container image | `docker.io/library/alpine:3.10` |
| Checkov | Terraform-compatible infrastructure security | Sample `.tf` files |

## Prerequisites and installation

Install Git, Bash, Python 3, and approved versions of all six executables on `PATH`. The proposed CI uses Gitleaks 8.30.1, Semgrep 1.184.0, Trivy 0.69.3, Syft 1.57.1, Grype 0.121.3 and Checkov 3.2.495. Obtain organizational approval first:

- [Gitleaks](https://github.com/gitleaks/gitleaks#installing), [Trivy](https://trivy.dev/latest/getting-started/installation/), [Syft](https://oss.anchore.com/docs/installation/syft/), [Grype](https://oss.anchore.com/docs/installation/grype/): install official releases for your operating system and verify their checksums.
- [Semgrep](https://semgrep.dev/docs/getting-started/) and [Checkov](https://www.checkov.io/2.Basics/Installing%20Checkov.html): install into separate approved Python environments, for example on Linux:
  ```bash
  pipx install 'semgrep==1.184.0'
  pipx install 'checkov==3.2.495'
  ```

On Windows 11 install approved Git for Windows and open **Git Bash** in the repository. Ensure approved scanner executables and Python are on Git Bash's `PATH`. On Linux use Bash with the same prerequisites. Internet access is needed for Semgrep's rules, Maven metadata, vulnerability databases and the container registry. Docker is not required: Grype explicitly downloads the image from the registry.

Windows Application Control has blocked Semgrep and Syft on this workstation; Docker and WSL were not available during the prior local checks. Do not disable or bypass Application Control, Smart App Control, execution policy or other security controls. Request IT approval, or use a GitHub-hosted Ubuntu runner. An executable appearing on `PATH` does not prove that policy permits it to run.

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

The script continues after findings or errors. `PASS` means a check completed and found nothing; `FINDINGS` means findings exist even if below a configured gate; `ERROR` means the scan or report failed; `SKIPPED` means it was not selected. Exit `0` means all selected gates passed, `1` means at least one gate failed, and `2` means an execution, configuration or report error (which takes precedence). Intentional sample findings are **not suppressed** and normally make a full run exit nonzero.

Set `TRIVY_FAIL_ON` to `low`, `medium`, `high` (default), `critical`, or `none`; set `GRYPE_FAIL_ON` to `negligible`, `low`, `medium`, `high` (default), `critical`, or `none`. Lower-severity and unknown findings remain in reports; unknown has no threshold rank. `none` disables that scanner's severity gate, not its findings. Gitleaks, Semgrep and Checkov fail on any finding. This sample has known vulnerabilities and is expected to fail gates.

Set `GRYPE_IMAGE` to a registry image reference (without `registry:`); the default is an intentionally old public image, whose tag can change. Pin a digest for reproducible use. `TRIVY_TARGET`, `SYFT_TARGET`, `CHECKOV_TARGET` select existing targets. `TRIVY_BIN`, `SYFT_BIN`, and `GRYPE_BIN` may select approved executables. `TRIVY_REPORT_DIR`, `GRYPE_REPORT_DIR`, `CHECKOV_REPORT_DIR`, `GITLEAKS_REPORT_PATH`, `SEMGREP_REPORT_PATH`, `SEMGREP_TEXT_REPORT_PATH`, `SYFT_CYCLONEDX_REPORT_PATH`, `SYFT_SPDX_REPORT_PATH` and `SCAN_SUMMARY_PATH` override report destinations. Syft requires components by default; `SYFT_REQUIRE_PACKAGES=0` permits an empty inventory. `SEMGREP_EXCLUDE` passes one optional exclusion pattern; exclusions can hide real findings and should be reviewed.

## Reports and interpretation

`reports/summary.txt` contains the last run's statuses. Generated reports are ignored by Git:

- `reports/gitleaks/gitleaks-report.json` and `gitleaks-report.txt` (matched secrets redacted).
- `reports/semgrep/semgrep-report.json` and `semgrep-report.txt` (rule, path, line and severity).
- `reports/trivy/dependency-report.json`, `dependency-summary.txt` and CSV.
- `reports/syft/sbom-cyclonedx.json`, `sbom-spdx.json`, and `sbom-summary.txt`.
- `reports/grype/grype-report.json` and `grype-report.txt` (image, severity counts and matches).
- `reports/checkov/checkov-report.json` and `checkov-report.txt`.

Reports are produced only by scanners, not fabricated. Old reports can remain after a failed run; use the current summary and timestamps, not file existence, as evidence. Gitleaks redacts matched values, but other reports may contain source snippets, paths, package metadata or configuration: restrict access, review before sharing, and never commit sensitive reports. A working-tree scan does not inspect Git history; separately run approved `gitleaks git . --config configs/gitleaks/.gitleaks.toml --redact=100` for history. Findings require triage, and a clean report does not guarantee security.

## GitHub Actions and tests

`.github/workflows/security-scan.yml` runs on pushes, pull requests and manual dispatch using GitHub-hosted Ubuntu, the same Bash runner, pinned actions, read-only repository permission, verified binary downloads, and separate Python environments. It runs tests and checks real sample reports, then uploads `security-reports` even on gate failure. The intentional samples normally make the job fail; inspect its summary and artifact rather than calling that a scanner error. Reports are artifacts, not commits. Rules, databases, registries and PyPI remain network dependencies.

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

The Maven sample inventories declared dependencies; resolved artifacts are preferable for complete transitive coverage. Grype scans an image independently of Syft; it does not scan an SBOM in place of the image. Database contents and findings change over time, network failures are errors, and component/JSON shape validation is not full SBOM schema validation. Terraform versus OpenTofu remains **Dilip's decision**; the sample uses common Terraform-compatible syntax and no tool choice is implied. The new combined workflow must be pushed and run on GitHub before its end-to-end execution can be claimed.
