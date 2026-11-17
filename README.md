# Local DevSecOps Starter Kit

A reusable security-scanning baseline for developer workstations and GitHub Actions. It demonstrates secret scanning, static code analysis, dependency auditing, SBOM generation, container vulnerability scanning, and Infrastructure-as-Code (IaC) checks.

> **Demonstration safety:** Files under `samples/` intentionally contain vulnerable code, dependency versions, fake credentials, and insecure Terraform settings so scanners have something to detect. Never copy these samples into production. The credentials are dummy test strings, not usable secrets.

## Included tools

| Area | Tool | Configuration / input | Report |
|---|---|---|---|
| Secret scanning | Gitleaks | `config/gitleaks/gitleaks.toml`, `samples/code` | `reports/gitleaks-local.json` |
| Code security | Semgrep | `config/semgrep/rules.yml`, `samples/code` | `reports/semgrep-local.json` |
| Dependency scanning | pip-audit | `samples/code/requirements.txt` | `reports/pip-audit-local.json` |
| SBOM | Syft | Repository directory | `reports/syft-local.spdx.json` |
| Container scanning | Grype | `samples/docker/Dockerfile` | `reports/grype-local.json` |
| IaC security | Checkov | `samples/terraform` | `reports/checkov-local.json` |

## Prerequisites

Install Git and Bash, Python 3.12+, Gitleaks, Semgrep, pip-audit, Syft, Grype, Checkov, and Docker Engine or Docker Desktop. Docker is required only for the container scan.

Install the Python-based tools:

```bash
python -m pip install --upgrade pip
python -m pip install semgrep pip-audit checkov
```

Install Gitleaks, Syft, and Grype using the official installation instructions for your operating system. Start Docker before running the container scan.

## Run all available checks

From the repository root:

```bash
bash scripts/security-scan.sh
```

The script checks which tools are installed, runs every available scanner, and writes JSON/SPDX reports to `reports/`. Missing tools are reported as **SKIP**; scanner execution/report errors are reported as **ERROR**. The script continues after individual scanner findings so one result does not hide the others.

On Windows, run the command in **Git Bash** or **WSL**, not Command Prompt. Docker Desktop must be running for Grype.

## Run individual tools

```bash
gitleaks dir samples/code --config config/gitleaks/gitleaks.toml --report-format json --report-path reports/gitleaks-local.json --exit-code 0
semgrep scan --config p/python --config config/semgrep/rules.yml --json --output reports/semgrep-local.json samples/code
pip-audit -r samples/code/requirements.txt --format json --output reports/pip-audit-local.json
syft dir:. -o spdx-json=reports/syft-local.spdx.json
docker build -t devsecops-sample:local -f samples/docker/Dockerfile samples/docker
grype devsecops-sample:local -o json > reports/grype-local.json
checkov -d samples/terraform --framework terraform -o json --soft-fail > reports/checkov-local.json
```

## Interpreting results

- **Gitleaks:** each finding represents a possible secret pattern. The sample environment file contains deliberately fake values for testing.
- **Semgrep:** review rule ID, file, line, and severity. The sample code intentionally uses `eval()` and `subprocess.run(..., shell=True)`.
- **pip-audit:** review each package, vulnerability ID, installed version, and available fixed version. The sample requirements file is intentionally outdated.
- **Syft:** the SPDX JSON file is an inventory of packages/components; it is not itself a vulnerability verdict.
- **Grype:** review the vulnerability ID, severity, affected package/version, and fix state. A report containing findings means the scan worked; it does not mean the image is safe.
- **Checkov:** review failed checks and their remediation guidance. The sample S3 public-access configuration is intentionally insecure.

The local script treats vulnerability findings as reportable demonstration results and does not stop subsequent scans. It exits non-zero when a scanner cannot execute or produce a valid report.

## GitHub Actions and Grype policy

The individual workflows run on pushes and pull requests to `main`, and can also be started manually. The combined `security-pipeline.yml` workflow is manually dispatched and calls the individual workflows.

The Grype workflow validates and uploads its JSON report. By default, findings are summarized in the workflow run without failing the demonstration job. This is intentional because the sample image is used to demonstrate detection.

To make High/Critical findings block the Grype job, configure a repository Actions variable:

1. Open **Settings → Secrets and variables → Actions → Variables**.
2. Create variable `GRYPE_ENFORCE` with value `true`.
3. Re-run the Grype workflow.

This strict mode is appropriate when scanning a production image with an agreed vulnerability policy. Do not enable it for the intentionally vulnerable demonstration image unless you expect the job to fail.

## Repository layout

```text
.github/workflows/   GitHub Actions scanner workflows
config/gitleaks/     Gitleaks configuration
config/semgrep/      Custom Semgrep rules
samples/code/        Intentionally vulnerable Python and dependency samples
samples/docker/      Container build context
samples/terraform/   Intentionally insecure Terraform sample
scripts/             Local one-command runner
reports/             Generated and example reports
```

## Notes and limitations

- The IaC example uses Terraform syntax for Checkov testing. The production IaC choice (Terraform vs OpenTofu) remains a separate architecture decision.
- The `.sh` runner is intended for Bash environments. On Windows use Git Bash or WSL.
- Local scanner availability depends on installed tools and endpoint security policy. If an application-control policy blocks an executable, run the workflow in GitHub Actions or use an approved installation method.
- Reports may contain sensitive paths or detected secret-like strings. Review them before sharing or committing them.