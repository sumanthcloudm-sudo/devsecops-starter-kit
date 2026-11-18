# Local DevSecOps Starter Kit

## 1. Project Overview

The Local DevSecOps Starter Kit provides a reusable collection of security and quality checks that developers can execute locally and later integrate into GitHub Actions.

The objective is to identify security vulnerabilities, exposed secrets, insecure code patterns, vulnerable dependencies, container risks, and Infrastructure as Code (IaC) misconfigurations early in development.

The project uses six security tools to perform automated checks and generate JSON reports for review.

## 2. Project Objectives

The project implements the following security checks:

| Work Item | Tool | Expected Implementation |
|---|---|---|
| Secret scanning | Gitleaks | Detect accidentally committed secrets |
| Code security | Semgrep | Static application code analysis |
| Dependency scanning | pip-audit | Identify vulnerable Python dependencies |
| SBOM generation | Syft | Generate Software Bill of Materials |
| Container scanning | Grype | Scan a sample Docker image |
| IaC security | Checkov | Detect Terraform/OpenTofu misconfigurations |
| Automation | Bash | Execute applicable security checks and generate reports |

## 3. Project Structure

```text
devsecops-starter-kit/
│
├── .github/
│   └── workflows/
│       ├── semgrep.yml
│       ├── pip-audit.yml
│       └── grype.yml
│
├── config/
│   ├── gitleaks/
│   │   └── gitleaks.toml
│   └── semgrep/
│       └── rules.yml
│
├── samples/
│   ├── code/
│   │   ├── requirements.txt
│   │   └── vulnerable_example.py
│   │
│   ├── docker/
│   │   ├── Dockerfile
│   │   └── requirements.txt
│   │
│   └── terraform/
│       └── main.tf
│
├── reports/
│
├── scripts/
│   └── security-scan.sh
│
├── .gitignore
└── README.md
```

Additional reports and workflow files may be added as the project evolves.

## 4. Prerequisites

The following software is required for the local development environment.

| Software | Purpose |
|---|---|
| Windows 10/11 | Operating system |
| Git for Windows | Version control and Git Bash |
| Visual Studio Code | Code editor |
| Python 3 | Python-based security tools |
| pip | Python package installation |
| Docker Desktop | Optional local container image scanning |

### 4.1 Install Git for Windows

Download:

https://git-scm.com/downloads/win

Install Git for Windows with Git Bash.

Verify:

```bash
git --version
```

### 4.2 Install Visual Studio Code

Download:

https://code.visualstudio.com/

Open the project directory in VS Code.

### 4.3 Install Python

Download:

https://www.python.org/downloads/

Verify Python and pip:

```bash
python --version
python -m pip --version
```

### 4.4 Clone the Repository

Clone the DevSecOps Starter Kit:

```bash
git clone https://github.com/sumanthcloudm-sudo/devsecops-starter-kit.git
```

Navigate to the project:

```bash
cd devsecops-starter-kit
```

Open the project in VS Code:

```bash
code .
```

## 5. Security Tool Installation

Install the six security tools described in the assignment.

### 5.1 Gitleaks – Secret Scanning

Gitleaks detects accidentally committed secrets, passwords, API keys, and credentials.

Install using Windows Package Manager.

Open PowerShell:

```powershell
winget install Gitleaks.Gitleaks
```

Verify installation:

```bash
gitleaks version
```

Configuration:

```text
config/gitleaks/gitleaks.toml
```

### 5.2 Semgrep – Static Application Security Testing

Semgrep performs static application security testing (SAST).

Install using Python:

```bash
python -m pip install --user semgrep
```

Verify:

```bash
semgrep --version
```

Configuration:

```text
config/semgrep/rules.yml
```

The project uses custom Semgrep rules to detect insecure Python coding patterns.

**Windows environment note:** Local Semgrep executable execution may be blocked by Windows Application Control. In this environment, use the GitHub-hosted Actions runner for Semgrep scanning rather than attempting to bypass the restriction.

### 5.3 pip-audit – Dependency Scanning

pip-audit identifies known vulnerabilities in Python dependencies.

Install:

```bash
python -m pip install --user pip-audit
```

Verify:

```bash
python -m pip_audit --version
```

Configuration/input:

```text
samples/code/requirements.txt
```

### 5.4 Syft – SBOM Generation

Syft generates a Software Bill of Materials (SBOM).

Install using PowerShell:

```powershell
winget install Anchore.Syft
```

Verify:

```bash
syft version
```

Syft generates an SPDX JSON inventory of software packages.

### 5.5 Grype – Container Vulnerability Scanning

Grype identifies known vulnerabilities in container images and filesystems.

Install using PowerShell:

```powershell
winget install Anchore.Grype
```

Verify:

```bash
grype version
```

Grype is used with the sample Docker image and filesystem scanning as an alternative when Docker Engine is unavailable.

### 5.6 Checkov – Infrastructure as Code
Checkov scans Infrastructure as Code configurations for security misconfigurations.

Install:

python -m pip install --user checkov

Verify:

checkov --version

Sample configuration:

samples/terraform/main.tf

IaC selection note: The assignment mentions both Terraform and OpenTofu. Final selection is pending Dilip's decision. The existing sample uses Terraform.

5.7 Docker Desktop – Optional

Install Docker Desktop for Windows:

https://docs.docker.com/desktop/setup/install/windows-install/

Verify:

docker --version
docker info

Docker Engine must be running for local Docker image building and scanning.

When Docker Engine is unavailable, the automation uses Grype filesystem scanning as a fallback. Filesystem scanning is not a replacement for a complete Docker image scan.

6. Verify All Installed Tools

Open Git Bash in the project directory.

Run:

git --version
python --version
gitleaks version
semgrep --version
python -m pip_audit --version
syft version
grype version
checkov --version

Confirm that the required tools are available.

If an executable is blocked by organizational Application Control, use the approved GitHub Actions runner where applicable.

Official Installation References

Tool

Official Documentation

Gitleaks

https://github.com/gitleaks/gitleaks

Semgrep

https://semgrep.dev/docs/getting-started/

pip-audit

https://github.com/pypa/pip-audit

Syft

https://oss.anchore.com/docs/installation/syft/

Grype

https://oss.anchore.com/docs/installation/grype/

Checkov

https://www.checkov.io/2.Basics/Installing%20Checkov.html

Docker

https://docs.docker.com/desktop/setup/install/windows-install/

7. Configuration Files

The project maintains scanner-specific configuration files.

File

Description

config/gitleaks/gitleaks.toml

Gitleaks configuration

config/semgrep/rules.yml

Custom Semgrep security rules

samples/code/requirements.txt

Python dependency scanning input

samples/code/vulnerable_example.py

Vulnerable Python sample

samples/docker/Dockerfile

Sample Docker image

samples/terraform/main.tf

Terraform security testing configuration

scripts/security-scan.sh

Main automation script

These files allow the security checks to be reused and extended.

8. Running Security Scans

All local commands should be executed from the repository root using Git Bash.

8.1 Navigate to the Project

cd ~/devsecops-starter-kit

8.2 Check the Automation Script

Check the Bash syntax:

bash -n scripts/security-scan.sh

If no error appears, the script passes the syntax check.

8.3 Execute All Applicable Security Checks

Run:

bash scripts/security-scan.sh

The automation script executes the configured security checks.

It generates JSON reports and a summary of the scan results.

8.4 View Generated Reports

List the reports:

ls -lh reports/

View the dependency report:

cat reports/pip-audit-local.json

View the Gitleaks report:

cat reports/gitleaks-local.json

View the Checkov report:

cat reports/checkov-local.json

The JSON reports can also be opened directly in Visual Studio Code.

9. Individual Security Scan Execution

9.1 Gitleaks – Secret Scanning

Scan repository sample code:

gitleaks dir samples/code \
  --config config/gitleaks/gitleaks.toml \
  --report-format json \
  --report-path reports/gitleaks-local.json

Scan the external test directory:

gitleaks dir "/c/security test" \
  --config config/gitleaks/gitleaks.toml \
  --report-format json \
  --report-path reports/gitleaks-external.json

Reports:

reports/gitleaks-local.json
reports/gitleaks-external.json

The main automation also supports repository and external-directory scanning. Its configured scan targets should be checked in scripts/security-scan.sh.

9.2 Semgrep – Code Security

Run Semgrep with the custom rules:

semgrep scan \
  --config config/semgrep/rules.yml \
  --json \
  --output reports/semgrep-local.json \
  samples/code

Report:

reports/semgrep-local.json

Semgrep can also execute through GitHub Actions when local Windows execution is restricted.

9.3 pip-audit – Dependency Scanning

Execute:

python -m pip_audit \
  -r samples/code/requirements.txt \
  --format json \
  --output reports/pip-audit-local.json

Report:

reports/pip-audit-local.json

The sample requirements file intentionally uses outdated dependencies for vulnerability detection demonstrations.

An earlier scan identified:

Package

Version

Findings

requests

2.19.1

10

idna

2.7

4

urllib3

1.23

23

Total



37

The number of findings can change when vulnerability databases are updated.

These intentionally vulnerable dependencies must only be used for testing, never production.

9.4 Syft – SBOM Generation

Generate an SPDX JSON SBOM:

mkdir -p reports

syft dir:samples \
  -o spdx-json=reports/syft-local.spdx.json

Report:

reports/syft-local.spdx.json

The SBOM contains software package inventory information.

It is not itself a vulnerability report.

9.5 Grype – Container Scanning

When Docker Engine is unavailable, execute filesystem scanning:

grype dir:samples/docker \
  -o json > reports/grype-local.json

Report:

reports/grype-local.json

When Docker Engine is available, build the sample image:

docker build \
  -t devsecops-sample:latest \
  samples/docker

Scan the image:

grype devsecops-sample:latest \
  -o json > reports/grype-image-report.json

Image scanning is also supported through GitHub Actions.

9.6 Checkov – IaC Security

Run Checkov against the sample Terraform configuration:

mkdir -p reports

checkov -d samples/terraform \
  --framework terraform \
  -o json > reports/checkov-local.json

Report:

reports/checkov-local.json

The Terraform sample intentionally contains insecure configurations to demonstrate security detection.

Do not deploy the vulnerable Terraform configuration.

10. External Test Folder Scanning

The automation supports an external test folder outside the repository.

Example Windows directory:

C:\security test\
    test.txt

Git Bash directory:

/c/security test/

The external folder can be used to demonstrate secret detection and applicable code scanning independently of the main repository.

External files are not automatically available to GitHub-hosted runners. They must be made available through an approved repository or artifact process if they need to be scanned in CI.

11. Generated JSON Reports

All generated reports are stored in the reports/ directory.

Security Tool

Generated Report

Gitleaks

reports/gitleaks-local.json

Gitleaks External

reports/gitleaks-external.json

Semgrep

reports/semgrep-local.json

pip-audit

reports/pip-audit-local.json

Syft

reports/syft-local.spdx.json

Checkov

reports/checkov-local.json

Grype

reports/grype-local.json

Grype Image

reports/grype-image-report.json

Automation Summary

reports/security-summary.md

The reports provide information about detected security issues and scanner execution.

12. Understanding Scan Results

The automation uses the following result statuses:

Status

Meaning

PASS

Scanner completed successfully with no detected findings

FINDINGS

Security issues were detected

ERROR

Scanner execution or report generation failed

SKIPPED

Scanner was unavailable or the required input was missing

COMPLETE

Scanner completed and generated its report; inspect the findings separately

Example Scan Output

===== Gitleaks =====
Gitleaks       FINDINGS

===== Semgrep =====
Semgrep        FINDINGS

===== Dependency =====
Dependency     FINDINGS

===== Syft =====
Syft           PASS

===== Checkov =====
Checkov        FINDINGS

===== Grype =====
Grype          FINDINGS

A finding does not necessarily indicate a scanner execution failure.

A successful scan does not guarantee that the application is completely secure.

Always inspect the generated JSON reports.

13. GitHub Actions Integration

The project supports automated security checks through GitHub Actions.

Existing workflow files include:

.github/workflows/
    semgrep.yml
    pip-audit.yml
    grype.yml

The workflows can execute security checks using GitHub-hosted runners.

GitHub Actions is particularly useful when local Windows execution is restricted by Application Control.

The workflows can generate reports and upload them as artifacts for review.

A combined GitHub Actions workflow is a proposed deliverable for future integration into the AccIDion repository.

Integration requires review and approval.

14. Security Recommendations

Never commit real passwords, API keys, or access tokens.

Use intentionally vulnerable samples only for security demonstrations.

Review Critical and High severity vulnerabilities first.

Upgrade vulnerable dependencies to supported fixed versions.

Review Gitleaks and Semgrep findings before merging code.

Remediate Terraform/OpenTofu misconfigurations before deployment.

Review generated SBOM and container vulnerability reports.

Keep security scanning enabled during development and CI/CD.

Do not deploy intentionally vulnerable sample configurations.

Do not bypass organizational endpoint security restrictions.

15. Expected Assignment Deliverables

The project aims to provide all deliverables requested in the assignment.

Deliverable

Location

Proposed GitHub Actions workflow

.github/workflows/

Installation and execution documentation

README.md

Sample security reports

reports/

Vulnerable sample code and configurations

samples/

Scanner configuration files

config/

Security automation script

scripts/security-scan.sh

Working local scanning setup

Project root

16. Conclusion

The Local DevSecOps Starter Kit provides a reusable security scanning setup for developers.

It supports:

Secret scanning using Gitleaks.

Static code analysis using Semgrep.

Dependency vulnerability scanning using pip-audit.

SBOM generation using Syft.

Container and filesystem scanning using Grype.

Infrastructure as Code scanning using Checkov.

Automated execution and JSON report generation using Bash.

The project establishes a foundation for local security testing and future GitHub Actions integration into the AccIDion repository.

The final IaC technology selection remains subject to Dilip's decision between Terraform and OpenTofu.