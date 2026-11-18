
# Local DevSecOps Starter Kit

## Overview

The Local DevSecOps Starter Kit provides reusable security checks that developers can run locally or through GitHub Actions.

The goal is to identify security issues early in development and generate reports that developers can review.

## Security Tools

| Tool | Purpose |
|------|---------|
| Gitleaks | Detect exposed secrets |
| Semgrep | Static application security testing |
| pip-audit | Identify vulnerable Python dependencies |
| Syft | Generate Software Bill of Materials |
| Grype | Scan Docker images and filesystems |
| Checkov | Scan Infrastructure as Code |

## Prerequisites

- Git
- Bash
- Python 3 and pip
- Gitleaks
- Semgrep
- pip-audit
- Syft
- Grype
- Checkov
- Docker (optional for local image scanning)

Install the tools using their official installation instructions.

## Running Security Scans

From the project root, execute:

```bash
bash scripts/security-scan.sh
```

The script runs the configured security checks and generates reports.

## Scan Results

The verified scan produced the following results:

| Tool | Result |
|------|--------|
| Gitleaks | 2 findings |
| Semgrep | 2 findings |
| pip-audit | 37 findings |
| Syft | SBOM generated (32 packages) |
| Checkov | 11 findings |
| Grype | 17 image vulnerabilities |

Grype image vulnerability severity:

- High: 4
- Medium: 11
- Low: 2

## Generated Reports

| Report | Location |
|--------|----------|
| Gitleaks | reports/gitleaks-local.json |
| Dependency scan | reports/pip-audit-local.json |
| Syft SBOM | reports/syft-local.spdx.json |
| Checkov | reports/checkov-local.json |
| Grype filesystem | reports/grype-local.json |
| Grype image | reports/grype-image-report.json |
| Summary | reports/security-summary.md |

Semgrep results are generated through GitHub Actions.

## Docker Fallback

When Docker Engine is unavailable locally, the automation uses Grype filesystem scanning.

Docker image scanning is performed through GitHub Actions.

Filesystem scanning does not replace a complete container image scan.

## Interpreting Results

PASS: The operation completed successfully.

FINDINGS: Security issues were detected and should be reviewed.

COMPLETE: The scanner finished, but findings must be inspected separately.

ERROR: The scan could not complete.

SKIPPED: The check was not executed.

Security findings do not necessarily indicate scanner execution failures.

## GitHub Actions Integration

The project supports running security checks in GitHub Actions.

A combined workflow can be proposed for future AccIDion integration after review and approval.

## Infrastructure as Code

Checkov is configured to scan sample IaC files.

**Selected IaC technology: Terraform.** Checkov scans `samples/terraform/main.tf` in the dedicated `Checkov Terraform Security Scan` workflow and the consolidated `DevSecOps Security Scan` workflow.

The existing Terraform example intentionally disables S3 public-access protections so Checkov can detect security misconfigurations. It is a **scan-only training example**: do not run `terraform apply` against it.

Run Checkov against the sample from the repository root:

```bash
mkdir -p reports
checkov -d samples/terraform --framework terraform -o json > reports/checkov-local.json
```

Checkov may return a nonzero exit code when it finds the intentionally insecure settings. Inspect the JSON report rather than interpreting findings as a scanner installation failure.

For a safer S3 configuration comparison, see `examples/terraform-secure/main.tf`. It enables public-access blocking, server-side encryption, and versioning. Both examples are for demonstration and must be reviewed before any deployment.

**Terraform is the project implementation choice.** Any separate organizational approval remains outside the scope of this repository.

## Current Verification Summary

Successful: 1
Findings: 5
Errors: 0
Skipped: 0

The summary reflects the recorded scan results, including findings obtained from GitHub Actions.

## Conclusion

The core six-tool DevSecOps scanning setup has been implemented and tested.

The starter kit supports automated security checks, vulnerability detection, SBOM generation, and report generation.

Final repository documentation and GitHub Actions integration readiness remain subject to review.
