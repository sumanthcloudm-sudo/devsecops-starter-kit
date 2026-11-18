
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
| Gitleaks | Findings detected |
| Semgrep | 8 detections |
| pip-audit | Vulnerabilities detected |
| Syft | SBOM generated successfully |
| Checkov | Findings detected |
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

The final selection between Terraform and OpenTofu is pending confirmation from Dilip.

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
