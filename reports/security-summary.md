# DevSecOps Starter Kit — Security Validation Report

Generated: 2026-11-17 08:00 UTC

## Local Scanner Validation

| Scanner | Status | Evidence |
|---|---|---|
| Gitleaks | Findings detected | reports/gitleaks-local.json |
| Semgrep | Blocked locally | Windows application-control restriction |
| pip-audit | Findings detected | reports/pip-audit-local.json |
| Syft | Report generated | reports/syft-local.spdx.json |
| Checkov | 11 failed security checks | reports/checkov-local.json |
| Grype | Filesystem scan completed | reports/grype-local.json |

## Validation Summary

- Five local scanner reports validated as JSON.
- Semgrep could not produce a valid local report.
- Semgrep was successfully executed in GitHub Actions.
- Grype filesystem scan detected zero installed packages.
- Docker image scanning was demonstrated in GitHub Actions.
- Security findings in intentionally vulnerable samples remain for demonstration.

## Important Limitations

A valid JSON report confirms report integrity, not the absence
of vulnerabilities.

The Grype filesystem scan is not equivalent to a container
image vulnerability scan.

Local Semgrep execution remains blocked by Windows security
controls; the CI workflow provides separate execution evidence.

## CI/CD Evidence

Repository:
https://github.com/sumanthcloudm-sudo/devsecops-starter-kit

GitHub Actions:
https://github.com/sumanthcloudm-sudo/devsecops-starter-kit/actions

## Conclusion

The DevSecOps Starter Kit demonstrates secret scanning,
static analysis, dependency auditing, SBOM generation,
infrastructure security scanning, and vulnerability scanning.

Five scanners generated locally validated reports.
Semgrep validation was completed separately through CI.
