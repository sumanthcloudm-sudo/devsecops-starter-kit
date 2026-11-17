# Local DevSecOps Security Scan Report

## Verified Six-Tool Scanner Results

| Scanner | Status | Findings / Packages | Source |
|---|---|---:|---|
| Gitleaks | FINDINGS | 2 findings | Local |
| Semgrep | FINDINGS | 8 findings | GitHub Actions |
| Dependency | FINDINGS | 19 findings | Local |
| Syft | PASS | 0 packages | Local SBOM |
| Checkov | FINDINGS | 11 findings | Local |
| Grype | FINDINGS | 17 findings | GitHub Actions |

## Execution Summary

- Successful: 1
- Findings: 5
- Errors: 0
- Skipped: 0

## Important Notes

- Semgrep findings are from a previously generated GitHub Actions report.
- Grype image findings are from a previously generated GitHub Actions report.
- Local Grype filesystem scanning is not equivalent to Docker image scanning.
- Syft generates an SBOM rather than vulnerability findings.
- The summary describes available reports, not six fresh local scanner executions.
- Do not deploy intentionally vulnerable demonstration samples.
