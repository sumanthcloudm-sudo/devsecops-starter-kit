# DevSecOps Starter Kit - Detailed Security Findings

## Gitleaks - Secret Scanning

- Rule: generic-api-key | File: samples/code/.env.example | Line: 6
- Rule: generic-api-key | File: samples/code/.env.example | Line: 10

## Semgrep - Code Security

- Severity: WARNING | Rule: yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag | File: .github/workflows/semgrep.yml
- Severity: WARNING | Rule: yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag | File: .github/workflows/semgrep.yml
- Severity: ERROR | Rule: configs.semgrep.devsecops-starter.python.shell-command-injection | File: samples/vulnerable-code/command-injection.py
- Severity: ERROR | Rule: python.lang.security.audit.subprocess-shell-true.subprocess-shell-true | File: samples/vulnerable-code/command-injection.py
- Severity: WARNING | Rule: configs.semgrep.devsecops-starter.python.hardcoded-credential | File: samples/vulnerable-code/hardcoded-credentials.py
- Severity: WARNING | Rule: configs.semgrep.devsecops-starter.python.insecure-hash | File: samples/vulnerable-code/insecure-cryptography.py
- Severity: WARNING | Rule: python.lang.security.insecure-hash-algorithms-md5.insecure-hash-algorithm-md5 | File: samples/vulnerable-code/insecure-cryptography.py
- Severity: ERROR | Rule: configs.semgrep.devsecops-starter.python.sql-injection-concatenation | File: samples/vulnerable-code/sql-injection.py

## pip-audit - Dependency Vulnerabilities

- Package: requests 2.19.1 | Vulnerability: PYSEC-2018-28 | Fix versions: ['2.20.0']
- Package: requests 2.19.1 | Vulnerability: PYSEC-2023-74 | Fix versions: ['2.31.0']
- Package: requests 2.19.1 | Vulnerability: PYSEC-2026-1873 | Fix versions: ['2.32.0']
- Package: requests 2.19.1 | Vulnerability: PYSEC-2026-1872 | Fix versions: ['2.32.4']
- Package: requests 2.19.1 | Vulnerability: PYSEC-2026-2275 | Fix versions: ['2.33.0']
- Package: idna 2.7 | Vulnerability: PYSEC-2024-60 | Fix versions: ['3.7']
- Package: idna 2.7 | Vulnerability: PYSEC-2026-215 | Fix versions: ['3.15']
- Package: urllib3 1.23 | Vulnerability: PYSEC-2019-133 | Fix versions: ['1.24.2']
- Package: urllib3 1.23 | Vulnerability: PYSEC-2019-132 | Fix versions: ['1.24.3']
- Package: urllib3 1.23 | Vulnerability: PYSEC-2020-148 | Fix versions: ['1.25.9']
- Package: urllib3 1.23 | Vulnerability: PYSEC-2026-1995 | Fix versions: ['1.26.19', '2.2.2']
- Package: urllib3 1.23 | Vulnerability: PYSEC-2023-192 | Fix versions: ['1.26.17', '2.0.6']
- Package: urllib3 1.23 | Vulnerability: PYSEC-2023-207 | Fix versions: ['1.24.2']
- Package: urllib3 1.23 | Vulnerability: PYSEC-2023-212 | Fix versions: ['1.26.18', '2.0.7']
- Package: urllib3 1.23 | Vulnerability: PYSEC-2026-1999 | Fix versions: ['2.5.0']
- Package: urllib3 1.23 | Vulnerability: PYSEC-2026-1994 | Fix versions: ['2.6.0']
- Package: urllib3 1.23 | Vulnerability: PYSEC-2026-1996 | Fix versions: ['2.6.3']
- Package: urllib3 1.23 | Vulnerability: PYSEC-2026-141 | Fix versions: ['2.7.0']
- Package: urllib3 1.23 | Vulnerability: PYSEC-2026-4177 | Fix versions: ['2.8.0']

## Checkov - IaC Security

- Check: CKV_AWS_53 | Resource: aws_s3_bucket_public_access_block.demo | Severity: Not assigned | Description: Ensure S3 bucket has block public ACLS enabled
- Check: CKV_AWS_54 | Resource: aws_s3_bucket_public_access_block.demo | Severity: Not assigned | Description: Ensure S3 bucket has block public policy enabled
- Check: CKV_AWS_55 | Resource: aws_s3_bucket_public_access_block.demo | Severity: Not assigned | Description: Ensure S3 bucket has ignore public ACLs enabled
- Check: CKV_AWS_56 | Resource: aws_s3_bucket_public_access_block.demo | Severity: Not assigned | Description: Ensure S3 bucket has 'restrict_public_buckets' enabled
- Check: CKV2_AWS_62 | Resource: aws_s3_bucket.demo | Severity: Not assigned | Description: Ensure S3 buckets should have event notifications enabled
- Check: CKV_AWS_18 | Resource: aws_s3_bucket.demo | Severity: Not assigned | Description: Ensure the S3 bucket has access logging enabled
- Check: CKV_AWS_144 | Resource: aws_s3_bucket.demo | Severity: Not assigned | Description: Ensure that S3 bucket has cross-region replication enabled
- Check: CKV_AWS_21 | Resource: aws_s3_bucket.demo | Severity: Not assigned | Description: Ensure all data stored in the S3 bucket have versioning enabled
- Check: CKV2_AWS_61 | Resource: aws_s3_bucket.demo | Severity: Not assigned | Description: Ensure that an S3 bucket has a lifecycle configuration
- Check: CKV_AWS_145 | Resource: aws_s3_bucket.demo | Severity: Not assigned | Description: Ensure that S3 buckets are encrypted with KMS by default
- Check: CKV2_AWS_6 | Resource: aws_s3_bucket.demo | Severity: Not assigned | Description: Ensure that S3 bucket has a Public Access block

## Syft - Software Bill of Materials

- Packages inventoried: 2

## Grype - Vulnerability Scanning

- Local filesystem vulnerability matches: 0
- Note: Local filesystem scanning is not equivalent to Docker image scanning.

## Recommended Remediation

1. Remove real exposed secrets and rotate compromised credentials.
2. Fix command injection and SQL injection vulnerabilities.
3. Remove hardcoded credentials and insecure hashing.
4. Upgrade vulnerable Python dependencies.
5. Correct failed AWS S3 security checks.
6. Review container-image vulnerabilities from GitHub Actions.

## Notes

- Sample vulnerabilities are intentionally introduced for demonstration.
- Semgrep results may originate from GitHub Actions.
- Scanner severity is preserved where available; missing severity is not inferred.
- Review all findings before applying this baseline to production.
