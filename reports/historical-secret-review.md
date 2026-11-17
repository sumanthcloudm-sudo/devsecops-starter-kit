# Historical Gitleaks Finding Review

Reviewed: 2026-11-17

## Scope
Gitleaks Git-history scan reported 8 detections across 43 commits. This review distinguishes intentional demonstration credentials from unresolved historical report content.

| Historical file | Detections | Assessment |
| --- | ---: | --- |
| `samples/code/.env.example` | 2 | User confirmed both INTERNAL_SERVICE_TOKEN and DATABASE_PASSWORD are synthetic demonstration values |
| `reports/gitleaks-report.json` | 4 | Duplicate occurrences of those two synthetic values in the JSON report's Match and Secret fields |
| `reports/grype-image-report.json` at commit `2a1d265` | 2 | GPG_KEY findings; Gitleaks reported decoded:percent and decoded:base64 with decode-depth:2. The underlying value has **not** been verified as synthetic or as a false positive |

## Mitigation completed
- The current Grype report was replaced in commit `92cac8c` with a minimal vulnerability summary retaining 17 matches (CVE ID, severity, artifact name and version).
- A Gitleaks directory scan of the current sanitized Grype report returned no leaks.
- All six individual GitHub Actions scanner workflows completed successfully for commit `92cac8c`.

## Remaining risk and follow-up
- **Open:** Confirm whether the historical GPG_KEY match was a live credential or an innocuous decoded package value. No proof of either classification is available.
- If live, revoke/rotate it immediately, then coordinate Git-history cleanup and any necessary notification. A normal commit does not erase old Git blobs.
- The historical Gitleaks findings in prior commits remain discoverable. Do not represent the entire repository history as free of secrets.
- The two synthetic sample credentials are intentionally retained to demonstrate Gitleaks detection.

## Scope of verification
Successful GitHub Actions jobs indicate the workflows ran successfully; they do not imply zero security findings. The sanitized Grype JSON is a reduced vulnerability summary, not a full native Grype output.
