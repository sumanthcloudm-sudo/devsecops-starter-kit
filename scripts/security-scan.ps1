param(
    [ValidateSet('all', 'gitleaks', 'semgrep', 'trivy', 'syft', 'grype', 'checkov')]
    [string]$Scanner = 'all'
)

$git = Get-Command git -ErrorAction SilentlyContinue
if (-not $git) {
    Write-Error 'Git Bash was not found. Install an approved Git for Windows distribution.'
    exit 2
}
$bash = Join-Path (Split-Path (Split-Path $git.Source -Parent) -Parent) 'bin\bash.exe'
if (-not (Test-Path -LiteralPath $bash -PathType Leaf)) {
    Write-Error 'Git Bash was not found. Install an approved Git for Windows distribution.'
    exit 2
}
& $bash (Join-Path $PSScriptRoot 'security-scan.sh') $Scanner
exit $LASTEXITCODE
