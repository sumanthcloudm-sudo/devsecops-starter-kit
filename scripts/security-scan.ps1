param(
    [ValidateSet('all', 'gitleaks', 'semgrep', 'grype')]
    [string]$Scanner = 'all'
)

$ErrorActionPreference = 'Continue'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$gitleaksConfig = Join-Path $repoRoot 'configs\gitleaks\.gitleaks.toml'
$semgrepConfig = 'configs/semgrep/semgrep.yml'
$gitleaksReport = if ($env:GITLEAKS_REPORT_PATH) { $env:GITLEAKS_REPORT_PATH } else { 'reports/gitleaks/gitleaks-report.json' }
$semgrepReport = if ($env:SEMGREP_REPORT_PATH) { $env:SEMGREP_REPORT_PATH } else { 'reports/semgrep/semgrep-report.json' }
$semgrepTextReport = if ($env:SEMGREP_TEXT_REPORT_PATH) { $env:SEMGREP_TEXT_REPORT_PATH } else { 'reports/semgrep/semgrep-report.txt' }

Set-Location $repoRoot
New-Item -ItemType Directory -Force -Path 'reports\gitleaks', 'reports\semgrep' | Out-Null

function Invoke-GitleaksScan {
    $gitleaks = Get-Command gitleaks -ErrorAction SilentlyContinue
    if (-not $gitleaks) {
        Write-Error 'Gitleaks was not found. Install an organization-approved Gitleaks release and retry.'
        return 2
    }

    Write-Host 'Running Gitleaks...'
    & $gitleaks.Source dir . --config $gitleaksConfig --report-format json --report-path $gitleaksReport 2>&1 | Out-Host
    $status = $LASTEXITCODE
    if ($status -eq 1) {
        Write-Error "Gitleaks found one or more secrets. Report: $gitleaksReport"
        return 1
    }
    if ($status -ne 0) {
        Write-Error "Gitleaks failed with exit code $status."
        return 2
    }

    Write-Host "Gitleaks completed without findings. Report: $gitleaksReport"
    return 0
}

function Invoke-GrypeScan {
    $python = Get-Command python -ErrorAction SilentlyContinue
    if (-not $python) { $python = Get-Command python3 -ErrorAction SilentlyContinue }
    if (-not $python) {
        Write-Error 'Python 3 is required to run Grype and generate reports.'
        return 2
    }

    & $python.Source (Join-Path $PSScriptRoot 'grype-scan.py') 2>&1 | Out-Host
    $status = $LASTEXITCODE
    if ($status -eq 0 -or $status -eq 1) { return $status }
    Write-Error "Grype scan or report generation failed with exit code $status."
    return 2
}

function Invoke-SemgrepScan {
    $docker = Get-Command docker -ErrorAction SilentlyContinue
    if (-not $docker) {
        Write-Error 'Docker was not found. Use an IT-approved Docker Desktop installation, or run scripts/security-scan.sh inside an approved WSL distro with Semgrep installed.'
        return 2
    }

    $volume = '{0}:/src' -f $repoRoot
    $dockerArgs = @(
        'run', '--rm',
        '--volume', $volume,
        '--workdir', '/src',
        'semgrep/semgrep',
        'scan',
        '--config', 'p/owasp-top-ten',
        '--config', 'p/python',
        '--config', $semgrepConfig,
        '--metrics=off',
        '--json-output', $semgrepReport,
        '--error',
        '.'
    )

    Write-Host 'Running Semgrep in the official semgrep/semgrep container...'
    $output = & $docker.Source @dockerArgs 2>&1
    $status = $LASTEXITCODE
    $output | Set-Content -LiteralPath $semgrepTextReport -Encoding UTF8
    $output | ForEach-Object { Write-Host $_ }

    if ($status -eq 0) {
        Write-Host "Semgrep completed without findings. Reports: $semgrepReport and $semgrepTextReport"
        return 0
    }
    if ($status -eq 1) {
        Write-Error "Semgrep found one or more issues. Reports: $semgrepReport and $semgrepTextReport"
        return 1
    }

    Write-Error "Semgrep failed with exit code $status. Check the text report and Docker/runtime configuration."
    return 2
}

$overallStatus = 0
if ($Scanner -eq 'all' -or $Scanner -eq 'gitleaks') {
    $status = Invoke-GitleaksScan
    if ($status -eq 2) {
        $overallStatus = 2
    }
    elseif ($status -eq 1 -and $overallStatus -eq 0) {
        $overallStatus = 1
    }
}

if ($Scanner -eq 'all' -or $Scanner -eq 'semgrep') {
    $status = Invoke-SemgrepScan
    if ($status -eq 2) {
        $overallStatus = 2
    }
    elseif ($status -eq 1 -and $overallStatus -eq 0) {
        $overallStatus = 1
    }
}

if ($Scanner -eq 'all' -or $Scanner -eq 'grype') {
    $status = Invoke-GrypeScan
    if ($status -eq 2) {
        $overallStatus = 2
    }
    elseif ($status -eq 1 -and $overallStatus -eq 0) {
        $overallStatus = 1
    }
}

exit $overallStatus
