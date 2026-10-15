param(
    [string]$Project = 'software-data-diode-coverage',
    [string]$CachedImagesFrom = '',
    [int]$DashboardPort = 38501,
    [switch]$Build
)
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
$Python = Join-Path $Root '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $Python)) {
    throw 'The project .venv is missing. Create it with Python 3.11+ and install requirements-dev.txt.'
}
$Arguments = @((Join-Path $PSScriptRoot 'coverage_local.py'), 'start', '--project', $Project, '--dashboard-port', "$DashboardPort")
if ($CachedImagesFrom) { $Arguments += @('--cached-images-from', $CachedImagesFrom) }
if ($Build) { $Arguments += '--build' }
& $Python @Arguments
if ($LASTEXITCODE -ne 0) { throw 'N11 operation failed. State was retained; inspect the preceding error.' }
