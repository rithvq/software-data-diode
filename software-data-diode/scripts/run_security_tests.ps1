param(
    [string]$ProjectName = "software-data-diode-security"
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$privateKey = Join-Path $projectRoot "secrets/edge_private_key.pem"
$publicKey = Join-Path $projectRoot "secrets/edge_public_key.pem"

if ($ProjectName -notmatch '^software-data-diode-(security|verification)(-[a-z0-9-]+)?$') {
    throw "Use a dedicated software-data-diode-security or verification project; test cleanup removes its volumes."
}
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    $candidates = @(
        (Join-Path $env:LOCALAPPDATA "Programs/DockerDesktop/resources/bin"),
        (Join-Path $env:ProgramFiles "Docker/Docker/resources/bin")
    )
    foreach ($directory in $candidates) {
        if (Test-Path -LiteralPath (Join-Path $directory "docker.exe")) {
            $env:PATH = "$directory;$env:PATH"
            break
        }
    }
}
if (-not $env:EDGE_GATEWAY_PORT) { $env:EDGE_GATEWAY_PORT = "28080" }

if (-not (Test-Path $privateKey) -or -not (Test-Path $publicKey)) {
    throw "Signing keys are missing. Run: python scripts/generate_keys.py"
}

Push-Location $projectRoot
try {
    New-Item -ItemType Directory -Force -Path "security-reports" | Out-Null
    New-Item -ItemType Directory -Force -Path "logs" | Out-Null
    $composeArgs = @(
        "compose",
        "-p", $ProjectName,
        "-f", "docker-compose.yml",
        "-f", "docker-compose.security.yml",
        "--profile", "security-test"
    )

    & docker @composeArgs up --build -d security-test-client
    if ($LASTEXITCODE -ne 0) {
        throw "The isolated security test stack failed to start."
    }

    & docker @composeArgs wait security-test-client
    $testExitCode = $LASTEXITCODE
    & docker @composeArgs logs --no-log-prefix security-test-client

    & "$PSScriptRoot/inspect_networks.ps1" -ProjectName $ProjectName
    $inspectExitCode = $LASTEXITCODE
}
finally {
    if ($composeArgs) {
        & docker @composeArgs down --volumes --remove-orphans
    }
    Pop-Location
}

if ($testExitCode -ne 0) {
    exit $testExitCode
}
exit $inspectExitCode
