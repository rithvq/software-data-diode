param(
    [string]$OutputDirectory = "logs"
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$outputPath = Join-Path $projectRoot $OutputDirectory
$files = @(
    "edge-gateway-audit.jsonl",
    "data-diode-audit.jsonl",
    "fog-receiver-audit.jsonl",
    "edge-gateway-sequences.json"
)

Push-Location $projectRoot
try {
    New-Item -ItemType Directory -Force -Path $outputPath | Out-Null
    foreach ($file in $files) {
        $destination = Join-Path $outputPath $file
        & docker compose --profile full cp "fog-receiver:/logs/$file" $destination
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "Could not export $file; it may not have been created yet."
        }
    }
}
finally {
    Pop-Location
}

Write-Host "Audit evidence exported to $outputPath"
