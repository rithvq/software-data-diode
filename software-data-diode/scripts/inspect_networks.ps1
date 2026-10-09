param(
    [string]$ProjectName = "software-data-diode-security",
    [string]$OutputPath = "security-reports/network-memberships.json"
)

$ErrorActionPreference = "Stop"
$networkKeys = @(
    "edge-network",
    "diode-network",
    "fog-ingress-network",
    "fog-services-network"
)
$memberships = @{}

foreach ($networkKey in $networkKeys) {
    $networkName = "${ProjectName}_${networkKey}"
    $raw = docker network inspect $networkName
    if ($LASTEXITCODE -ne 0) {
        throw "docker network inspect failed for $networkName"
    }
    $network = ($raw | ConvertFrom-Json)[0]
    $containers = @(
        $network.Containers.PSObject.Properties.Value |
            ForEach-Object { $_.Name } |
            Sort-Object
    )
    $memberships[$networkKey] = $containers
    Write-Host "`n$networkName"
    $containers | ForEach-Object { Write-Host "  $_" }
}

$edgeMembers = @($memberships["edge-network"])
$fogMembers = @($memberships["fog-services-network"])
$evidence = [ordered]@{
    timestamp = (Get-Date).ToUniversalTime().ToString("o")
    project = $ProjectName
    networks = $memberships
    assertions = [ordered]@{
        fog_receiver_absent_from_edge_network = ($edgeMembers -notcontains "${ProjectName}-fog-receiver-1")
        edge_gateway_absent_from_fog_services_network = ($fogMembers -notcontains "${ProjectName}-edge-gateway-1")
        edge_devices_absent_from_fog_services_network = -not ($fogMembers | Where-Object { $_ -like "${ProjectName}-edge-device-*" })
    }
}

$resolvedOutput = Join-Path (Get-Location) $OutputPath
$outputDirectory = Split-Path -Parent $resolvedOutput
New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null
$evidence | ConvertTo-Json -Depth 8 | Set-Content -Path $resolvedOutput -Encoding utf8
Write-Host "`nSaved network evidence to $resolvedOutput"

if ($evidence.assertions.Values -contains $false) {
    exit 1
}
