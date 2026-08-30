<#
.SYNOPSIS
    Exports or imports Microsoft Sentinel analytics rules.

.EXAMPLES
    Export enabled rules:

    .\SentinelRules.ps1 `
        -Mode Export `
        -ResourceGroupName "sentinelsphere-rg" `
        -WorkspaceName "SentinelSphere-log" `
        -ExportFolder "C:\Temp\SentinelExport"

    Import only missing rules:

    .\SentinelRules.ps1 `
        -Mode Import `
        -ResourceGroupName "target-resource-group" `
        -WorkspaceName "target-workspace" `
        -JsonFile "C:\Temp\SentinelExport\ActiveAnalyticsRules.json"
#>

[CmdletBinding()]
param
(
    [Parameter(Mandatory)]
    [ValidateSet("Export", "Import")]
    [string]$Mode,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$ResourceGroupName,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$WorkspaceName,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ExportFolder = "C:\Temp\SentinelExport",

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$JsonFile = "C:\Temp\SentinelExport\ActiveAnalyticsRules.json",

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ApiVersion = "2025-09-01",

    [Parameter()]
    [switch]$DeviceCode
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$modulePath = Join-Path `
    -Path $PSScriptRoot `
    -ChildPath "SentinelRules.psm1"

if (-not (Test-Path -LiteralPath $modulePath))
{
    throw "The module was not found at '$modulePath'. Ensure SentinelRules.ps1 and SentinelRules.psm1 are in the same folder."
}

Import-Module `
    -Name $modulePath `
    -Force `
    -ErrorAction Stop

try
{
    switch ($Mode)
    {
        "Export"
        {
            Export-SentinelRules `
                -ResourceGroupName $ResourceGroupName `
                -WorkspaceName $WorkspaceName `
                -ExportFolder $ExportFolder `
                -ApiVersion $ApiVersion `
                -DeviceCode:$DeviceCode
        }

        "Import"
        {
            Import-SentinelRules `
                -ResourceGroupName $ResourceGroupName `
                -WorkspaceName $WorkspaceName `
                -JsonFile $JsonFile `
                -ApiVersion $ApiVersion `
                -DeviceCode:$DeviceCode
        }
    }
}
catch
{
    Write-Host ""
    Write-Host "Sentinel rule operation failed." -ForegroundColor DarkYellow
    Write-Host $_.Exception.Message -ForegroundColor DarkYellow

    if ($_.ErrorDetails.Message)
    {
        Write-Host ""
        Write-Host "Azure response:" -ForegroundColor DarkYellow
        Write-Host $_.ErrorDetails.Message -ForegroundColor DarkYellow
    }

    exit 1
}