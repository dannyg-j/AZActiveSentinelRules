
# ===== Inputs =====
$ResourceGroupName = "" #The resource group where Sentinel/Log Analytics resides
$WorkspaceName     = "" #The Sentinel workspace name
$outPath           = "C:\temp\ActiveAnalyticsRules.csv" #The path to the CSV that active rules will be exported to

#Authenticate to Entra ID
Connect-AzAccount -DeviceCode

# Ensure output folder exists
$dir = Split-Path -Path $outPath -Parent
if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }

# ===== Auth (needs Az.Accounts) =====
$ctx           = Get-AzContext
if (-not $ctx) { throw "No Az context found. Run Connect-AzAccount first." }
$profile       = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
$profileClient = New-Object Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient($profile)
$token         = $profileClient.AcquireAccessToken($ctx.Subscription.TenantId)
$authHeader    = @{ 'Authorization' = "Bearer $($token.AccessToken)"; 'Content-Type'='application/json' }

$subscriptionId = $ctx.Subscription.Id
$apiVersion     = "2023-09-01-preview"

function Invoke-ArmGetAllPages {
    param(
        [Parameter(Mandatory=$true)][string]$Url,
        [Parameter(Mandatory=$true)][hashtable]$Headers
    )
    $all  = @()
    $next = $Url
    while ($next) {
        $resp = Invoke-RestMethod -Method GET -Uri $next -Headers $Headers
        if ($resp.value) { $all += $resp.value }
        if     ($resp.nextLink)          { $next = $resp.nextLink }
        elseif ($resp.'@odata.nextLink') { $next = $resp.'@odata.nextLink' }
        else { $next = $null }
    }
    return $all
}

# --- In-use rules endpoint (NOT templates) ---
$baseUrl = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/alertRules?api-version=$apiVersion"

$rules = Invoke-ArmGetAllPages -Url $baseUrl -Headers $authHeader

# Keep only enabled rules, then select the four columns
$rows =
    $rules |
    Where-Object { $_.properties.enabled -eq $true } |
    Select-Object @{
        n='Id';          e={$_.id}
    }, @{
        n='Kind';        e={$_.kind}
    }, @{
        n='Enabled';     e={$_.properties.enabled}
    }, @{
        n='DisplayName'; e={$_.properties.displayName}
    }

# Export clean CSV
$rows | Export-Csv -Path $outPath -NoTypeInformation -Encoding UTF8

Write-Host "Exported $($rows.Count) active rules to $outPath" -ForegroundColor Green