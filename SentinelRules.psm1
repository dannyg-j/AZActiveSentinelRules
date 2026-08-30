<#
.SYNOPSIS
    Functions for exporting and importing Microsoft Sentinel analytics rules.

.DESCRIPTION
    Export-SentinelRules:
        - Retrieves analytics rules from a Microsoft Sentinel workspace.
        - Filters to enabled rules only.
        - Creates a human-readable CSV inventory.
        - Creates a JSON deployment package containing full rule properties.

    Import-SentinelRules:
        - Reads the JSON deployment package.
        - Retrieves current rules from the target workspace.
        - Matches existing rules by TemplateId first, then by DisplayName + Kind.
        - Skips existing rules.
        - Creates missing rules and forces them enabled.
        - Does not update or delete existing rules (missing-only import).
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

#region Private helper functions

function Connect-Sentinel
{
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [switch]$DeviceCode
    )

    $context = Get-AzContext -ErrorAction SilentlyContinue

    if (-not $context)
    {
        if ($DeviceCode)
        {
            Connect-AzAccount -DeviceCode -ErrorAction Stop | Out-Null
        }
        else
        {
            Connect-AzAccount -ErrorAction Stop | Out-Null
        }

        $context = Get-AzContext -ErrorAction Stop
    }

    if (-not $context.Subscription -or -not $context.Subscription.Id)
    {
        throw "The current Azure context does not contain a subscription. Run Connect-AzAccount and select a subscription."
    }

    if (-not $context.Tenant -or -not $context.Tenant.Id)
    {
        throw "The current Azure context does not contain a tenant."
    }

    $azProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile

    $profileClient = New-Object `
        -TypeName Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient `
        -ArgumentList $azProfile

    $token = $profileClient.AcquireAccessToken($context.Subscription.TenantId)

    if (-not $token -or -not $token.AccessToken)
    {
        throw "An Azure Resource Manager access token could not be acquired."
    }

    [PSCustomObject]@{
        SubscriptionId = $context.Subscription.Id
        TenantId       = $context.Tenant.Id
        Subscription   = $context.Subscription.Name
        Account        = $context.Account.Id
        Headers        = @{
            Authorization  = "Bearer $($token.AccessToken)"
            "Content-Type" = "application/json"
            Accept         = "application/json"
        }
    }
}

function Get-SentinelAlertRulesUri
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$SubscriptionId,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ResourceGroupName,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$WorkspaceName,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ApiVersion,

        [Parameter()]
        [string]$RuleId
    )

    $baseUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/alertRules"

    if (-not [string]::IsNullOrWhiteSpace($RuleId))
    {
        return "$baseUri/$RuleId`?api-version=$ApiVersion"
    }

    return "$baseUri`?api-version=$ApiVersion"
}

function Invoke-ArmGetAllPages
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Url,

        [Parameter(Mandatory)]
        [hashtable]$Headers
    )

    $allResults = [System.Collections.Generic.List[object]]::new()
    $nextUrl = $Url

    while ($nextUrl)
    {
        $response = Invoke-RestMethod `
            -Method Get `
            -Uri $nextUrl `
            -Headers $Headers `
            -ErrorAction Stop

        if ($null -ne $response.PSObject.Properties['value'] -and $null -ne $response.value)
        {
            foreach ($item in @($response.value))
            {
                $allResults.Add($item)
            }
        }

        if ($response.PSObject.Properties['nextLink'] -and $response.nextLink)
        {
            $nextUrl = $response.nextLink
        }
        elseif ($response.PSObject.Properties['@odata.nextLink'] -and $response.'@odata.nextLink')
        {
            $nextUrl = $response.'@odata.nextLink'
        }
        else
        {
            $nextUrl = $null
        }
    }

    return $allResults.ToArray()
}

function Get-SentinelRules
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ResourceGroupName,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$WorkspaceName,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ApiVersion,

        [Parameter(Mandatory)]
        [psobject]$Connection
    )

    $uri = Get-SentinelAlertRulesUri -SubscriptionId $Connection.SubscriptionId -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName -ApiVersion $ApiVersion

    return @(
        Invoke-ArmGetAllPages -Url $uri -Headers $Connection.Headers
    )
}

function Test-HasProperty
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [AllowNull()]
        [psobject]$InputObject,

        [Parameter(Mandatory)]
        [string]$Name
    )

    if ($null -eq $InputObject)
    {
        return $false
    }

    return [bool]($InputObject.PSObject.Properties.Name -contains $Name)
}

function Get-SentinelRuleTemplateId
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [psobject]$Rule
    )

    if ((Test-HasProperty -InputObject $Rule -Name 'properties') -and $null -ne $Rule.properties)
    {
        if (Test-HasProperty -InputObject $Rule.properties -Name 'alertRuleTemplateName')
        {
            return [string]$Rule.properties.alertRuleTemplateName
        }
    }

    if (Test-HasProperty -InputObject $Rule -Name 'TemplateId')
    {
        return [string]$Rule.TemplateId
    }

    return $null
}

function Get-SentinelRuleDisplayName
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [psobject]$Rule
    )

    if ((Test-HasProperty -InputObject $Rule -Name 'properties') -and $null -ne $Rule.properties)
    {
        if (Test-HasProperty -InputObject $Rule.properties -Name 'displayName')
        {
            return [string]$Rule.properties.displayName
        }
    }

    if (Test-HasProperty -InputObject $Rule -Name 'DisplayName')
    {
        return [string]$Rule.DisplayName
    }

    return $null
}

function Get-SentinelRuleKind
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [psobject]$Rule
    )

    if (Test-HasProperty -InputObject $Rule -Name 'kind')
    {
        return [string]$Rule.kind
    }

    if (Test-HasProperty -InputObject $Rule -Name 'Kind')
    {
        return [string]$Rule.Kind
    }

    return $null
}

function Get-SentinelRuleSourceId
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [psobject]$Rule
    )

    if ((Test-HasProperty -InputObject $Rule -Name 'SourceRuleId') -and (-not [string]::IsNullOrWhiteSpace([string]$Rule.SourceRuleId)))
    {
        return [string]$Rule.SourceRuleId
    }

    if ((Test-HasProperty -InputObject $Rule -Name 'name') -and (-not [string]::IsNullOrWhiteSpace([string]$Rule.name)))
    {
        return [string]$Rule.name
    }

    return $null
}

function Test-SentinelRuleExists
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [psobject]$Rule,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$ExistingRules
    )

    $templateId  = Get-SentinelRuleTemplateId  -Rule $Rule
    $displayName = Get-SentinelRuleDisplayName -Rule $Rule
    $kind        = Get-SentinelRuleKind        -Rule $Rule

    if (-not [string]::IsNullOrWhiteSpace($templateId))
    {
        $templateMatch = $ExistingRules |
            Where-Object {
                $existingTemplateId = Get-SentinelRuleTemplateId -Rule $_
                (-not [string]::IsNullOrWhiteSpace($existingTemplateId)) -and ($existingTemplateId -eq $templateId)
            } |
            Select-Object -First 1

        if ($null -ne $templateMatch)
        {
            return [PSCustomObject]@{
                Exists      = $true
                MatchMethod = "TemplateId"
                Match       = $templateMatch
            }
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($displayName))
    {
        $nameMatch = $ExistingRules |
            Where-Object {
                $existingDisplayName = Get-SentinelRuleDisplayName -Rule $_
                $existingKind        = Get-SentinelRuleKind        -Rule $_

                ($existingDisplayName -eq $displayName) -and `
                (
                    [string]::IsNullOrWhiteSpace($kind) -or `
                    ($existingKind -eq $kind)
                )
            } |
            Select-Object -First 1

        if ($null -ne $nameMatch)
        {
            return [PSCustomObject]@{
                Exists      = $true
                MatchMethod = "DisplayNameAndKind"
                Match       = $nameMatch
            }
        }
    }

    return [PSCustomObject]@{
        Exists      = $false
        MatchMethod = $null
        Match       = $null
    }
}

function Copy-SentinelRuleProperties
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [psobject]$Properties
    )

    # JSON round-trip creates an independent copy so the imported package
    # object is not mutated while preparing the ARM request body.
    $copiedProperties = $Properties |
        ConvertTo-Json -Depth 100 |
        ConvertFrom-Json

    # lastModifiedUtc is returned by GET but is managed by Sentinel; strip it.
    if (Test-HasProperty -InputObject $copiedProperties -Name 'lastModifiedUtc')
    {
        $copiedProperties.PSObject.Properties.Remove('lastModifiedUtc')
    }

    # Imported rules must be active.
    if (Test-HasProperty -InputObject $copiedProperties -Name 'enabled')
    {
        $copiedProperties.enabled = $true
    }
    else
    {
        $copiedProperties |
            Add-Member -MemberType NoteProperty -Name 'enabled' -Value $true
    }

    return $copiedProperties
}

function New-SentinelRule
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [psobject]$Rule,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ResourceGroupName,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$WorkspaceName,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ApiVersion,

        [Parameter(Mandatory)]
        [psobject]$Connection
    )

    $displayName = Get-SentinelRuleDisplayName -Rule $Rule
    $kind        = Get-SentinelRuleKind        -Rule $Rule

    if ([string]::IsNullOrWhiteSpace($displayName))
    {
        throw "The exported rule does not contain a DisplayName."
    }

    if ([string]::IsNullOrWhiteSpace($kind))
    {
        throw "The exported rule '$displayName' does not contain a Kind."
    }

    if ((-not (Test-HasProperty -InputObject $Rule -Name 'Properties')) -or $null -eq $Rule.Properties)
    {
        throw "The exported rule '$displayName' does not contain Properties."
    }

    $sourceRuleId = Get-SentinelRuleSourceId -Rule $Rule

    if ([string]::IsNullOrWhiteSpace($sourceRuleId))
    {
        $ruleId = (New-Guid).Guid
    }
    else
    {
        $ruleId = $sourceRuleId
    }

    $properties = Copy-SentinelRuleProperties -Properties $Rule.Properties

    $requestBody = [PSCustomObject]@{
        kind       = $kind
        properties = $properties
    }

    $jsonBody = $requestBody | ConvertTo-Json -Depth 100

    $uri = Get-SentinelAlertRulesUri -SubscriptionId $Connection.SubscriptionId -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName -ApiVersion $ApiVersion -RuleId $ruleId

    return Invoke-RestMethod -Method Put -Uri $uri -Headers $Connection.Headers -Body $jsonBody -ErrorAction Stop
}

#endregion

#region Public functions

function Export-SentinelRules
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ResourceGroupName,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$WorkspaceName,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ExportFolder,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$ApiVersion = "2023-09-01-preview",

        [Parameter()]
        [switch]$DeviceCode
    )

    Write-Host ""
    Write-Host "Connecting to Azure..." -ForegroundColor Cyan

    $connection = Connect-Sentinel -DeviceCode:$DeviceCode

    Write-Host "Subscription : $($connection.Subscription)"
    Write-Host "Account      : $($connection.Account)"
    Write-Host "Workspace    : $WorkspaceName"
    Write-Host ""

    if (-not (Test-Path -LiteralPath $ExportFolder))
    {
        New-Item -ItemType Directory -Path $ExportFolder -Force -ErrorAction Stop | Out-Null
    }

    $csvPath  = Join-Path -Path $ExportFolder -ChildPath "ActiveAnalyticsRules.csv"
    $jsonPath = Join-Path -Path $ExportFolder -ChildPath "ActiveAnalyticsRules.json"

    Write-Host "Retrieving analytics rules..." -ForegroundColor Cyan

    $allRules = @(
        Get-SentinelRules -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName -ApiVersion $ApiVersion -Connection $connection
    )

    $activeRules = @(
        $allRules |
            Where-Object {
                $null -ne $_.properties -and $_.properties.enabled -eq $true
            } |
            Sort-Object { $_.properties.displayName }
    )

    $inventory = @(
        $activeRules |
            ForEach-Object {
                [PSCustomObject]@{
                    DisplayName = $_.properties.displayName
                    Kind        = $_.kind
                    Severity    = $_.properties.severity
                    Enabled     = $_.properties.enabled
                    TemplateId  = $_.properties.alertRuleTemplateName
                    RuleId      = $_.name
                }
            }
    )

    $inventory |
        Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8 -Force

    $exportRules = @(
        $activeRules |
            ForEach-Object {
                [PSCustomObject]@{
                    DisplayName  = $_.properties.displayName
                    Kind         = $_.kind
                    TemplateId   = $_.properties.alertRuleTemplateName
                    Enabled      = $_.properties.enabled
                    SourceRuleId = $_.name
                    Properties   = $_.properties
                }
            }
    )

    $exportPackage = [PSCustomObject]@{
        SchemaVersion        = "1.0"
        ExportDateUtc        = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        SourceSubscriptionId = $connection.SubscriptionId
        SourceResourceGroup  = $ResourceGroupName
        SourceWorkspace      = $WorkspaceName
        ApiVersion           = $ApiVersion
        RuleCount            = $exportRules.Count
        Rules                = $exportRules
    }

    $exportPackage |
        ConvertTo-Json -Depth 100 |
        Set-Content -Path $jsonPath -Encoding UTF8 -Force

    Write-Host ""
    Write-Host "Export complete." -ForegroundColor Green
    Write-Host "CSV inventory : $csvPath"
    Write-Host "JSON package  : $jsonPath"
    Write-Host "Rules exported: $($exportRules.Count)"
}

function Import-SentinelRules
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ResourceGroupName,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$WorkspaceName,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$JsonFile,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$ApiVersion = "2023-09-01-preview",

        [Parameter()]
        [switch]$DeviceCode
    )

    if (-not (Test-Path -LiteralPath $JsonFile -PathType Leaf))
    {
        throw "The JSON package was not found at '$JsonFile'."
    }

    Write-Host ""
    Write-Host "Reading JSON package..." -ForegroundColor Cyan

    try
    {
        $package = Get-Content -LiteralPath $JsonFile -Raw -ErrorAction Stop |
            ConvertFrom-Json -ErrorAction Stop
    }
    catch
    {
        throw "The JSON package could not be read or is invalid. $($_.Exception.Message)"
    }

    if (-not (Test-HasProperty -InputObject $package -Name 'Rules'))
    {
        throw "The JSON package does not contain a Rules collection."
    }

    $packageRules = @($package.Rules)

    if ($packageRules.Count -eq 0)
    {
        Write-Host "The package contains no rules. Nothing was imported." -ForegroundColor Yellow
        return
    }

    Write-Host "Package rules : $($packageRules.Count)"
    Write-Host "Target        : $WorkspaceName"
    Write-Host ""

    Write-Host "Connecting to Azure..." -ForegroundColor Cyan

    $connection = Connect-Sentinel -DeviceCode:$DeviceCode

    Write-Host "Subscription : $($connection.Subscription)"
    Write-Host "Account      : $($connection.Account)"
    Write-Host ""

    Write-Host "Retrieving existing target rules..." -ForegroundColor Cyan

    $existingRules = @(
        Get-SentinelRules -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName -ApiVersion $ApiVersion -Connection $connection
    )

    $created = 0
    $skipped = 0
    $failed  = 0

    $results = [System.Collections.Generic.List[object]]::new()

    foreach ($rule in $packageRules)
    {
        $displayName = Get-SentinelRuleDisplayName -Rule $rule
        $kind        = Get-SentinelRuleKind        -Rule $rule
        $templateId  = Get-SentinelRuleTemplateId  -Rule $rule

        if ([string]::IsNullOrWhiteSpace($displayName))
        {
            $failed++
            Write-Host "FAILED <missing DisplayName>" -ForegroundColor DarkYellow

            $results.Add([PSCustomObject]@{
                DisplayName = "<missing>"
                Kind        = $kind
                TemplateId  = $templateId
                Result      = "Failed"
                MatchMethod = $null
                Message     = "The exported rule has no DisplayName."
            })
            continue
        }

        $existence = Test-SentinelRuleExists -Rule $rule -ExistingRules $existingRules

        if ($existence.Exists)
        {
            $skipped++
            Write-Host ("SKIP   {0} [{1}]" -f $displayName, $existence.MatchMethod) -ForegroundColor Yellow

            $results.Add([PSCustomObject]@{
                DisplayName = $displayName
                Kind        = $kind
                TemplateId  = $templateId
                Result      = "Skipped"
                MatchMethod = $existence.MatchMethod
                Message     = "An equivalent rule already exists."
            })
            continue
        }

        Write-Host "CREATE $displayName" -ForegroundColor Green

        try
        {
            $createdRule = New-SentinelRule -Rule $rule -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName -ApiVersion $ApiVersion -Connection $connection

            $created++

            # Add the newly created rule so a duplicate later in the same
            # package is also detected as existing.
            $existingRules += $createdRule

            $results.Add([PSCustomObject]@{
                DisplayName = $displayName
                Kind        = $kind
                TemplateId  = $templateId
                Result      = "Created"
                MatchMethod = $null
                Message     = "The missing rule was created and enabled."
            })
        }
        catch
        {
            $failed++

            $errorMessage = $_.Exception.Message

            if (($null -ne $_.ErrorDetails) -and `
                (-not [string]::IsNullOrWhiteSpace([string]$_.ErrorDetails.Message)))
            {
                $errorMessage = "$errorMessage Azure response: $($_.ErrorDetails.Message)"
            }

            Write-Host "FAILED $displayName" -ForegroundColor DarkYellow
            Write-Host "       $errorMessage" -ForegroundColor DarkYellow

            $results.Add([PSCustomObject]@{
                DisplayName = $displayName
                Kind        = $kind
                TemplateId  = $templateId
                Result      = "Failed"
                MatchMethod = $null
                Message     = $errorMessage
            })
        }
    }

    Write-Host ""
    Write-Host "Import complete." -ForegroundColor Green
    Write-Host "Created : $created"
    Write-Host "Skipped : $skipped"
    Write-Host "Failed  : $failed"
    Write-Host ""
    Write-Host "Import results:" -ForegroundColor Cyan

    $results |
        Format-Table -Property DisplayName, Kind, Result, MatchMethod -AutoSize

    return $results
}

#endregion

Export-ModuleMember -Function Export-SentinelRules, Import-SentinelRules
