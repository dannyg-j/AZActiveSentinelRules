**#AZActiveSentinelRules**
PowerShell script that provides a list of the active analytics rules within a Microsoft Sentinel workspace. Useful for documentation or when migrating active rules from one workspace to another.

Provide the Resource Group Name, Sentinel Workspace Name and Output path for your CSV file in the variables at the start of the script. 

The script relies on the Az PowerShell module (install-module az) and requires you to select the appropriate Azure subscription that contains the Microsoft Sentinel workspace.

**#SentinelRules new script and module**

Added export and import functions in the module sentinelrules.psm1 that exports all active rules from Sentinel into a JSON file.

You can use this as a rule configuration backup before rule changes or when migrating from one Sentinel workspace to another. Depends on solutions imported from the content hub.

**Usage Examples:**

Export
.\SentinelRules.ps1 -Mode Export -ResourceGroupName "sentinelsphere-rg" -WorkspaceName "SentinelSphere-log" -ExportFolder "C:\Temp\SentinelExport"

Import
.\SentinelRules.ps1 -Mode Import -ResourceGroupName "sentinelsphere-rg" -WorkspaceName "SentinelSphere-log" -JsonFile "C:\temp\SentinelExport\ActiveAnalyticsRules.json"
