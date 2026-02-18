# AZActiveSentinelRules
PowerShell script that provides a list of the active analytics rules within a Microsoft Sentinel workspace. Useful for documentation or when migrating active rules from one workspace to another.

Provide the Resource Group Name, Sentinel Workspace Name and Output path for your CSV file in the variables at the start of the script. 

The script relies on the Az PowerShell module (install-module az) and requires you to select the appropriate Azure subscription that contains the Microsoft Sentinel workspace.
