<#
.SYNOPSIS
Undoes the configuration changes made by the init.ps1 script.

.DESCRIPTION
The reset.ps1 script undoes the configuration changes made by the init.ps1 script. It:

.EXAMPLE
.\reset.ps1

Demonstrates how to call this script.
#>
[CmdletBinding()]
param(
)

Set-StrictMode -Version 'Latest'
