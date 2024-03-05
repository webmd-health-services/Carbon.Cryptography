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

prism install
prism install -Path (Join-Path -Path $PSScriptRoot -ChildPath 'Carbon.Cryptography' -Resolve)

& {
    Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath 'Carbon.Cryptography' -Resolve) `
                  -Function @('Uninstall-CCertificate') `
                  -Verbose:$false
}

$thumbprints = @('44A7C2F73353BC53F82318C14490D7E2500B6DE9', '6CF94E242624811F7E12A5340502C1ECE88F1B18')
foreach ($thumbprint in $thumbprints)
{
    Uninstall-CCertificate -Thumbprint $thumbprint -StoreLocation LocalMachine -StoreName My
    Uninstall-CCertificate -Thumbprint $thumbprint -StoreLocation CurrentUser -StoreName My
}
