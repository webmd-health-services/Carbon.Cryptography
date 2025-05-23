<#
.SYNOPSIS
Gets things ready for your tests to run.

.DESCRIPTION
The `Initialize-Test.ps1` script gets your tests ready to run by:

* Importing the module you're testing.
* Importing your test helper module.
* Importing any other module dependencies your tests have.

Execute this script as the first thing in each of your test fixtures:

    #Requires -Version 5.1
    Set-StrictMode -Version 'Latest'

    & (Join-Path -Path $PSScriptRoot -ChildPath 'Initialize-Test.ps1' -Resolve)
#>
[CmdletBinding()]
param(
)

$originalVerbosePref = $Global:VerbosePreference
$originalWhatIfPref = $Global:WhatIfPreference

$Global:VerbosePreference = $VerbosePreference = 'SilentlyContinue'
$Global:WhatIfPreference = $WhatIfPreference = $false

$Global:PSModuleAutoloadingPreference = 'None'
if( (Get-Module -Name 'Carbon') )
{
    Write-Warning -Message ('Removing Carbon. How did it get imported?')
    Remove-Module -Name 'Carbon' -Force
}

$privateModulesPath = Join-Path -Path $PSScriptRoot -ChildPath '..\Carbon.Cryptography\Modules' -Resolve
Import-Module -Name 'Microsoft.PowerShell.Security'
Import-Module -Name (Join-Path -Path $privateModulesPath -ChildPath 'Carbon.Core' -Resolve) `
              -Prefix 'T' `
              -Force `
              -Verbose:$false
Import-Module -Name (Join-Path -Path $privateModulesPath -ChildPath 'Carbon.Accounts' -Resolve) `
              -Function @('Resolve-CPrincipalName', 'Test-CPrincipal') `
              -Prefix 'T' `
              -Force `
              -Verbose:$false

try
{
    $modules = [ordered]@{
        'Carbon.Cryptography' = '..\Carbon.Cryptography';
        'Carbon.CryptographyTestHelper' = 'Carbon.CryptographyTestHelper';
    }
    foreach( $moduleName in $modules.Keys )
    {
        $module = Get-Module -Name $moduleName
        $modulePath = Join-Path $PSScriptRoot -ChildPath $modules[$moduleName] -Resolve
        if( $module )
        {
            # Don't constantly reload modules on the build server.
            if( (Test-Path -Path 'env:WHS_CI') -and $module.Path.StartsWith($modulePath) )
            {
                continue
            }

            Write-Verbose -Message ('Removing module "{0}".' -f $moduleName)
            Remove-Module -Name $moduleName -Force
        }

        Write-Verbose -Message ('Importing module "{0}" from "{1}".' -f $moduleName,$modulePath)
        Import-Module -Name $modulePath
    }
}
finally
{
    $Global:VerbosePreference = $originalVerbosePref
    $Global:WhatIfPreference = $originalWhatIfPref
}

