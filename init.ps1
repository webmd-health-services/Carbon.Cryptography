<#
.SYNOPSIS
Gets your computer ready to develop the Carbon.Cryptography module.

.DESCRIPTION
The init.ps1 script makes the configuraion changes necessary to get your computer ready to develop for the
Carbon.Cryptography module. It:


.EXAMPLE
.\init.ps1

Demonstrates how to call this script.
#>
[CmdletBinding()]
param(
)

#Requires -RunAsAdministrator
Set-StrictMode -Version 'Latest'
$ErrorActionPreference = 'Stop'
$InformationPreference = 'Continue'

prism install
prism install -Path (Join-Path -Path $PSScriptRoot -ChildPath 'Carbon.Cryptography' -Resolve)

& {
    Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath 'PSModules\Carbon' -Resolve) `
                  -Function @('Install-CGroup', 'Install-CUser', 'Grant-CPrivateKeyPermission') `
                  -Verbose:$false
    Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath 'Carbon.Cryptography\Modules\Carbon.Core' -Resolve) `
                  -Function @('Test-COperatingSystem', 'Invoke-CPowerShell') `
                  -Verbose:$false
    Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath 'Carbon.Cryptography' -Resolve) `
                  -Function @('Install-CCertificate') `
                  -Verbose:$false
}

Install-CGroup -Name 'CCryptoTestGroup1' -Description 'Group used by Carbon.Cryptography PowerShell module tests.'

$passwordPath = Join-Path -Path $PSScriptRoot -ChildPath 'Tests\.password'
if( -not (Test-Path -Path $passwordPath) )
{
    Write-Verbose -Message ('Generating random password for test accounts.')
    $rng = [Security.Cryptography.RNGCryptoServiceProvider]::New()
    $randomBytes = [byte[]]::New(12)
    do
    {
        $rng.GetBytes($randomBytes);
        $password = [Convert]::ToBase64String($randomBytes)
    }
    # Password needs to contain uppercase letter, lowercase letter, a number, and symbol.
    while( -not ($password -cmatch '[A-Z]' -and `
                 $password -cmatch '[a-z]' -and `
                 $password -match '\d' -and `
                 $password -match '=|\+|\/') )
    $password | Set-Content -Path $passwordPath

    Write-Verbose -Message ('Generating IV for encrypting test account password on Linux.')
    $randomBytes = [byte[]]::New(6)
    $rng.GetBytes($randomBytes)
    $salt = [Convert]::ToBase64String($randomBytes)
    $salt | Add-Content -Path $passwordPath
}
else
{
    Get-Content -Path $passwordPath -Raw | Write-Verbose
}

$password,$salt = Get-Content -Path $passwordPath -TotalCount 2
$users =
    Import-LocalizedData -BaseDirectory (Join-Path -Path $PSScriptRoot -ChildPath 'Tests') -FileName 'users.psd1' |
    ForEach-Object { $_['Users'] } |
    ForEach-Object {
        $_['Description'] = "Carbon.Cryptography $($_['For']) test user."
        [pscustomobject]$_ | Write-Output
    }

foreach( $user in $users )
{
    $credential = [pscredential]::New($user.Name, (ConvertTo-SecureString $password -AsPlainText -Force))
    $username = $credential.UserName

    if( (Test-COperatingSystem -IsWindows) )
    {
        $maxLength = $user.Description.Length
        if( $maxLength -gt 48 )
        {
            $maxLength = 48
        }
        $description = $user.Description.Substring(0, $maxLength)
        Install-CUser -Credential $credential -Description $description -UserCannotChangePassword
    }
    elseif( (Test-COperatingSystem -IsMacOS) )
    {
        if( -not (sudo dscl . -list /Users | Where-Object { $_ -eq $username }) )
        {
            $newUid =
                sudo dscl . -list /Users UniqueID |
                ForEach-Object { $username,$uid = $_ -split ' +' ; return [int]$uid } |
                Sort-Object |
                Select-Object -Last 1
            Write-Verbose "  Found highest user ID ""$($newUid)""."
            $newUid += 1

            Write-Verbose "  Creating $($username) (uid: $($newUid))"
            # Create the user account
            sudo dscl . -create /Users/$username
            sudo dscl . -create /Users/$username UserShell /bin/bash
            sudo dscl . -create /Users/$username RealName $username
            sudo dscl . -create /Users/$username UniqueID $newUid
            sudo dscl . -create /Users/$username PrimaryGroupID 20
        }
    }
    elseif( (Test-COperatingSystem -IsLinux) )
    {
        $userExists =
            Get-Content '/etc/passwd' |
            Where-Object { $_ -match "^$([regex]::Escape($username))\b"}

        if( -not $userExists )
        {
            Write-Verbose -Message ("Adding user ""$($username)"".")
            $encryptedPassword = $password | openssl passwd -stdin -salt $salt
            sudo useradd -p $encryptedPassword -m $username --comment $user.Description
        }
    }
}

$testsPath =  Join-Path -Path $PSScriptRoot -ChildPath 'Tests' -Resolve
foreach ($fileName in @('CarbonRsaCng.pfx', 'CarbonTestPrivateKey.pfx'))
{
    $certPath = Join-Path -Path $testsPath -ChildPath $fileName
    Write-Information "Install ${fileName} in LocalMachine My store."
    Install-CCertificate -Path $certPath -StoreLocation LocalMachine -StoreName My
    Write-Information "Install ${fileName} in CurrentUser My store."
    Install-CCertificate -Path $certPath -StoreLocation CurrentUser -StoreName My
}
