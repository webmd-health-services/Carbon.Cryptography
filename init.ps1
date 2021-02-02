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

& {
    Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath 'PSModules\Carbon' -Resolve) -Verbose:$false
    Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath 'PSModules\Carbon.Core' -Resolve) -Verbose:$false
}

$passwordPath = Join-Path -Path $PSScriptRoot -ChildPath 'Tests\.password'
if( -not (Test-Path -Path $passwordPath) )
{
    $rng = [Security.Cryptography.RNGCryptoServiceProvider]::New()
    $randomBytes = [byte[]]::New(9)
    do 
    {
        Write-Verbose -Message ('Generating random password for test accounts.')
        $rng.GetBytes($randomBytes);
        $password = [Convert]::ToBase64String($randomBytes)
    }
    # Password needs to contain uppercase letter, lowercase letter, and a number.
    while( $password -cnotmatch '[A-Z]' -and $password -cnotmatch '[a-z]' -and $password -notmatch '\d' )
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
        $_['Description'] = "Carbon.Core $($_['For']) test user."
        [pscustomobject]$_ | Write-Output
    }

foreach( $user in $users )
{
    if( (Test-COperatingSystem -IsWindows) )
    {
        $maxLength = $user.Description.Length
        if( $maxLength -gt 48 )
        {
            $maxLength = 48
        }
        $description = $user.Description.Substring(0, $maxLength)
        $credential = [pscredential]::New($user.Name, (ConvertTo-SecureString $password -AsPlainText -Force))
        Install-CUser -Credential $credential -Description $description -UserCannotChangePassword
    }
    elseif( (Test-COperatingSystem -IsMacOS) )
    {
        $newUid = 
            sudo dscl . -list /Users UniqueID | 
            ForEach-Object { $username,$uid = $_ -split ' +' ; return [int]$uid } |
            Sort-Object |
            Select-Object -Last 1
        Write-Verbose "  Found highest user ID ""$($newUid)""."
        $newUid += 1

        $username = $user.Name

        Write-Verbose "  Creating $($username) (uid: $($newUid))"
        # Create the user account
        sudo dscl . -create /Users/$username
        sudo dscl . -create /Users/$username UserShell /bin/bash
        sudo dscl . -create /Users/$username RealName $username
        sudo dscl . -create /Users/$username UniqueID $newUid
        sudo dscl . -create /Users/$username PrimaryGroupID 20
        sudo dscl . -create /Users/$username NFSHomeDirectory /Users/$username
        sudo dscl . -passwd /Users/$username $password
        sudo createhomedir -c
    }
    elseif( (Test-COperatingSystem -IsLinux) )
    {
        $userExists = Get-Content '/etc/passwd' | Where-Object { $_ -match "^$([regex]::Escape($user.Name))\b"}
        if( $userExists )
        {
            continue
        }

        Write-Verbose -Message ("Adding user ""$($user.Name)"".")
        $encryptedPassword = $password | openssl passwd -stdin -salt $salt
        sudo useradd -p $encryptedPassword -m $user.Name --comment $user.Description
    }
}
