
function Get-TestUserCredential
{
    param(
        [Parameter(Mandatory)]
        [String]$Name
    )

    $passwordFilePath = Join-Path -Path $PSScriptRoot -ChildPath '..\.password' -Resolve
    if( -not (Test-Path -Path $passwordFilePath -PathType Leaf) )
    {
        $initPs1Path = Join-Path -Path $PSScriptRoot -ChildPath '..\..\init.ps1'
        $msg = "Password file ""$($passwordFilePath) does not exist. Please run " +
               """$($initPs1Path | Resolve-Path -Relative)"" to initialize test user accounts and passwords."
        Write-Error -Message $msg -ErrorAction Stop
        return
    }

    $password = Get-Content -Path $passwordFilePath -TotalCount 1
    return [pscredential]::New($Name, (ConvertTo-SecureString -String $password -AsPlainText -Force))
}

# When the Carbon.Accounts PowerShell module gets created, use the Test-CAdminPrivilege from that module instead.
function Test-IsAdministrator
{
    if( (Test-TCOperatingSystem -IsWindows) )
    {
        [Security.Principal.WindowsPrincipal]$currentIdentity =[Security.Principal.WindowsIdentity]::GetCurrent()
        return $currentIdentity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    # Don't know how to do this check on other platforms or even if it makes sense?
    return $false
}

function Test-RunningUnderBuildServer
{
    return (Test-Path -Path 'env:CARBON_CI')
}
