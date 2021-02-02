
function Get-TestUserCredential
{
    param(
        [Parameter(Mandatory)]
        [String]$Name
    )

    $password = Get-Content -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\.password' -Resolve) -TotalCount 1
    return [pscredential]::New($Name, (ConvertTo-SecureString -String $password -AsPlainText -Force))
}

# When the Carbon.Accounts PowerShell module gets created, use the Test-CAdminPrivilege from that module instead.
function Test-IsAdministrator
{
    if( (Test-COperatingSystem -IsWindows) )
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
