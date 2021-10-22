
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

function Test-TCertificate
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ParameterSetName='1')]
        [switch] $MustBeExportable,

        [Parameter(Mandatory, ParameterSetName='2')]
        [switch] $AutomaticallyExportable
    )

    if( $MustBeExportable )
    {
        return (Test-TCOperatingSystem -MacOS)
    }

    if( $AutomaticallyExportable )
    {
        return (Test-TCOperatingSystem -Linux)
    }
}

function Test-CustomStore
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [switch] $IsSupported,

        [Parameter(Mandatory)]
        [Security.Cryptography.X509Certificates.StoreLocation] $Location
    )

    if( (Test-TCOperatingSystem -Windows) )
    {
        return $true
    }

    return $Location -eq [Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
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
    if( (Get-Command -Name 'id' -ErrorAction Ignore) )
    {
        return (id -u) -eq 0
    }
    
    Write-Error -Message ('Unable to determine on the current operating system if the current user has admin rights.') `
                -ErrorAction Stop
}

# Does the current user have permission to write to the Local Machine stores?
function Test-LocalMachineStore
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ParameterSetName='1')]
        [switch] $IsReadOnly
    )

    if( $IsReadOnly )
    {
        return -not (Test-TCOperatingSystem -Windows)
    }
}

function Test-MyStore
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [switch] $IsSupported,

        [Parameter(Mandatory)]
        [Security.Cryptography.X509Certificates.StoreLocation] $Location
    )

    if( $Location -eq [Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser )
    {
        return $true
    }

    if( (Test-TCOperatingSystem -Linux) )
    {
        return $false
    }

    return $true
}

function Test-PhysicalStore
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [switch] $IsReadable
    )

    return (Test-TCOperatingSystem -IsWindows)
}

function Test-Remoting
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [switch] $IsAvailable
    )

    return -not (Test-RunningUnderBuildServer) -and (Test-TCOperatingSystem -Windows) -and (Test-IsAdministrator)
}

function Test-RunningUnderBuildServer
{
    return (Test-Path -Path 'env:CARBON_CI')
}

if( (Test-Remoting -IsAvailable) -and (Get-Command -Name 'Get-Service' -ErrorAction Ignore) )
{
    Start-Service 'WinRM'
}
