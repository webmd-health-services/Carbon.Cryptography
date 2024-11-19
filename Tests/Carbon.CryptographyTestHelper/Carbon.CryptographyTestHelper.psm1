
$psModulesRoot = Join-Path -Path $PSScriptRoot -ChildPath '..\..\Carbon.Cryptography' -Resolve

Import-Module -Name (Join-Path -Path $psModulesRoot -ChildPath 'Carbon.Core' -Resolve) `
              -Function ('Test-COperatingSystem')

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

function Invoke-CPrivateCommand
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [String] $Name,

        [hashtable] $Parameter = @{}
    )

    $Global:CTName = $Name
    $Global:CTParameter = $Parameter

    if( $VerbosePreference -eq 'Continue' )
    {
        $Parameter['Verbose'] = $true
    }

    $Parameter['ErrorAction'] = $ErrorActionPreference

    try
    {
        InModuleScope 'Carbon.Cryptography' {
            & $CTName @CTParameter
        }
    }
    finally
    {
        Remove-Variable -Name 'CTParameter' -Scope 'Global'
        Remove-Variable -Name 'CTName' -Scope 'Global'
    }
}

function New-MockCertificate
{
    param(
        [Parameter(Mandatory)]
        [String] $Subject,

        [String] $Thumbprint,

        [switch] $HasPrivateKey,

        [String[]] $SubjectAlternateName = @(),

        [String[]] $KeyUsageName = @(),

        [String[]] $KeyUsageOid = @(),

        [switch] $Trusted,

        [datetime] $NotBefore = (Get-Date).AddDays(-1),

        [datetime] $NotAfter = (Get-Date).AddYears(2)
    )

    if( -not $Thumbprint )
    {
        $Thumbprint = [Guid]::NewGuid().ToString() + [Guid]::NewGuid().ToString()
        $Thumbprint = $Thumbprint -replace '[^a-f0-9]', ''
        $Thumbprint = $Thumbprint.Substring(0, 40).ToUpperInvariant()
    }
    $keyUsages = [Collections.ArrayList]::New()
    $KeyUsageName |
        ForEach-Object { [pscustomobject]@{ 'FriendlyName' = $_; 'ObjectId' = ''; } } |
        ForEach-Object { [void]$keyUsages.Add($_) }
    $KeyUsageOid |
        ForEach-Object { [pscustomobject]@{ 'FriendlyName' = '' ; 'ObjectId' = $_; } } |
        ForEach-Object { [void]$keyUsages.Add($_) }


    $certificate = [pscustomobject]@{
        'Thumbprint' = $Thumbprint;
        'Subject' = $Subject;
        'SubjectName' = [pscustomobject]@{
            'Name' = $Subject;
        };
        'DnsNameList' = $SubjectAlternateName;
        'EnhancedKeyUsageList' = $keyUsages;
        'HasPrivateKey' = $HasPrivateKey;
        'NotBefore' = $NotBefore;
        'NotAfter' = $NotAfter;
    }
    $verify = { $false }
    if( $Trusted )
    {
        $verify = { $true }
    }
    $certificate | Add-Member -MemberType ScriptMethod -Name 'Verify' -Value $verify
    return $certificate
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
        return (Test-COperatingSystem -MacOS)
    }

    if( $AutomaticallyExportable )
    {
        return (Test-COperatingSystem  -Linux)
    }
}

function Test-CustomStore
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ParameterSetName='IsSupported')]
        [switch] $IsSupported,

        [Parameter(Mandatory, ParameterSetName='IsReadOnly')]
        [switch] $IsReadOnly,

        [Parameter(Mandatory)]
        [Security.Cryptography.X509Certificates.StoreLocation] $Location
    )

    if( $IsReadOnly )
    {
        if( (Test-COperatingSystem -Windows) -and -not (Test-IsAdministrator) )
        {
            return $true
        }

        return $false
    }

    if( (Test-COperatingSystem -Windows) )
    {
        return $true
    }

    return $Location -eq [Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
}

function Test-FriendlyName
{
    param(
        [Parameter(Mandatory)]
        [switch] $IsSupported
    )

    return (Test-COperatingSystem -IsWindows)
}

# When the Carbon.Accounts PowerShell module gets created, use the Test-CAdminPrivilege from that module instead.
function Test-IsAdministrator
{
    if( (Test-COperatingSystem -IsWindows) )
    {
        [Security.Principal.WindowsPrincipal]$currentIdentity =[Security.Principal.WindowsIdentity]::GetCurrent()
        return $currentIdentity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    # Don't know how to do this check on other platfornms or even if it makes sense?
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
        return -not (Test-COperatingSystem -Windows)
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

    if( (Test-COperatingSystem -Linux) )
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

    return (Test-COperatingSystem -IsWindows)
}

function Test-Remoting
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [switch] $IsAvailable
    )

    return -not (Test-RunningUnderBuildServer) -and (Test-COperatingSystem -Windows) -and (Test-IsAdministrator)
}

function Test-RunningUnderBuildServer
{
    return (Test-Path -Path 'env:WHS_CI')
}

if( (Test-Remoting -IsAvailable) -and (Get-Command -Name 'Get-Service' -ErrorAction Ignore) )
{
    Start-Service 'WinRM'
}
