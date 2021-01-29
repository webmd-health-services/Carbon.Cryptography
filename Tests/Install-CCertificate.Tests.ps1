
#Requires -Version 5.1
Set-StrictMode -Version 'Latest'

& (Join-Path -Path $PSScriptRoot -ChildPath 'Initialize-Test.ps1' -Resolve)

$TestCertPath = Join-Path -Path $PSScriptRoot -ChildPath 'Resources\CarbonTestCertificate.cer' -Resolve
$TestCert = New-Object 'Security.Cryptography.X509Certificates.X509Certificate2' $TestCertPath
$TestCertProtectedPath = Join-Path -Path $PSScriptRoot -ChildPath 'Resources\CarbonTestCertificateWithPassword.cer' -Resolve
$TestCertProtected = New-Object 'Security.Cryptography.X509Certificates.X509Certificate2' $TestCertProtectedPath,'password'

$onWindows = Test-COperatingSystem -IsWindows

$skipRemotingTests = (Test-RunningUnderBuildServer) -or -not (Test-IsAdministrator)
$skipRemotingParam = @{
    'Skip' = $skipRemotingTests;
}

if( -not $onWindows )
{
    Write-Warning -Message ('TODO: Get Install-CCertificate working on non-Windows platforms.')
    return
}

function Init
{
    $Global:Error.Clear()

    if( (Get-CCertificate -Thumbprint $TestCert.Thumbprint -StoreLocation CurrentUser -StoreName My) )
    {
        Uninstall-CCertificate -Certificate $TestCert -StoreLocation CurrentUser -StoreName My
    }

    if( (Get-CCertificate -Thumbprint $TestCertProtected.Thumbprint -StoreLocation CurrentUser -StoreName My) )
    {
        Uninstall-CCertificate -Certificate $TestCertProtected -StoreLocation CurrentUser -StoreName My
    }
}

function Reset
{
    Uninstall-CCertificate -Certificate $TestCert -StoreLocation CurrentUser -StoreName My
    Uninstall-CCertificate -Certificate $TestCertProtected -StoreLocation CurrentUser -StoreName My

    # Local Machine store is read-only on non-Windows operating systems.
    if( $onWindows )
    {
        Uninstall-CCertificate -Certificate $TestCert -StoreLocation LocalMachine -StoreName My
        Uninstall-CCertificate -Certificate $TestCertProtected -StoreLocation LocalMachine -StoreName My
    }
}

function ThenCertificateInstalled
{
    param(
        [Parameter(Mandatory)]
        [String]$WithThumbprint,

        $For = 'CurrentUser', 

        $In = 'My'
    )

    $cert = Get-CCertificate -Thumbprint $WithThumbprint -StoreLocation $For -StoreName $In
    $cert | Should -Not -BeNullOrEmpty | Out-Null
    $cert.Thumbprint | Should -Be $WithThumbprint | Out-Null
    return $cert
}

function ThenNoError
{
    $Global:Error | Should -BeNullOrEmpty
}

function WhenInstalling
{
    [CmdletBinding()]
    param(
        $Certificate,
        $For,
        $In,
        [switch]$WithForce
    )

    $conditionalParams = @{}
    if( $WithForce )
    {
        $conditionalParams['Force'] = $WithForce
    }

    Install-CCertificate -Certificate $Certificate -StoreLocation $For -StoreName $In @conditionalParams
}

Describe "Install-CCertificate" {
    BeforeEach { Init }
    AfterEach { Reset }

    It 'should install certificate to local machine' {
        $cert = Install-CCertificate -Path $TestCertPath -StoreLocation CurrentUser -StoreName My
        $cert.Thumbprint | Should -Be $TestCert.Thumbprint
        $cert = ThenCertificateInstalled $TestCert.Thumbprint -For 'CurrentUser' -In 'My' 
        {
            $cert.Export( [Security.Cryptography.X509Certificates.X509ContentType]::Pfx ) | Out-Null
        } | Should -Throw
    }

    It 'should install certificate to local machine with relative path' {
        $DebugPreference = 'Continue'
        Push-Location -Path $PSScriptRoot
        try
        {
            $path = '.\Resources\{0}' -f (Split-Path -Leaf -Path $TestCertPath)
            $cert = Install-CCertificate -Path $path -StoreLocation CurrentUser -StoreName My -Verbose
            $cert.Thumbprint | Should -Be $TestCert.Thumbprint
            $cert = ThenCertificateInstalled $TestCert.Thumbprint -For 'CurrentUser' -In 'My' 
        }
        finally
        {
            Pop-Location
        }
    }

    It 'should install certificate to local machine as exportable' {
        $cert = Install-CCertificate -Path $TestCertPath -StoreLocation CurrentUser -StoreName My -Exportable
        $cert.Thumbprint | Should -Be $TestCert.Thumbprint
        $cert = ThenCertificateInstalled $TestCert.Thumbprint -For 'CurrentUser' -In 'My' 
        $bytes = $cert.Export( [Security.Cryptography.X509Certificates.X509ContentType]::Pfx )
        $bytes | Should -Not -BeNullOrEmpty
    }

    It 'should install certificate in custom store' {
        $cert = Install-CCertificate -Path $TestCertPath -StoreLocation CurrentUser -CustomStoreName 'SharePoint' 
        $cert | Should -Not -BeNullOrEmpty
        'cert:\CurrentUser\SharePoint' | Should -Exist
        ('cert:\CurrentUser\SharePoint\{0}' -f $cert.Thumbprint) | Should -Exist
    }

    It 'should install certificate' {
        $cert = Install-CCertificate -Certificate $TestCert -StoreLocation CurrentUser -StoreName My
        $cert | Should -Not -BeNullOrEmpty
        ThenCertificateInstalled $TestCert.Thumbprint -For 'CurrentUser' -In 'My'
    }

    It 'should install password protected certificate' {
        $cert = Install-CCertificate -Certificate $TestCertProtected -StoreLocation CurrentUser -StoreName My
        $cert | Should -Not -BeNullOrEmpty
        ThenCertificateInstalled $TestCertProtected.Thumbprint -For 'CurrentUser' -In 'My'
    }

    It 'should install certificate in remote computer' @skipRemotingParam {
        $session = New-PSSession -ComputerName $env:COMPUTERNAME
        try
        {
            $cert = Install-CCertificate -Certificate $TestCert -StoreLocation CurrentUser -StoreName My -Session $session
            $cert | Should -Not -BeNullOrEmpty
            ThenCertificateInstalled $TestCert.Thumbprint -For 'CurrentUser' -In 'My'
        }
        finally
        {
            Remove-PSSession -Session $session
        }
    }

    It 'should support ShouldProcess' {
        $cert = Install-CCertificate -Path $TestCertPath -StoreLocation CurrentUser -StoreName My -WhatIf
        $cert.Thumbprint | Should -Be $TestCert.Thumbprint
        Join-Path -Path 'cert:\CurrentUser\My' -ChildPath $TestCert.Thumbprint |
            Should -Not -Exist
    }
}

Describe 'Install-CCertificate.when certificate is already installed' {
    It 'should not re-install it' {
        Init
        $output =
            WhenInstalling $TestCert -For 'CurrentUser' -In 'My' -Verbose 4>&1 |
            Where-Object { $_ -is [Management.Automation.VerboseRecord] }
        $output | Should -HaveCount 1
        $output.Message | Should -Match 'Installing certificate'
        ThenCertificateInstalled $TestCert.Thumbprint -For 'CurrentUser' -In 'My'
        ThenNoError

        # Install it again.
        $output = 
            WhenInstalling $TestCert -For 'CurrentUser' -In 'My' -Verbose 4>&1 |
            Where-Object { $_ -is [Management.Automation.VerboseRecord] }
        $output | Should -BeNullOrEmpty -Because 'certificates shouldn''t get re-installed'
        ThenNoError
        ThenCertificateInstalled $TestCert.Thumbprint -For 'CurrentUser' -In 'My'
    }
}

Describe 'Install-CCertificate.when certificate is already installed and forcing install' {
    It 'should not re-install it' {
        Init
        $output =
            WhenInstalling $TestCert -For 'CurrentUser' -In 'My' -Verbose 4>&1 |
            Where-Object { $_ -is [Management.Automation.VerboseRecord] }
        ThenNoError
        $output | Should -HaveCount 1
        $output.Message | Should -Match 'Installing certificate'
        ThenCertificateInstalled $TestCert.Thumbprint -For 'CurrentUser' -In 'My'

        # Install it again.
        $output = 
            WhenInstalling $TestCert -For 'CurrentUser' -In 'My' -WithForce -Verbose 4>&1 |
            Where-Object { $_ -is [Management.Automation.VerboseRecord] }
        ThenNoError
        $output | Should -HaveCount 1
        $output.Message | Should -Match 'Installing certificate'
        ThenCertificateInstalled $TestCert.Thumbprint -For 'CurrentUser' -In 'My'
    }
}

if( $skipRemotingTests )
{
    $msg = 'Tests to ensure Install-CCertificate works over remoting were not run. Remoting tests require ' +
            'administrator rights. Make sure to run these tests as an administrator.'
    Write-Warning -Message $msg
}
