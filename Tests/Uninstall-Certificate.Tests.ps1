
#Requires -Version 5.1
Set-StrictMode -Version 'Latest'

& (Join-Path -Path $PSScriptRoot -ChildPath 'Initialize-Test.ps1' -Resolve)

$onWindows = Test-TCOperatingSystem -IsWindows
if( -not $onWindows )
{
    Write-Warning -Message ('TODO: Get Uninstall-Certificate working on non-Windows platforms.')
    return
}

$TestCertPath = Join-Path -Path $PSScriptRoot -ChildPath 'Resources\CarbonTestCertificate.pfx' -Resolve
$TestCert = New-Object Security.Cryptography.X509Certificates.X509Certificate2 $TestCertPath

# Some tests work with local machine stores, and thus require admin access.
$skipAdminTests = -not (Test-IsAdministrator)
$skipAdminTestParam = @{
    'Skip' = $skipAdminTests;
}

$skipRemotingTests = (Test-RunningUnderBuildServer) -or $skipAdminTests
$skipRemotingParam = @{
    'Skip' = $skipRemotingTests;
}

function Init
{
    # Make sure there's no local machine cert "inheriting" down to the current user's store.
    if( (Test-Path -Path "cert:\*\My\$($TestCert.Thumbprint)") )
    {
        Uninstall-CCertificate -Thumbprint $TestCert.Thumbprint -StoreLocation LocalMachine -StoreName My
        Uninstall-CCertificate -Thumbprint $TestCert.Thumbprint -StoreLocation CurrentUser -StoreName My
    }

    if( -not (Test-Path Cert:\CurrentUser\My\$TestCert.Thumbprint -PathType Leaf) )
    {
        Install-CCertificate -Path $TestCertPath -StoreLocation CurrentUser -StoreName My
    }
}

Describe 'Uninstall-Certificate' {

    It 'should remove certificate by certificate' {
        Init
        Uninstall-CCertificate -Certificate $TestCert -StoreLocation CurrentUser -StoreName My
        $cert = Get-CCertificate -Thumbprint $TestCert.Thumbprint -StoreLocation CurrentUser -StoreName My
        $cert | Should -BeNullOrEmpty
    }

    It 'should remove certificate by thumbprint' {
        Init
        Uninstall-CCertificate -Thumbprint $TestCert.Thumbprint -StoreLocation CurrentUser -StoreName My
        $maxTries = 10
        $tryNum = 0
        do
        {
            $cert = Get-CCertificate -Thumbprint $TestCert.Thumbprint -StoreLocation CurrentUser -StoreName My
            if( -not $cert )
            {
                break
            }
            Start-Sleep -Milliseconds 100
        }
        while( $tryNum++ -lt $maxTries )
        $cert | Should -BeNullOrEmpty
    }

    It 'should support WhatIf' {
        Init
        Uninstall-CCertificate -Thumbprint $TestCert.Thumbprint -StoreLocation CurrentUser -StoreName My -WhatIf
        $cert = Get-CCertificate -Thumbprint $TestCert.Thumbprint -StoreLocation CurrentUser -StoreName My
        $cert | Should -Not -BeNullOrEmpty
    }

    It 'should uninstall certificate from custom store' {
        Init
        # Make sure there's no local machine cert "inheriting" down to the current user's store.
        Uninstall-CCertificate -Thumbprint $TestCert.Thumbprint -StoreLocation LocalMachine -CustomStoreName 'Carbon'
        $cert = Install-CCertificate -Path $TestCertPath -StoreLocation CurrentUser -CustomStoreName 'Carbon' -PassThru
        $cert | Should -Not -BeNullOrEmpty
        $certPath = 'Cert:\CurrentUser\Carbon\{0}' -f $cert.Thumbprint
        $certPath | Should -Exist
        Uninstall-CCertificate -Thumbprint $cert.Thumbprint -StoreLocation CurrentUser -CustomStoreName 'Carbon' -Verbose
        while( (Test-Path -Path $certPath) )
        {
            Write-Verbose -Message ('Waiting for "{0}" to get deleted.' -f $certPath)
            Start-Sleep -Seconds 1
        }
        $certPath | Should -Not -Exist
    }

    It 'should uninstall certificate from remote computer' @skipRemotingParam {
        Init
        $Global:Error.Clear()

        $session = New-PSSession -ComputerName $env:COMPUTERNAME
        try
        {
            Uninstall-CCertificate -Thumbprint $TestCert.Thumbprint `
                                  -StoreLocation CurrentUser `
                                  -StoreName My `
                                  -Session $session
            $Global:Error.Count | Should -Be 0

            $cert = Get-CCertificate -Thumbprint $TestCert.Thumbprint -StoreLocation CurrentUser -StoreName My
            $cert | Should -BeNullOrEmpty
        }
        finally
        {
            Remove-PSSession -Session $session
        }
    }
}

function GivenARemotingSession
{
    $script:session = New-PSSession -ComputerName $env:COMPUTERNAME
}

function GivenAnInstalledCertificate
{
    param(
        $StoreLocation = 'CurrentUser',
        $StoreName = 'My'
    )
    Install-CCertificate -Path $TestCertPath -StoreLocation $StoreLocation -StoreName $StoreName
}

function WhenPipedMultipleThumbprints
{
    $TestCert.Thumbprint,$TestCert.Thumbprint | Uninstall-CCertificate
}

function WhenUninstallingViaRemoting
{
    try
    {
        $TestCert | Uninstall-CCertificate -Session $session
    }
    finally
    {
        $session | Remove-PSSession
    }
}

function WhenUninstallPipedCertificate
{
    $TestCert | Uninstall-CCertificate
}

function WhenUninstallingByThumbprint
{
    Uninstall-CCertificate -Thumbprint $TestCert.Thumbprint
}

function WhenUninstallPipedThumbprint
{
    $TestCert.Thumbprint | Uninstall-CCertificate
}

function ThenCertificateUninstalled
{
    Join-Path -Path 'cert:\*\*' -ChildPath $TestCert.Thumbprint | Should -Not -Exist
}

Describe 'Uninstall-Certificate.when given just the certificate thumbprint' {
    It 'should find and uninstall the certificate' {
        Init
        GivenAnInstalledCertificate
        WhenUninstallingByThumbprint
        ThenCertificateUninstalled
    }
}

Describe 'Uninstall-Certificate.when given just the certificate thumbprint and installed in multiple stores' {
    It 'should find and uninstall the certificate from all stores' @skipAdminTestParam {
        Init
        GivenAnInstalledCertificate
        GivenAnInstalledCertificate -StoreLocation 'CurrentUser' -StoreName 'My'
        GivenAnInstalledCertificate -StoreLocation 'LocalMachine' -StoreName 'My'
        GivenAnInstalledCertificate -StoreLocation 'LocalMachine' -StoreName 'Root'
        WhenUninstallingByThumbprint
        ThenCertificateUninstalled
    }
}

Describe 'Uninstall-Certificate.when piped thumbprint' {
    It 'should uninstall the certificate with that thumbprint' {
        Init
        GivenAnInstalledCertificate
        WhenUninstallPipedThumbprint
        ThenCertificateUninstalled
    }
}

Describe 'Uninstall-Certificate.when piped certificate object' {
    It 'should uninstall that certificate' {
        Init
        GivenAnInstalledCertificate
        WhenUninstallPipedCertificate
        ThenCertificateUninstalled
    }
}

Describe 'Uninstall-Certificate.when piped multiple thumbprints' {
    It 'should uninstall all the certificates' {
        Init
        GivenAnInstalledCertificate
        WhenPipedMultipleThumbprints
        ThenCertificateUninstalled
    }
}

# This test ensures that certificates are uninstalled from LocalMachine stores *first*, since they will also show up in CurrentUser stores and if SYSTEM deletes the certificate in a headless process from the CurrentUser stores first, it will fail.
Describe 'Uninstall-Certificate.when local machine cert shows up in current user store' {
    It 'should delete from local machine store first' @skipAdminTestParam {
        Init
        GivenAnInstalledCertificate
        Mock -CommandName 'Get-ChildItem' `
             -ModuleName 'Carbon.Cryptography' `
             -ParameterFilter { $Path.Count -eq 2 -and $Path[0] -eq 'Cert:\LocalMachine' -and $Path[1] -eq 'Cert:\CurrentUser' } 
        WhenUninstallingByThumbprint
        Assert-MockCalled -CommandName 'Get-ChildItem' -ModuleName 'Carbon.Cryptography' -Times 1
    }
}

if( $skipAdminTests )
{
    $msg = 'Tests to ensure Uninstall-Certificate works over remoting were not run. Remoting tests require ' +
            'administrator rights. Make sure to run these tests as an administrator.'
    Write-Warning -Message $msg
}
