
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

Describe "Install-CCertificate" {

    function Assert-CertificateInstalled
    {
        param(
            $StoreLocation = 'CurrentUser', 
            $StoreName = 'My',
            $ExpectedCertificate = $TestCert
        )
        $cert = Get-CCertificate -Thumbprint $ExpectedCertificate.Thumbprint -StoreLocation $StoreLocation -StoreName $StoreName
        $cert | Should -Not -BeNullOrEmpty | Out-Null
        $cert.Thumbprint | Should -Be $ExpectedCertificate.Thumbprint | Out-Null
        return $cert
    }

    BeforeEach {
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

    AfterEach {
        Uninstall-CCertificate -Certificate $TestCert -StoreLocation CurrentUser -StoreName My
        Uninstall-CCertificate -Certificate $TestCertProtected -StoreLocation CurrentUser -StoreName My

        # Local Machine store is read-only on non-Windows operating systems.
        if( $onWindows )
        {
            Uninstall-CCertificate -Certificate $TestCert -StoreLocation LocalMachine -StoreName My
            Uninstall-CCertificate -Certificate $TestCertProtected -StoreLocation LocalMachine -StoreName My
        }
    }

    It 'should install certificate to local machine' {
        $cert = Install-CCertificate -Path $TestCertPath -StoreLocation CurrentUser -StoreName My
        $cert.Thumbprint | Should -Be $TestCert.Thumbprint
        $cert = Assert-CertificateInstalled -StoreLocation CurrentUser -StoreName My 
        {
            $bytes = $cert.Export( [Security.Cryptography.X509Certificates.X509ContentType]::Pfx )
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
            $cert = Assert-CertificateInstalled -StoreLocation CurrentUser -StoreName My 
        }
        finally
        {
            Pop-Location
        }
    }

    It 'should install certificate to local machine as exportable' {
        $cert = Install-CCertificate -Path $TestCertPath -StoreLocation CurrentUser -StoreName My -Exportable
        $cert.Thumbprint | Should -Be $TestCert.Thumbprint
        $cert = Assert-CertificateInstalled -StoreLocation CurrentUser -StoreName My 
        $bytes = $cert.Export( [Security.Cryptography.X509Certificates.X509ContentType]::Pfx )
        $bytes | Should -Not -BeNullOrEmpty
    }

    It 'should install certificate in custom store' {
        $cert = Install-CCertificate -Path $TestCertPath -StoreLocation CurrentUser -CustomStoreName 'SharePoint' 
        $cert | Should -Not -BeNullOrEmpty
        'cert:\CurrentUser\SharePoint' | Should -Exist
        ('cert:\CurrentUser\SharePoint\{0}' -f $cert.Thumbprint) | Should -Exist
    }

    It 'should install certificate idempotently' {
        Install-CCertificate -Certificate $TestCert -StoreLocation CurrentUser -StoreName My
        $Global:Error | Should -BeNullOrEmpty
        Install-CCertificate -Certificate $TestCert -StoreLocation CurrentUser -StoreName My
        $Global:Error | Should -BeNullOrEmpty
        Assert-CertificateInstalled CurrentUser My
    }

    It 'should install certificate' {
        $cert = Install-CCertificate -Certificate $TestCert -StoreLocation CurrentUser -StoreName My
        $cert | Should -Not -BeNullOrEmpty
        Assert-CertificateInstalled CurrentUser My
    }

    It 'should install password protected certificate' {
        $cert = Install-CCertificate -Certificate $TestCertProtected -StoreLocation CurrentUser -StoreName My
        $cert | Should -Not -BeNullOrEmpty
        Assert-CertificateInstalled CurrentUser My $TestCertProtected
    }

    It 'should install certificate in remote computer' @skipRemotingParam {
        $session = New-PSSession -ComputerName $env:COMPUTERNAME
        try
        {
            $cert = Install-CCertificate -Certificate $TestCert -StoreLocation CurrentUser -StoreName My -Session $session
            $cert | Should -Not -BeNullOrEmpty
            Assert-CertificateInstalled CurrentUser My
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

if( $skipRemotingTests )
{
    $msg = 'Tests to ensure Install-CCertificate works over remoting were not run. Remoting tests require ' +
            'administrator rights. Make sure to run these tests as an administrator.'
    Write-Warning -Message $msg
}
