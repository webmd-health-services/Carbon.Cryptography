
#Requres -Version 5.1
Set-StrictMode -Version 'Latest'

& (Join-Path -Path $PSScriptRoot -ChildPath 'Initialize-Test.ps1' -Resolve)

$TestCertPath = Join-Path -Path $PSScriptRoot -ChildPath 'Resources\CarbonTestCertificate.cer' -Resolve
$TestCert = New-Object Security.Cryptography.X509Certificates.X509Certificate2 $TestCertPath
$testCertificateThumbprint = '7D5CE4A8A5EC059B829ED135E9AD8607977691CC'
$testCertFriendlyName = 'Pup Test Certificate'
$testCertCertProviderPath = 'cert:\CurrentUser\My\{0}' -f $testCertificateThumbprint

$onWindows = Test-COperatingSystem -IsWindows

function Assert-TestCert
{
    param(
        $actualCert
    )
        
    $actualCert | Should -Not -BeNullOrEmpty
    $actualCert.Thumbprint | Should -Be $TestCert.Thumbprint
}

function Init
{
    if( (Get-Module 'Carbon') )
    {
        Write-Warning 'Removing Carbon. How did it get imported?'
        Remove-Module 'Carbon' -Force
    }

    $Global:Error.Clear()
    if( $onWindows )
    {
        if( -not (Get-CCertificate -Thumbprint $TestCert.Thumbprint -StoreLocation CurrentUser -StoreName My) ) 
        {
            Write-Debug "TestCertPath  $($TestCertPath)"
            Install-CCertificate -Path $TestCertPath -StoreLocation CurrentUser -StoreName My
        }
    }
}

Describe 'Get-CCertificate.when getting certificate from a file' {
    Init
    $cert = Get-CCertificate -Path $TestCertPath
    It ('should have Path property') {
        $cert.Path | Should -Be $TestCertPath
    }
}

if( $onWindows )
{
    Describe 'Get-CCertificate.when getting certificate by path from certificate store' {
        Init
        $cert = Get-CCertificate -Path $testCertCertProviderPath
        It ('should have Path property') {
            $cert.Path | Should -Be $testCertCertProviderPath
        }
    }

    Describe 'Get-CCertificate.when getting certificate by thumbprint' {
        Init
        $cert = Get-CCertificate -Thumbprint $testCertificateThumbprint -StoreLocation CurrentUser -StoreName My
        It ('should have Path property') {
            $cert.Path | Should -Be $testCertCertProviderPath
        }
    }

    Describe 'Get-CCertificate.when getting certificate by friendly name' {
        Init
        $cert = Get-CCertificate -FriendlyName $testCertFriendlyName -StoreLocation CurrentUser -StoreName My
        It ('should have Path property') {
            $cert.Path | Should -Be $testCertCertProviderPath
        }
    }
}

Describe 'Get-CCertificate' {
    if( $onWindows )
    {
        It 'should find certificates by friendly name' {
            Init
            $cert = Get-CCertificate -FriendlyName $TestCert.friendlyName -StoreLocation CurrentUser -StoreName My
            Assert-TestCert $cert
        }

        It 'should find certificate by thumbprint' {
            Init
            $cert = Get-CCertificate -Thumbprint $TestCert.Thumbprint -StoreLocation CurrentUser -StoreName My
            Assert-TestCert $cert
        }
    
        It 'should not throw error when certificate does not exist' {
            Init
            $cert = Get-CCertificate -Thumbprint '1234567890abcdef1234567890abcdef12345678' -StoreLocation CurrentUser -StoreName My -ErrorAction SilentlyContinue
            $Global:Error.Count | Should -Be 0
            $cert | Should -BeNullOrEmpty
        }
        
        It 'should find certificate in custom store by thumbprint' {
            Init
            $expectedCert = Install-CCertificate -Path $TestCertPath -StoreLocation CurrentUser -CustomStoreName 'Carbon'
            try
            {
                $cert = Get-CCertificate -Thumbprint $expectedCert.Thumbprint -StoreLocation CurrentUser -CustomStoreName 'Carbon'
                $cert | Should -Not -BeNullOrEmpty
                $cert.Thumbprint | Should -Be $expectedCert.Thumbprint
            }
            finally
            {
                Uninstall-CCertificate -Certificate $expectedCert -StoreLocation CurrentUser -CustomStoreName 'Carbon'
            }
        }
        
        It 'should find certificate in custom store by friendly name' {
            Init
            $expectedCert = Install-CCertificate -Path $TestCertPath -StoreLocation CurrentUser -CustomStoreName 'Carbon'
            try
            {
                $cert = Get-CCertificate -FriendlyName $expectedCert.FriendlyName -StoreLocation CurrentUser -CustomStoreName 'Carbon'
                $cert | Should -Not -BeNullOrEmpty
                $cert.Thumbprint | Should -Be $expectedCert.Thumbprint
            }
            finally
            {
                Uninstall-CCertificate -Certificate $expectedCert -StoreLocation CurrentUser -CustomStoreName 'Carbon'
            }
        }

        It 'should get certificates in CA store' {
            Init
            $foundACert = $false
            dir Cert:\CurrentUser\CA | ForEach-Object {
                $cert = Get-CCertificate -Thumbprint $_.Thumbprint -StoreLocation CurrentUser -StoreName CertificateAuthority
                $cert | Should -Not -BeNullOrEmpty
                $foundACert = $true
            }
        }    
    }
    
    It 'should find certificate by path' {
        Init
        $cert = Get-CCertificate -Path $TestCertPath
        Assert-TestCert $cert
    }
    
    It 'should find certificate by relative path' {
        Init
        Push-Location -Path $PSScriptRoot
        try
        {
            $cert = Get-CCertificate -Path ('.\Resources\{0}' -f (Split-Path -Leaf -Path $TestCertPath))
            Assert-TestCert $cert
        }
        finally
        {
            Pop-Location
        }
    }
    
    It 'should get password protected certificate' {
        Init
        $certPath = Join-Path -Path $PSScriptRoot -ChildPath 'Resources\CarbonTestCertificateWithPassword.cer' -Resolve
        [Security.Cryptography.X509Certificates.X509Certificate2]$cert = 
            Get-CCertificate -Path $certPath -Password (ConvertTo-SecureString 'password' -AsPlainText -Force)
        $Global:Error.Count | Should -Be 0
        $cert | Should -Not -BeNullOrEmpty
        $cert.Thumbprint | Should -Be 'DE32D78122C2B5136221DE51B33A2F65A98351D2'
        if( $onWindows )
        {
            $cert.FriendlyName | Should -Be 'Carbon Test Certificate - Password Protected'
        }
    }
    
    It 'should include exception when failing to load certificate' {
        Init
        $cert = Get-CCertificate -Path (Join-Path -Path $PSScriptRoot -ChildPath 'Resources\CarbonTestCertificateWithPassword.cer') -ErrorAction SilentlyContinue
        $Global:Error.Count | Should -BeGreaterThan 0
        $Global:Error[0] | Should -Match 'password'
        $cert | Should -BeNullOrEmpty
        $Error[1].Exception | Should -Not -BeNullOrEmpty
        $Error[1].Exception | Should -BeOfType ([Management.Automation.MethodInvocationException])
    }
}

if( $onWindows )
{
    Uninstall-CCertificate -Certificate $TestCert -storeLocation CurrentUser -StoreName My
}
