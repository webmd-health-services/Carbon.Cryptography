
#Requires -Version 5.1
Set-StrictMode -Version 'Latest'

if (-not (Get-Command -Name 'certutil' -ErrorAction Ignore))
{
    'Convert-CCertificateProvider tests can''t run on this system because the certutil command does not exist.' |
        Write-Warning
    return
}

BeforeAll {
    Set-StrictMode -Version 'Latest'

    & (Join-Path -Path $PSScriptRoot -ChildPath 'Initialize-Test.ps1' -Resolve)

    $script:testDir = ''
    $script:testNum = 0
    $script:result = $null
    $script:sourceCertPathProtected =
        Join-Path -Path $PSScriptRoot -ChildPath 'Resources\CarbonTestCertificateWithPassword.pfx' -Resolve

    $script:oldProviderName = 'Microsoft Enhanced Cryptographic Provider v1.0'
    $script:password = ConvertTo-SecureString -String 'password' -AsPlainText -Force

    $script:sourceCertPathUnprotected =
       Join-Path -Path $PSScriptRoot -ChildPath 'Resources\CarbonTestCertificate.pfx' -Resolve

    $script:newProviderName = 'Microsoft Enhanced RSA and AES Cryptographic Provider'

    function GivenCertificate
    {
        param(
            $Named,
            $From
        )

        Copy-Item -Path $From -Destination (Join-Path -Path $script:testDir -ChildPath $Named)
    }

    function ThenCertificate
    {
        param(
            [String] $Named,

            [String] $HasProvider,

            [securestring] $RequiresPassword,

            [String] $IsIdenticalTo
        )

        $certPath = Join-Path -Path $script:testDir -ChildPath $Named

        $cert = Get-CCertificate -Path $certPath -Password $RequiresPassword
        $cert | Should -Not -BeNullOrEmpty
        $cert.PrivateKey | Should -Not -BeNullOrEmpty
        $pk = $cert.PrivateKey
        if ($pk | Get-Member 'CspKeyContainerInfo')
        {
            $pk.CspKeyContainerInfo.ProviderName | Should -Be $HasProvider
        }
        elseif ($pk | Get-Member 'Key')
        {
            $pk.Key.Provider.Provider | Should -Be $HasProvider
        }
        else
        {
            throw "Unrecognized private key class type."
        }

        if ($IsIdenticalTo)
        {
            (Get-FileHash -Path $certPath).Hash | Should -Be (Get-FileHash -Path $IsIdenticalTo).Hash
        }
    }

    function ThenNoError
    {
        $Global:Error | Should -BeNullOrEmpty
    }

    function ThenCertNotInStore
    {
        'Cert:\CurrentUser\Temp' | Should -Exist
        Get-ChildItem -Path 'Cert:\CurrentUser\Temp' | Should -BeNullOrEmpty
    }

    function ThenFails
    {
        param(
            $WithErrorThatMatches
        )

        $script:result | Should -BeNullOrEmpty
        $Global:Error | Should -Not -BeNullOrEmpty
        $Global:Error | Should -Match $WithErrorThatMatches
    }

    function ThenReturned
    {
        param(
            $Name,
            $WithOldProvider,
            $WithNewProvider,
            [switch] $Nothing
        )

        if ($Nothing)
        {
            $script:result | Should -BeNullOrEmpty
            return
        }

        $script:result | Should -Not -BeNullOrEmpty
        $script:result.Path | Should -Be (Join-Path -Path $script:testDir -ChildPath $Name)
        $script:result.Path | Should -Exist
        $script:result.OldProviderName | Should -Be $WithOldProvider
        $script:result.NewProviderName | Should -Be $WithNewProvider
        $script:result.NewCertificateBase64Encoded | Should -Not -BeNullOrEmpty
    }

    function WhenConverting
    {
        [CmdletBinding()]
        param(
            [String] $File,
            [hashtable] $WithArgs = @{}
        )

        $WithArgs['FilePath'] = Join-Path -Path $script:testDir -ChildPath $File
        $script:result = Convert-CCertificateProvider @WithArgs
    }
}

Describe 'Convert-CCertificateProvider' {
    BeforeEach {
        $Global:Error.Clear()
        $script:null = $null
        $script:testNum += 1
        $script:testDir = Join-Path -Path $TestDrive -ChildPath $script:testNum
        New-Item -Path $script:testDir -ItemType 'Directory'
    }

    It 'should convert password-protected certificate' {
        GivenCertificate 'cert.pfx' -From $script:sourceCertPathProtected
        WhenConverting 'cert.pfx' -WithArgs @{
            ProviderName = $script:newProviderName;
            Password = $script:password;
        }
        ThenNoError
        ThenCertificate 'cert.pfx' -HasProvider $script:newProviderName -RequiresPassword $script:password
        ThenReturned 'cert.pfx' -WithOldProvider $script:oldProviderName -WithNewProvider $script:newProviderName
    }

    It 'should convert unprotected certificate' {
        GivenCertificate 'open.pfx' -From $script:sourceCertPathUnprotected
        WhenConverting 'open.pfx' -WithArgs @{ ProviderName = $script:newProviderName }
        ThenNoError
        ThenCertificate 'open.pfx' -HasProvider $script:newProviderName
        ThenReturned 'open.pfx' -WithOldProvider $script:oldProviderName -WithNewProvider $script:newProviderName
    }

    It 'should change nothing' {
        GivenCertificate 'open.pfx' -From $script:sourceCertPathUnprotected
        WhenConverting 'open.pfx' -WithArgs @{ ProviderName = $script:oldProviderName }
        ThenNoError
        ThenCertificate 'open.pfx' -HasProvider $script:oldProviderName -IsIdenticalTo $script:sourceCertPathUnprotected
        ThenReturned -Nothing
    }

    It 'should validate file path' {
        WhenConverting 'fubarsnafu.pfx' -WithArgs @{ ProviderName = $script:newProviderName } -ErrorAction SilentlyContinue
        ThenFails -WithErrorMatching 'does not exist'
    }

    It 'should validate private key' {
        $sourcePath = Join-Path -Path $PSScriptRoot -ChildPath 'Resources\CarbonTestPublicKey.cer' -Resolve
        GivenCertificate 'nopk.cer' -From $sourcePath
        WhenConverting 'nopk.cer' -WithArgs @{ ProviderName = $script:newProviderName } -ErrorAction SilentlyContinue
        ThenFails -WithErrorMatching 'does not have a private key'
    }

    It 'should check for certutil' {
        GivenCertificate 'open.pfx' -From $script:sourceCertPathUnprotected
        Mock -CommandName 'Get-Command' -ModuleName 'Carbon.Cryptography'
        WhenConverting 'open.pfx' -WithArgs @{ ProviderName = $script:newProviderName } -ErrorAction SilentlyContinue
        ThenFails -WithErrorMatching 'certutil\.exe command does not exist'
    }
}