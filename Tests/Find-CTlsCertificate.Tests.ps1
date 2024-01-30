
#Requires -Version 5.1
Set-StrictMode -Version 'Latest'

BeforeDiscovery {
    & (Join-Path -Path $PSScriptRoot -ChildPath 'Initialize-Test.ps1' -Resolve)
}

BeforeAll {
    function GivenCertificate
    {
        param(
            [Parameter(Mandatory)]
            [String] $For,

            [String] $WithThumbprint,

            [switch] $WithNoPrivateKey,

            [String[]] $WithDnsNames = @(),

            [String[]] $WithUsages = @(),

            [switch] $ThatIsTrusted,

            [datetime] $ThatStarts = (Get-Date).AddDays(-1),

            [datetime] $ThatExpires = (Get-Date).AddYears(2)
        )

        $fullDnsList = & {
            $For
            if( $WithDnsNames )
            {
                $WithDnsNames
            }
        }

        $mockArgs = @{}
        if( $WithThumbprint )
        {
            $mockArgs['Thumbprint'] = $WithThumbprint
        }

        if( $WithUsages )
        {
            $mockArgs['KeyUsageName'] = $WithUsages
        }

        if( $ThatIsTrusted )
        {
            $mockArgs['Trusted'] = $true
        }

        if( -not $WithNoPrivateKey )
        {
            $mockArgs['HasPrivateKey'] = $true
        }

        $mockCert = New-MockCertificate -Subject "CN=$($For)" `
                                        -SubjectAlternateName $fullDnsList `
                                        -NotBefore $ThatStarts `
                                        -NotAfter $ThatExpires `
                                        @mockArgs

        [void] $script:mockedCertificates.Add($mockCert)
    }

    function ThenFoundCertificate
    {
        param(
            [String] $WithThumbprint
        )

        if( -not $WithThumbprint )
        {
            $WithThumbprint = $script:mockedCertificates[0].Thumbprint
        }

        $script:foundCert | Should -Not -BeNullOrEmpty
        $script:foundCert | Should -HaveCount 1
        $script:foundCert.Thumbprint | Should -Be $WithThumbprint
    }

    function ThenNoCertificateFound
    {
        param(
            [switch] $AndNoError
        )

        $script:foundCert | Should -BeNullOrEmpty

        if( $AndNoError )
        {
            return
        }

        $Global:Error | Should -Not -BeNullOrEmpty
        $Global:Error | Should -Match 'certificate for .* does not exist'
    }

    function WhenFindingTlsCertificate
    {
        [CmdletBinding()]
        param(
            [String] $Name,

            [switch] $ThatIsTrusted
        )

        $installedCertificates = $script:mockedCertificates

        Mock -CommandName 'Get-CCertificate' `
            -ModuleName 'Carbon.Cryptography' `
            -MockWith { $installedCertificates }.GetNewClosure()

        $optionalParams = @{}
        if( $Name )
        {
            $optionalParams['HostName'] = $Name
        }

        if( $ThatIsTrusted )
        {
            $optionalParams['Trusted'] = $ThatIsTrusted
        }

        $script:foundCert = Find-CTlsCertificate @optionalParams
    }
}

Describe 'Find-CTlsCertificate' {
    BeforeEach {
        $Global:Error.Clear()
        $script:foundCert = $null
        $script:mockedCertificates = [Collections.ArrayList]::new()
    }

    It 'should find a certificate when a matching certificate exists' {
        GivenCertificate -For 'cert1'
        GivenCertificate -For 'cert2'
        GivenCertificate -For 'cert3'
        GivenCertificate -For 'cert4'
        GivenCertificate -For 'cert5' -WithThumbprint 'cert5thumbprint' -ThatExpires (Get-Date).AddYears(1)
        WhenFindingTlsCertificate 'cert5'
        ThenFoundCertificate -WithThumbprint 'cert5thumbprint'
    }

    It 'should not find a certificate when no certificates match hostname' {
        GivenCertificate -For 'does not match hostname'
        GivenCertificate -For 'also does not match hostname'
        WhenFindingTlsCertificate 'example.com' -ErrorAction SilentlyContinue
        ThenNoCertificateFound
    }

    It 'should not find a certificate when no private key exists' {
        GivenCertificate -For 'noprivatekey.com' -WithNoPrivateKey
        WhenFindingTlsCertificate 'noprivatekey.com' -ErrorAction SilentlyContinue
        ThenNoCertificateFound
    }

    It 'should find the certificate when subject alternate name matches' {
        GivenCertificate -For [Environment]::MachineName -WithDnsNames ('fake.net', 'fake2.net')
        WhenFindingTlsCertificate 'fake2.net'
        ThenFoundCertificate
    }

    It 'should find the certificate when subject alternate name matches wildcard' {
        GivenCertificate -For 'localhost' -WithDnsNames ('*.example.com')
        WhenFindingTlsCertificate 'test.example.com'
        ThenFoundCertificate
    }

    It 'should not find a certificate when key usage is not Server Authentication' {
        GivenCertificate -For 'invalidkeyusage.com' -WithUsages ('Remote Desktop Authentication', 'Client Authentication')
        WhenFindingTlsCertificate 'invalidkeyusage.com' -ErrorAction SilentlyContinue
        ThenNoCertificateFound
    }

    It 'should not find a certificate when key usage is Server Authentication' {
        GivenCertificate -For 'validkeyusage.com' -WithUsages ('Remote Desktop Authentication', 'Server Authentication')
        WhenFindingTlsCertificate 'validkeyusage.com'
        ThenFoundCertificate
    }

    It 'should not find a certificate when certificate is trusted' {
        GivenCertificate -For 'trusted.com' -ThatIsTrusted
        WhenFindingTlsCertificate 'trusted.com' -ThatIsTrusted
        ThenFoundCertificate
    }

    It 'should not find a certificate when certificate is not trusted' {
        GivenCertificate -For 'nottrusted.com'
        WhenFindingTlsCertificate 'nottrusted.com' -ThatIsTrusted -ErrorAction SilentlyContinue
        ThenNoCertificateFound
    }

    It 'should not find a certificate when certificate is expired' {
        GivenCertificate -For 'expired.com' -ThatExpires (Get-Date).AddDays(-1)
        WhenFindingTlsCertificate 'expired.com' -ErrorAction SilentlyContinue
        ThenNoCertificateFound
    }

    It 'should not find a certificate when certificate has not started' {
        GivenCertificate -For 'notstarted.com' -ThatStarts (Get-Date).AddDays(1)
        WhenFindingTlsCertificate 'notstarted.com' -ErrorAction SilentlyContinue
        ThenNoCertificateFound
    }

    It 'should return cert that matches hostname from global IP properties when getting certificate for current machine' {
        $ipProperties = [Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
        $thisHostName= "$($ipProperties.HostName).$($ipProperties.DomainName)"
        GivenCertificate -For $thisHostName
        WhenFindingTlsCertificate
        ThenFoundCertificate
    }

    It 'should not fail when ignoring that a certificate is not found' {
        WhenFindingTlsCertificate 'doesnotexist.com' -ErrorAction Ignore
        ThenNoCertificateFound -AndNoError
    }
}