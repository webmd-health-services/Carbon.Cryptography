
#Requires -Version 5.1
Set-StrictMode -Version 'Latest'

BeforeDiscovery {
    & (Join-Path -Path $PSScriptRoot -ChildPath 'Initialize-Test.ps1' -Resolve)

    $script:machineName = [Environment]::MachineName
    $script:foundCert = $null
    $script:mockedCertificates = [Collections.ArrayList]::new()
    $script:thumbprint = $null
}

BeforeAll {
    function GivenCertificate
    {
        param(
            [Parameter(Mandatory)]
            [String] $For,

            [String] $WithThumbprint = $script:thumbprint,

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
        $keyUsages = [Collections.ArrayList]::New()
        $WithUsages |
            ForEach-Object { [pscustomobject]@{ 'FriendlyName' = $_; } } |
            ForEach-Object { [void]$keyUsages.Add($_) }
        $certificate = [pscustomobject]@{
            'Thumbprint' = $WithThumbprint;
            'SubjectName' = [pscustomobject]@{
                'Name' = "CN=$($For)";
            };
            'DnsNameList' = $fullDnsList;
            'EnhancedKeyUsageList' = $keyUsages;
            'HasPrivateKey' = -not $WithNoPrivateKey;
            'NotBefore' = $ThatStarts;
            'NotAfter' = $ThatExpires;
        }
        $verify = { $false }
        if( $ThatIsTrusted )
        {
            $verify = { $true }
        }
        $certificate | Add-Member -MemberType ScriptMethod -Name 'Verify' -Value $verify
        [void] $mockedCertificates.Add($certificate)
    }

    function Init 
    {
        $Global:Error.Clear()
        $script:foundCert = $null
        $script:mockedCertificates = [Collections.ArrayList]::new()
        $script:thumbprint = [Guid]::NewGuid().ToString()
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

        Mock -CommandName 'Get-Certificate' `
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

Describe 'Find-TlsCertificate' {
    It 'should find a certificate when a matching certificate exists' {
        Init
        GivenCertificate -For 'cert1'
        GivenCertificate -For 'cert2'
        GivenCertificate -For 'cert3'
        GivenCertificate -For 'cert4'
        GivenCertificate -For 'cert5' -WithThumbprint 'cert5thumbprint' -ThatExpires (Get-Date).AddYears(1)
        WhenFindingTlsCertificate 'cert5'
        ThenFoundCertificate -WithThumbprint 'cert5thumbprint'
    }

    It 'should not find a certificate when no certificates match hostname' {
        Init
        GivenCertificate -For 'does not match hostname'
        GivenCertificate -For 'also does not match hostname'
        WhenFindingTlsCertificate 'example.com' -ErrorAction SilentlyContinue
        ThenNoCertificateFound 
    }

    It 'should not find a certificate when no private key exists' {
        Init
        GivenCertificate -For 'noprivatekey.com' -WithNoPrivateKey
        WhenFindingTlsCertificate 'noprivatekey.com' -ErrorAction SilentlyContinue
        ThenNoCertificateFound 
    }

    It 'should find the certificate when subject alternate name matches' {
        Init
        GivenCertificate -For $machineName -WithDnsNames ('fake.net', 'fake2.net')
        WhenFindingTlsCertificate 'fake2.net'
        ThenFoundCertificate
    }

    It 'should not find a certificate when key usage is not Server Authentication' {
        Init
        GivenCertificate -For 'invalidkeyusage.com' -WithUsages ('Remote Desktop Authentication', 'Client Authentication') 
        WhenFindingTlsCertificate 'invalidkeyusage.com' -ErrorAction SilentlyContinue
        ThenNoCertificateFound 
    }

    It 'should not find a certificate when key usage is Server Authentication' {
        Init
        GivenCertificate -For 'validkeyusage.com' -WithUsages ('Remote Desktop Authentication', 'Server Authentication') 
        WhenFindingTlsCertificate 'validkeyusage.com'
        ThenFoundCertificate
    }

    It 'should not find a certificate when certificate is trusted' {
        Init
        GivenCertificate -For 'trusted.com' -ThatIsTrusted
        WhenFindingTlsCertificate 'trusted.com' -ThatIsTrusted
        ThenFoundCertificate
    }

    It 'should not find a certificate when certificate is not trusted' {
        Init
        GivenCertificate -For 'nottrusted.com'
        WhenFindingTlsCertificate 'nottrusted.com' -ThatIsTrusted -ErrorAction SilentlyContinue
        ThenNoCertificateFound
    }

    It 'should not find a certificate when certificate is expired' {
        Init
        GivenCertificate -For 'expired.com' -ThatExpires (Get-Date).AddDays(-1)
        WhenFindingTlsCertificate 'expired.com' -ErrorAction SilentlyContinue
        ThenNoCertificateFound 
    }

    It 'should not find a certificate when certificate has not started' {
        Init
        GivenCertificate -For 'notstarted.com' -ThatStarts (Get-Date).AddDays(1)
        WhenFindingTlsCertificate 'notstarted.com' -ErrorAction SilentlyContinue
        ThenNoCertificateFound
    }

    It 'should return cert that matches hostname from global IP properties when getting certificate for current machine' {
        Init
        $ipProperties = [Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
        $thisHostName= "$($ipProperties.HostName).$($ipProperties.DomainName)"
        GivenCertificate -For $thisHostName
        WhenFindingTlsCertificate
        ThenFoundCertificate
    }

    It 'should not fail when ignoring that a certificate is not found' {
        Init
        WhenFindingTlsCertificate 'doesnotexist.com' -ErrorAction Ignore
        ThenNoCertificateFound -AndNoError
    }
}