
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

            [switch] $WithPrivateKey,

            [String[]] $WithDnsNames = @(),

            [String[]] $WithKeyUsageNames = @(),

            [String[]] $WithKeyUsageOids = @(),

            [switch] $ThatIsTrusted,

            [datetime] $ThatStarts = (Get-Date).AddDays(-1),

            [datetime] $ThatExpires = (Get-Date).AddYears(2)
        )

        $mockArgs = @{}
        if( $WithThumbprint )
        {
            $mockArgs['Thumbprint'] = $WithThumbprint
        }

        if( $WithKeyUsageNames )
        {
            $mockArgs['KeyUsageName'] = $WithKeyUsageNames
        }

        if( $WithKeyUsageOIds )
        {
            $mockArgs['KeyUsageOid'] = $WithKeyUsageOIds
        }

        if( $ThatIsTrusted )
        {
            $mockArgs['Trusted'] = $true
        }

        if( $WithPrivateKey )
        {
            $mockArgs['HasPrivateKey'] = $true
        }

        if( $WithDnsNames )
        {
            $mockArgs['SubjectAlternateName'] = $WithDnsNames
        }

        $mockCert = New-MockCertificate -Subject $For -NotBefore $ThatStarts -NotAfter $ThatExpires @mockArgs

        [void] $script:mockedCertificates.Add($mockCert)
    }

    function ThenFound
    {
        [CmdletBinding()]
        param(
            [String[]]$CertificatesWithSubjects,

            [String] $In = 'My',

            [String] $For
        )

        $script:result | Should -HaveCount $CertificatesWithSubjects.Count

        $script:result | ForEach-Object -MemberName 'Subject' | Should -Be $CertificatesWithSubjects

        Assert-MockCalled -CommandName 'Get-CCertificate' `
                          -ModuleName 'Carbon.Cryptography' `
                          -ParameterFilter { $StoreName -eq $In }

        if( $For )
        {
            Assert-MockCalled -CommandName 'Get-CCertificate' `
                              -ModuleName 'Carbon.Cryptography' `
                              -ParameterFilter { $StoreLocation -eq $For }
        }
        else
        {
            Assert-MockCalled -CommandName 'Get-CCertificate' `
                              -ModuleName 'Carbon.Cryptography' `
                              -ParameterFilter { $null -eq $StoreLocation }
        }
    }

    function WhenFinding
    {
        [CmdletBinding()]
        param(
            [hashtable] $WithArgs
        )
        $installedCertificates = $script:mockedCertificates

        Mock -CommandName 'Get-CCertificate' `
             -ModuleName 'Carbon.Cryptography' `
             -MockWith { $installedCertificates }.GetNewClosure()

        $script:result = Find-CCertificate @WithArgs
    }
}

Describe 'Find-CCertificate' {
    BeforeEach {
        $script:mockedCertificates = [Collections.ArrayList]::New()
        $script:result = $null
    }

    It 'should find all certificates' {
        GivenCertificate -For 'one.example.com'
        GivenCertificate -For 'two.example.com'
        GivenCertificate -For 'three.example.com'
        WhenFinding
        ThenFound @( 'one.example.com', 'two.example.com', 'three.example.com' )
    }

    It 'should find by subject' {
        GivenCertificate -For 'example.com'
        GivenCertificate -For 'four.example.com'
        WhenFinding @{ Subject = '*.example.com' }
        ThenFound 'four.example.com'
    }

    It 'should find by literal subject' {
        GivenCertificate -For 'five.example.com'
        GivenCertificate -For '*.example.com'
        WhenFinding @{ LiteralSubject = '*.example.com' }
        ThenFound '*.example.com'
    }

    It 'should find active certificates' {
        GivenCertificate -For 'expired' -ThatExpires (Get-Date).AddDays(-1) -ThatStarts (Get-Date).AddDays(-366)
        GivenCertificate -For 'inactive' -ThatExpires (Get-Date).AddDays(395) -ThatStarts (Get-Date).AddDays(30)
        GivenCertificate -For 'active'
        WhenFinding @{ Active = $true }
        ThenFound 'active'
    }

    It 'should find certificates with private key' {
        GivenCertificate -For 'public key'
        GivenCertificate -for 'private key' -WithPrivateKey
        WhenFinding @{ HasPrivateKey = $true }
        ThenFound 'private key'
    }

    It 'should find hostname that matches subject common name' {
        GivenCertificate -For 'CN=six.example.com'
        GivenCertificate -For 'CN=seven.example.com,OU=example,OU=com'
        GivenCertificate -For 'OU=eight.example.com'
        WhenFinding @{ HostName = '*.example.com' }
        ThenFound 'CN=six.example.com','CN=seven.example.com,OU=example,OU=com'
    }

    It 'should find hostname using subject alternate name' {
        GivenCertificate -For 'example.com' -WithDnsNames @('example.com', 'anotherexample.com')
        GivenCertificate -For 'CN=example.com' -WithDnsNames @('example.com', 'nine.example.com')
        WhenFinding @{ HostName = '*.example.com' }
        ThenFound 'CN=example.com'
    }

    It 'should find hostname using subject alternate name with wildcard' {
        GivenCertificate -For 'CN=*.test.example.com' -WithDnsNames @('*.test.example.com')
        GivenCertificate -For 'CN=andnot.example.com' -WithDnsNames @('*.example.com')
        WhenFinding @{ HostName = 'fourteen.test.example.com' }
        ThenFound 'CN=*.test.example.com'
    }

    It 'finds certificate by penultimate subject alternate name' {
        GivenCertificate -For 'CN=*.carbon' -WithDnsNames @('*.one.carbon', '*.two.carbon')
        WhenFinding @{ HostName = '*.one.carbon' }
        ThenFound 'CN=*.carbon'
    }

    It 'should find wildcard hostname using subject alternate name with wildcard' {
        GivenCertificate -For 'CN=*.example.com' -WithDnsNames @('*.example.com')
        WhenFinding @{ HostName = '*.example.com' }
        ThenFound 'CN=*.example.com'
    }

    It 'should find literal hostname that matches subject common name' {
        GivenCertificate -For 'CN=ten.example.com'
        GivenCertificate -For 'CN=*.example.com'
        WhenFinding @{ LiteralHostName = '*.example.com' }
        ThenFound 'CN=*.example.com'
    }

    It 'should find literal hostname that matches subject alternate name' {
        GivenCertificate -For 'CN=Example' -WithDnsNames @('example.com', 'eleven.example.com')
        GivenCertificate -For 'CN=Dev,OU=Example' -WithDnsNames @('example.com', '*.example.com')
        WhenFinding @{ LiteralHostName = '*.example.com' }
        ThenFound 'CN=Dev,OU=Example'
    }

    It 'should find by key usage name' {
        GivenCertificate -For 'clientauthonly' -WithKeyUsageNames @('Client Authentication')
        GivenCertificate -For 'allusages'
        GivenCertificate -For 'serverauthclientauth' -WithKeyUsageNames @('Client Authentication', 'Server Authentication')
        WhenFinding @{ KeyUsageName = 'Server Authentication' }
        ThenFound 'allusages', 'serverauthclientauth'
    }

    It 'should find by key usage oid' {
        GivenCertificate -For 'twelve.example.com' -WithKeyUsageOids @('1.2.3.4', '5.6.7.8')
        GivenCertificate -For 'thirteen.example.com' -WithKeyUsageOids @('9.10.11.12', '13.14.15.16')
        GivenCertificate -For 'allusages'
        WhenFinding @{ KeyUsageOid = '13.14.15.16' }
        ThenFound 'thirteen.example.com', 'allusages'
    }

    It 'should find trusted' {
        GivenCertificate -For 'nottrusted.example.com'
        GivenCertificate -For 'trusted.example.com' -ThatIsTrusted
        WhenFinding @{ Trusted = $true }
        ThenFound 'trusted.example.com'
    }

    It 'should find trusted' {
        GivenCertificate -For 'nottrusted.example.com'
        GivenCertificate -For 'trusted.example.com' -ThatIsTrusted
        WhenFinding @{ Trusted = $true }
        ThenFound 'trusted.example.com'
    }

    It 'should search other stores' {
        GivenCertificate -For 'example.com'
        WhenFinding @{ StoreName = 'Root' ; StoreLocation = 'CurrentUser' }
        ThenFound 'example.com' -In 'Root' -For 'CurrentUser'
    }
}
