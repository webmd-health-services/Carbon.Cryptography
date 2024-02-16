
#Requires -Version 5.1
Set-StrictMode -Version 'Latest'

$script:rsaCertPath = 'Cert:\CurrentUser\My\44A7C2F73353BC53F82318C14490D7E2500B6DE9'
$script:cngCertPath = 'Cert:\CurrentUser\My\6CF94E242624811F7E12A5340502C1ECE88F1B18'

BeforeAll {
    Set-StrictMode -Version 'Latest'

    & (Join-Path -Path $PSScriptRoot -ChildPath 'Initialize-Test.ps1' -Resolve)

    $script:reader = 'CCryptoTestUser1'
    $script:admin = 'CCryptoTestUser2'
    $script:rsaCertPath = 'Cert:\CurrentUser\My\44A7C2F73353BC53F82318C14490D7E2500B6DE9'
    $script:cngCertPath = 'Cert:\CurrentUser\My\6CF94E242624811F7E12A5340502C1ECE88F1B18'

    function ThenError
    {
        [CmdletBinding()]
        [Diagnostics.CodeAnalysis.SuppressMessage('PSAvoidAssignmentToAutomaticVariable', '')]
        param(
            [int] $AtIndex,

            [Parameter(Mandatory, ParameterSetName='IsEmpty')]
            [switch] $IsEmpty,

            [Parameter(Mandatory, ParameterSetName='Matches')]
            [String] $Matches
        )

        $errorsToCheck = $Global:Error
        if ($PSBoundParameters.ContainsKey('AtIndex'))
        {
            $errorsToCheck = $Global:Error[$AtIndex]
        }

        if ($Matches)
        {
            $errorsToCheck | Should -Match $Matches
        }

        if ($IsEmpty)
        {
            $errorsToCheck | Should -BeNullOrEmpty
        }
    }
}

Describe 'Test-CPrivateKeyPermission' {
    BeforeAll {
        Grant-CPrivateKeyPermission -Path $script:rsaCertPath -Identity $script:reader -Permission Read
        Grant-CPrivateKeyPermission -Path $script:rsaCertPath -Identity $script:admin -Permission FullControl

        Grant-CPrivateKeyPermission -Path $script:cngCertPath -Identity $script:reader -Permission Read
        Grant-CPrivateKeyPermission -Path $script:cngCertPath -Identity $script:admin -Permission FullControl
    }

    BeforeEach {
        $Global:Error.Clear()
    }

    AfterAll {
        Revoke-CPrivateKeyPermission -Path $script:cngCertPath -Identity $script:admin
        Revoke-CPrivateKeyPermission -Path $script:cngCertPath -Identity $script:reader

        Revoke-CPrivateKeyPermission -Path $script:rsaCertPath -Identity $script:admin
        Revoke-CPrivateKeyPermission -Path $script:rsaCertPath -Identity $script:reader
    }

    $testCases = @(
        @{ Description = 'RSA' ; CertPath = $script:rsaCertPath },
        @{ Description = 'CNG' ; CertPath = $script:cngCertPath }
    )

    Context '<Description>' -ForEach $testCases {
        It 'validates path' {
            Test-CPrivateKeyPermission -Path 'cert:\CurrentUser\My\IDoNotExist' `
                                       -Identity $script:reader `
                                       -Permission 'Read' `
                                       -ErrorAction SilentlyContinue |
                Should -BeNullOrEmpty
            ThenError -Matches 'path does not exist'
        }

        It 'checks non-existent permission' {
            Test-CPrivateKeyPermission -Path $CertPath -Identity $script:reader -Permission 'FullControl' |
                Should -BeFalse
            ThenError -IsEmpty
        }

        It 'checks existent permission' {
            Test-CPrivateKeyPermission -Path $CertPath -Identity $script:reader -Permission 'Read' |
                Should -BeTrue
            Test-CPrivateKeyPermission -Path $CertPath -Identity $script:admin -Permission 'Read' |
                Should -BeTrue
            ThenError -IsEmpty
        }

        It 'checks exact permission' {
            Test-CPrivateKeyPermission -Path $CertPath -Identity $script:reader -Permission 'Read' -Strict |
                Should -BeTrue
            Test-CPrivateKeyPermission -Path $CertPath -Identity $script:admin -Permission 'Read' -Strict |
                Should -BeFalse
            Test-CPrivateKeyPermission -Path $CertPath -Identity $script:admin -Permission 'FullControl' -Strict |
                Should -BeTrue
            ThenError -IsEmpty
        }

        It 'does not check inherited permissions by default' {
            Get-CPrivateKeyPermission -Path $CertPath -Inherited |
                Where-Object 'IsInherited' -EQ $true |
                ForEach-Object {
                    $perms = $_ | Select-Object -ExpandProperty '*Rights'
                    Test-CPrivateKeyPermission -Path $CertPath  -Identity $_.IdentityReference -Permission $perms
                } |
                Should -BeFalse
            ThenError -IsEmpty
        }

        It 'checks inherited permissions' {
            $inheritedPerms =
                Get-CPrivateKeyPermission -Path $CertPath -Inherited | Where-Object 'IsInherited' -EQ $true
            if ($inheritedPerms)
            {
                $inheritedPerms |
                    ForEach-Object {
                        $perms = $_ | Select-Object -ExpandProperty '*Rights'
                        Test-CPrivateKeyPermission -Path $CertPath `
                                                   -Identity $_.IdentityReference `
                                                   -Inherited `
                                                   -Permission $perms
                    } |
                    Should -BeTrue
            }
            ThenError -IsEmpty
        }
    }
}
