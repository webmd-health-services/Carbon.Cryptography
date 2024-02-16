
#Requires -Version 5.1
Set-StrictMode -Version 'Latest'

$script:rsaCertPath = 'Cert:\CurrentUser\My\44A7C2F73353BC53F82318C14490D7E2500B6DE9'
$script:cngCertPath = 'Cert:\CurrentUser\My\6CF94E242624811F7E12A5340502C1ECE88F1B18'

BeforeAll {
    Set-StrictMode -Version 'Latest'

    & (Join-Path -Path $PSScriptRoot -ChildPath 'Initialize-Test.ps1' -Resolve)

    $script:user = 'CCryptoTestUser1'
    $script:rsaCertPath = 'Cert:\CurrentUser\My\44A7C2F73353BC53F82318C14490D7E2500B6DE9'
    $script:cngCertPath = 'Cert:\CurrentUser\My\6CF94E242624811F7E12A5340502C1ECE88F1B18'

    function ThenPermission
    {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [String] $OnPrivateKey,

            [Parameter(Mandatory)]
            [String] $For,

            [switch] $Inherited,

            [switch] $Not,

            [switch] $Exists
        )

        $accessRule = Get-CPrivateKeyPermission -Path $OnPrivateKey -Identity $For -Inherited:$Inherited
        if ($Not)
        {
            $accessRule | Should -BeNullOrEmpty
        }
        else
        {
            $accessRule | Should -Not -BeNullOrEmpty
            $expectedPerms = 'Read, Synchronize'
            $pk = Get-CCertificate -Path $OnPrivateKey | Get-CPrivateKey
            $usesCryptoKeyRights =
                Invoke-CPrivateCommand -Name 'Test-CCryptoKeyAvailable' -Parameter @{ InputObject = $pk }
            if ($usesCryptoKeyRights)
            {
                $expectedPerms = 'Synchronize, GenericRead'
            }
            $accessRule | Select-Object -ExpandProperty '*Rights' | Should -Be $expectedPerms
        }
    }

    function ThenError
    {
        [CmdletBinding()]
        [Diagnostics.CodeAnalysis.SuppressMessage('PSAvoidAssignmentToAutomaticVariable', '')]
        param(
            [Parameter(Mandatory, ParameterSetName='IsEmpty')]
            [switch] $IsEmpty
        )

        $Global:Error | Should -BeNullOrEmpty
    }
}

Describe 'Revoke-CPrivateKeyPermission' {
    BeforeEach {
        $Global:Error.Clear()
        Grant-CPrivateKeyPermission -Path $script:rsaCertPath -Identity $script:user -Permission Read
        Grant-CPrivateKeyPermission -Path $script:cngCertPath -Identity $script:user -Permission Read
    }

    $testCases = @(
        @{ Description = 'RSA' ; CertPath = $script:rsaCertPath },
        @{ Description = 'CNG' ; CertPath = $script:cngCertPath }
    )

    Context '<Description>' -ForEach $testCases {

        It 'revokes permission' {
            Revoke-CPrivateKeyPermission -Path $CertPath -Identity $script:user
            ThenError -IsEmpty
            ThenPermission -OnPrivateKey $CertPath -For $script:user -Not -Exists
        }

        It 'ignores inherited permissions' {
            Get-CPrivateKeyPermission -Path $CertPath -Inherited
                Where-Object { $_.IdentityReference -notlike ('*{0}*' -f $script:user) } |
                ForEach-Object {
                    $result = Revoke-CPrivateKeyPermission -Path $CertPath -Identity $_.IdentityReference
                    ThenError -IsEmpty
                    $result | Should -BeNullOrEmpty
                    ThenPermission -OnPrivateKey $CertPath -For $script:user -Inherited -Exists
                }
        }

        It 'ignores non existent permission' {
            Revoke-CPrivateKeyPermission -Path $CertPath -Identity $script:user
            ThenError -IsEmpty
            ThenPermission -OnPrivateKey $CertPath -For $script:user -Not -Exists
            Revoke-CPrivateKeyPermission -Path $CertPath -Identity $script:user
            ThenError -IsEmpty
            ThenPermission -OnPrivateKey $CertPath -For $script:user -Not -Exists
        }

        It 'should support what if' {
            Revoke-CPrivateKeyPermission -Path $CertPath -Identity $script:user -WhatIf
            ThenPermission -OnPrivateKey $CertPath -For $script:user -Exists
        }
    }
}
