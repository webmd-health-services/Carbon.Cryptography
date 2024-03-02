
#Requires -Version 5.1
Set-StrictMode -Version 'Latest'

if ((Test-Path -Path 'variable:IsWindows') -and -not $IsWindows)
{
    Write-Warning -Message 'Grant-CPrivateKeyPermission only supports Windows.'
    return
}

$script:rsaCertPath = 'Cert:\CurrentUser\My\44A7C2F73353BC53F82318C14490D7E2500B6DE9'
$script:cngCertPath = 'Cert:\CurrentUser\My\6CF94E242624811F7E12A5340502C1ECE88F1B18'

BeforeAll {
    Set-StrictMode -Version 'Latest'

    & (Join-Path -Path $PSScriptRoot -ChildPath 'Initialize-Test.ps1' -Resolve)

    $script:user = 'CCryptoTestUser1'
    $script:user2 = 'CCryptoTestUser2'
    $script:rsaCertPath = 'Cert:\CurrentUser\My\44A7C2F73353BC53F82318C14490D7E2500B6DE9'
    $script:cngCertPath = 'Cert:\CurrentUser\My\6CF94E242624811F7E12A5340502C1ECE88F1B18'

    function ThenIdentity
    {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory, Position=0)]
            [String] $Named,

            [Parameter(Mandatory, ParameterSetName='Not')]
            [switch] $HasNoPermission,

            [Parameter(Mandatory, ParameterSetName='Has')]
            [ValidateSet('Read', 'FullControl')]
            [String] $HasPermission,

            [Parameter(ParameterSetName='Has')]
            [ValidateSet('Allow', 'Deny')]
            [String] $OfType,

            [Parameter(Mandatory)]
            [String] $OnPrivateKey
        )

        $pk = Get-CCertificate -Path $OnPrivateKey | Get-CPrivateKey
        $expectedPerm = $HasPermission
        $usesCryptoKeyRights = Invoke-CPrivateCommand -Name 'Test-CCryptoKeyAvailable' -Parameter @{ InputObject = $pk }

        if ($HasPermission -eq 'Read')
        {
            if ($usesCryptoKeyRights)
            {
                $expectedPerm = 'GenericRead'
            }

            if ($OfType -ne 'Deny')
            {
                if ($expectedPerm -eq 'GenericRead')
                {
                    $expectedPerm = "Synchronize, ${expectedPerm}"
                }
                else
                {
                    $expectedPerm = "${expectedPerm}, Synchronize"
                }
            }
        }
        elseif ($HasPermission -eq 'FullControl' -and $usesCryptoKeyRights)
        {
            $expectedPerm = 'Synchronize, GenericAll, GenericRead'
        }

        $accessRule = Get-CPrivateKeyPermission -Path $OnPrivateKey -Identity $Named
        if ($HasNoPermission)
        {
            $accessRule | Should -BeNullOrEmpty
        }
        else
        {
            $accessRule | Select-Object -ExpandProperty '*Rights' | Should -Be $expectedPerm

            if (-not $OfType)
            {
                $OfType = 'Allow'
            }
            $accessRule.AccessControlType | Should -Be $OfType
        }
    }

    function ThenError
    {
        [CmdletBinding()]
        [Diagnostics.CodeAnalysis.SuppressMessage('PSAvoidAssignmentToAutomaticVariable', '')]
        param(
            [Parameter(Mandatory, ParameterSetName='IsEmpty')]
            [switch] $IsEmpty,

            [Parameter(Mandatory, ParameterSetName='Matches')]
            [String] $Matches
        )

        if ($Matches)
        {
            $Global:Error | Should -Match $Matches
        }

        if ($IsEmpty)
        {
            $Global:Error | Should -BeNullOrEmpty
        }
    }
}

Describe 'Grant-CPrivateKeyPermission' {
    BeforeEach {
        Write-Information 'Clearing Permissions'
        Revoke-CPrivateKeyPermission -Path $script:rsaCertPath -Identity $script:user
        Revoke-CPrivateKeyPermission -Path $script:rsaCertPath -Identity $script:user2

        Revoke-CPrivateKeyPermission -Path $script:cngCertPath -Identity $script:user
        Revoke-CPrivateKeyPermission -Path $script:cngCertPath -Identity $script:user2
        Write-Information 'Done'

        $Global:Error.Clear()
    }

    $testCases = @(
        @{ Description = 'RSA' ; CertPath = $script:rsaCertPath },
        @{ Description = 'CNG' ; CertPath = $script:cngCertPath }
    )

    Context '<Description>' -ForEach $testCases {
        It 'validates permission' {
            {
                Grant-CPrivateKeyPermission -Identity 'BUILTIN\Administrators' `
                                            -Permission 'BlahBlahBlah' `
                                            -Path $CertPath `
                                            -ErrorAction Stop
            } | Should -Throw '*does not belong to the set*'
        }

        It 'clears existing permissions' {
            Grant-CPrivateKeyPermission -Path $CertPath -Identity $script:user -Permission FullControl -Clear

            $result = Grant-CPrivateKeyPermission -Identity $script:user2 `
                                                  -Permission 'Read' `
                                                  -Path $CertPath `
                                                  -Clear `
                                                  -PassThru
            $result | Should -Not -BeNullOrEmpty

            ThenIdentity $script:user -HasNoPermission -OnPrivateKey $CertPath
            ThenIdentity $script:user2 -HasPermission 'Read' -OnPrivateKey $CertPath
        }

        It 'handles no permissions to clear' {
            Get-CPrivateKeyPermission -Path $CertPath -Identity $script:user | Should -BeNullOrEmpty
            Get-CPrivateKeyPermission -Path $CertPath -Identity $script:user2 | Should -BeNullOrEmpty
            $result = Grant-CPrivateKeyPermission -Identity $script:user `
                                                  -Permission 'Read' `
                                                  -Path $CertPath `
                                                  -Clear `
                                                  -PassThru `
                                                  -ErrorAction SilentlyContinue
            $result | Should -Not -BeNullOrEmpty
            $result.IdentityReference | Should -BeLike "*\$($script:user)"
            ThenError -IsEmpty
            ThenIdentity $script:user -HasPermission 'Read' -OnPrivateKey $CertPath
        }

        It 'updates existing permissions' {
            Grant-CPrivateKeyPermission -Identity $script:user -Permission Read -path $CertPath
            ThenIdentity $script:user -HasPermission Read -OnPrivateKey $CertPath
            Grant-CPrivateKeyPermission -Identity $script:user -Permission FullControl -path $CertPath
            ThenIdentity $script:user -HasPermission FullControl -OnPrivateKey $CertPath
        }

        It 'does not re-set existing permission' {
            Grant-CPrivateKeyPermission -Identity $script:user -Permission Read -Path $CertPath
            ThenIdentity $script:user -HasPermission Read -OnPrivateKey $CertPath

            Mock -CommandName 'Set-Acl' -Verifiable -ModuleName 'Carbon.Cryptography'
            Grant-CPrivateKeyPermission -Identity $script:user -Permission Read -Path $CertPath
            Should -Not -Invoke 'Set-Acl' -ModuleName 'Carbon.Cryptography'
        }

        It 'validates path' {
            $result = Grant-CPrivateKeyPermission -Identity $script:user `
                                                  -Permission Read `
                                                  -Path 'C:\I\Do\Not\Exist' `
                                                  -PassThru `
                                                  -ErrorAction SilentlyContinue
            $result | Should -BeNullOrEmpty
            ThenError -Matches 'certificate does not exist'
        }

        It 'sets deny rule type' {
            Grant-CPrivateKeyPermission -Identity $script:user -Permission Read -Path $CertPath -Type Deny
            ThenIdentity $script:user -HasPermission Read -OfType Deny -OnPrivateKey $CertPath
        }
    }

    # CNG key permissions are site using NTFS permissions and Set-Acl.
    It 're-sets existing permission' {
        Grant-CPrivateKeyPermission -Identity $script:user -Permission Read -Path $script:cngCertPath
        ThenIdentity $script:user -HasPermission Read -OnPrivateKey $script:cngCertPath

        Mock -CommandName 'Grant-CPermission' -Verifiable -ModuleName 'Carbon.Cryptography'
        Grant-CPrivateKeyPermission -Identity $script:user -Permission Read -Path $script:cngCertPath -Force
        Should -Invoke 'Grant-CPermission' -ModuleName 'Carbon.Cryptography' -Times 1
    }

}
