
#Requires -Version 5.1
Set-StrictMode -Version 'Latest'

if ((Test-Path -Path 'variable:IsWindows') -and -not $IsWindows)
{
    Write-Warning -Message 'Get-CPrivateKeyPermission only supports Windows.'
    return
}

$script:rsaCertPath = 'Cert:\CurrentUser\My\44A7C2F73353BC53F82318C14490D7E2500B6DE9'
$script:cngCertPath = 'Cert:\CurrentUser\My\6CF94E242624811F7E12A5340502C1ECE88F1B18'

BeforeAll {
    Set-StrictMode -Version 'Latest'

    & (Join-Path -Path $PSScriptRoot -ChildPath 'Initialize-Test.ps1' -Resolve)

    $psModulesPath = Join-Path -Path $PSScriptRoot -ChildPath '..\Carbon.Cryptography' -Resolve
    Import-Module -Name (Join-Path -Path $psModulesPath -ChildPath 'Carbon.Accounts' -Resolve) `
                  -Function @('Test-CPrincipal') `
                  -Verbose:$false

    $script:rsaCertPath = 'Cert:\CurrentUser\My\44A7C2F73353BC53F82318C14490D7E2500B6DE9'
    $script:cngCertPath = 'Cert:\CurrentUser\My\6CF94E242624811F7E12A5340502C1ECE88F1B18'

    function Get-CertificateWithPrivateKey
    {
        Get-Item -Path 'Cert:\*\*' |
            Where-Object 'Name' -NE 'UserDS' | # This store causes problems on PowerShell 7.
            Get-ChildItem |
            Where-Object { -not $_.PsIsContainer } |
            Where-Object { $_.HasPrivateKey } |
            Where-Object { $_ | Get-CPrivateKey -ErrorAction Ignore } |
            Where-Object { -not ($_.EnhancedKeyUsageList | Where-Object 'FriendlyName' -EQ 'Smart Card Logon') }
    }
}

Describe 'Get-CPrivateKeyPermission' {
    BeforeEach {
        $Global:Error.Clear()
    }

    $testCases = @(
        @{ Description = 'RSA' ; CertPath = $script:rsaCertPath },
        @{ Description = 'CNG' ; CertPath = $script:cngCertPath }
    )

    Context '<Description>' -ForEach $testCases {
        It 'gets private cert permission' {
            $perms = Get-CPrivateKeyPermission -Path $certPath -Inherited -ErrorAction SilentlyContinue
            $perms | Should -Not -BeNullOrEmpty -Because "${certPath} should have private key permissions"
            $pk = Get-Item -Path $CertPath | Get-CPrivateKey
            $usesCryptoKeyRights =
                Invoke-CPrivateCommand -Name 'Test-CCryptoKeyAvailable' -Parameter @{ InputObject = $pk }
            $expectedType = [System.Security.AccessControl.FileSystemAccessRule]
            if ($usesCryptoKeyRights)
            {
                $expectedType = [System.Security.AccessControl.CryptoKeyAccessRule]
            }
            $perms | Should -BeOfType $expectedType
        }
    }

    It 'gets specific identity permissions' {
        Get-CertificateWithPrivateKey |
            Where-Object { $_.PrivateKey } |
            ForEach-Object { Join-Path -Path 'cert:' -ChildPath (Split-Path -NoQualifier -Path $_.PSPath) } |
            ForEach-Object {
                [Object[]]$rules =
                    Get-CPrivateKeyPermission -Path $_ -ErrorAction Ignore | Where-Object { Test-CPrincipal $_.IdentityReference.Value }
                foreach( $rule in $rules )
                {
                    [Object[]]$identityRule = Get-CPrivateKeyPermission -Path $_ -Identity $rule.IdentityReference.Value
                    $identityRule | Should -Not -BeNullOrEmpty
                    $identityRule.Count | Should -BeLessOrEqual $rules.Count
                }
            }
    }
}
