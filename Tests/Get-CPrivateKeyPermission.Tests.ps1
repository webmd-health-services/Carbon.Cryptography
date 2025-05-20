
#Requires -Version 5.1
Set-StrictMode -Version 'Latest'

if ((Test-Path -Path 'variable:IsWindows') -and -not $IsWindows)
{
    Write-Warning -Message 'Get-CPrivateKeyPermission only supports Windows.'
    return
}

BeforeDiscovery {
    Set-StrictMode -Version 'Latest'

    & (Join-Path -Path $PSScriptRoot -ChildPath 'Initialize-Test.ps1' -Resolve)

    $script:rsaKeyFilePath =
        Join-Path -Path $PSScriptRoot -ChildPath 'Certificates\GetCPrivateKeyPermissionUnprotected.pfx' -Resolve
    $script:rsaKey =
        Install-CCertificate -Path $script:rsaKeyFilePath -StoreLocation CurrentUser -StoreName My -PassThru
    $script:rsaCertPath = Join-Path -Path 'Cert:\CurrentUser\My' -ChildPath $script:rsaKey.Thumbprint

    $script:cngKeyFilePath =
        Join-Path -Path $PSScriptRoot -ChildPath 'Certificates\GetCPrivateKeyPermissionCngUnprotected.pfx' -Resolve
    $script:cngKey =
        Install-CCertificate -Path $script:cngKeyFilePath -StoreLocation CurrentUser -StoreName My -PassThru
    $script:cngCertPath = Join-Path -Path 'Cert:\CurrentUser\My' -ChildPath $script:cngKey.Thumbprint
}

BeforeAll {
    Set-StrictMode -Version 'Latest'

    $psModulesPath = Join-Path -Path $PSScriptRoot -ChildPath '..\Carbon.Cryptography\Modules' -Resolve
    Import-Module -Name (Join-Path -Path $psModulesPath -ChildPath 'Carbon.Accounts' -Resolve) `
                  -Function @('Test-CPrincipal') `
                  -Verbose:$false
}

AfterAll {
    Uninstall-CCertificate -Thumbprint $rsaKey.Thumbprint `
                           -StoreLocation CurrentUser `
                           -StoreName My
    Uninstall-CCertificate -Thumbprint $cngKey.Thumbprint `
                           -StoreLocation CurrentUser `
                           -StoreName My
}

Describe 'Get-CPrivateKeyPermission' {
    BeforeEach {
        $Global:Error.Clear()
    }

    $testCases = & {
        if (Test-IsAdministrator)
        {
            @{ Description = 'RSA' ; CertPath = $script:rsaCertPath } | Write-Output
        }
        else
        {
            $msg = 'Unable to test if Get-CPrivateKeyPermission works for RSA keys: granting permissions on RSA ' +
                   'keys requires admin privileges. Yes. Even on CurrentUser keys. Re-run PowerShell as an ' +
                   'administrator if you also want to test getting permission on RSA keys.'
            Write-Warning -Message $msg
        }

        @{ Description = 'CNG' ; CertPath = $script:cngCertPath } | Write-Output
    }

    Context '<Description>' -ForEach $testCases {
        It 'gets private cert permission' {
            Grant-CPrivateKeyPermission -Path $certPath -Identity 'Everyone' -Permission Read
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

        It 'gets specific identity permissions' {
            [Object[]]$rules =
                Get-CPrivateKeyPermission -Path $certPath -ErrorAction Ignore |
                Where-Object { Test-CPrincipal $_.IdentityReference.Value }

            foreach( $rule in $rules )
            {
                [Object[]]$identityRule =
                    Get-CPrivateKeyPermission -Path $certPath -Identity $rule.IdentityReference.Value
                $identityRule | Should -Not -BeNullOrEmpty
                $identityRule.Count | Should -BeLessOrEqual $rules.Count
            }
        }
    }
}
