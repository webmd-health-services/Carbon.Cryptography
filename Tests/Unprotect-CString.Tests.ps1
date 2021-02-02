
#Requires -Version 5.1
Set-StrictMode -Version 'Latest'

& (Join-Path -Path $PSScriptRoot 'Initialize-Test.ps1' -Resolve)

$originalText = $null
$secret = [Guid]::NewGuid().ToString()
$rsaCipherText = $null
$publicKeyPath = Join-Path -Path $PSScriptRoot -ChildPath 'Resources\CarbonTestPublicKey.cer' -Resolve
$privateKeyPath = Join-Path -Path $PSScriptRoot -ChildPath 'Resources\CarbonTestPrivateKey.pfx' -Resolve
$publicKey2Path = Join-Path -Path $PSScriptRoot -ChildPath 'Resources\CarbonTestPublicKey2.cer' -Resolve
$privateKey2Path = Join-Path -Path $PSScriptRoot -ChildPath 'Resources\CarbonTestPrivateKey2.pfx' -Resolve

$rsaCipherText = Protect-CString -String $secret -PublicKeyPath $privateKeyPath

Describe 'Unprotect-CString' {
    BeforeEach {
        $Global:Error.Clear()
    }

    if( (Test-COperatingSystem -IsWindows) )
    {
        It 'should unprotect string' {
            $originalText = [Guid]::NewGuid().ToString()
            $protectedText = Protect-CString -String $originalText -ForUser
            $actualText = Unprotect-CString -ProtectedString $protectedText
            $actualText | Convert-CSecureStringToString | Should -Be $originalText
        }


        It 'should unprotect string from machine scope' {
            $secret = Protect-CString -String 'Hello World' -ForComputer
            $machine = Unprotect-CString -ProtectedString $secret
            $machine | Convert-CSecureStringToString | Should -Be 'Hello World'
        }

        It 'should unprotect string from user scope' {
            $secret = Protect-CString -String 'Hello World' -ForUser
            $machine = Unprotect-CString -ProtectedString $secret
            $machine | Convert-CSecureStringToString | Should -Be 'Hello World'
        }


        It 'should unprotect strings in pipeline' {
            $secrets = @('Foo', 'Fizz', 'Buzz', 'Bar') | Protect-CString -ForUser | Unprotect-CString
            $secrets | Should -HaveCount 4
            $secrets[0] | Convert-CSecureStringToString | Should -Be 'Foo'
            $secrets[1] | Convert-CSecureStringToString | Should -Be 'Fizz'
            $secrets[2] | Convert-CSecureStringToString | Should -Be 'Buzz'
            $secrets[3] | Convert-CSecureStringToString | Should -Be 'Bar'
        }

        It 'should handle thumbprint to cert with no private key' {
            $cert = Get-ChildItem -Path 'cert:\*\*' -Recurse |
                        Where-Object { $_.PublicKey.Key -is [Security.Cryptography.RSA] } |
                        Where-Object { -not $_.HasPrivateKey } |
                        Select-Object -First 1
            $cert | Should -Not -BeNullOrEmpty
            $revealedSecret = Unprotect-CString -ProtectedString $rsaCipherText -Thumbprint $cert.Thumbprint -ErrorAction SilentlyContinue
            $Global:Error.Count | Should -BeGreaterThan 0
            $Global:Error[0] | Should -Match 'doesn''t have a private key'
            $revealedSecret | Should -BeNullOrEmpty
        }

        It 'should decrypt with path to cert in store' {
            $cert = Install-CCertificate -Path $privateKeyPath -StoreLocation CurrentUser -StoreName My -PassThru
            try
            {
                $revealedSecret = Unprotect-CString -ProtectedString $rsaCipherText -PrivateKeyPath ('cert:\CurrentUser\My\{0}' -f $cert.Thumbprint)
                $Global:Error.Count | Should -Be 0
                $revealedSecret | Convert-CSecureStringToString | Should -Be $secret
            }
            finally
            {
                Uninstall-CCertificate -Thumbprint $cert.Thumbprint -StoreLocation CurrentUser -StoreName My
            }
        }

        It 'should decrypt with thumbprint' {
            $cert = Install-CCertificate -Path $privateKeyPath -StoreLocation CurrentUser -StoreName My -PassThru
            try
            {
                $revealedSecret = Unprotect-CString -ProtectedString $rsaCipherText -Thumbprint $cert.Thumbprint
                $Global:Error.Count | Should -Be 0
                $revealedSecret | Convert-CSecureStringToString | Should -Be $secret
            }
            finally
            {
                Uninstall-CCertificate -Thumbprint $cert.Thumbprint -StoreLocation CurrentUser -StoreName My
            }
        }

        It 'should convert to plain text' {
            $originalText = [Guid]::NewGuid().ToString()
            $protectedText = Protect-CString -String $originalText -ForUser
            $plainText = Unprotect-CString -ProtectedString $protectedText -AsPlainText
            $plainText | Should -BeOfType ([String])
            $plainText | Should -Be $originalText
        }
    }

    It 'should load certificate from file' {
        $revealedSecret = Unprotect-CString -ProtectedString $rsaCipherText -PrivateKeyPath $privateKeyPath
        $Global:Error.Count | Should -Be 0
        $revealedSecret | Convert-CSecureStringToString | Should -Be $secret
    }

    It 'should handle missing private key' {
        $revealedSecret = Unprotect-CString -ProtectedString $rsaCipherText -PrivateKeyPath $publicKeyPath -ErrorAction SilentlyContinue
        $Global:Error.Count | Should -BeGreaterThan 0
        $Global:Error[0] | Should -Match 'doesn''t have a private key'
        $revealedSecret | Convert-CSecureStringToString | Should -BeNullOrEmpty
    }

    It 'should load password protected private key' {
        $ciphertext = Protect-CString -String $secret -PublicKeyPath $publicKey2Path
        $revealedText = Unprotect-CString -ProtectedString $ciphertext `
                                          -PrivateKeyPath $privateKey2Path `
                                          -Password (ConvertTo-SecureString -String 'fubar' -AsPlainText -Force)
        $Global:Error.Count | Should -Be 0
        $revealedText | Convert-CSecureStringToString | Should -Be $secret
    }

    It 'should decrypt with certificate' {
        $cert = Get-CCertificate -Path $privateKeyPath
        $revealedSecret = Unprotect-CString -ProtectedString $rsaCipherText -Certificate $cert
        $Global:Error.Count | Should -Be 0
        $revealedSecret | Convert-CSecureStringToString | Should -Be $secret
    }

    It 'should handle invalid thumbprint' {
        $revealedSecret = Unprotect-CString -ProtectedString $rsaCipherText -Thumbprint ('1' * 40) -ErrorAction SilentlyContinue
        $Global:Error.Count | Should -BeGreaterThan 0
        $Global:Error[0] | Should -Match 'not found'
        $revealedSecret | Should -BeNullOrEmpty
    }

    It 'should handle path not found' {
        $revealedSecret = Unprotect-CString -ProtectedString $rsaCipherText -PrivateKeyPath 'C:\fubar.cer' -ErrorAction SilentlyContinue
        $Global:Error.Count | Should -BeGreaterThan 0
        $Global:Error[0] | Should -Match 'not found'
        $revealedSecret | Should -BeNullOrEmpty
    }
}
