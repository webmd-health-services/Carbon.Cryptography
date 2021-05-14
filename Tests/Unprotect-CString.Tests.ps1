
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

function Reset
{
    # Uninstall-CCertificate only works on Windows
    if( -not (Test-COperatingSystem -IsWindows) )
    {
        return
    }

    # Uninstall the test certs from all locations and stores
    $certsToUninstall = @($publicKeyPath, $publicKey2Path)
    foreach ($cert in $certsToUninstall)
    {
        $thumbprint = Get-CCertificate -Path $cert | Select-Object -ExpandProperty 'Thumbprint'
        $storeLocations = [enum]::GetValues([System.Security.Cryptography.X509Certificates.StoreLocation])

        foreach ($location in $storeLocations)
        {
            $storeNames = [enum]::GetValues([System.Security.Cryptography.X509Certificates.StoreName])

            foreach ($name in $storeNames)
            {
                Uninstall-CCertificate -Thumbprint $thumbprint -StoreLocation $location -StoreName $name
            }
        }
    }
}

Describe 'Unprotect-CString' {
    BeforeEach {
        $Global:Error.Clear()
    }

    AfterEach {
        Reset
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

        It 'should convert to plain text' {
            $originalText = [Guid]::NewGuid().ToString()
            $protectedText = Protect-CString -String $originalText -ForUser
            $plainText = Unprotect-CString -ProtectedString $protectedText -AsPlainText
            $plainText | Should -BeOfType ([String])
            $plainText | Should -Be $originalText
        }

        It 'should handle thumbprint to cert with no private key' {
            $cert = Install-CCertificate -Path $publicKeyPath -StoreLocation CurrentUser -StoreName My -PassThru
            $cert | Should -Not -BeNullOrEmpty
            $revealedSecret = Unprotect-CString -ProtectedString $rsaCipherText `
                                                -Thumbprint $cert.Thumbprint `
                                                -ErrorAction SilentlyContinue `
                                                -WarningAction SilentlyContinue
            $Global:Error.Count | Should -BeGreaterThan 0
            $Global:Error[0] | Should -Match 'doesn''t have a private key'
            $revealedSecret | Should -BeNullOrEmpty
        }

        It 'should decrypt with path to cert in store' {
            $cert = Install-CCertificate -Path $privateKeyPath -StoreLocation CurrentUser -StoreName My -PassThru
            $revealedSecret = Unprotect-CString -ProtectedString $rsaCipherText -PrivateKeyPath ('cert:\CurrentUser\My\{0}' -f $cert.Thumbprint)
            $Global:Error.Count | Should -Be 0
            $revealedSecret | Convert-CSecureStringToString | Should -Be $secret
        }

        It 'should decrypt with thumbprint' {
            $cert = Install-CCertificate -Path $privateKeyPath -StoreLocation CurrentUser -StoreName My -PassThru
            $revealedSecret = Unprotect-CString -ProtectedString $rsaCipherText -Thumbprint $cert.Thumbprint
            $Global:Error.Count | Should -Be 0
            $revealedSecret | Convert-CSecureStringToString | Should -Be $secret
        }

        It 'should handle when cert is installed multiple times with private key' {
            $cert = Install-CCertificate -Path $privateKeyPath -StoreLocation CurrentUser -StoreName My -PassThru
            $null = Install-CCertificate -Path $privateKeyPath -StoreLocation CurrentUser -StoreName CertificateAuthority

            $revealedSecret = Unprotect-CString -ProtectedString $rsaCipherText `
                                                -Thumbprint $cert.Thumbprint `
                                                -WarningVariable 'warnings' `
                                                -WarningAction SilentlyContinue
            $Global:Error.Count | Should -Be 0
            $revealedSecret | Convert-CSecureStringToString | Should -Be $secret
            $warnings | Should -Match '^Found 2 certificates'
        }

        It 'should handle when cert is installed multiple times, once without the private key' {
            $cert = Install-CCertificate -Path $privateKeyPath -StoreLocation CurrentUser -StoreName My -PassThru
            $null = Install-CCertificate -Path $publicKeyPath -StoreLocation CurrentUser -StoreName CertificateAuthority

            $revealedSecret = Unprotect-CString -ProtectedString $rsaCipherText -Thumbprint $cert.Thumbprint -WarningVariable 'warnings'
            $Global:Error.Count | Should -Be 0
            $revealedSecret | Convert-CSecureStringToString | Should -Be $secret
            $warnings | Should -BeNullOrEmpty
        }

        It 'should handle when cert is installed multiple times, all without the private key' {
            $cert = Install-CCertificate -Path $publicKeyPath -StoreLocation CurrentUser -StoreName My -PassThru
            $null = Install-CCertificate -Path $publicKeyPath -StoreLocation CurrentUser -StoreName CertificateAuthority

            $revealedSecret = Unprotect-CString -ProtectedString $rsaCipherText -Thumbprint $cert.Thumbprint -ErrorAction SilentlyContinue
            $Global:Error.Count | Should -BeGreaterThan 0
            $Global:Error[0] | Should -Match '^Found 2 certificates at ".+" but none of them contain a private key or the private key is null'
            $revealedSecret | Should -BeNullOrEmpty
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

Describe 'Unprotect-String.AES' {
    It 'should fail on invalid key length' {
        $key = ConvertTo-SecureString ('a' * 8) -AsPlainText -Force
        { Protect-CString -String 'text' -Key $key -ErrorAction Stop } |
            Should -Throw 'requires a 128-bit, 192-bit, or 256-bit key (16, 24, or 32 bytes, respectively).'
    }

    foreach ($keyLength in @(16, 24, 32))
    {
        It "should succeed with key length: $($keyLength)" {
            $key = ConvertTo-SecureString ('a' * $keyLength) -AsPlainText -Force
            $originalText = [Guid]::NewGuid().ToString()
            $protectedText = Protect-CString -String $originalText -Key $key
            $actualText = Unprotect-CString -ProtectedString $protectedText -Key $key -AsPlainText
            $actualText | Should -Be $originalText -Because 'the decrypted string should be unchanged'
            $actualText.Length | Should -Be $originalText.Length -Because 'the decrypted string should not contain any extra bytes'
        }
    }
}

Describe 'Unprotect-CString.when user does not have access to private key' {
    It 'should fail' {
        $cert = Get-CCertificate -Path $privateKeyPath
        $cert | Add-member -MemberType NoteProperty -Name 'PrivateKey' -Value $null -Force
        $cert | Add-Member -MemberType NoteProperty -Name 'HasPrivateKey' -Value $true -Force

        { Unprotect-CString -ProtectedString 'doesn''t matter' -Certificate $cert -ErrorAction Stop } |
            Should -Throw 'has a private key, but it is null'
    }
}

Describe 'Unprotect-CString.when decryption fails' {
    if( (Test-COperatingSystem -IsWindows) )
    {
        Context 'DPAPI' {
            It 'should fail' {
                {
                    $Global:Error.Clear()
                    Unprotect-CString -ProtectedString 'not encrypted' -ErrorAction SilentlyContinue |
                        Should -BeNullOrEmpty
                    $Global:Error | Should -Match 'parameter is incorrect'
                } |
                    Should -Not -Throw
            }
        }
    }
    Context 'RSA' {
        It 'should fail' {
            {
                $Global:Error.Clear()
                Unprotect-CString -ProtectedString 'not encrypted' `
                                  -PrivateKeyPath $privateKeyPath `
                                  -ErrorAction SilentlyContinue |
                    Should -BeNullOrEmpty
                # Different error message on different versions of .NET.
                $Global:Error | Should -Match 'decoding OAEP padding|length of the data to decrypt'
            } |
                Should -Not -Throw
        }
    }
    Context 'AES' {
        It 'should fail' {
            {
                $Global:Error.Clear()
                $key = 'passwordpasswordpasswordpassword'
                $fakeCipherText =
                    "$('iv' * 8)not encrypted)" | ConvertTo-CBase64 -Encoding ([Text.Encoding]::UTF8)
                Unprotect-CString -ProtectedString $fakeCipherText `
                                  -Key (ConvertTo-SecureString $key -AsPlainText -Force) `
                                  -ErrorAction SilentlyContinue |
                    Should -BeNullOrEmpty
                $Global:Error | Should -Match 'input data is not a complete block' #head
            } |
                Should -Not -Throw
        }
    }
}