
#Requires -Version 5.1
Set-StrictMode -Version 'Latest'

& (Join-Path -Path $PSScriptRoot -ChildPath 'Initialize-Test.ps1' -Resolve)

$publicKeyFilePath = Join-Path -Path $PSScriptRoot -ChildPath 'Resources\CarbonTestPublicKey.cer' -Resolve
$privateKeyFilePath = Join-Path -Path $PSScriptRoot -ChildPath 'Resources\CarbonTestPrivateKey.pfx' -Resolve
$dsaKeyPath = Join-Path -Path $PSScriptRoot -ChildPath 'Resources\CarbonTestDsaKey.cer' -Resolve
$unprotectStringPath = Join-Path -Path $PSScriptRoot -ChildPath 'Resources\Unprotect-String.ps1' -Resolve
$testUserCred = Get-TestUserCredential -Name 'CPtString'

Describe 'Protect-String' {

    BeforeEach {
        $Global:Error.Clear()
    }
        
    function Assert-IsBase64EncodedString($String)
    {
        $String | Should -Not -BeNullOrEmpty 'Didn''t encrypt cipher text.'
        { [Convert]::FromBase64String( $String ) } | Should -Not -Throw
    }
    
    if( (Test-TCOperatingSystem -IsWindows) )
    {
        It 'should protect string' {
            $cipherText = Protect-CString -String 'Hello World!' -ForUser
            Assert-IsBase64EncodedString( $cipherText )
        }
        
        It 'should protect string with scope' {
            $user = Protect-CString -String 'Hello World' -ForUser 
            $machine = Protect-CString -String 'Hello World' -ForComputer
            $machine | Should -Not -Be $user -Because 'encrypting at different scopes resulted in the same string'
        }
        
        It 'should protect strings in pipeline' {
            $secrets = @('Foo','Fizz','Buzz','Bar') | Protect-CString -ForUser
            $secrets.Length | Should -Be 4 -Because 'Didn''t encrypt all items in the pipeline.'
            foreach( $secret in $secrets )
            {
                Assert-IsBase64EncodedString $secret
            }
        }
        
        It 'should encrypt from cert store by thumbprint' {
            $cert = Get-ChildItem -Path cert:\* -Recurse |
                        Where-Object { $_ | Get-Member 'PublicKey' } |
                        Where-Object { $_.PublicKey.Key -is [Security.Cryptography.RSA] } |
                        Select-Object -First 1
            $cert | Should -Not -BeNullOrEmpty
            $secret = [Guid]::NewGuid().ToString().Substring(0,20)
            $expectedCipherText = Protect-CString -String $secret -Thumbprint $cert.Thumbprint
            $expectedCipherText | Should -Not -BeNullOrEmpty
        }

        It 'should encrypt from cert store by cert path' {
            $cert = Get-ChildItem -Path cert:\* -Recurse |
                        Where-Object { $_ | Get-Member 'PublicKey' } |
                        Where-Object { $_.PublicKey.Key -is [Security.Cryptography.RSA] } |
                        Select-Object -First 1
            $cert | Should -Not -BeNullOrEmpty
            $secret = [Guid]::NewGuid().ToString().Substring(0,20)
            $certPath = Join-Path -Path 'cert:\' -ChildPath (Split-Path -NoQualifier -Path $cert.PSPath)
            $expectedCipherText = Protect-CString -String $secret -PublicKeyPath $certPath
            $expectedCipherText | Should -Not -BeNullOrEmpty
        }
        
        It 'should handle path not found' {
            $ciphertext = Protect-CString -String 'fubar' -PublicKeyPath 'cert:\currentuser\fubar' -ErrorAction SilentlyContinue
            $Global:Error.Count | Should -BeGreaterThan 0
            $Global:Error[0] | Should -Match 'not found'
            $ciphertext | Should -BeNullOrEmpty
        }
    }

    It 'should encrypt with certificate' {
        $cert = Get-CCertificate -Path $publicKeyFilePath
        $cert | Should -Not -BeNullOrEmpty
        $secret = [Guid]::NewGuid().ToString()
        $ciphertext = Protect-CString -String $secret -Certificate $cert
        $ciphertext | Should -Not -BeNullOrEmpty
        $ciphertext | Should -Not -Be $secret
        $privateKey = Get-CCertificate -Path $privateKeyFilePath
        (Unprotect-CString -ProtectedString $ciphertext -Certificate $privateKey) |
            Convert-CSecureStringToString |
            Should -Be $secret
    }
    
    It 'should handle not getting an rsa certificate' {
        $cert = Get-CCertificate -Path $dsaKeyPath
        $cert | Should -Not -BeNullOrEmpty
        $secret = [Guid]::NewGuid().ToString()
        $ciphertext = Protect-CString -String $secret -Certificate $cert -ErrorAction SilentlyContinue
        $Global:Error.Count | Should -BeGreaterThan 0
        $Global:Error[0] | Should -Match 'not an RSA public key'
        $ciphertext | Should -BeNullOrEmpty
    }
    
    It 'should handle thumbprint not in store' {
       $ciphertext = Protect-CString -String 'fubar' -Thumbprint '1111111111111111111111111111111111111111' -ErrorAction SilentlyContinue
       $Global:Error.Count | Should -BeGreaterThan 0
       $Global:Error[0] | Should -Match 'not found'
       $ciphertext | Should -BeNullOrEmpty
    }
    
    It 'should encrypt from certificate file' {
        $cert = Get-CCertificate -Path $publicKeyFilePath
        $cert | Should -Not -BeNullOrEmpty
        $secret = [Guid]::NewGuid().ToString()
        $ciphertext = Protect-CString -String $secret -PublicKeyPath $publicKeyFilePath
        $ciphertext | Should -Not -BeNullOrEmpty
        $ciphertext | Should -Not -Be $secret
        $privateKey = Get-CCertificate -Path $privateKeyFilePath 
        (Unprotect-CString -ProtectedString $ciphertext -Certificate $privateKey) |
            Convert-CSecureStringToString |
            Should -Be $secret
    }
    
    It 'should encrypt a secure string' {
        $cert = Get-CCertificate -Path $publicKeyFilePath
        $cert | Should -Not -BeNullOrEmpty
        $password = 'waffles'
        $secret = New-Object -TypeName System.Security.SecureString
        $password.ToCharArray() | ForEach-Object { $secret.AppendChar($_) }

        $ciphertext = Protect-CString -String $secret -PublicKeyPath $publicKeyFilePath
        $ciphertext | Should -Not -BeNullOrEmpty
        $ciphertext | Should -Not -Be $secret
        $privateKey = Get-CCertificate -Path $privateKeyFilePath 
        $decryptedPassword = 
            Unprotect-CString -ProtectedString $ciphertext -Certificate $privateKey | Convert-CSecureStringToString
        $decryptedPassword | Should -Be $password
        $passwordBytes = [Text.Encoding]::Unicode.GetBytes($password)
        $decryptedBytes = [Text.Encoding]::Unicode.GetBytes($decryptedPassword)
        $decryptedBytes.Length | Should -Be $passwordBytes.Length
        $passwordBytes | ConvertTo-TCBase64 | Should -Be ($decryptedPassword | ConvertTo-TCBase64)
    }

    It 'should convert passed objects to string' {
        $cert = Get-CCertificate -Path $publicKeyFilePath
        $cert | Should -Not -BeNullOrEmpty
        $object = @{}
        $cipherText = Protect-CString -String $object -PublicKeyPath $publicKeyFilePath
        $cipherText | Should -Not -BeNullOrEmpty
        $cipherText | Should -Not -Be $object
        $privateKey = Get-CCertificate -Path $privateKeyFilePath
        Assert-IsBase64EncodedString( $cipherText )
        (Unprotect-CString -ProtectedString $cipherText -Certificate $privateKey) |
            Convert-CSecureStringToString |
            Should -Be $object.ToString()
    }

    It 'should encrypt from certificate file with relative path' {
        $cert = Get-CCertificate -Path $publicKeyFilePath
        $cert | Should -Not -BeNullOrEmpty
        $secret = [Guid]::NewGuid().ToString()
        $ciphertext = Protect-CString -String $secret -PublicKeyPath (Resolve-Path -Path $publicKeyFilePath -Relative)
        $ciphertext | Should -Not -BeNullOrEmpty
        $ciphertext | Should -Not -Be $secret
        $privateKey = Get-CCertificate -Path $privateKeyFilePath
        (Unprotect-CString -ProtectedString $ciphertext -Certificate $privateKey) |
            Convert-CSecureStringToString |
            Should -Be $secret
    }
    
    It 'should use direct encryption padding switch' {
        $secret = [Guid]::NewGuid().ToString()
        $ciphertext = Protect-CString -String $secret `
                                      -PublicKeyPath $publicKeyFilePath `
                                      -Padding ([Security.Cryptography.RSAEncryptionPadding]::Pkcs1)
        $ciphertext | Should -Not -BeNullOrEmpty
        $ciphertext | Should -Not -Be $secret
        $revealedSecret = Unprotect-CString -ProtectedString $ciphertext `
                                            -PrivateKeyPath $privateKeyFilePath `
                                            -Padding ([Security.Cryptography.RSAEncryptionPadding]::Pkcs1)
        $revealedSecret | Convert-CSecureStringToString | Should -Be $secret
    }

}

if( (Test-TCOperatingSystem -IsWindows) )
{
    Describe 'Protect-String.when protecting string as another user' {
        It 'should protect that string using DPAPI' {
            # special chars to make sure they get handled correctly
            $string = ' f u b a r '' " > ~!@#$%^&*()_+`-={}|:"<>?[]\;,./'
            $protectedString = Protect-CString -String $string -Credential $testUserCred
            $protectedString | Should -Not -BeNullOrEmpty "Failed to protect a string as user $($testUserCred.UserName)."

            $decrypedString = Invoke-TCPowerShell -ArgumentList @(
                                                    '-NonInteractive',
                                                    '-File',
                                                    $unprotectStringPath,
                                                    '-ProtectedString',
                                                    $protectedString
                                                ) `
                                                -Credential $testUserCred
            $decrypedString | Should -Be $string
        }
    }
}

foreach( $keySize in @( 128, 192, 256 ) )
{
    Describe ('Protect-String.when given a {0}-bit key' -f $keySize) {
        $Global:Error.Clear()
        # Generate a secret that is too long for asymmetric encryption
        $secret = [Guid]::NewGuid().ToString() * 20
        $guid = [Guid]::NewGuid()
        $passphrase = $guid.ToString().Substring(0,($keySize / 8))
        $keyBytes = [Text.Encoding]::UTF8.GetBytes($passphrase)
        $keySecureString = New-Object -TypeName 'Security.SecureString'
        foreach( $char in $passphrase.ToCharArray() )
        {
            $keySecureString.AppendChar($char)
        }

        foreach( $key in @( $keyBytes, $keySecureString) )
        {
            Context ('key as {0}' -f $key.GetType().FullName) {
                $ciphertext = Protect-CString -String $secret -Key $key
                It 'should return ciphertext' {
                    $ciphertext | Should -Not -BeNullOrEmpty
                    [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($ciphertext)) |
                        Should -Not -BeNullOrEmpty
                    $Global:Error.Count | Should -Be 0
                }

                It 'should encrypt ciphertext' {
                    $revealedSecret = Unprotect-CString -ProtectedString $ciphertext -Key $key
                    $revealedSecret | Convert-CSecureStringToString | Should -Be $secret
                }
            }
        }
    }
}

Describe 'Protect-String.when encryption fails' {
    # Anyone know how to get DPAPI or AES encryption to fail?
    Context 'RSA' {
        It 'should fail' {
            { 
                $Global:Error.Clear()
                # Definitely too big to be encrypted by RSA.
                $plainText = 'a' * 1000
                Protect-CString -String $plainText -PublicKeyPath $publicKeyFilePath -ErrorAction SilentlyContinue |
                    Should -BeNullOrEmpty
                # Different error message on different versions of .NET and different platforms
                #                              WinPS 5.1 | PS Core 7            | Linux        | macOS
                $Global:Error | Should -Match 'Bad Length|parameter is incorrect|data too large|message exceeds the maximum'
            } |
                Should -Not -Throw
        }
    }
}