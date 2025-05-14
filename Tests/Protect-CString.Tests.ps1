
#Requires -Version 5.1
Set-StrictMode -Version 'Latest'

BeforeAll {

    Set-StrictMode -Version 'Latest'

    & (Join-Path -Path $PSScriptRoot -ChildPath 'Initialize-Test.ps1' -Resolve)

    $script:publicKeyFilePath = Join-Path -Path $PSScriptRoot -ChildPath 'Certificates\ProtectCString.pem' -Resolve
    $script:publicKey = Get-CCertificate -Path $script:publicKeyFilePath
    $script:privateKeyFilePath =
        Join-Path -Path $PSScriptRoot -ChildPath 'Certificates\ProtectCStringUnprotected.pfx' -Resolve
    $script:privateKey = Get-CCertificate -Path $script:privateKeyFilePath
    # installed by init.ps1.
    $script:unprotectStringPath = Join-Path -Path $PSScriptRoot -ChildPath 'Resources\Unprotect-CString.ps1' -Resolve
    $script:testUserCred = Get-TestUserCredential -Name 'CPtString'
    $script:certsToUninstall = [Collections.ArrayList]::New()

    function Assert-IsBase64EncodedString($String)
    {
        $String | Should -Not -BeNullOrEmpty 'Didn''t encrypt cipher text.'
        { [Convert]::FromBase64String( $String ) } | Should -Not -Throw
    }

    function GivenCertificate
    {
        param(
            [Parameter(Mandatory, Position=0)]
            [String] $Path,
            [switch] $Installed,
            [String] $In
        )

        # macOS requires private keys be exportable.
        $exportableArg = @{}
        if ((Test-Path -Path 'variable:IsMacOS') -and $IsMacOS)
        {
            $cert = Get-CCertificate -Path $Path
            Write-Verbose "${Path}  HasPrivateKey $($cert.HasPrivateKey)" -Verbose
            if ($cert.HasPrivateKey)
            {
                $exportableArg['Exportable'] = $True
            }
        }

        $cert = Install-CCertificate -Path $Path -StoreLocation CurrentUser -StoreName $In -PassThru @exportableArg
        [void]$script:certsToUninstall.Add($cert)
        return $cert
    }
}

Describe 'Protect-CString' {
    BeforeEach {
        $script:certsToUninstall.Clear()
        $Global:Error.Clear()
    }

    AfterEach {
        foreach ($cert in $script:certsToUninstall)
        {
            Uninstall-CCertificate -Thumbprint $cert.Thumbprint `
                                   -StoreLocation $cert.StoreLocation `
                                   -StoreName $cert.StoreName
        }
    }

    $isNotOnWindows = (Test-Path -Path 'variable:IsWindows') -and -not $IsWindows

    Context 'DPAPI' -Skip:$isNotOnWindows {
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

        It 'handles all printable characters' {
            # special chars to make sure they get handled correctly
            $string = ' f u b a r '' " > ~!@#$%^&*()_+`-={}|:"<>?[]\;,./'
            $protectedString = Protect-CString -String $string -Credential $script:testUserCred
            $protectedString |
                Should -Not -BeNullOrEmpty "Failed to protect a string as user $($script:testUserCred.UserName)."

            $decrypedString = Invoke-TCPowerShell -ArgumentList @(
                                                    '-NonInteractive',
                                                    '-File',
                                                    $script:unprotectStringPath,
                                                    '-ProtectedString',
                                                    $protectedString
                                                ) `
                                                -Credential $script:testUserCred
            $decrypedString | Should -Be $string
        }
    }

    It 'encrypts from cert store by thumbprint' {
        GivenCertificate $script:publicKeyFilePath -Installed -In My
        $secret = [Guid]::NewGuid().ToString().Substring(0,20)
        $expectedCipherText = Protect-CString -String $secret -Thumbprint $script:publicKey.Thumbprint
        $expectedCipherText | Should -Not -BeNullOrEmpty
    }

    Context 'Certificate Provider' -Skip:$isNotOnWindows {
        It 'encrypts from cert store by cert path' {
            GivenCertificate $script:publicKeyFilePath -Installed -In My
            $certPath = Join-Path -Path 'Cert:\CurrentUser\My' -ChildPath $script:publicKey.Thumbprint
            $secret = [Guid]::NewGuid().ToString().Substring(0,20)
            $expectedCipherText = Protect-CString -String $secret -PublicKeyPath $certPath
            $expectedCipherText | Should -Not -BeNullOrEmpty
        }

        It 'should handle path not found' {
            $ciphertext = Protect-CString -String 'fubar' `
                                          -PublicKeyPath 'cert:\currentuser\fubar' `
                                          -ErrorAction SilentlyContinue
            $Global:Error.Count | Should -BeGreaterThan 0
            $Global:Error[0] | Should -Match 'not found'
            $ciphertext | Should -BeNullOrEmpty
        }
    }

    It 'should encrypt with certificate' {
        $secret = [Guid]::NewGuid().ToString()
        $ciphertext = Protect-CString -String $secret -Certificate $script:publicKey
        $ciphertext | Should -Not -BeNullOrEmpty
        $ciphertext | Should -Not -Be $secret
        (Unprotect-CString -ProtectedString $ciphertext -Certificate $script:privateKey) |
            Convert-CSecureStringToString |
            Should -Be $secret
    }

    It 'should handle not getting an rsa certificate' {
        $dsaKeyPath = Join-Path -Path $PSScriptRoot -ChildPath 'Resources\CarbonTestDsaKey.cer' -Resolve
        $cert = Get-CCertificate -Path $dsaKeyPath
        $cert | Should -Not -BeNullOrEmpty
        $secret = [Guid]::NewGuid().ToString()
        $ciphertext = Protect-CString -String $secret -Certificate $cert -ErrorAction SilentlyContinue
        $Global:Error.Count | Should -BeGreaterThan 0
        $Global:Error[0] | Should -Match 'not an RSA public key'
        $ciphertext | Should -BeNullOrEmpty
    }

    It 'should handle thumbprint not in store' {
       $ciphertext = Protect-CString -String 'fubar' `
                                     -Thumbprint '1111111111111111111111111111111111111111' `
                                     -ErrorAction SilentlyContinue
       $Global:Error.Count | Should -BeGreaterThan 0
       $Global:Error[0] | Should -Match 'not found'
       $ciphertext | Should -BeNullOrEmpty
    }

    It 'should encrypt from certificate file' {
        $secret = [Guid]::NewGuid().ToString()
        $ciphertext = Protect-CString -String $secret -PublicKeyPath $script:publicKeyFilePath
        $ciphertext | Should -Not -BeNullOrEmpty
        $ciphertext | Should -Not -Be $secret
        (Unprotect-CString -ProtectedString $ciphertext -Certificate $script:privateKey) |
            Convert-CSecureStringToString |
            Should -Be $secret
    }

    It 'should encrypt a secure string' {
        $password = 'waffles'
        $secret = New-Object -TypeName System.Security.SecureString
        $password.ToCharArray() | ForEach-Object { $secret.AppendChar($_) }

        $ciphertext = Protect-CString -String $secret -Certificate $script:publicKey
        $ciphertext | Should -Not -BeNullOrEmpty
        $ciphertext | Should -Not -Be $secret
        $decryptedPassword =
            Unprotect-CString -ProtectedString $ciphertext -Certificate $script:privateKey | Convert-CSecureStringToString
        $decryptedPassword | Should -Be $password
        $passwordBytes = [Text.Encoding]::Unicode.GetBytes($password)
        $decryptedBytes = [Text.Encoding]::Unicode.GetBytes($decryptedPassword)
        $decryptedBytes.Length | Should -Be $passwordBytes.Length
        $passwordBytes | ConvertTo-TCBase64 | Should -Be ($decryptedPassword | ConvertTo-TCBase64)
    }

    It 'should convert passed objects to string' {
        $object = @{}
        $cipherText = Protect-CString -String $object -Certificate $script:publicKey
        $cipherText | Should -Not -BeNullOrEmpty
        $cipherText | Should -Not -Be $object
        Assert-IsBase64EncodedString( $cipherText )
        (Unprotect-CString -ProtectedString $cipherText -Certificate $script:privateKey) |
            Convert-CSecureStringToString |
            Should -Be $object.ToString()
    }

    It 'should encrypt from certificate file with relative path' {
        $secret = [Guid]::NewGuid().ToString()
        $ciphertext =
            Protect-CString -String $secret -PublicKeyPath (Resolve-Path -Path $script:publicKeyFilePath -Relative)
        $ciphertext | Should -Not -BeNullOrEmpty
        $ciphertext | Should -Not -Be $secret
        (Unprotect-CString -ProtectedString $ciphertext -Certificate $script:privateKey) |
            Convert-CSecureStringToString |
            Should -Be $secret
    }

    It 'should use direct encryption padding switch' {
        $secret = [Guid]::NewGuid().ToString()
        $ciphertext = Protect-CString -String $secret `
                                      -Certificate $script:publicKey `
                                      -Padding ([Security.Cryptography.RSAEncryptionPadding]::Pkcs1)
        $ciphertext | Should -Not -BeNullOrEmpty
        $ciphertext | Should -Not -Be $secret
        $revealedSecret = Unprotect-CString -ProtectedString $ciphertext `
                                            -Certificate $script:privateKey `
                                            -Padding ([Security.Cryptography.RSAEncryptionPadding]::Pkcs1)
        $revealedSecret | Convert-CSecureStringToString | Should -Be $secret
    }

    $keySizes = @( 128, 192, 256 )
    Context '<_>-bit key' -ForEach $keySizes {
        $keySize = $_

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

        $keys = @(
            @{ KeyType = $keyBytes.GetType().FullName; Key = $keyBytes; KeySize = $keySize; Secret = $secret; }
            @{
                KeyType = $keySecureString.GetType().FullName;
                Key = $keySecureString;
                KeySize = $keySize;
                Secret = $secret;
            }
        )

        Context '<KeyType> key' -ForEach $keys {
            It 'encrypts' {
                $ciphertext = Protect-CString -String $secret -Key $key
                $ciphertext | Should -Not -BeNullOrEmpty
                [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($ciphertext)) |
                    Should -Not -BeNullOrEmpty
                $Global:Error.Count | Should -Be 0
            }

            It 'decrypts' {
                $ciphertext = Protect-CString -String $secret -Key $key
                $revealedSecret = Unprotect-CString -ProtectedString $ciphertext -Key $key
                $revealedSecret | Convert-CSecureStringToString | Should -Be $secret
            }

        }
    }

    # Anyone know how to get DPAPI or AES encryption to fail?
    Context 'RSA' {
        Context 'when encryption fails' {
            It 'does not throw terminating exception' {
                {
                    $Global:Error.Clear()
                    # Definitely too big to be encrypted by RSA.
                    $plainText = 'a' * 1000
                    Protect-CString -String $plainText -Certificate $script:publicKey -ErrorAction SilentlyContinue |
                        Should -BeNullOrEmpty
                    # Different error message on different versions of .NET and different platforms
                    #         WinPS 5.1 | Win PS Core 7                      | Linux        | macOS                     | macOS
                    $regex = 'Bad Length|parameter is incorrect|Unknown error|data too large|message exceeds the maximum|wrong input size'
                    $Global:Error | Should -Match $regex
                } |
                    Should -Not -Throw
            }
        }
    }
}
