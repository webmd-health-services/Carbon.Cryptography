
#Requires -Version 5.1
Set-StrictMode -Version 'Latest'

BeforeAll {
    Set-StrictMode -Version 'Latest'

    & (Join-Path -Path $PSScriptRoot 'Initialize-Test.ps1' -Resolve)

    $script:originalText = $null
    $script:secret = [Guid]::NewGuid().ToString()
    $script:rsaCipherText = $null
    $script:publicKeyPath = Join-Path -Path $PSScriptRoot -ChildPath 'Resources\CarbonTestPublicKey.cer' -Resolve
    $script:privateKeyPath = Join-Path -Path $PSScriptRoot -ChildPath 'Resources\CarbonTestPrivateKey.pfx' -Resolve
    $script:publicKey2Path = Join-Path -Path $PSScriptRoot -ChildPath 'Resources\CarbonTestPublicKey2.cer' -Resolve
    $script:privateKey2Path = Join-Path -Path $PSScriptRoot -ChildPath 'Resources\CarbonTestPrivateKey2.pfx' -Resolve

    $script:rsaCipherText = Protect-CString -String $script:secret -PublicKeyPath $script:privateKeyPath

    $script:certsToUninstall = [Collections.ArrayList]::New()

    function GivenCertificate
    {
        param(
            [Parameter(Mandatory, Position=0)]
            [String] $Path,
            [switch] $Installed,
            [String] $For,
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

        $cert = Install-CCertificate -Path $Path -StoreLocation $For -StoreName $In -PassThru @exportableArg
        [void]$script:certsToUninstall.Add($cert)
        return $cert
    }
}

Describe 'Unprotect-CString' {
    BeforeEach {
        $Global:Error.Clear()
        $script:certsToUninstall.Clear()
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
        It 'should unprotect string' {
            $script:originalText = [Guid]::NewGuid().ToString()
            $protectedText = Protect-CString -String $script:originalText -ForUser
            $actualText = Unprotect-CString -ProtectedString $protectedText
            $actualText | Convert-CSecureStringToString | Should -Be $script:originalText
        }

        It 'should unprotect string from machine scope' {
            $ciphertext = Protect-CString -String 'Hello World' -ForComputer
            $machine = Unprotect-CString -ProtectedString $ciphertext
            $machine | Convert-CSecureStringToString | Should -Be 'Hello World'
        }

        It 'should unprotect string from user scope' {
            $ciphertext = Protect-CString -String 'Hello World' -ForUser
            $machine = Unprotect-CString -ProtectedString $ciphertext
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
            $script:originalText = [Guid]::NewGuid().ToString()
            $protectedText = Protect-CString -String $script:originalText -ForUser
            $plainText = Unprotect-CString -ProtectedString $protectedText -AsPlainText
            $plainText | Should -BeOfType ([String])
            $plainText | Should -Be $script:originalText
        }

        It 'does not throw terminating exception' {
            {
                $Global:Error.Clear()
                Unprotect-CString -ProtectedString 'not encrypted' -ErrorAction SilentlyContinue |
                    Should -BeNullOrEmpty
                $Global:Error | Should -Match 'parameter is incorrect'
            } |
                Should -Not -Throw
        }
    }

    It 'should handle thumbprint to cert with no private key' {
        $cert = GivenCertificate $script:publicKeyPath -Installed -For CurrentUser -In My
        $cert | Should -Not -BeNullOrEmpty
        $revealedSecret = Unprotect-CString -ProtectedString $script:rsaCipherText `
                                            -Thumbprint $cert.Thumbprint `
                                            -ErrorAction SilentlyContinue `
                                            -WarningAction SilentlyContinue
        $Global:Error.Count | Should -BeGreaterThan 0
        $Global:Error[0] | Should -Match 'doesn''t have a private key'
        $revealedSecret | Should -BeNullOrEmpty
    }

    Context 'Cerificate Provider' -Skip:$isNotOnWindows {
        It 'should decrypt with path to cert in store' {
            $cert = GivenCertificate $script:privateKeyPath -Installed -For CurrentUser -In My
            $certStorePath = Join-Path -Path 'cert:\CurrentUser\My' -ChildPath $cert.Thumbprint
            $revealedSecret = Unprotect-CString -ProtectedString $script:rsaCipherText -PrivateKeyPath $certStorePath
            $Global:Error.Count | Should -Be 0
            $revealedSecret | Convert-CSecureStringToString | Should -Be $script:secret
        }
    }

    It 'should decrypt with thumbprint' {
        $cert = GivenCertificate $script:privateKeyPath -Installed -For CurrentUser -In My
        $revealedSecret = Unprotect-CString -ProtectedString $script:rsaCipherText -Thumbprint $cert.Thumbprint
        $Global:Error.Count | Should -Be 0
        $revealedSecret | Convert-CSecureStringToString | Should -Be $script:secret
    }

    It 'should handle when cert is installed multiple times with private key' {
        $cert = GivenCertificate $script:privateKeyPath -Installed -For CurrentUser -In My
        $null = GivenCertificate $script:privateKeyPath -Installed -For CurrentUser -In CertificateAuthority

        $revealedSecret = Unprotect-CString -ProtectedString $script:rsaCipherText `
                                            -Thumbprint $cert.Thumbprint `
                                            -WarningVariable 'warnings' `
                                            -WarningAction SilentlyContinue
        $Global:Error.Count | Should -Be 0
        $revealedSecret | Convert-CSecureStringToString | Should -Be $script:secret
        $warnings | Should -Match '^Found 2 certificates'
    }

    It 'should handle when cert is installed multiple times, once without the private key' {
        $cert = GivenCertificate $script:privateKeyPath -Installed -For CurrentUser -In My
        $null = GivenCertificate $script:publicKeyPath -Installed -For CurrentUser -In CertificateAuthority

        $revealedSecret = Unprotect-CString -ProtectedString $script:rsaCipherText -Thumbprint $cert.Thumbprint -WarningVariable 'warnings'
        $Global:Error.Count | Should -Be 0
        $revealedSecret | Convert-CSecureStringToString | Should -Be $script:secret
        $warnings | Should -BeNullOrEmpty
    }

    It 'should handle when cert is installed multiple times, all without the private key' {
        $cert = GivenCertificate $script:publicKeyPath -Installed -For CurrentUser -In My
        $null = GivenCertificate $script:publicKeyPath -Installed -For CurrentUser -In CertificateAuthority

        $revealedSecret = Unprotect-CString -ProtectedString $script:rsaCipherText -Thumbprint $cert.Thumbprint -ErrorAction SilentlyContinue
        $Global:Error.Count | Should -BeGreaterThan 0
        $Global:Error[0] | Should -Match '^Found 2 certificates .+ but none of them contain a private key or the private key is null'
        $revealedSecret | Should -BeNullOrEmpty
    }

    It 'should load certificate from file' {
        $revealedSecret =
            Unprotect-CString -ProtectedString $script:rsaCipherText -PrivateKeyPath $script:privateKeyPath
        $Global:Error.Count | Should -Be 0
        $revealedSecret | Convert-CSecureStringToString | Should -Be $script:secret
    }

    It 'should handle missing private key' {
        $revealedSecret = Unprotect-CString -ProtectedString $script:rsaCipherText -PrivateKeyPath $script:publicKeyPath -ErrorAction SilentlyContinue
        $Global:Error.Count | Should -BeGreaterThan 0
        $Global:Error[0] | Should -Match 'doesn''t have a private key'
        $revealedSecret | Convert-CSecureStringToString | Should -BeNullOrEmpty
    }

    It 'should load password protected private key' {
        $cipherText = Protect-CString -String $script:secret -PublicKeyPath $script:publicKey2Path
        $revealedText = Unprotect-CString -ProtectedString $cipherText `
                                          -PrivateKeyPath $script:privateKey2Path `
                                          -Password (ConvertTo-SecureString -String 'fubar' -AsPlainText -Force)
        $Global:Error.Count | Should -Be 0
        $revealedText | Convert-CSecureStringToString | Should -Be $script:secret
    }

    It 'should decrypt with certificate' {
        $cert = Get-CCertificate -Path $script:privateKeyPath
        $revealedSecret = Unprotect-CString -ProtectedString $script:rsaCipherText -Certificate $cert
        $Global:Error.Count | Should -Be 0
        $revealedSecret | Convert-CSecureStringToString | Should -Be $script:secret
    }

    It 'should handle invalid thumbprint' {
        $revealedSecret = Unprotect-CString -ProtectedString $script:rsaCipherText -Thumbprint ('1' * 40) `
                                            -ErrorAction SilentlyContinue
        $Global:Error.Count | Should -BeGreaterThan 0
        $Global:Error[0] | Should -Match 'failed to find'
        $revealedSecret | Should -BeNullOrEmpty
    }

    It 'should handle path not found' {
        $revealedSecret = Unprotect-CString -ProtectedString $script:rsaCipherText -PrivateKeyPath 'C:\fubar.cer' -ErrorAction SilentlyContinue
        $Global:Error.Count | Should -BeGreaterThan 0
        $Global:Error[0] | Should -Match 'not found'
        $revealedSecret | Should -BeNullOrEmpty
    }

    Context 'AES' {
        It 'should fail on invalid key length' {
            $key = ConvertTo-SecureString ('a' * 8) -AsPlainText -Force
            { Protect-CString -String 'text' -Key $key -ErrorAction Stop } |
                Should -Throw '*requires a 128-bit, 192-bit, or 256-bit key (16, 24, or 32 bytes, respectively)*'
        }

        $keyLengths = @(16, 24, 32)
        It "supports <_>-byte key" -ForEach $keyLengths {
            $keyLength = $_
            $key = ConvertTo-SecureString ('a' * $keyLength) -AsPlainText -Force
            $script:originalText = [Guid]::NewGuid().ToString()
            $protectedText = Protect-CString -String $script:originalText -Key $key
            $actualText = Unprotect-CString -ProtectedString $protectedText -Key $key -AsPlainText
            $actualText | Should -Be $script:originalText -Because 'the decrypted string should be unchanged'
            $actualText.Length | Should -Be $script:originalText.Length -Because 'the decrypted string should not contain any extra bytes'
        }

        It 'does not throw terminating exception' {
            {
                $Global:Error.Clear()
                $key = 'passwordpasswordpasswordpassword'
                $fakeCipherText =
                    "$('iv' * 8)not encrypted)" | ConvertTo-TCBase64 -Encoding ([Text.Encoding]::UTF8)
                Unprotect-CString -ProtectedString $fakeCipherText `
                                -Key (ConvertTo-SecureString $key -AsPlainText -Force) `
                                -ErrorAction SilentlyContinue |
                    Should -BeNullOrEmpty
                $Global:Error | Should -Match 'input data is not a complete block' #head
            } |
                Should -Not -Throw
        }
    }

    Context 'when user does not have access to private key' {
        It 'fails' {
            $cert = Get-CCertificate -Path $script:privateKeyPath
            $cert | Add-member -MemberType NoteProperty -Name 'PrivateKey' -Value $null -Force
            $cert | Add-Member -MemberType NoteProperty -Name 'HasPrivateKey' -Value $true -Force

            { Unprotect-CString -ProtectedString 'doesn''t matter' -Certificate $cert -ErrorAction Stop } |
                Should -Throw '*has a private key, but it is null*'
        }
    }

    Context 'RSA' {
        It 'does not throw a terminating exception' {
            {
                $Global:Error.Clear()
                Unprotect-CString -ProtectedString 'not encrypted' `
                                -PrivateKeyPath $script:privateKeyPath `
                                -ErrorAction SilentlyContinue |
                    Should -BeNullOrEmpty
                # Different error message on different versions of .NET.
                $Global:Error | Should -Match 'decoding OAEP padding|length of the data to decrypt'
            } |
                Should -Not -Throw
        }
    }
}
