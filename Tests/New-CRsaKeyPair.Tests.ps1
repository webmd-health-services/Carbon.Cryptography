# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

Set-StrictMode -Version 'Latest'

BeforeAll {
    & (Join-Path -Path $PSScriptRoot -ChildPath 'Initialize-Test.ps1' -Resolve)

    $script:testDir = $null
    $script:testNum = 0
    $script:privateKeyPassword = ConvertTo-SecureString -String 'fubarsnafu' -AsPlainText -Force
    $script:subject = $null
    $script:publicKeyPath = $null
    $script:privateKeyPath = $null

    function Assert-KeyProperty
    {
        param(
            $Length = 4096,
            [datetime]
            $ValidTo,
            $Algorithm = 'sha512RSA'
        )

        Set-StrictMode -Version 'Latest'

        if( -not $ValidTo )
        {
            $ValidTo = (Get-Date).AddDays( [Math]::Floor(([DateTime]::MaxValue - [DateTime]::UtcNow).TotalDays) )
        }

        $cert = Get-CCertificate -Path $script:publicKeyPath
        # Weird date/time stamps in generated certificate that I can't figure out/replicate. So we'll just check that
        # the expected/actual dates are within a day of each other.
        [timespan]$span = $ValidTo - $cert.NotAfter
        $span.TotalDays | Should -BeGreaterThan (-2)
        $span.TotalDays | Should -BeLessThan 2
        $cert.Subject | Should -Be $script:subject
        $cert.PublicKey.Key.KeySize | Should -Be $Length
        $cert.PublicKey.Key.KeyExchangeAlgorithm | Should -BeLike 'RSA*'
        $cert.SignatureAlgorithm.FriendlyName | Should -Be $Algorithm
        $keyUsage = $cert.Extensions | Where-Object { $_ -is [Security.Cryptography.X509Certificates.X509KeyUsageExtension] }
        $keyUsage | Should -Not -BeNullOrEmpty
        $keyUsage.KeyUsages.HasFlag([Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DataEncipherment) |
            Should -BeTrue
        $keyUsage.KeyUsages.HasFlag([Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyEncipherment) |
            Should -BeTrue
        $enhancedKeyUsage =
            $cert.Extensions |
            Where-Object { $_ -is [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension] }
        $enhancedKeyUsage | Should -Not -BeNullOrEmpty

        # I don't think Windows 2008 supports Enhanced Key Usages.
        $osVersion = (Get-WmiObject -Class 'Win32_OperatingSystem').Version
        if( $osVersion -notmatch '6.1\b' )
        {
            $usage = $enhancedKeyUsage.EnhancedKeyUsages | Where-Object { $_.FriendlyName -eq 'Document Encryption' }
            $usage | Should -Not -BeNullOrEmpty
        }
    }
}

Describe 'New-RsaKeyPair' {
    BeforeEach {
        $script:testDir = Join-Path -Path $TestDrive -ChildPath ($script:testNum++)
        $Global:Error.Clear()

        $script:subject = 'CN={0}' -f [Guid]::NewGuid()
        $script:publicKeyPath = Join-Path -Path $script:testDir -ChildPath 'public.cer'
        $script:privateKeyPath = Join-Path -Path $script:testDir -ChildPath 'private.pfx'
    }

    It 'should generate a public/private key pair' {
        $output = New-CRsaKeyPair -Subject $script:subject `
                                  -PublicKeyFile $script:publicKeyPath `
                                  -PrivateKeyFile $script:privateKeyPath `
                                  -Password $script:privateKeyPassword
        $output | Should -Not -BeNullOrEmpty
        $output.Count | Should -Be 2

        $script:publicKeyPath | Should -Exist
        $output[0].FullName | Should -Be $script:publicKeyPath

        $script:privateKeyPath | Should -Exist
        $output[1].FullName | Should -Be $script:privateKeyPath

        Assert-KeyProperty
    }

    It 'should generate a key usable by DSC' -Skip:($PSVersionTable['PSEdition'] -eq 'Core') {
        $output = New-CRsaKeyPair -Subject $script:subject `
                                  -PublicKeyFile $script:publicKeyPath `
                                  -PrivateKeyFile $script:privateKeyPath `
                                  -Password $script:privateKeyPassword
        # Make sure we can decrypt things with it.
        $secret = [IO.Path]::GetRandomFileName()
        $protectedSecret = Protect-CString -String $secret -Certificate $script:publicKeyPath
        $decryptedSecret = Unprotect-CString -ProtectedString $protectedSecret `
                                             -PrivateKeyPath $script:privateKeyPath `
                                             -Password $script:privateKeyPassword `
                                             -AsPlainText

        $decryptedSecret | Should -Be $secret

        $publicKey = Get-CCertificate -Path $script:publicKeyPath
        $publicKey | Should -Not -BeNullOrEmpty

        # Make sure it works with DSC
        $configData = @{
            AllNodes = @(
                @{
                    NodeName = 'localhost';
                    CertificateFile = $script:publicKeyPath;
                    Thumbprint = $publicKey.Thumbprint;
                }
            )
        }

        configuration TestEncryption
        {
            Set-StrictMode -Off

            node $AllNodes.NodeName
            {
                User 'CreateDummyUser'
                {
                    UserName = 'fubarsnafu';
                    Password =
                        ([pscredential]::New('fubarsnafu', (ConvertTo-SecureString 'Password1' -AsPlainText -Force)))
                }
            }
        }

        & TestEncryption -ConfigurationData $configData -OutputPath $script:testDir

        # DSC will silently write errors if this key doesn't exist even though no functionality is impacted by the
        # missing key.
        $dscRegKey = 'HKLM:\SOFTWARE\Microsoft\PowerShell\3\DSC'
        $dscRegKeyErrorMessages =
            $Global:Error |
            Where-Object { $_ -is [System.Management.Automation.ErrorRecord] } |
            Where-Object { $_.Exception.Message -like ('*Cannot find path ''{0}''*' -f $dscRegKey) }

        foreach ($error in $dscRegKeyErrorMessages)
        {
            $Global:Error.Remove($error)
        }

        $Global:Error.Count | Should -Be 0
        $mofPath = Join-Path -Path $script:testDir -ChildPath 'localhost.mof'
        Get-Content -Path $mofPath -Raw | Write-Debug
        $mofPath | Should -Not -Contain 'Password1'
    }

    It 'should generate key pairs that can be used by CMS cmdlets' `
       -Skip:(-not (Get-Command -Name 'Protect-CmsMessage' -ErrorAction Ignore)) {
        $output = New-CRsaKeyPair -Subject $script:subject `
                                  -PublicKeyFile $script:publicKeyPath `
                                  -PrivateKeyFile $script:privateKeyPath `
                                  -Password $script:privateKeyPassword

        $cert = Install-CCertificate -Path $script:privateKeyPath `
                                     -StoreLocation CurrentUser `
                                     -StoreName My `
                                     -Password $script:privateKeyPassword `
                                     -PassThru

        try
        {
            $message = 'fubarsnafu'
            $protectedMessage = Protect-CmsMessage -To $script:publicKeyPath -Content $message
            Unprotect-CmsMessage -Content $protectedMessage | Should -Be $message
        }
        finally
        {
            Uninstall-CCertificate -Thumbprint $cert.Thumbprint -StoreLocation CurrentUser -StoreName My
        }
    }

    It 'should generate key with custom configuration' {
        $validTo = [datetime]::Now.AddDays(30)
        $length = 2048

        $output = New-CRsaKeyPair -Subject $script:subject `
                                  -PublicKeyFile $script:publicKeyPath `
                                  -PrivateKeyFile $script:privateKeyPath `
                                  -Password $script:privateKeyPassword `
                                  -ValidTo $validTo `
                                  -Length $length `
                                  -Algorithm sha1

        Assert-KeyProperty -Length $length -ValidTo $validTo -Algorithm 'sha1RSA'

    }

    It 'should reject subjects that don''t begin with CN=' {
        {
            New-CRsaKeyPair -Subject 'fubar' `
                            -PublicKeyFile $script:publicKeyPath `
                            -PrivateKeyFile $script:privateKeyPath `
                            -Password $script:privateKeyPassword
        } | Should -Throw
        $Global:Error[0] | Should -Match 'does not match'
    }

    It 'should not protect private key' {
        $output = New-CRsaKeyPair -Subject $script:subject `
                                  -PublicKeyFile $script:publicKeyPath `
                                  -PrivateKeyFile $script:privateKeyPath `
                                  -Password $null
        $output.Count | Should -Be 2

        $privateKey = Get-CCertificate -Path $script:privateKeyPath
        $privateKey | Should -Not -BeNullOrEmpty

        $secret = [IO.Path]::GetRandomFileName()
        $protectedSecret = Protect-CString -String $secret -PublicKeyPath $script:publicKeyPath
        Unprotect-CString -ProtectedString $protectedSecret -PrivateKeyPath $script:privateKeyPath -AsPlainText |
            Should -Be $secret
    }
}