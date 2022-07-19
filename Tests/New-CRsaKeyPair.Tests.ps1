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

#Requires -Version 5.1
Set-StrictMode -Version 'Latest'

BeforeAll {
    & (Join-Path -Path $PSScriptRoot -ChildPath 'Initialize-Test.ps1' -Resolve)

    $script:testDir = $null
    $script:testNum = 0
    $script:privateKeyPassword = ConvertTo-SecureString -String 'fubarsnafu' -AsPlainText -Force
    $script:subject = $null
    $script:publicKeyPath = $null
    $script:privateKeyPath = $null
    $script:output = $null

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
    }

    function ThenKeyPairCreated
    {
        param(
            [String[]] $WithKeyUsage = @(),
            [String[]] $WithEnhancedKeyUsage = @()
        )

        $script:publicKeyPath | Should -Exist
        $script:privateKeyPath | Should -Exist

        $cert = Get-CCertificate -Path $script:publicKeyPath
        if( $WithKeyUsage )
        {
            $actualKeyUsage = 
                $cert.Extensions |
                Where-Object { $_.Oid.FriendlyName -eq 'Key Usage' } |
                Select-Object -ExpandProperty 'KeyUsages' |
                Sort-Object
            (($actualKeyUsage -split ',\ ' | Sort-Object) -join ',') |
                Should -Be (($WithKeyUsage | Sort-Object) -join ',')
        }
        else
        {
            $cert.Extensions | Where-Object { $_.Oid.FriendlyName -eq 'Key Usage' } | Should -BeNullOrEmpty
        }

        if( $WithEnhancedKeyUsage )
        {
            $cert.EnhancedKeyUsageList.FriendlyName | Should -BeIn $WithEnhancedKeyUsage
        }
        else
        {
            $cert.EnhancedKeyUsageList | Should -BeNullOrEmpty
        }
    }

    function ThenNotInCertStore
    {
        $cert = Get-CCertificate -Path $script:output.PublicKeyFile.FullName
        $cert | Should -Not -BeNullOrEmpty
        Join-Path -Path 'cert:\LocalMachine\CurrentUser' -ChildPath $cert.Thumbprint | Should -Not -Exist
    }

    function ThenReturnedKeyPairInfo
    {
        $script:output | Should -Not -BeNullOrEmpty
        $script:output | Should -HaveCount 1
        $script:output.PublicKeyFile.FullName | Should -Be $script:publicKeyPath
        $script:output.PrivateKeyFile.FullName | Should -Be $script:privateKeyPath
    }

    function WhenCreatingKeyPair
    {
        param(
            [Parameter(Position=0)]
            [hashtable] $WithArgument = @{}
        )

        if( -not $WithArgument.ContainsKey('Subject') )
        {
            $WithArgument['Subject'] = $script:subject
        }

        if( -not $WithArgument.ContainsKey('PublicKeyFile') )
        {
            $WithArgument['PublicKeyFile'] = $script:publicKeyPath
        }

        if( -not $WithArgument.ContainsKey('PrivateKeyFile') )
        {
            $WithArgument['PrivateKeyFile'] = $script:privateKeyPath
        }

        if( -not $WithArgument.ContainsKey('Password') )
        {
            $WithArgument['Password'] = $script:privateKeyPassword
        }

        $script:output = New-CRsaKeyPair @WithArgument
    }
}

Describe 'New-CRsaKeyPair' -Skip:(-not (Get-Command -Name 'certreq.exe' -ErrorAction Ignore)) {
    BeforeEach {
        $script:testDir = Join-Path -Path $TestDrive -ChildPath ($script:testNum++)
        $Global:Error.Clear()

        $script:subject = 'CN={0}' -f [Guid]::NewGuid()
        $script:publicKeyPath = Join-Path -Path $script:testDir -ChildPath 'public.cer'
        $script:privateKeyPath = Join-Path -Path $script:testDir -ChildPath 'private.pfx'
        $script:output = $null
    }

    AfterEach {
        Copy-Item $script:publicKeyPath -Destination $PSScriptRoot -ErrorAction Ignore
        Copy-Item $script:privateKeyPath -Destination $PSScriptRoot -ErrorAction Ignore
        [pscredential]::New('user', $script:privateKeyPassword).GetNetworkCredential().Password |
            Set-Content -Path (Join-Path -Path $PSScriptRoot -ChildPath 'PASSWORD')
    }

    It 'should generate a public/private key pair' {
        WhenCreatingKeyPair -WithArgument @{ 'KeyUsage' = 'DocumentEncryption' }
        ThenKeyPairCreated -WithKeyUsage 'DataEncipherment', 'KeyEncipherment' `
                           -WithEnhancedKeyUsage 'Document Encryption'
        ThenReturnedKeyPairInfo
        ThenNotInCertStore
        Assert-KeyProperty
    }

    It 'should generate a key usable by DSC' -Skip:($PSVersionTable['PSEdition'] -eq 'Core') {
        WhenCreatingKeyPair -WithArgument @{ 'KeyUsage' = 'DocumentEncryption' }
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
        WhenCreatingKeyPair -WithArgument @{ 'KeyUsage' = 'DocumentEncryption' }

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

        $withArgs = @{
            ValidTo = $validTo;
            Length = $length;
            Algorithm = 'sha1';
            KeyUsage = 'DocumentEncryption'
        }

        WhenCreatingKeyPair -WithArgument $withArgs
        ThenKeyPairCreated -WithKeyUsage 'DataEncipherment', 'KeyEncipherment' `
                           -WithEnhancedKeyUsage 'Document Encryption'
        ThenReturnedKeyPairInfo
        ThenNotInCertStore
        Assert-KeyProperty -Length $length -ValidTo $validTo -Algorithm 'sha1RSA'
    }

    It 'should reject subjects that don''t begin with CN=' {
        { WhenCreatingKeyPair -WithArgument @{ Subject = 'What''s up doc?' } } | Should -Throw
        $Global:Error[0] | Should -Match 'does not match'
    }

    It 'should not protect private key' {
        WhenCreatingKeyPair -WithArgument @{ KeyUsage = 'DocumentEncryption' ; Password = $null }
        ThenKeyPairCreated -WithKeyUsage 'DataEncipherment', 'KeyEncipherment' `
                           -WithEnhancedKeyUsage 'Document Encryption'
        ThenReturnedKeyPairInfo

        $privateKey = Get-CCertificate -Path $script:privateKeyPath
        $privateKey | Should -Not -BeNullOrEmpty

        $secret = [IO.Path]::GetRandomFileName()
        $protectedSecret = Protect-CString -String $secret -PublicKeyPath $script:publicKeyPath
        Unprotect-CString -ProtectedString $protectedSecret -PrivateKeyPath $script:privateKeyPath -AsPlainText |
            Should -Be $secret
    }

    It 'should generate certificate for client authentication' {
        WhenCreatingKeyPair -WithArgument @{ KeyUsage = 'ClientAuthentication' }
        ThenKeyPairCreated -WithKeyUsage 'DigitalSignature', 'KeyEncipherment' `
                           -WithEnhancedKeyUsage 'Client Authentication'
        ThenReturnedKeyPairInfo
        ThenNotInCertStore
    }

    It 'should generate certificate for code signing' {
        WhenCreatingKeyPair -WithArgument @{ KeyUsage = 'CodeSigning' }
        ThenKeyPairCreated -WithKeyUsage 'DigitalSignature' -WithEnhancedKeyUsage 'Code Signing'
        ThenReturnedKeyPairInfo
        ThenNotInCertStore
    }

    It 'should generate certificate for document encryption' {
        WhenCreatingKeyPair -WithArgument @{ KeyUsage = 'DocumentEncryption' }
        ThenKeyPairCreated -WithKeyUsage 'DataEncipherment','KeyEncipherment' `
                           -WithEnhancedKeyUsage 'Document Encryption'
        ThenReturnedKeyPairInfo
        ThenNotInCertStore
    }

    It 'should generate certificate for document signing' {
        WhenCreatingKeyPair -WithArgument @{ KeyUsage = 'DocumentSigning' }
        ThenKeyPairCreated -WithKeyUsage 'DigitalSignature' -WithEnhancedKeyUsage 'Document Signing'
        ThenReturnedKeyPairInfo
        ThenNotInCertStore
    }

    It 'should generate certificate for server authentication' {
        WhenCreatingKeyPair -WithArgument @{ KeyUsage = 'ServerAuthentication' }
        ThenKeyPairCreated -WithKeyUsage 'DigitalSignature', 'KeyEncipherment' `
                           -WithEnhancedKeyUsage 'Server Authentication'
        ThenReturnedKeyPairInfo
        ThenNotInCertStore
    }

    It 'should generate certificate for all usages' {
        $allUsages =
            @('ClientAuthentication', 'CodeSigning', 'DocumentEncryption', 'DocumentSigning', 'ServerAuthentication')
        WhenCreatingKeyPair -WithArgument @{ KeyUsage = $allUsages }
        $enhancedUsage = @(
            'Client Authentication',
            'Code Signing',
            'Document Encryption',
            'Document Signing',
            'Server Authentication'
        )
        ThenKeyPairCreated -WithKeyUsage 'DataEncipherment', 'DigitalSignature', 'KeyEncipherment' `
                           -WithEnhancedKeyUsage $enhancedUsage
        ThenReturnedKeyPairInfo
        ThenNotInCertStore
    }

    It 'should replace existing files' {
        New-Item -Path $script:testDir -ItemType 'Directory' -Force
        New-Item -Path $script:publicKeyPath
        New-Item -Path $script:privateKeyPath
        WhenCreatingKeyPair -WithArgument @{ Force = $true }
        ThenKeyPairCreated
        ThenReturnedKeyPairInfo
        ThenNotInCertStore
        (Get-Item -Path $script:publicKeyPath).Length | Should -Not -Be 0
        (Get-Item -Path $script:privateKeyPath).Length | Should -Not -Be 0
    }

    It 'should create a cert suitable for any purpose' {
        WhenCreatingKeyPair
        ThenKeyPairCreated
        ThenReturnedKeyPairInfo
        ThenNotInCertStore
    }
}