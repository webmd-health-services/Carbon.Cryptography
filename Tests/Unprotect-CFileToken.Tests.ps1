
Set-StrictMode -Version 'Latest'

BeforeAll {
    & (Join-Path -Path $PSScriptRoot 'Initialize-Test.ps1' -Resolve)

    $script:testNum = 0

    $script:publicKeyPath = Join-Path -Path $PSScriptRoot -ChildPath 'Certificates\UnprotectCString.pem' -Resolve
    $script:publicKey = Get-CCertificate -Path $script:publicKeyPath
    $script:privateKeyUnprotectedPath =
        Join-Path -Path $PSScriptRoot -ChildPath 'Certificates\UnprotectCStringUnprotected.pfx' -Resolve
    $script:privateKeyProtectedPath =
        Join-Path -Path $PSScriptRoot -ChildPath 'Certificates\UnprotectCStringProtected.pfx' -Resolve
    $script:privateKey = Get-CCertificate -Path $script:privateKeyUnprotectedPath

    $script:certsToUninstall = [Collections.ArrayList]::New()

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

    function GivenFile
    {
        param(
            [String] $Path,
            [String] $Content
        )

        $filePath = Join-Path -Path $script:testDir -ChildPath $Path
        New-Item -Path ($filePath | Split-Path -Parent) -ItemType Directory -Force | Write-Debug
        [IO.File]::WriteAllText($filePath, $Content)
    }

    function ThenFile
    {
        param(
            [String] $Path,
            [String] $ExpectedContent
        )

        $filePath = Join-Path -Path $script:testDir -ChildPath $Path
        $filePath | Should -Exist

        if (-not (Test-Path $filePath))
        {
            return
        }

        # $DebugPreference = 'Continue'
        Write-Debug (Get-Content -LiteralPath $filePath -Raw)

        Get-Content -Path $filePath -Raw | Should -BeExactly $ExpectedContent
    }

    function ThenNoError
    {
        $Global:Error | Should -BeNullOrEmpty
    }

    function WhenUnprotectingFileToken
    {
        [CmdletBinding(DefaultParameterSetName='DPAPI', SupportsShouldProcess)]
        param(
            [Parameter(Mandatory)]
            [String] $Path,

            [Parameter(Mandatory)]
            [String] $OutputPath,

            [String]
            $TokenExpression,

            [switch] $Force,

            [Parameter(Mandatory, ParameterSetName='RSAByCertificate')]
            [Security.Cryptography.X509Certificates.X509Certificate2] $Certificate,

            [Parameter(Mandatory, ParameterSetName='RSAByThumbprint')]
            [String] $Thumbprint,

            [Parameter(Mandatory, ParameterSetName='RSAByPath')]
            [String] $PrivateKeyPath,

            [Parameter(ParameterSetName='RSAByPath')]
            [securestring] $Password,

            [Parameter(ParameterSetName='RSAByCertificate')]
            [Parameter(ParameterSetName='RSAByThumbprint')]
            [Parameter(ParameterSetName='RSAByPath')]
            [Security.Cryptography.RSAEncryptionPadding] $Padding,

            [Parameter(Mandatory, ParameterSetName='Symmetric')]
            [Object] $Key
        )

        $testPath = Join-Path -Path $testDir -ChildPath $Path
        $testOutputPath = Join-Path -Path $testDir -ChildPath $OutputPath

        $PSBoundParameters.Remove('Path')
        $PSBoundParameters.Remove('OutputPath')

        Unprotect-CFileToken -Path $testPath -OutputPath $testOutputPath @PSBoundParameters
    }
}

Describe 'Unprotect-CFileToken' {
    BeforeEach {
        $Global:Error.Clear()
        $script:certsToUninstall.Clear()
        $script:testDir = Join-Path -Path $TestDrive -ChildPath ($script:testNum++)
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
        It 'should unprotect token' {
            $secret = 'hunter2'
            $cipherText = Protect-CString -String $secret -ForUser
            GivenFile 'config.txt' @"
password = !ENCRYPTED:${cipherText}!
"@
            WhenUnprotectingFileToken -Path 'config.txt' -OutputPath 'config.txt.decrypted'
            ThenFile 'config.txt.decrypted' @"
password = ${secret}
"@
            ThenNoError
        }

        It 'should unprotect token from machine scope' {
            $secret = 'hunter2'
            $cipherText = Protect-CString -String $secret -ForComputer
            GivenFile 'config.txt' @"
password = !ENCRYPTED:${cipherText}!
"@
            WhenUnprotectingFileToken -Path 'config.txt' -OutputPath 'config.txt.decrypted'
            ThenFile 'config.txt.decrypted' @"
password = ${secret}
"@
            ThenNoError
        }

        It 'should fail when Path does not exist' {
            { WhenUnprotectingFileToken -Path 'nonexistent.txt' -OutputPath 'nonexistent.txt.decrypted' -ErrorAction Stop } |
                Should -Throw 'Path "*nonexistent.txt" does not exist.'
        }

        It 'should fail when OutputPath exists' {
            $secret = 'hunter2'
            $cipherText = Protect-CString -String $secret -ForUser
            GivenFile 'config.txt' @"
password = !ENCRYPTED:${cipherText}!
"@
            { WhenUnprotectingFileToken -Path 'config.txt' -OutputPath 'config.txt' -ErrorAction Stop } |
                Should -Throw 'OutputPath file "*config.txt" already exists. Use the -Force switch to overwrite.'
        }

        It 'should succeed when OutputPath exists and using Force' {
            $secret = 'hunter2'
            $cipherText = Protect-CString -String $secret -ForUser
            GivenFile 'config.txt' @"
password = !ENCRYPTED:${cipherText}!
"@
            WhenUnprotectingFileToken -Path 'config.txt' -OutputPath 'config.txt' -Force
            ThenFile 'config.txt' @"
password = hunter2
"@
            ThenNoError
        }

        It 'should unprotect multiple tokens' {
            $secret1 = 'hunter2'
            $secret2 = '1e77df6f-bb0e-4263-8d7c-83979b5c5976'
            $cipherText1 = Protect-CString -String $secret1 -ForUser
            $cipherText2 = Protect-CString -String $secret2 -ForUser
            GivenFile 'config.txt' @"
password = !ENCRYPTED:${cipherText1}!
username = notasecret

database_pass = !ENCRYPTED:${cipherText2}!
"@
            WhenUnprotectingFileToken -Path 'config.txt' -OutputPath 'config.txt.decrypted'
            ThenFile 'config.txt.decrypted' @"
password = hunter2
username = notasecret

database_pass = 1e77df6f-bb0e-4263-8d7c-83979b5c5976
"@
            ThenNoError
        }

        It 'should not remove characters that are similar to the regex token' {
            $secret = 'hunter2'
            $cipherText = Protect-CString -String $secret -ForUser
            GivenFile 'config.txt' @"
password1 = !!ENCRYPTED:${cipherText}!
password2 = !ENCRYPTED:${cipherText}!!
password3 = !ENCRYPTED:!!ENCRYPTED:${cipherText}!!
"@
            WhenUnprotectingFileToken -Path 'config.txt' -OutputPath 'config.txt.decrypted'
            ThenFile 'config.txt.decrypted' @"
password1 = !hunter2
password2 = hunter2!
password3 = !ENCRYPTED:!hunter2!
"@
            ThenNoError
        }

        It 'should replace tokens with a custom regex' {
            $secret = 'hunter2'
            $cipherText = Protect-CString -String $secret -ForUser
            GivenFile 'config.txt' @"
password = `$`$${cipherText}`$`$
"@
            WhenUnprotectingFileToken -Path 'config.txt' -OutputPath 'config.txt.decrypted' -TokenExpression '\$\$(.+)\$\$'
            ThenFile 'config.txt.decrypted' @"
password = hunter2
"@
            ThenNoError
        }

        It 'should write a warning when no tokens exist' {
            GivenFile 'config.txt' @"
username = notasecret
"@
            WhenUnprotectingFileToken -Path 'config.txt' -OutputPath 'config.txt.decrypted' -WarningVariable 'warnings'
            $warnings[0].Message | Should -BeLike 'No encrypted tokens matching the regular expression /*/ were found in "*config.txt".'
            ThenFile 'config.txt.decrypted' @"
username = notasecret
"@
            ThenNoError
        }

        It 'should write an error when regex does not contain a capture group' {
            $secret = 'hunter2'
            $cipherText = Protect-CString -String $secret -ForUser
            GivenFile 'config.txt' @"
password = !ENCRYPTED:${cipherText}!
"@
            { WhenUnprotectingFileToken -Path 'config.txt' -OutputPath 'config.txt.decrypted' -TokenExpression '!ENCRYPTED:.+!' -ErrorAction Stop } |
                Should -Throw 'The regular expression /*/ must contain one capture group to isolate the ciphertext.'
        }

        It 'should write an error when regex contains more than one capture group' {
            $secret = 'hunter2'
            $cipherText = Protect-CString -String $secret -ForUser
            GivenFile 'config.txt' @"
password = !ENCRYPTED:${cipherText}!
"@
            { WhenUnprotectingFileToken -Path 'config.txt' -OutputPath 'config.txt.decrypted' -TokenExpression '!ENCRYPTED:(.+)(.*)!' -ErrorAction Stop } |
                Should -Throw 'The regular expression /*/ must contain one capture group to isolate the ciphertext.'
        }

        It 'should fail when decryption fails' {
            $cipherText = 'fakeciphertext'
            GivenFile 'config.txt' @"
password = !ENCRYPTED:${cipherText}!
"@
            { WhenUnprotectingFileToken -Path 'config.txt' -OutputPath 'config.txt.decrypted' -ErrorAction Stop } |
                Should -Throw 'Failed to decrypt token "!ENCRYPTED:fakeciphertext!", it will be left as-is. Underlying error: *'
        }

        It 'should succeed when one token fails to decrypt with ErrorAction continue' {
            $secret1 = 'hunter2'
            $cipherText1 = Protect-CString -String $secret1 -ForUser
            $cipherText2 = 'fakeciphertext'
            GivenFile 'config.txt' @"
username = notasecret
password = !ENCRYPTED:${cipherText1}!

database_pass = !ENCRYPTED:${cipherText2}!
"@
            WhenUnprotectingFileToken -Path 'config.txt' -OutputPath 'config.txt.decrypted' -ErrorAction SilentlyContinue
            ThenFile 'config.txt.decrypted' @"
username = notasecret
password = hunter2

database_pass = !ENCRYPTED:${cipherText2}!
"@
        }

        It 'should support WhatIf' {
            $secret = 'hunter2'
            $cipherText = Protect-CString -String $secret -ForUser
            GivenFile 'config.txt' @"
password = !ENCRYPTED:${cipherText}!
"@
            WhenUnprotectingFileToken -Path 'config.txt' -OutputPath 'config.txt' -Force -WhatIf
            ThenFile 'config.txt' @"
password = !ENCRYPTED:${cipherText}!
"@
            ThenNoError
        }
    }

    It 'should decrypt with thumbprint' {
        GivenCertificate $script:privateKeyUnprotectedPath -Installed -In My
        $secret = 'hunter2'
        $cipherText = Protect-CString -String $secret -Thumbprint $script:privateKey.Thumbprint
        GivenFile 'config.txt' @"
password = !ENCRYPTED:${cipherText}!
"@
        WhenUnprotectingFileToken -Path 'config.txt' -OutputPath 'config.txt' -Force -Thumbprint $script:privateKey.Thumbprint
        ThenFile 'config.txt' @"
password = ${secret}
"@
        ThenNoError
    }

    It 'should decrypt with private key from file' {
        $secret = 'hunter2'
        $cipherText = Protect-CString -String $secret -PublicKeyPath $script:publicKeyPath
        GivenFile 'config.txt' @"
password = !ENCRYPTED:${cipherText}!
"@
        WhenUnprotectingFileToken -Path 'config.txt' -OutputPath 'config.txt' -Force -PrivateKeyPath $script:privateKeyUnprotectedPath
        ThenFile 'config.txt' @"
password = ${secret}
"@
        ThenNoError
    }

    It 'should decrypt with password protected private key' {
        $secret = 'hunter2'
        $cipherText = Protect-CString -String $secret -PublicKeyPath $script:publicKeyPath
        GivenFile 'config.txt' @"
password = !ENCRYPTED:${cipherText}!
"@
        WhenUnprotectingFileToken -Path 'config.txt' `
                                  -OutputPath 'config.txt' `
                                  -Force `
                                  -PrivateKeyPath $script:privateKeyProtectedPath `
                                  -Password (ConvertTo-SecureString -String 'fubar' -AsPlainText -Force)
        ThenFile 'config.txt' @"
password = ${secret}
"@
        ThenNoError
    }

    It 'should decrypt with certificate' {
        $secret = 'hunter2'
        $cipherText = Protect-CString -String $secret -Certificate $script:privateKey
        GivenFile 'config.txt' @"
password = !ENCRYPTED:${cipherText}!
"@
        WhenUnprotectingFileToken -Path 'config.txt' `
                                  -OutputPath 'config.txt' `
                                  -Force `
                                  -Certificate $script:privateKey
        ThenFile 'config.txt' @"
password = ${secret}
"@
        ThenNoError
    }

    Context 'AES' {
        $keyLengths = @(16, 24, 32)
        It "supports <_>-byte key" -ForEach $keyLengths {
            $keyLength = $_
            $key = ConvertTo-SecureString ('a' * $keyLength) -AsPlainText -Force
            $secret = [Guid]::NewGuid().ToString()
            $ciphertext = Protect-CString -String $secret -Key $key
            GivenFile 'config.txt' @"
key = !ENCRYPTED:${cipherText}!
"@

            WhenUnprotectingFileToken -Path 'config.txt' -OutputPath 'config.txt' -Force -Key $key
            ThenFile 'config.txt' @"
key = ${secret}
"@
            ThenNoError
        }
    }
}
