
function New-CRsaKeyPair
{
    <#
    .SYNOPSIS
    Generates a public/private RSA key pair.

    .DESCRIPTION
    The `New-CRsaKeyPair` function uses the `certreq.exe` program to generate an RSA public/private key pair suitable
    for use in encrypting/decrypting CMS messages, credentials in DSC resources, etc.

    Pass the subject to the `Subject` parameter (it must begin with `CN=`) and the paths where you want the public and
    private keys saved to the `PublicKeyPath` and `PrivateKeyPath` parameters, respectively. `New-CRsaKeyPair` creates
    a temporary .inf file and passes it to the `certreq.exe` program. You will be prompted for a password, unless you
    pass a password to the `Password` parameter.

    By default, a key pair with no key usages or enhanced key usages is generated that is 4096 bits in length, uses
    `SHA512` as the signature/hash algorithm, and is valid until December 31st, 9999. An object with
    `[IO.FileInfo] PublicKeyFile` and `[IO.FileInfo] PrivateKeyFile` properties is returned.

    You can change the key's length, algorithm, expiration date, and provider with the `Length`, `Algorithm`, `ValidTo`,
    and `ProviderName` parameters, respectively. You can set the key pair's usages with the `KeyUsage` parameter. Valid
    usages this function supports are `ClientAuthentication`, `CodeSigning`, `DocumentEncryption`, `DocumentSigning`,
    and `ServerAuthentication`.

    If the destination files already exist, you'll get an error and no keys will be generated. Use the `Force` switch to
    overwrite any existing files.

    The `certreq.exe` command stores the private key in the current user's `My` certificate store. This function exports
    that private key to a file and removes it from the current user's `My` store. The private key is protected with the
    password provided via the `-Password` parameter. If you don't provide a password, you will be prompted for one. To
    not protect the private key with a password, pass `$null` as the value of the `-Password` parameter.

    The public key is saved as an X509Certificate. The private key is saved as a PFX file. Both can be loaded by .NET's
    `X509Certificate` class. Returns `System.IO.FileInfo` objects for the public and private key, in that order.

    .LINK
    Get-CCertificate

    .LINK
    Install-CCertificate

    .EXAMPLE
    New-CRsaKeyPair -Subject 'CN=MyName' -PublicKeyFile 'MyName.cer' -PrivateKeyFile 'MyName.pfx' -Password $secureString

    Demonstrates the minimal parameters needed to generate a key pair. The key will use a sha512 signing algorithm, have
    a length of 4096 bits, and expire on `12/31/9999`. The public key will be saved in the current directory as
    `MyName.cer`. The private key will be saved to the current directory as `MyName.pfx` and protected with password in
    `$secureString`. The key pair will have no usages, so you won't be able to do much with it.

    .EXAMPLE
    New-CRsaKeyPair -Subject 'CN=MyName' -PublicKeyFile 'MyName.cer' -PrivateKeyFile 'MyName.pfx' -Password $null

    Demonstrates how to save the private key unprotected (i.e. without a password). You must set the password to
    `$null`. This functionality was introduced in Carbon 2.1.

    .EXAMPLE
    New-CRsaKeyPair -Subject 'CN=MyName' -PublicKeyFile 'MyName.cer' -PrivateKeyFile 'MyName.pfx' -Algorithm 'sha1' -ValidTo (Get-Date -Year 2015 -Month 12 -Day 31) -Length 1024 -Password $secureString -KeyUsage DocumentSigning, DocumentEncryption -ProviderName 'Microsoft AES Cryptographic Provider'

    Demonstrates how to use all the parameters to create a truly customized key pair. The generated certificate will use
    the sha1 signing algorithm, expires 12/31/2015, is 1024 bits in length, uses the "Microsoft AES Cryptographic
    Provider", and can be used to sign and encrypt.
    #>
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingUserNameAndPassWordParams', '')]
    param(
        # The key's subject. Should be of the form `CN=Name,OU=Name,O=SuperMagicFunTime,ST=OR,C=US`. Only the `CN=Name`
        # part is required.
        [Parameter(Mandatory, Position=0)]
        [ValidatePattern('^CN=')]
        [string] $Subject,

        # The signature algorithm. Default is `sha512`.
        [ValidateSet('md5', 'sha1', 'sha256', 'sha384', 'sha512')]
        [string] $Algorithm = 'sha512',

        # The date/time the keys should expire. Default is `DateTime::MaxValue`.
        [DateTime] $ValidTo = ([DateTime]::MaxValue),

        # The length, in bits, of the generated key length. Default is `4096`.
        [int] $Length = 4096,

        # What extended key usages the certificate will have. By default, it will be for any purpose (OID 2.5.29.37.0).
        [ValidateSet('ClientAuthentication', 'CodeSigning', 'DocumentEncryption', 'DocumentSigning',
                     'ServerAuthentication')]
        [String[]] $KeyUsage,

        # The display name of the Cryptographic Service Provider (CSP) to use. The default is "Microsoft Enhanced RSA
        # and AES Cryptographic Provider" (i.e. "Microsoft RSA Cryptographic Provider"). Run `certutil -csplist` to see
        # providers available on your system and [Microsoft Cryptographic Service Providers](https://learn.microsoft.com/en-us/windows/win32/seccrypto/microsoft-cryptographic-service-providers)
        # for more documentation.
        [String] $ProviderName = 'Microsoft Enhanced RSA and AES Cryptographic Provider',

        # The file where the public key should be stored. Saved as an X509 certificate.
        [Parameter(Mandatory, Position=1)]
        [string] $PublicKeyFile,

        # The file where the private key should be stored. The private key will be saved as an X509 certificate in PFX
        # format and will include the public key.
        [Parameter(Mandatory, Position=2)]
        [string] $PrivateKeyFile,

        # The password for the private key. If one is not provided, you will be prompted for one. Pass `$null` to not
        # protect your private key with a password.
        #
        # This parameter was introduced in Carbon 2.1.
        [securestring] $Password,

        # Overwrites `PublicKeyFile` and/or `PrivateKeyFile`, if they exist.
        [Switch] $Force
    )

    Set-StrictMode -Version 'Latest'
    Use-CallerPreference -Cmdlet $PSCmdlet -Session $ExecutionContext.SessionState

    function Resolve-KeyPath
    {
        param(
            [Parameter(Mandatory)]
            [string] $Path
        )

        Set-StrictMode -Version 'Latest'

        $Path = [IO.Path]::GetFullPath($Path)

        if( (Test-Path -Path $Path -PathType Leaf) )
        {
            if( -not $Force )
            {
                Write-Error ('File ''{0}'' exists. Use the -Force switch to overwrite.' -f $Path)
                return
            }
        }
        else
        {
            $root = Split-Path -Parent -Path $Path
            if( -not (Test-Path -Path $root -PathType Container) )
            {
                New-Item -Path $root -ItemType 'Directory' -Force | Out-Null
            }
        }

        return $Path
    }

    $PublicKeyFile = Resolve-KeyPath -Path $PublicKeyFile
    if( -not $PublicKeyFile )
    {
        return
    }

    $PrivateKeyFile = Resolve-KeyPath -Path $PrivateKeyFile
    if( -not $PrivateKeyFile )
    {
        return
    }

    if( (Test-Path -Path $PrivateKeyFile -PathType Leaf) )
    {
        if( -not $Force )
        {
            Write-Error ('Private key file ''{0}'' exists. Use the -Force switch to overwrite.' -f $PrivateKeyFile)
            return
        }
    }

    $tempDir = '{0}-{1}' -f (Split-Path -Leaf -Path $PSCommandPath),([IO.Path]::GetRandomFileName())
    $tempDir = Join-Path -Path $env:TEMP -ChildPath $tempDir
    New-Item -Path $tempDir -ItemType 'Directory' | Out-Null
    $tempInfFile = Join-Path -Path $tempDir -ChildPath 'temp.inf'

    # Adapted from
    # * https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/certreq_1
    # * https://docs.microsoft.com/en-us/windows/win32/api/certenroll/ne-certenroll-x509keyusageflags
    # * https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509keyusageflags
    # * https://omvs.de/2019/11/13/key-usage-extensions-at-x-509-certificates/
    # CERT_DIGITAL_SIGNATURE_KEY_USAGE (0x80/128):
    #   The key can be used as a digital signature. The key is used with a Digital Signature Algorithm (DSA) to support
    #   services other than nonrepudiation, certificate signing, or revocation list signing.
    # CERT_NON_REPUDIATION_KEY_USAGE (0x40/64):
    #   The key can be used for authentication. The key is used to verify a digital signature as part of a
    #   nonrepudiation service that protects against false denial of action by a signing entity.
    # CERT_KEY_ENCIPHERMENT_KEY_USAGE (0x20/32):
    #   The key can be used for key encryption. The key is used for key transport. That is, the key is used to manage a
    #   key passed from its point of origination to another point of use.
    # CERT_DATA_ENCIPHERMENT_KEY_USAGE (0x10/16):
    #   The key can be used for data encryption. The key is used to encrypt user data other than cryptographic keys.
    # CERT_KEY_AGREEMENT_KEY_USAGE (8):
    #   The key can be used to determine key agreement, such as a key created using the Diffie-Hellman key agreement
    #   algorithm. The key agreement or key exchange protocol enables two or more
    #   parties to negotiate a key value without transferring the key and without previously establishing a shared
    #   secret.
    # CERT_KEY_CERT_SIGN_KEY_USAGE (4):
    #   The key can be used to sign certificates. The key is used to verify a certificate signature. This value can only
    #   be used for certificates issued by certification authorities.
    # CERT_OFFLINE_CRL_SIGN_KEY_USAGE (2):
    #   The key can be used to sign a certificate revocation list (CRL). The key is used to verify an offline
    #   certificate revocation list (CRL) signature.
    # CERT_CRL_SIGN_KEY_USAGE (2):
    #   The key can be used to sign a certificate revocation list (CRL). The key is used to verify a CRL signature.
    # CERT_ENCIPHER_ONLY_KEY_USAGE (1):
    #   The key can be used for encryption only. The key is used to encrypt data while performing key agreement. When
    #   this value is specified, the CERT_KEY_AGREEMENT_KEY_USAGE value must also be specified.
    # CERT_DECIPHER_ONLY_KEY_USAGE (0x8000/32768):
    #   The key can be used for decryption only. The key is used to decrypt data while performing key agreement. When
    #   this value is specified, the CERT_KEY_AGREEMENT_KEY_USAGE must also be specified.

    $usageMap = @{
        ClientAuthentication = @('CERT_DIGITAL_SIGNATURE_KEY_USAGE', 'CERT_KEY_ENCIPHERMENT_KEY_USAGE');
        CodeSigning = 'CERT_DIGITAL_SIGNATURE_KEY_USAGE';
        DocumentEncryption = @('CERT_KEY_ENCIPHERMENT_KEY_USAGE', 'CERT_DATA_ENCIPHERMENT_KEY_USAGE');
        DocumentSigning = 'CERT_DIGITAL_SIGNATURE_KEY_USAGE';
        ServerAuthentication = @('CERT_DIGITAL_SIGNATURE_KEY_USAGE', 'CERT_KEY_ENCIPHERMENT_KEY_USAGE');
    }

    try
    {
        $certReqPath = Get-Command -Name 'certreq.exe' -ErrorAction Ignore | Select-Object -ExpandProperty 'Path'
        if( -not $certReqPath )
        {
            'Command "certreq.exe" does not exist. This is a Windows-only command. If you''re on Windows, make sure ' +
            '"C:\Windows\System32" is part of your "Path" environment variable.' |
                Write-Error -ErrorAction $ErrorActionPreference
            return
        }

        # Taken from example 1 of the Protect-CmsMessage help topic.
        [int]$daysValid = [Math]::Floor(($ValidTo - (Get-Date)).TotalDays)
        [int]$MaxDaysValid = [Math]::Floor(([DateTime]::MaxValue - [DateTime]::UtcNow).TotalDays)
        Write-Debug -Message ('Days Valid:              {0}' -f $daysValid)
        Write-Debug -Message ('Max Days Valid:          {0}' -f $MaxDaysValid)
        if( $daysValid -gt $MaxDaysValid )
        {
            Write-Debug -Message ('Adjusted Days Valid:     {0}' -f $daysValid)
            $daysValid = $MaxDaysValid
        }

        $keyUsages = & {
            foreach( $usage in $KeyUsage )
            {
                if( $usageMap.ContainsKey($usage) )
                {
                    $usageMap[$usage] | Write-Output
                }
            }
        } | Select-Object -Unique

        $extensions = & {
            if( -not $KeyUsage )
            {
                return
            }

            foreach( $usage in $KeyUsage )
            {
                switch( $usage )
                {
                    'ClientAuthentication' { 'szOID_CLIENT_AUTHENTICATION' }
                    'CodeSigning' { 'szOID_CODE_SIGNING' }
                    'DocumentEncryption' { 'szOID_DOCUMENT_ENCRYPTION' }
                    'DocumentSigning' { 'szOID_DOCUMENT_SIGNING' }
                    'ServerAuthentication' { 'szOID_SERVER_AUTHENTICATION' }
                }
            }
        }

        $keySpec = 'AT_NONE'
        if( $KeyUsage | Where-Object { $_ -like '*Signing' } )
        {
            $keySpec = 'AT_SIGNATURE'
        }
        if( $KeyUsage | Where-Object { $_ -notlike '*Signing' } )
        {
            $keySpec = 'AT_KEYEXCHANGE'
        }

        $keyUsageLine = ''
        if( $keyUsages )
        {
            $keyUsageLine = "KeyUsage = ""$($keyUsages -join ' | ')"""
        }

        $extensionsLine = ''
        if( $extensions )
        {
            $extensionsLine = $extensions -join "%,""$([Environment]::NewLine)_continue_ = ""%"
            $extensionsLine = "%szOID_ENHANCED_KEY_USAGE% = ""{text}%$($extensionsLine)%"""
        }

        @"
[Version]
Signature = "`$Windows NT`$"

[Strings]
szOID_ANY_PURPOSE = 2.5.29.37.0
szOID_CLIENT_AUTHENTICATION = 1.3.6.1.5.5.7.3.2
szOID_CODE_SIGNING = 1.3.6.1.5.5.7.3.3
szOID_DOCUMENT_ENCRYPTION = 1.3.6.1.4.1.311.80.1
szOID_DOCUMENT_SIGNING = 1.3.6.1.4.1.311.10.3.12
szOID_ENHANCED_KEY_USAGE = 2.5.29.37
szOID_SERVER_AUTHENTICATION = 1.3.6.1.5.5.7.3.1

[NewRequest]
Subject = "$($Subject)"
MachineKeySet = false
KeyLength = $($Length)
KeySpec = $($keySpec)
HashAlgorithm = $($Algorithm)
Exportable = true
RequestType = Cert
ValidityPeriod = Days
ValidityPeriodUnits = $($daysValid)
ProviderName = $($ProviderName)
$($keyUsageLine)

[Extensions]
$($extensionsLine)
"@ | Set-Content -Path $tempInfFile

        Get-Content -Raw -Path $tempInfFile | Write-Verbose

        $forceArg = ''
        if( $Force )
        {
            $forceArg = ' -f'
        }
        Write-Debug "& ""$($certReqPath)"" -q$($forceArg) -new ""$($tempInfFile)"" ""$($PublicKeyFile)"""
        $output = & $certReqPath -q ($forceArg.TrimStart()) -new $tempInfFile $PublicKeyFile
        if( $LASTEXITCODE -or -not (Test-Path -Path $PublicKeyFile -PathType Leaf) )
        {
            Write-Error ('Failed to create public/private key pair:{0}{1}' -f ([Environment]::NewLine),($output -join ([Environment]::NewLine)))
            return
        }
        else
        {
            $output | Write-Debug
        }

        $publicKey = Get-CCertificate -Path $PublicKeyFile
        if( -not $publicKey )
        {
            Write-Error ('Failed to load public key ''{0}'':{1}{2}' -f $PublicKeyFile,([Environment]::NewLine),($output -join ([Environment]::NewLine)))
            return
        }

        $privateCertPath = Join-Path -Path 'cert:\CurrentUser\My' -ChildPath $publicKey.Thumbprint
        if( -not (Test-Path -Path $privateCertPath -PathType Leaf) )
        {
            Write-Error -Message ('Private key ''{0}'' not found. Did certreq.exe fail to install the private key there?' -f $privateCertPath)
            return
        }

        try
        {
            $privateCert = Get-Item -Path $privateCertPath
            if( -not $privateCert.HasPrivateKey )
            {
                Write-Error -Message ('Certificate ''{0}'' doesn''t have a private key.' -f $privateCertPath)
                return
            }

            if( -not $PSBoundParameters.ContainsKey('Password') )
            {
                $Password = Read-Host -Prompt 'Enter private key password' -AsSecureString
            }

            $privateCertBytes = $privateCert.Export( 'PFX', $Password )
            [IO.File]::WriteAllBytes( $PrivateKeyFile, $privateCertBytes )

            [pscustomobject]@{
                'PublicKeyFile' = (Get-Item $PublicKeyFile);
                'PrivateKeyFile' = (Get-Item $PrivateKeyFile);
            } | Write-Output
        }
        finally
        {
            Remove-Item -Path $privateCertPath
        }
    }
    finally
    {
        Remove-Item -Path $tempDir -Recurse
    }
}
