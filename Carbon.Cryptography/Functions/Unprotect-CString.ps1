
function Unprotect-CString
{
    <#
    .SYNOPSIS
    Decrypts a string.

    .DESCRIPTION
    `Unprotect-CString` decrypts a string encrypted via the Data Protection API (DPAPI), RSA, or AES into an array of
    bytes, which is then converted to an array of chars, which are stored in a `[securestring]`. All arrays of bytes and
    chars are cleared from memory once decryption completes.

    Use the `AsPlainText` switch to return a plain text string instead. When you do this, your decrypted string will
    remain in memory (and maybe disk) for an unknowable amount of time.

    `Unprotect-CString` can decrypt using the following techniques.

    ## Data Protection API

    The DPAPI only works on Windows. The encrypted string must have also been encrypted with the DPAPI. The string must
    have been encrypted at the current user's scope or the local machine scope.

    ## RSA

    RSA is an assymetric encryption/decryption algorithm, which requires a public/private key pair. It uses a private
    key to decrypt a secret encrypted with the public key. Only the private key can decrypt secrets.

    You can specify the private key in these ways:

     * with a `[Security.Cryptography.X509Certificates.X509Certificate2]` object, via the `Certificate` parameter
     * with an X509 certificate file, via the `PrivateKeyPath` parameter. On Windows, you can use paths to items in the
       `cert:\` drive.

     On Windows, you can also pass the thumbprint to a certificate to the `Thumbprint` parameter, and
     `Unprotect-CString` will search the `cert:\` store for a matching certificate with a private key.

    ## AES

    AES is a symmetric encryption/decryption algorithm. You supply a 16-, 24-, or 32-byte key, password, or passphrase
    with the `Key` parameter, and that key is used to decrypt. You must decrypt with the same key you used to encrypt.
    `Unprotect-CString` uses `[Security.Cryptography.Aes]::Create()` to get an object that can do the decryption.

    You can only pass a `[securestring]` or byte array as the key. When passing a secure string, make sure that when
    encoded as UTF-8 and converted to a byte array, it is 16, 24, or 32 bytes long. This code will tell you how long your
    plain text password is, in UTF-8 bytes:

        [Text.Encoding]::Convert([Text.Encoding]::Unicode, [Text.Encoding]::UTF8, [Text.Encoding]::Unicode.GetBytes($key)).Length

    Symmetric encryption requires a random, unique initialization vector (i.e. IV) everytime you encrypt something. If
    you encrypted the string with `Protect-CString`, one was generated for you and prepended to the encrypted string. If
    you encrypted the original string yourself, make sure the first 16 bytes of the encrypted text is the IV (since
    the encrypted bytes are base64 encoded, that means the first 24 characters of the encrypted string should be the
    IV).

    The help topic for `Protect-CString` demonstrates how to generate an AES key and how to encode it as a base64
    string.

    .LINK
    New-CRsaKeyPair

    .LINK
    Protect-CString

    .LINK
    http://msdn.microsoft.com/en-us/library/system.security.cryptography.protecteddata.aspx

    .EXAMPLE
    Unprotect-CString -ProtectedString $encryptedPassword

    Demonstrates how to decrypt a protected string which was encrypted with Microsoft's DPAPI. Windows only.

    .EXAMPLE
    Unprotect-CString -ProtectedString $ciphertext -Certificate $myCert

    Demonstrates how to decrypt a secret using RSA with a `[Security.Cryptography.X509Certificates.X509Certificate2]`
    object. You're responsible for creating/loading it. (Carbon's `New-CRsaKeyPair` function can create public/private
    key pairs for you.)

    .EXAMPLE
    $ciphertext | Unprotect-CString -Certificate $certWithPrivateKey

    Demonstrates that you can pipe encrypted strings to `Unprotect-CString`.

    .EXAMPLE
    $ciphertext | Unprotect-CString -Certificate $certWithPrivateKey -AsSecureString

    Demonstrates that you can get a secure string returned to you by using the `AsSecureString` switch. This is the most
    secure way to decrypt, as the decrypted text is only in memory as arrays of bytes/chars during decryption. The
    arrays are immediately cleared after decryption. The decrypted text is never stored as a `[String]` (which remain
    in memory).

    .EXAMPLE
    Unprotect-CString -ProtectedString $ciphertext -Thumbprint '44A7C27F3353BC53F82318C14490D7E2500B6D9E'

    Demonstrates how to decrypt a secret with a certificate by passing its thumbprint to the `Thumbprint` parameter.
    `Unprotect-CString` will search the Windows certificate stores to find the certificate. All local machine and user
    stores are searched. The current user must have permission/access to the certificate's private key. Windows only.

    .EXAMPLE
    Unprotect -ProtectedString $ciphertext -PrivateKeyPath 'C:\Projects\Security\publickey.cer'

    Demonstrates how to decrypt a secret by passing the path to an  RSA private key to the `PrivateKeyPath` parameter.
    The private key file must be loadable by the `[Security.Cryptography.X509Certificates.X509Certificate]` class.

    .EXAMPLE
    Unprotect -ProtectedString $ciphertext -PrivateKeyPath 'cert:\LocalMachine\My\44A7C27F3353BC53F82318C14490D7E2500B6D9E'

    Demonstrates how to decrypt a secret using a certificate in the Windows store by passing the path to the certificate
    in PowerShell's `cert:` drive. The certificate must have a private key. Windows only.

    .EXAMPLE
    Unprotect-CString -ProtectedString $ciphertext -Key 'gT4XPfvcJmHkQ5tYjY3fNgi7uwG4FB9j'

    Demonstrates how to decrypt a secret that was encrypted with a key, password, or passphrase. In this case, we are
    decrypting with a plaintext password.

    .EXAMPLE
    Unprotect-CString -ProtectedString $ciphertext -Key (Read-Host -Prompt 'Enter password (must be 16, 24, or 32 characters long):') -AsSecureString)

    Demonstrates how to decrypt a secret with a secure string that is the key, password, or passphrase. In this case,
    the user is prompted for the password securely.

    .EXAMPLE
    Unprotect-CString -ProtectedString $ciphertext -Key ([byte[]]@(163,163,185,174,205,55,157,219,121,146,251,116,43,203,63,38,73,154,230,112,82,112,151,29,189,135,254,187,164,104,45,30))

    Demonstrates that you can pass in an array of bytes as the key to the `Key` parameter. Those bytes will be used to
    decrypt the ciphertext.
    #>
    [CmdletBinding(DefaultParameterSetName='DPAPI')]
    param(
        [Parameter(Mandatory, Position=0, ValueFromPipeline)]
        # The text to decrypt.
        [String]$ProtectedString,

        [Parameter(Mandatory, ParameterSetName='RSAByCertificate')]
        # The private key to use for decrypting.
        [Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter(Mandatory, ParameterSetName='RSAByThumbprint')]
        # The thumbprint of the certificate, found in one of the Windows certificate stores, to use when decrypting. All
        # certificate stores are searched. The current user must have permission to the private key. Windows only.
        [String]$Thumbprint,

        [Parameter(Mandatory, ParameterSetName='RSAByPath')]
        # The path to the private key to use for decrypting. If given a path on the file system, the file must be
        # loadable as a `[Security.X509Certificates.X509Certificate2]` object. On Windows, you can also pass the path
        # to a certificate in PowerShell's `cert:` drive.
        [String]$PrivateKeyPath,

        [Parameter(ParameterSetName='RSAByPath')]
        # The password for the private key, if it has one. Must be a `[securestring]`.
        [securestring]$Password,

        [Parameter(ParameterSetName='RSAByCertificate')]
        [Parameter(ParameterSetName='RSAByThumbprint')]
        [Parameter(ParameterSetName='RSAByPath')]
        # The padding mode to use when decrypting. Defaults to `[Security.Cryptography.RSAEncryptionPadding]::OaepSHA1`.
        [Security.Cryptography.RSAEncryptionPadding]$Padding,

        [Parameter(Mandatory, ParameterSetName='Symmetric')]
        # The key to use to decrypt the secret. Must be a `[securestring]` or an array of bytes. The characters in the
        # secure string are converted to UTF-8 encoding before being converted into bytes. Make sure the key is the
        # correct length when UTF-8 encoded, i.e. make sure the following code returns a 16, 24, or 32 byte byte array
        # (where $key is the plain text key).
        #
        #     [Text.Encoding]::Convert([Text.Encoding]::Unicode, [Text.Encoding]::UTF8, [Text.Encoding]::Unicode.GetBytes($key)).Length
        [Object]$Key,

        # Returns the decrypted value as plain text. The default is to return the decrypted value as a `[securestring]`.
        # When returned as a secure string, the decrypted bytes are only stored in memory as arrays of bytes and chars,
        # which are all cleared once the decrypted text is in the secure string. Once a secure string is converted to a
        # string, that string stays in memory (and possibly disk) for an unknowable amout of time.
        [switch]$AsPlainText
    )

    process
    {
        Set-StrictMode -Version 'Latest'
        Use-CallerPreference -Cmdlet $PSCmdlet -Session $ExecutionContext.SessionState

        [byte[]]$keyBytes = [byte[]]::New(0)

        # When loading a certificate from a file, Windows will temporarily write the private key to disk for the
        # lifetime of the certificate object. To limit the amount of time the private key spends on disk, dispose the
        # certificate object as soon as we are done with it.
        $disposeCertWhenDone = ($PrivateKeyPath -ne '') -and ($PrivateKeyPath -notlike 'Cert:\*')

        # Find and validate the RSA certificate, if needed. We do it here so our try/catch around the actual
        # decryption doesn't handle these errors.
        if( $PSCmdlet.ParameterSetName -like 'RSA*' )
        {
            if( $PSCmdlet.ParameterSetName -notlike '*ByCertificate' )
            {
                if( $PSCmdlet.ParameterSetName -like '*ByThumbprint' )
                {
                    $PrivateKeyPath = "cert:\*\*\$($Thumbprint)"
                }

                $passwordParam = @{ }
                if( $Password )
                {
                    $passwordParam = @{ Password = $Password }
                }

                $certificates = Get-CCertificate -Path $PrivateKeyPath @passwordParam
                $count = $certificates | Measure-Object | Select-Object -ExpandProperty 'Count'
                if( $count -gt 1 )
                {
                    $certificates = $certificates | Where-Object { $_.HasPrivateKey -and $_.PrivateKey }
                    $privateKeyCount = $certificates | Measure-Object | Select-Object -ExpandProperty 'Count'

                    if( $privateKeyCount -gt 1 )
                    {
                        $msg = "Found $($privateKeyCount) certificates (which contain private keys) at ""$($PrivateKeyPath)"". " +
                            'Arbitrarily choosing the first one. If you get errors, consider passing the exact path to ' +
                            'the certificate you want to the "Unprotect-CString" function''s "PrivateKeyPath" parameter.'
                        Write-Warning -Message $msg
                    }
                    elseif( $privateKeyCount -eq 0 )
                    {

                        $installedInCertStoreMsg = ''
                        if ($PSCmdlet.ParameterSetName -eq 'RSAByThumbprint')
                        {
                            $installedInCertStoreMsg =
                                'This is usually because the certificate was installed without a private key or the ' +
                                'current user doesn''t have permission to read the private key.'
                        }

                        "Found $($count) certificates at ""$($PrivateKeyPath)"" but none of them contain a private " +
                        "key or the private key is null.$(' ' + $installedInCertStoreMsg)" | Write-Error
                        return
                    }
                }
                $Certificate = $certificates | Select-Object -First 1
                if( -not $Certificate )
                {
                    return
                }

                if ($disposeCertWhenDone)
                {
                    # Dispose the other unused certificates.
                    foreach ($unusedCert in ($certificates | Select-Object -Skip 1))
                    {
                        $unusedCert.Dispose()
                    }
                }
            }

            $certDesc = "Certificate ""$($Certificate.Subject)"" ($($Certificate.Thumbprint))"
            if( -not $Certificate.HasPrivateKey )
            {
                $msg = "$($certDesc) doesn't have a private key. When decrypting with RSA, secrets are encrypted with " +
                    'the public key, and decrypted with a private key.'
                Write-Error -Message $msg -ErrorAction $ErrorActionPreference
                return
            }

            if( -not $Certificate.PrivateKey )
            {
                $msg = "$($certDesc) has a private key, but it is null or not set. This usually means your certificate " +
                    'was imported incorrectly or was created without a private key. Make sure you''ve generated an ' +
                    'RSA public/private key pair and are using the private key. If the private key is in the Windows ' +
                    'certificate store, make sure the current user has permission to read the private key (use ' +
                    'Carbon''s `Grant-CPermission` function).'
                Write-Error -Message $msg -ErrorAction $ErrorActionPreference
                return
            }
        }
        elseif( $PSCmdlet.ParameterSetName -eq 'Symmetric' )
        {
            $keyBytes = ConvertTo-AesKey -InputObject $Key -From 'Unprotect-CString'
            if( -not $keyBytes )
            {
                return
            }
        }


        [byte[]]$decryptedBytes = [byte[]]::New(0)
        [byte[]]$encryptedBytes = [Convert]::FromBase64String($ProtectedString)
        try
        {
            if( $PSCmdlet.ParameterSetName -eq 'DPAPI' )
            {
                $decryptedBytes = [Security.Cryptography.ProtectedData]::Unprotect( $encryptedBytes, $null, 0 )
            }
            elseif( $PSCmdlet.ParameterSetName -like 'RSA*' )
            {
                [Security.Cryptography.RSA]$privateKey = $null
                $privateKeyType = $Certificate.PrivateKey.GetType()
                $isRsa = $privateKeyType.IsSubclassOf([Security.Cryptography.RSA])
                if( -not $isRsa )
                {
                    $msg = "$($certDesc) is not an RSA key. Found a private key of type " +
                           """$($privateKeyType.FullName)"", but expected type " +
                           """$([Security.Cryptography.RSA].FullName)"" or one of its sub-types."
                    Write-Error -Message $msg -ErrorAction $ErrorActionPreference
                    return
                }

                if( -not $Padding )
                {
                    $Padding = [Security.Cryptography.RSAEncryptionPadding]::OaepSHA1
                }

                $privateKey = $Certificate.PrivateKey
                $decryptedBytes = $privateKey.Decrypt($encryptedBytes, $padding)
            }
            elseif( $PSCmdlet.ParameterSetName -eq 'Symmetric' )
            {
                $aes = [Security.Cryptography.Aes]::Create()
                try
                {
                    $aes.Padding = [Security.Cryptography.PaddingMode]::PKCS7
                    $aes.KeySize = $keyBytes.Length * 8
                    $aes.Key = $keyBytes
                    $iv = [byte[]]::New($aes.IV.Length)
                    [Array]::Copy($encryptedBytes, $iv, 16)

                    $encryptedBytes = $encryptedBytes[16..($encryptedBytes.Length - 1)]
                    $encryptedStream = New-Object -TypeName 'IO.MemoryStream' -ArgumentList (,$encryptedBytes)
                    try
                    {
                        $cryptoStream =
                            [Security.Cryptography.CryptoStream]::New($encryptedStream,
                                $aes.CreateDecryptor($aes.Key, $iv),
                                ([Security.Cryptography.CryptoStreamMode]::Read))
                        try
                        {
                            $streamReader = [IO.StreamReader]::New($cryptoStream)
                            try
                            {
                                [byte[]]$decryptedBytes = [Text.Encoding]::UTF8.GetBytes($streamReader.ReadToEnd())
                            }
                            finally
                            {
                                $streamReader.Dispose()
                            }
                        }
                        finally
                        {
                            $cryptoStream.Dispose()
                        }
                    }
                    finally
                    {
                        $encryptedStream.Dispose()
                    }
                }
                finally
                {
                    $aes.Dispose()
                }
            }

            $decryptedBytes = [Text.Encoding]::Convert([Text.Encoding]::UTF8, [Text.Encoding]::Unicode, $decryptedBytes)
            if( $AsPlainText )
            {
                return [Text.Encoding]::Unicode.GetString($decryptedBytes)
            }
            else
            {
                $secureString = [Security.SecureString]::New()
                [char[]]$chars = [Text.Encoding]::Unicode.GetChars( $decryptedBytes )
                for( $idx = 0; $idx -lt $chars.Count ; $idx++ )
                {
                    $secureString.AppendChar( $chars[$idx] )
                    $chars[$idx] = 0
                }

                $secureString.MakeReadOnly()
                return $secureString
            }
        }
        catch
        {
            Write-Error -ErrorRecord $_ -ErrorAction $ErrorActionPreference
        }
        finally
        {
            if ($decryptedBytes)
            {
                $decryptedBytes.Clear()
            }

            if ($encryptedBytes)
            {
                $encryptedBytes.Clear()
            }

            if ($keyBytes)
            {
                $keyBytes.Clear()
            }

            if ($disposeCertWhenDone)
            {
                $Certificate.Dispose()
            }
        }
    }
}