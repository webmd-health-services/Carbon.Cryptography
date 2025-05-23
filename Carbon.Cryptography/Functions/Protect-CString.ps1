
function Protect-CString
{
    <#
    .SYNOPSIS
    Encrypts a string.

    .DESCRIPTION
    The `Protect-CString` function encrypts a string using the Windows Data Protection API (DPAPI), RSA, or AES. Pass
    a plaintext string or a secure string to the `String` parameter. When encrypting a `SecureString`, it is converted
    to an array of bytes, encrypted, then the array of bytes is cleared from memory (i.e. the plaintext version of the
    `SecureString` is only in memory long enough to encrypt it). All strings and secure string bytes are re-encoded
    from UTF-16/Unicode to UTF-8 before encrypting.

    ##  Windows Data Protection API (DPAPI)

    The DPAPI hides the encryptiong/decryption keys. There is a unique key for each user and a machine key. Anything
    encrypted with a user's key, can only be decrypted by that user. Anything encrypted with the machine key can be
    decrypted by anyone on that machine. Use the `ForUser` switch to encrypt with the current user's key.  Use the
    `ForComputer` switch to encrypt at the machine level.

    If you want to encrypt something as a different user, pass that user's credentials to the `Credential` parameter.
    `Protect-CString` will launch a PowerShell process as that user to do the encryption. Encrypting as another user
    doesn't work over PowerShell Remoting.

    ## RSA

    RSA is an assymetric encryption/decryption algorithm, which requires a public/private key pair. The secret is
    encrypted with the public key, and can only be decrypted with the corresponding private key. The secret being
    encrypted can't be larger than the RSA key pair's size/length, usually 1024, 2048, or 4096 bits (128, 256, and 512
    bytes, respectively). `Protect-CString` encrypts with .NET's `System.Security.Cryptography.RSACryptoServiceProvider`
    class.

    You can specify the public key in three ways:

     * by passing the `System.Security.Cryptography.X509Certificates.X509Certificate2` object to use to the
       `Certificate` parameter.
     * with a certificate in one of the Windows certificate stores. Pass its thumbprint to the `Thumbprint`
       parameter.
     * with an X509 certificate file. Pass the file's path to the `PublicKeyPath` parameter. You can also pass a
       certificate provider path to the `PublicKeyPath` parameter (e.g. `cert:`).

    You can generate an RSA public/private key pair with the `New-CRsaKeyPair` function.

    ## AES

    AES is a symmetric encryption/decryption algorithm. You supply a 16-, 24-, or 32-byte key/password/passphrase with
    the `Key` parameter, and that key is used to encrypt. There is no limit on the size of the data you want to encrypt.
    `Protect-CString` encrypts with the object returned by `[Security.Cryptography.Aes]::Create()`

    You can only pass a `[securestring]` or array of bytes as the key. The array of bytes must be 16, 24, or 32 bytes
    long. When passing a secure string, when UTF-8 encoded and converted to a byte array, it must also be 16, 24, or 32
    bytes long. You can use this code to check on the byte length of a plain text string (where $key is the plain text
    key):

        [Text.Encoding]::Convert([Text.Encoding]::Unicode, [Text.Encoding]::UTF8, [Text.Encoding]::Unicode.GetBytes($key)).Length

    Symmetric encryption requires a random, unique initialization vector (i.e. IV) everytime you encrypt something.
    `Protect-CString` generates one for you. This IV must be known to decrypt the secret, so it is pre-pendeded to the
    encrypted text.

    This code demonstrates how to generate a key:

        $key = [Security.Cryptography.AesManaged]::New().Key

    You can save this key as a string by encoding it as a base64 string:

        $base64EncodedKey = [Convert]::ToBase64String($key)

    If you base64 encode your key's bytes, they must be converted back to bytes before passing it to `Protect-CString`.

        Protect-CString -String 'the secret sauce' -Key ([Convert]::FromBase64String($base64EncodedKey))

    .LINK
    New-CRsaKeyPair

    .LINK
    Unprotect-CString

    .LINK
    http://msdn.microsoft.com/en-us/library/system.security.cryptography.protecteddata.aspx

    .EXAMPLE
    Protect-CString -String 'TheStringIWantToEncrypt' -ForUser | Out-File MySecret.txt

    Encrypts the given string and saves the encrypted string into MySecret.txt.  Only the user who encrypts the string
    can unencrypt it.

    .EXAMPLE
    Protect-CString -String $credential.Password -ForUser | Out-File MySecret.txt

    Demonstrates that `Protect-CString` can encrypt a `SecureString`.

    .EXAMPLE
    Protect-CString -String "MySuperSecretIdentity" -ForComputer

    Demonstrates how to encrypt a value that can only be decrypted on the current computer.

    .EXAMPLE
    Protect-CString -String 's0000p33333r s33333cr33333t' -Credential (Get-Credential 'builduser')

    Demonstrates how to use `Protect-CString` to encrypt a secret as a specific user. This is useful for situation where
    a secret needs to be encrypted by a user other than the user running `Protect-CString`. Encrypting as a specific
    user won't work over PowerShell remoting.

    .EXAMPLE
    Protect-CString -String 'the secret sauce' -Certificate $myCert

    Demonstrates how to encrypt a secret using RSA with a `System.Security.Cryptography.X509Certificates.X509Certificate2`
    object. You're responsible for creating/loading the certificate. The `New-CRsaKeyPair` function will create a key
    pair for you, if you've got a Windows SDK installed.

    .EXAMPLE
    Protect-CString -String 'the secret sauce' -Thumbprint '44A7C27F3353BC53F82318C14490D7E2500B6D9E'

    Demonstrates how to encrypt a secret using RSA with a certificate in one of the Windows certificate stores. All
    local machine and user stores are searched for the certificate with the given thumbprint that has a private key.

    .EXAMPLE
    Protect-CString -String 'the secret sauce' -PublicKeyPath 'C:\Projects\Security\publickey.cer'

    Demonstrates how to encrypt a secret using RSA with a certificate file. The file must be loadable by the
    `System.Security.Cryptography.X509Certificates.X509Certificate` class.

    .EXAMPLE
    Protect-CString -String 'the secret sauce' -PublicKeyPath 'cert:\LocalMachine\My\44A7C27F3353BC53F82318C14490D7E2500B6D9E'

    Demonstrates how to encrypt a secret using RSA with a certificate in the Windows certificate store, giving its exact
    path.

    .EXAMPLE
    Protect-CString -String 'the secret sauce' -Key 'gT4XPfvcJmHkQ5tYjY3fNgi7uwG4FB9j'

    Demonstrates how to encrypt a secret with a key, password, or passphrase. In this case, we are encrypting with a
    plaintext password.

    .EXAMPLE
    Protect-CString -String 'the secret sauce' -Key (Read-Host -Prompt 'Enter password (must be 16, 24, or 32 characters long):' -AsSecureString)

    Demonstrates that you can use a `SecureString` as the key, password, or passphrase.

    .EXAMPLE
    Protect-CString -String 'the secret sauce' -Key ([byte[]]@(163,163,185,174,205,55,157,219,121,146,251,116,43,203,63,38,73,154,230,112,82,112,151,29,189,135,254,187,164,104,45,30))

    Demonstrates that you can use an array of bytes as the key, password, or passphrase.
    #>
    [CmdletBinding()]
    param(
        # The string to encrypt. Any non-string object you pass will be converted to a string before encrypting by
        # calling the object's `ToString` method.
        #
        # This can also be a `SecureString` object. The `SecureString` is converted to an array of bytes, the bytes are
        # encrypted, then the plaintext bytes are cleared from memory (i.e. the plaintext password is in memory for the
        # amount of time it takes to encrypt it). Passing a secure string is the most secure usage.
        #
        # The string and secure string bytes are re-encoded as UTF-8 before encrypting.
        [Parameter(Mandatory, Position=0, ValueFromPipeline)]
        [Object] $String,

        # Encrypts for the current user so that only they can decrypt.
        [Parameter(Mandatory, ParameterSetName='DPAPICurrentUser')]
        [switch] $ForUser,

        # Encrypts for the current computer so that any user logged into the computer can decrypt.
        [Parameter(Mandatory, ParameterSetName='DPAPILocalMachine')]
        [switch] $ForComputer,

        # Encrypts for a specific user.
        [Parameter(Mandatory, ParameterSetName='DPAPIForUser')]
        [pscredential] $Credential,

        # The public key to use for encrypting.
        [Parameter(Mandatory, ParameterSetName='RsaByCertificate')]
        [Security.Cryptography.X509Certificates.X509Certificate2] $Certificate,

        # The thumbprint of the certificate, found in one of the Windows certificate stores, to use when encrypting. All
        # certificate stores are searched.
        [Parameter(Mandatory, ParameterSetName='RsaByThumbprint')]
        [String] $Thumbprint,

        # The path to the public key to use for encrypting. Must be to an `X509Certificate2` object.
        [Parameter(Mandatory, ParameterSetName='RsaByPath')]
        [String] $PublicKeyPath,

        # The padding mode to use when encrypting. When using an RSA public key, defaults to
        # [Security.Cryptography.RSAEncryptionPadding]::OaepSHA1.
        [Parameter(ParameterSetName='RsaByCertificate')]
        [Parameter(ParameterSetName='RsaByPath')]
        [Parameter(ParameterSetName='RsaByThumbprint')]
        [Security.Cryptography.RSAEncryptionPadding] $Padding,

        # The key to use to encrypt the secret. Must be a `[securestring]` or an array of bytes. If passing a byte
        # array, # must be 16, 24, or 32 bytes long. If passing a secure string, when it is UTF-8 encoded and converted
        # to a byte # array, that array must also be 16, 24, or 32 bytes long. This code will tell you the length, in
        # bytes, of your plain text key (stored in the `$key`variable):
        #
        #   [Text.Encoding]::Convert([Text.Encoding]::Unicode, [Text.Encoding]::UTF8, [Text.Encoding]::Unicode.GetBytes($key)).Length
        [Parameter(Mandatory, ParameterSetName='Symmetric')]
        [Object] $Key
    )

    process
    {
        Set-StrictMode -Version 'Latest'
        Use-CallerPreference -Cmdlet $PSCmdlet -Session $ExecutionContext.SessionState

        # We find and validate the certificate/key here so our try/catch block around actual encryption doesn't catch
        # these errors.
        [byte[]]$keyBytes = [byte[]]::New(0)
        if( $PSCmdlet.ParameterSetName -like 'Rsa*' )
        {
            if( $PSCmdlet.ParameterSetName -eq 'RsaByThumbprint' )
            {
                $Certificate = Get-CCertificate -Thumbprint $Thumbprint | Select-Object -First 1
                if (-not $Certificate)
                {
                    Write-Error "Certificate with thumbprint ""$($Thumbprint)"" not found."
                    return
                }
            }
            elseif( $PSCmdlet.ParameterSetName -eq 'RsaByPath' )
            {
                $Certificate = Get-CCertificate -Path $PublicKeyPath
                if( -not $Certificate )
                {
                    return
                }
            }

            $rsaKey = $Certificate.PublicKey.Key
            if( -not $rsaKey.GetType().IsSubclassOf([Security.Cryptography.RSA]) )
            {
                $msg = "Certificate ""$($Certificate.Subject)"" ($($Certificate.Thumbprint)) is not an RSA public " +
                    "key. Found a public key of type ""$($rsaKey.GetType().FullName)"", but expected type " +
                    """$([Security.Cryptography.RSACryptoServiceProvider].FullName)""."
                Write-Error $msg
                return
            }
        }
        elseif( $PSCmdlet.ParameterSetName -eq 'Symmetric' )
        {
            $keyBytes = ConvertTo-AesKey -InputObject $Key -From 'Protect-CString'
            if( -not $keyBytes )
            {
                return
            }
        }


        $stringBytes = [byte[]]::New(0)
        $unicodeBytes = [Text.Encoding]::Unicode.GetBytes( $String.ToString() )
        [byte[]]$encryptedBytes = [byte[]]::New(0)
        try
        {
            if( $String -is [securestring] )
            {
                $unicodeBytes = Convert-CSecureStringToByte -SecureString $String
            }
            # Unicode takes up two bytes, so the max length of strings we can encrypt is cut from about 472 characters
            # to 236. Let's re-encode in UTF-8, which only uses one byte per character. This also maintains
            # backwards-compatability with Carbon 2.
            $stringBytes = [Text.Encoding]::Convert([Text.Encoding]::Unicode, [Text.Encoding]::UTF8, $unicodeBytes)
        }
        finally
        {
            $unicodeBytes.Clear()
        }

        try
        {
            if( $PSCmdlet.ParameterSetName -like 'DPAPI*' )
            {
                if( $PSCmdlet.ParameterSetName -eq 'DPAPIForUser' )
                {
                    $protectStringPath = Join-Path -Path $moduleBinRoot -ChildPath 'Protect-CString.ps1' -Resolve
                    $encodedString = Protect-CString -String $String -ForComputer
                    $powershellArgs = @(
                        '-ExecutionPolicy',
                        'ByPass',
                        '-NonInteractive',
                        '-File',
                        $protectStringPath,
                        '-ProtectedString',
                        $encodedString
                    )
                    return Invoke-CPowerShell -ArgumentList $powershellArgs -Credential $Credential | Select-Object -First 1
                }
                else
                {
                    $scope = [Security.Cryptography.DataProtectionScope]::CurrentUser
                    if( $PSCmdlet.ParameterSetName -eq 'DPAPILocalMachine' )
                    {
                        $scope = [Security.Cryptography.DataProtectionScope]::LocalMachine
                    }

                    $encryptedBytes = [Security.Cryptography.ProtectedData]::Protect( $stringBytes, $null, $scope )
                }
            }
            elseif( $PSCmdlet.ParameterSetName -like 'Rsa*' )
            {

                if( -not $Padding )
                {
                    $Padding = [Security.Cryptography.RSAEncryptionPadding]::OaepSHA1
                }

                $encryptedBytes = $Certificate.PublicKey.Key.Encrypt($stringBytes, $Padding)
            }
            elseif( $PSCmdlet.ParameterSetName -eq 'Symmetric' )
            {
                $aes = [Security.Cryptography.Aes]::Create()
                try
                {
                    $aes.Padding = [Security.Cryptography.PaddingMode]::PKCS7
                    $aes.KeySize = $keyBytes.Length * 8
                    $aes.Key = $keyBytes

                    $memoryStream = [IO.MemoryStream]::New()
                    try
                    {
                        $cryptoStream =
                            [Security.Cryptography.CryptoStream]::New(
                                $memoryStream,
                                $aes.CreateEncryptor(),
                                ([Security.Cryptography.CryptoStreamMode]::Write)
                            )

                        try
                        {
                            $cryptoStream.Write($stringBytes, 0, $stringBytes.Length)
                        }
                        finally
                        {
                            $cryptoStream.Dispose()
                        }

                        $encryptedBytes = & {
                                                $aes.IV
                                                $memoryStream.ToArray()
                                            }
                    }
                    finally
                    {
                        $memoryStream.Dispose()
                    }
                }
                finally
                {
                    $aes.Dispose()
                }
            }

            return [Convert]::ToBase64String( $encryptedBytes )
        }
        catch
        {
            Write-Error -ErrorRecord $_ -ErrorAction $ErrorActionPreference
        }
        finally
        {
            if( $encryptedBytes )
            {
                $encryptedBytes.Clear()
            }

            if( $stringBytes )
            {
                $stringBytes.Clear()
            }

            if( $keyBytes )
            {
                $keyBytes.Clear()
            }
        }
    }
}
