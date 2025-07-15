function Unprotect-CFileToken
{
    <#
    .SYNOPSIS
    Finds and decrypts all encrypted tokens within a file which were encrypted with `Protect-CString`.

    .DESCRIPTION
    The `Unprotect-CFileToken` function reads a file, finds all tokens matching the provided regular expression, and
    replaces each token with its decrypted plaintext value. The result is written back out to a file. Pass the file with
    encrypted tokens to the `Path` parameter and the destination path for the decrypted file to the `OutputPath`
    parameter. Pass the `Force` switch to overwrite an existing file.

    Encrypted tokens in the file must be in the format`!ENCRYPTED:ciphertext!` where `ciphertext` is the full ciphertext
    string for the encrypted secret. Use the `Protect-CString` function to protect a secret and get the resulting
    ciphertext string.

    For example, a file `Path` with content:

        username=AzureDiamond
        password=!ENCRYPTED:oW/mJYC1YExRNd1RwO8od3325EnuxHKO/n6+TUQKbU0=!

    Would be decrypted to `OutPath` with the content:

        username=AzureDiamond
        password=hunter2

    To customize the format of the token, pass a regular expression to the `TokenExpression`
    parameter. The regular expression must match the full token, which will be replaced, and must include one capture
    group for the ciphertext to decrypt within the token.

    If no tokens are found within the file, a warning is written and the file is written as-is to `OutputPath`.

    The function attempts to decrypt as many tokens as it can before writing the results to the output file. If
    decryption for a specific token fails: an error is written, the original token is left as-is, and the
    function continues to process subsequent tokens.

    .EXAMPLE
    Unprotect-CFileToken -Path ./config.ini -OutputPath ./config.decrypted.ini -Key $secretKey

    Finds all tokens like `!ENCRYPTED:ciphertext!` in "config.ini", decrypts them using the provided AES key,
    and saves the result to "config.decrypted.ini".

    .EXAMPLE
    Unprotect-CFileToken -Path ./config.ini -OutputPath ./config.ini -Key $secretKey -Force

    Decrypts tokens in "config.ini" and uses `-Force` to overwrite "config.ini" with the decrypted content.

    .EXAMPLE
    Unprotect-CFileToken -Path ./config.ini -OutputPath ./config.decrypted.ini -TokenExpression '\$\$(.+)\$\$'

    Decrypts tokens using a custom token format of `$$ciphertext$$` by passing a custom regular expression with a
    capture group to the `TokenExpression` parameter.

    .EXAMPLE
    Unprotect-CFileToken -Path ./config.ini -OutputPath ./config.decrypted.ini -Thumbprint 'B7826080B02DE2D2457A974C0AC6DE2B1E7ECF1A'

    Decrypts tokens using a certificate by passing its thumbprint to the `Thumbprint` parameter. The certificate's
    private key is read from the system's certificate store to decrypt the tokens. See `Unprotect-CString` for more
    information on certificate decryption.

    .EXAMPLE
    Unprotect-CFileToken -Path ./config.ini -OutputPath ./config.decrypted.ini -PrivateKeyPath 'private.key' -Password $privateKeyPass

    Decrypts tokens using a password-protected PKCS12 (PFX) certificate file by passing the path to the PFX file to the
    `PrivateKeyPath` parameter and the password to the `Password` parameter. See `Unprotect-CString` for more
    information on decryption using PKCS12 certificate files.
    #>
    [CmdletBinding(DefaultParameterSetName='DPAPI', SupportsShouldProcess)]
    param(
        # Path to the file with tokens to decrypt.
        [Parameter(Mandatory)]
        [String] $Path,

        # Path where the file with decrypted tokens is written to.
        [Parameter(Mandatory)]
        [String] $OutputPath,

        # The regular expression pattern identifying the token and the capture group for the cipher text within the token.
        [String] $TokenExpression = '!ENCRYPTED:([^!]+)!',

        # Overwrites an existing file at OutputPath.
        [switch] $Force,

        # The private key to use for decrypting.
        [Parameter(Mandatory, ParameterSetName='RSAByCertificate')]
        [Security.Cryptography.X509Certificates.X509Certificate2] $Certificate,

        # The thumbprint of the certificate, found in one of the Windows certificate stores, to use when decrypting. All
        # certificate stores are searched. The current user must have permission to the private key. Windows only.
        [Parameter(Mandatory, ParameterSetName='RSAByThumbprint')]
        [String] $Thumbprint,

        # The path to the private key to use for decrypting. If given a path on the file system, the file must be
        # loadable as a `[Security.X509Certificates.X509Certificate2]` object. On Windows, you can also pass the path
        # to a certificate in PowerShell's `cert:` drive.
        [Parameter(Mandatory, ParameterSetName='RSAByPath')]
        [String] $PrivateKeyPath,

        # The password for the private key, if it has one. Must be a `[securestring]`.
        [Parameter(ParameterSetName='RSAByPath')]
        [securestring] $Password,

        # The padding mode to use when decrypting. Defaults to `[Security.Cryptography.RSAEncryptionPadding]::OaepSHA1`.
        [Parameter(ParameterSetName='RSAByCertificate')]
        [Parameter(ParameterSetName='RSAByThumbprint')]
        [Parameter(ParameterSetName='RSAByPath')]
        [Security.Cryptography.RSAEncryptionPadding] $Padding,

        # The key to use to decrypt the secret. Must be a `[securestring]` or an array of bytes. The characters in the
        # secure string are converted to UTF-8 encoding before being converted into bytes. Make sure the key is the
        # correct length when UTF-8 encoded, i.e. make sure the following code returns a 16, 24, or 32 byte byte array
        # (where $key is the plain text key).
        #
        #     [Text.Encoding]::Convert([Text.Encoding]::Unicode, [Text.Encoding]::UTF8, [Text.Encoding]::Unicode.GetBytes($key)).Length
        [Parameter(Mandatory, ParameterSetName='Symmetric')]
        [Object] $Key
    )

    Set-StrictMode -Version 'Latest'
    Use-CallerPreference -Cmdlet $PSCmdlet -Session $ExecutionContext.SessionState

    $unprotectArgs = $PSBoundParameters
    $unprotectArgs.Remove('Path') | Out-Null
    $unprotectArgs.Remove('OutputPath') | Out-Null
    $unprotectArgs.Remove('TokenExpression') | Out-Null
    $unprotectArgs.Remove('Force') | Out-Null
    $unprotectArgs.Remove('WhatIf') | Out-Null

    # We handle the errors from Unprotect-CString
    $unprotectArgs.Remove('ErrorAction') | Out-Null

    # We always need plaintext back from Unprotect-CString to substitute it into the file content.
    $unprotectArgs['AsPlainText'] = $true


    if (-not (Test-Path -LiteralPath $Path -PathType Leaf))
    {
        $msg = "Path ""${Path}"" does not exist."
        Write-Error $msg -ErrorAction $ErrorActionPreference
        return
    }

    if ((Test-Path -LiteralPath $OutputPath) -and (-not $Force))
    {
        $msg = "OutputPath file ""${OutputPath}"" already exists. Use the -Force switch to overwrite."
        Write-Error $msg -ErrorAction $ErrorActionPreference
        return
    }

    $fileContent = Get-Content -LiteralPath $Path -Raw
    $tokenMatches = [regex]::Matches($fileContent, $TokenExpression)

    if ($tokenMatches.Count -eq 0)
    {
        Write-Warning "No encrypted tokens matching the regular expression /${TokenExpression}/ were found in ""${Path}""."
    }

    # Iterate backwards through the matches to preserve the index positions of earlier matches.
    # If we iterated forwards, each replacement would shift the string and invalidate subsequent match indexes.
    for ($i = $tokenMatches.Count - 1; $i -ge 0; $i--)
    {
        $match = $tokenMatches[$i]
        if ($match.Groups.Count -ne 2)
        {
            # This is a configuration error with the regex, so it should stop processing and return.
            $msg = "The regular expression /${TokenExpression}/ must contain one capture group to isolate the ciphertext."
            Write-Error $msg -ErrorAction $ErrorActionPreference
            return
        }

        try
        {
            $ciphertext = $match.Groups[1].Value

            # Use -ErrorAction Stop to ensure that any error from Unprotect-CString becomes a terminating
            # error that will be caught by our catch block.
            $plaintext = Unprotect-CString -ProtectedString $ciphertext @unprotectArgs -ErrorAction Stop

            $fileContent = $fileContent.Remove($match.Index, $match.Length).Insert($match.Index, $plaintext)
        }
        catch
        {
            $msg = "Failed to decrypt token ""$($match.Value)"", it will be left as-is. Underlying error: $($_.Exception.Message)"
            Write-Error $msg -ErrorAction $ErrorActionPreference
        }
    }

    if ($PSCmdlet.ShouldProcess($OutputPath, 'Write decrypted content'))
    {
        $parentDir = $OutputPath | Split-Path -Parent
        if (-not (Test-Path $parentDir) -and $Force)
        {
            New-Item -Path $parentDir -ItemType Directory -Force | Write-Verbose
        }

        [IO.File]::WriteAllText($OutputPath, $fileContent)
    }
}
