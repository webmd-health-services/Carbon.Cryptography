
function Convert-CCertificateProvider
{
    <#
    .SYNOPSIS
    Converts the provider of a certificate's private key.

    .DESCRIPTION
    The `Convert-CCertificateProvider` function changes the provider of a certificate's private key. Pass the path to
    the certificate file to the `FilePath` parameter, and the new provider name to the `ProviderName` parameter. If the
    certificate file is password-protected, pass the password to the `Password` parameter.

    If the private key's provider is already the value passed to the function, nothing happens.

    The function uses the `certutil` command to import the certificate with its private key into a "Temp" store for the
    current user using the new provider. This command actually does the conversion process. Then,
    `Convert-CCertificateProvider` exports the certificate, overwriting the original file. (If the `Password` parameter
    has a value, the certificate file is password-protected with that password.) The temporary certificate is removed
    from the current user's "Temp" store. Finally, the function returns an object with the following properties:

    * `Path`: the path to the file that was converted
    * `OldProviderName`: the name of the private key's original/old provider name
    * `NewProviderName`: the name of the private key's new provider
    * `NewCertificateBase64Encoded`: the raw bytes of the new certificate file, base-64 encoded.

    The `certutil -csplist` shows a list of available cryptographic providers.

    .EXAMPLE
    Convert-CCertificateProvider -FilePath .\mycert.pfx -ProviderName 'Microsoft Enhanced RSA and AES Cryptographic Provider'

    Demonstrates how to convert the provider of a certificate's private key and the certificate file is ***not***
    password protected.

    .EXAMPLE
    Convert-CCertificateProvider -FilePath .\mycert.pfx -ProviderName 'Microsoft Enhanced RSA and AES Cryptographic Provider' -Password $password

    Demonstrates how to convert the provider of a certificate's private key and the certificate file ***is*** password
    protected. The password *must* be a `[securestring]`.
    #>
    [CmdletBinding()]
    param(
        # The path to the certificate file to convert. Must have a private key.
        [Parameter(Mandatory)]
        [String] $FilePath,

        # The new provider name for the certifcate's private key. The `certutil -csplist` command shows the list of
        # available cryptographic providers.
        [Parameter(Mandatory)]
        [String] $ProviderName,

        # The password for the certificate file, if any. When replacing the existing certificate file, it will be
        # protected with the same password (or not protected if no password is passed).
        [securestring] $Password
    )

    Set-StrictMode -Version 'Latest'
    Use-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    if (-not (Get-Command -Name 'certutil' -ErrorAction Ignore))
    {
        "Unable to convert provider for certificate ""$($FilePath)"" because the certutil.exe command does not exist " +
            'or is not in the current PATH.' | Write-Error -ErrorAction $ErrorActionPreference
        return
    }

    if (-not (Test-Path -Path $FilePath -PathType Leaf))
    {
        "Unable to convert provider for certificate ""$($FilePath)"" because it does not exist." |
            Write-Error -ErrorAction $ErrorActionPreference
        return
    }

    $FilePath = $FilePath | Resolve-Path | Select-Object -ExpandProperty 'ProviderPath'

    $pwdArg = @{}
    if ($Password)
    {
        $pwdArg['Password'] = $Password
    }
    $cert = Get-CCertificate -Path $FilePath @pwdArg

    if (-not $cert.PrivateKey)
    {
        "Unable to convert provider for certificate ""$($FilePath)"" because the certificate does not have a private " +
        'key.' |
            Write-Error -ErrorAction $ErrorActionPreference
        return
    }

    $pk = $cert.PrivateKey
    $pkProviderName = ''
    if ($pk | Get-Member 'Key')
    {
        $pkProviderName = $pk.Key.Provider.Provider
    }
    elseif ($pk | Get-Member 'CspKeyContainerInfo')
    {
        $pkProviderName = $pk.CspKeyContainerInfo.ProviderName
    }
    else
    {
        "Unable to convert provider for certificate ""$($FilePath)"" because it does not have a supported private key " +
            'implementation.' | Write-Error -ErrorAction $ErrorActionPreference
        return
    }

    if ($pkProviderName -eq $ProviderName)
    {
        return [pscustomobject]@{
            Path = $FilePath;
            OldProviderName = $pkProviderName;
            NewProviderName = $ProviderName;
            NewCertificateBase64Encoded = ([IO.File]::ReadAllBytes($FilePath) | ConvertTo-CBase64);
        }
        return
    }

    Write-Verbose "Importing ""$($FilePath)"" into temporary certificate store using provider ""$($ProviderName)""."
    $certUtilArgs = & {
        '-user'
        '-csp'
        $ProviderName
        if ($Password)
        {
            '-p'
            Convert-CSecureStringToString -SecureString $Password
        }
        '-ImportPfx'
        'Temp'
        $FilePath
        'AT_KEYEXCHANGE,NoRoot'
    }

    $output = '' | certutil $certUtilArgs
    if ($LASTEXITCODE)
    {
        $msg = "Failed to convert provider for ""$($FilePath)"" because the certutil conversion command failed:" +
               $([Environment]::NewLine) +
               $output
        Write-Error -Message $msg -ErrorAction $ErrorActionPreference
        return
    }

    $certPath = Join-Path -Path 'Cert:\CurrentUser\Temp\' -ChildPath $cert.Thumbprint
    $cert = Get-Item -Path $certPath
    if (-not $cert)
    {
        "Failed to convert provider for imported certificate ""$($certPath)"" because the certificate failed to " +
            'import.' | Write-Error -ErrorAction $ErrorActionPreference
        return
    }

    try
    {
        [byte[]] $certBytes = $cert.Export([Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $Password)
    }
    finally
    {
        Remove-Item -Path $certPath -Force
    }

    Write-Verbose "Exporting ""$($certPath)"" to ""$($FilePath)""."
    [IO.File]::WriteAllBytes($FilePath, $certBytes)

    $certBase64 = $certBytes | ConvertTo-CBase64

    return [pscustomobject]@{
        Path = $FilePath;
        OldProviderName = $pkProviderName;
        NewProviderName = $ProviderName;
        NewCertificateBase64Encoded = $certBase64;
    }
}
