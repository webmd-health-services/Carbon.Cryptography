
function Get-CPrivateKey
{
    <#
    .SYNOPSIS
    Gets an X509 certificate's private key.

    .DESCRIPTION
    The `Get-CPrivateKey` function gets an X509 certificate's private key. It works across all PowerShell editions and
    platforms. Pipe the certificate (as a `Security.Cryptography.X509Certificates.X509Certificate2` object) or pass it
    to the `Certificate` parameter. The certificate's private key is returned. If the certificate does not have a
    private key (i.e. its `HasPrivateKey` property is `false`), then an error is written and nothing is returned.

    .EXAMPLE
    Get-Item -Path 'Cert:\CurrentUser\My\DEADBEEDEADBEEDEADBEEDEADBEEDEADBEEDEADB | Get-CPrivateKey

    Demonstrates how to pipe an X509 certificate object to `Get-CPrivateKey` to get its private key.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position=0, ValueFromPipeline)]
        [X509Certificate2] $Certificate
    )

    process
    {
        if (-not $Certificate.HasPrivateKey)
        {
            $msg = "Failed to get private key on certificate ""$($Certificate.Subject)"" " +
                   "($($Certificate.Thumbprint)) because it doesn't have a private key."
            Write-Error -Message $msg -ErrorAction $ErrorActionPreference
            return
        }

        if ($Certificate.PrivateKey)
        {
            return $Certificate.PrivateKey
        }

        try
        {
            return [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
        }
        catch
        {
            $msg = "Failed to get private key for certificate ""$($Certificate.Subject)"" " +
                   "($($Certificate.Thumbprint)): ${_}"
            Write-Error -Message $msg -ErrorAction $ErrorActionPreference
        }
    }
}
