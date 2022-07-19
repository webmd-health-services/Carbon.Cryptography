
function Find-TlsCertificate
{
    <#
    .SYNOPSIS
    Finds a TLS certificate that matches a hostname from the certificate stores.

    .DESCRIPTION
    The `Find-CTlsCertficate` function finds a TLS certificate for the current computer. It determines the computer's
    domain name/hostname using the `HostName` and `DomainName` properties from 
    `[System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()`. To get a certificate for a custom
    hostname, pass that hostname to the `HostName` parameter.

    The `Find-CTlsCertificate` function returns the first certificate that:

    * has a private key.
    * hasn't expired and whose start date is in the past
    * contains the `HostName` in its subject or Subject Alternative Name list.
    * has 'Server Authentication' in its enhanced key usage list or has no enhanced key usage metadata.

    Additionally, you can use the `-Trusted` switch to only return trusted certificates, i.e. certificates whose
    issuing certificate authorities in its cert chain are installed in the local machine or current user's [trusted
    certificate stores](https://docs.microsoft.com/en-us/dotnet/standard/security/cross-platform-cryptography#x509store).
    `Find-CTlsCertificate` calls the `Verify()` method on each `X509Certificate2` object to determine if that
    certificate is trusted.

    If multiple certificates are found, `Find-CTlsCertificate` will return the certificate that expires later. If no
    certificate is found, it writes an error and returns nothing.

    Use the `-Verbose` switch to see why a certificate is or isn't being found and selected by `Find-CTlsCertificate`.
    You'll see messages for each selection criteria and if a criterium isn't met, you'll see a `!` flag. For example,
    this verbose output from `Find-CTlsCertificate -HostName 'example.com' -Trusted -Verbose`

        VERBOSE: FCD157FCB753E2B388183C19021301B1739DF1E2
        VERBOSE: CN=sub.example.com
        VERBOSE:     private key      True
        VERBOSE:     start date       2021-10-18 15:43:23
        VERBOSE:     expiration date  2023-10-19 15:43:23
        VERBOSE:   ! hostname         ['sub.example.com']
        VERBOSE: 
        VERBOSE: 7F660D4F7201B8EB8F7F6AC2A0906253C240584F
        VERBOSE: CN=example.com
        VERBOSE:     private key      True
        VERBOSE:     start date       2021-10-18 15:43:23
        VERBOSE:     expiration date  2022-10-19 15:43:23
        VERBOSE:     hostname         ['example.com']
        VERBOSE:     key usage        Any
        VERBOSE:     trusted          True
        VERBOSE: ^--------------------------------------^

    shows that certificate `FCD157FCB753E2B388183C19021301B1739DF1E2` wasn't selected because its hostname didn't match
    the `example.com` hostname, but that certificate `7F660D4F7201B8EB8F7F6AC2A0906253C240584F` was selected because
    it matched all six criteria.

    .OUTPUTS
    System.Security.Cryptography.x509Certificates.X509Certificate2 that was found or `$null` if no match was found.

    .EXAMPLE
    Find-CTlsCertificate

    Demonstrates how to find a TLS certificate for the current computer using the computer's hostname and domain name
    as determined by the `[System.Net.NetworkInformation.IPGlobalProperties]` object returned by the 
    ``[System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()::GetIPGlobalProperties()` method.

    .EXAMPLE
    Find-CTlsCertificate -HostName 'example.com'

    Demonstrates how to find a valid TLS valid certificate for a hostname, in this example, `example.com`.

    .EXAMPLE
    Find-CTlsCertificate -HostName 'example.com' -Trusted

    Demonstrates how to find a valid *trusted* TLS certificate by using the `-Trusted` switch. Trusted certificates
    are issued by certificate authorities whose certificates (and all certificates in the certificate chain) are in the
    local machine or current user's [trusted certificate stores](https://docs.microsoft.com/en-us/dotnet/standard/security/cross-platform-cryptography#x509store).
    #>
    [CmdletBinding()]
    [OutputType([Security.Cryptography.X509Certificates.X509Certificate2])]
    param(
        # The hostname whose TLS certificate to find.
        [String] $HostName,

        # In addition to all other search criteria, if set, causes `Find-CTLSCertificate` to only return trusted 
        # certificates, i.e. certificates that are issued by a certificate authority installed in the local machine or
        # current user's [trusted certificate stores](https://docs.microsoft.com/en-us/dotnet/standard/security/cross-platform-cryptography#x509store).
        # `Find-CTlsCertificate` calls the `Verify()` method on each certificate to determine if a certificate is
        # trusted.
        [switch] $Trusted
    )

    Set-StrictMode -Version 'Latest'
    Use-CallerPreference -Cmdlet $PSCmdlet -Session $ExecutionContext.SessionState
    
    if( -not $HostName )
    {
        $ipProperties = [Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
        $HostName= "$($ipProperties.HostName).$($ipProperties.DomainName)"
    }

    $certificate =
        Find-Certificate -HostName $HostName `
                         -Active `
                         -HasPrivateKey `
                         -KeyUsageName 'Server Authentication' `
                         -Trusted:$Trusted |
        Sort-Object -Property 'NotAfter' -Descending |
        Select-Object -First 1
    
    if( $certificate )
    {
        return $certificate
    }

    $isTrustedMsg = ''
    if( $Trusted )
    {
        $isTrustedMsg = '* is trusted.' + [Environment]::NewLine
    }
    $msg = "TLS certificate for $($HostName) does not exist. Make sure there is a certificate in the My certificate " +
           'store for the LocalMachine or CurrentUser that:' + [Environment]::NewLine +
           ' ' + [Environment]::NewLine +
           '* has a private key' + [Environment]::NewLine +
           '* hasn''t expired and whose "NotBefore"/"Valid From" date is in the past' + [Environment]::NewLine +
           "* has subject ""CN=$($HostName)""; or whose Server Alternative Name contains ""$($HostName)""" +
           [Environment]::NewLine +
           '* has an enhanced key usage of "Server Authentication" (or no enhanced key usage ' +
           'metadata) ' + [Environment]::NewLine +
           $isTrustedMsg +
           ' ' + [Environment]::NewLine + 
           'Use the -Verbose switch to see why each certificate was rejected.'

    Write-Error -Message $msg -ErrorAction $ErrorActionPreference
}