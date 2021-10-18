
function Find-CTlsCertificate
{
    <#
    .SYNOPSIS
    Gets a certificate from the My store from the current user or local machine's certificates that matches a hostname
    being passed in as a parameter.

    .DESCRIPTION
    The `Find-CTlsCertificate` function returns the first certificate that:

    * has a private key.
    * hasn't expired and whose start date is in the past
    * contains the server's fully-qualified domain name in its DNS name list (the fully-qualified domain name is the
    hostname and domain name from `[Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()`).
    * has 'Server Authentication' in its enhanced key usage list.
    * is trusted by the local computer (i.e. its 
    `System.Security.Cryptography.X509Certificates.X509Certificate2.Verify()` method returns `true`.
    * the certificate's subject alternate name contains the hostname passed in.

    .OUTPUTS
    System.Security.Cryptography.x509Certificates.X509Certificate2 that was found or `$null` if no match was found.

    .EXAMPLE
    Find-CTlsCertificate -Hostaname ("example.com")

    Gets the first X509Certificate2 object with a Subject Alternative Name matching the hostname.
    #>

    [CmdletBinding()]
    [OutputType([Security.Cryptography.X509Certificates.X509Certificate2])]
    param(
        # The hostname to be matched with a certificate's subject alternate name.
        [Parameter]
        [String] $HostName
    )

    Set-StrictMode -Version 'Latest'
    Use-CallerPreference -Cmdlet $PSCmdlet -Session $ExecutionContext.SessionState
    
    if( -not $HostName )
    {
        $ipProperties = [Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
        $HostName= "$($ipProperties.HostName).$($ipProperties.DomainName)"
    }

    $installedCertificates = [Collections.ArrayList]::new()

    $installedCertificates = Get-LocalCertificate | Sort-Object -Property 'NotAfter' -Descending

    # Loop through certificates on local machine My store after ordering by NotAfter date descending to get
    # certificate with longest valid date
    foreach( $certificate in $installedCertificates )
    {
        Write-Verbose -Message ("$($certificate.Thumbprint)  $($certificate.SubjectName.Name)")
        if( $certificate.HasPrivateKey )
        {
            Write-Verbose -message ("    private key")
        }
        else
        {
            Write-Verbose -Message ("  ! private key")
            continue
        }

        if( $certificate.NotBefore -lt  (Get-Date) )
        {
            Write-Verbose -Message "   not before"
        }
        else
        {
            Write-Verbose -Message "  ! not before  $($certificate.NotBefore.ToString('yyyy-MM-dd HH:mm:ss'))"
            continue
        }

        if( (Get-Date) -lt $certificate.NotAfter )
        {
            Write-Verbose -Message "   not after"
        }
        else
        {
            Write-Verbose -Message "  ! not after  $($certificate.NotAfter.ToString('yyyy-MM-dd HH:mm:ss'))"
            continue
        }

        if( $certificate.DnsNameList -contains $HostName )
        {
            Write-Verbose -Message ("    $($HostName)")
        }
        else
        {
            Write-Verbose -Message ("  ! $($HostName) ($($certificate.DnsNameList -join ', '))")
            continue
        }

        if( $certificate.EnhancedKeyUsageList | Where-Object { $_.FriendlyName -eq 'Server Authentication' } )
        {
            Write-Verbose -Message ("    Server Authentication")
        }
        else
        {
            Write-Verbose -Message ("  ! Server Authentication  ($($certificate.EnhancedKeyUsageList -join ','))")
            continue
        }

        # Do this last as it can be slow.
        if( $certificate.Verify() )
        {
            Write-Verbose -Message ("    verified")
        }
        else
        {
            Write-Verbose -Message ("  ! verified")
            continue
        }
        
        Write-Verbose -Message ('^--------------------------------------^')
        return $certificate
    }

    $msg = "HTTPS certificate for $($HostName) does not exist. Make sure there is a certificate in the the LocalMachine " +
       'or CurrentUser My certificate stores that:' + [Environment]::NewLine +
       ' ' + [Environment]::NewLine +
       '* has a private key' + [Environment]::NewLine +
       '* hasn''t expired and whose "NotBefore"/"Valid From" date is in the past' + [Environment]::NewLine +
       "* has subject ""CN=$($HostName)""; or whose Server Alternative Names contains ""$($HostName)""" +
       [Environment]::NewLine +
       '* has an enhanced key usage of "Server Authentication"' +
       '* is trusted.' + [Environment]::NewLine +
       ' ' + [Environment]::NewLine + 
       'Use the -Verbose switch to see why each certificate was rejected.'

    Write-Error -Message $msg
}