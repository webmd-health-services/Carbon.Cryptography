
function Find-CTlsCertificate
{
    <#
    .SYNOPSIS
    Gets a certificate from the My store from the current user or local machine's certificates that matches a list of 
    hostnames being passed in as a parameter.

    .DESCRIPTION
    The `Find-CTlsCertificate` function gets a certificate from the My store from the current user or local machine's
    certificates. A list of hostnames are passed in as a parameter. The certificates are ordered by NotAfter date 
    descending so that the certificate with the longest valid date will be returned if there is a match. The hostnames
    are checked against the certificate's Subject Alternate Names and the first match will be returned.

    .OUTPUTS
    System.Security.Cryptography.x509Certificates.X509Certificate2 that was found or `$null` if no match was found.

    .EXAMPLE
    Find-CTlsCertificate ("2.5.29.17", "2.6.19.34")

    Gets the first X509Certificate2 object with a Subject Alternative Name matching any of the hostnames in our list.
    #>

    [CmdletBinding()]
    [OutputType([Security.Cryptography.X509Certificates.X509Certificate2])]
    param(
        # The hostname to be matched with a certificate's subject alternate name.
        [Parameter(Mandatory)]
        [String[]] $HostName
    )

    Set-StrictMode -Version 'Latest'
    Use-CallerPreference -Cmdlet $PSCmdlet -Session $ExecutionContext.SessionState
    
    $ipProperties = [Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
    $serverFqdn = "$($ipProperties.HostName).$($ipProperties.DomainName)"
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

        if( $certificate.DnsNameList -contains $serverFqdn )
        {
            Write-Verbose -Message ("    $($serverFqdn)")
        }
        else
        {
            Write-Verbose -Message ("  ! $($serverFqdn) ($($certificate.DnsNameList -join ', '))")
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
        
        # Checking certificate's extensions for Subject Alternative Name matching hostnames
        foreach($extension in $certificate.Extensions)
        {
            if($extension.Oid.FriendlyName -ne "Subject Alternative Name")
            {
                continue
            }

            if( ($HostName | Where-Object { $_ -eq $Extension.Oid.Value }) )
            {
                Write-Verbose -Message ('^--------------------------------------^')
                return $certificate
            }
        }
    }

    Write-Error -Message ("Unable to find a trusted machine TLS certificate. See verbose output for more information.")
}