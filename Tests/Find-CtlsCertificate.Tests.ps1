<#
    .SYNOPSIS
    Gets a certificate from the local machine's My store that matches a list of hostname being passed in as a parameter.

    .DESCRIPTION
    The `Find-CTlsCertificate` function gets a certificate from the local machine's My store. A list of hostnames are passed in 
    as a parameter. The certificates are ordered by NotAfter date descending so that the certificate with the longest valid date
    will be returned if there is a match. The hostnames are checked against the certificate's Subject Alternate Names and the first 
    match will be returned.

    .OUTPUTS
    Certificate that was found or `$null` if no match was found.

    .EXAMPLE
    Find-CTlsCertificate ("2.5.29.17", "2.6.19.34")

    Gets the first certificate object with a Subject Alternative Name matching any of the hostnames in our list.
    #>
    function Find-CTlsCertificate
    {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            # The hostname to be matched with a certificate's subject alternate name
            [String[]]$hostNames,
    
            [String]$path = "Cert:\LocalMachine\My"
        )
    
        Set-StrictMode -Version 'Latest'
        $ipProperties = [Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
        $serverFqdn = "$($ipProperties.HostName).$($ipProperties.DomainName)"
        $foundCert = $false
    
        <# Loop through certificates on local machine My store after ordering by NotAfter date descending to get
        certificate with longest valid date #>
        foreach( $certificate in (Get-ChildItem -Path $path | Sort-Object -Property NotAfter -Descending) )
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
            
            # Checking certificate's extensions for Subject Alternative Name matching hostnames
            foreach($extension in $certificate.Extensions)
            {
                if($extension.Oid.FriendlyName -eq "Subject Alternative Name")
                {
                    foreach($hostName in $hostNames)
                    {
                        if($Extension.Oid.Value -eq $hostName)
                        {
                            Write-Verbose -Message ("    Tls certificate matching hostname found.")
                            $foundCert = $true
                            return $certificate
                        }
                    }
                }
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
        }
    
        if( -not $foundCert )
        {
            Write-Error -Message ("Unable to find a trusted machine TLS certificate. See verbose output for more information.")
            return $null;
        }
    }
    
    function Init{
        [Object]$foundCertificate = Find-CTlsCertificate ("2.5.29.17")
    }
    
    Init