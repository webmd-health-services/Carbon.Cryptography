
function Get-LocalCertificate{
    <#
    .SYNOPSIS
    Gets a list of certificates from the My store from the current user or local machine's certificates based on the OS

    .DESCRIPTION
    The `Get-LocalCertificate` function gets a list of certificates from the My store from the current user or local 
    machine's certificates. The list will be sorted by NotAfter date descending to put the longest valid certificates
    first. The store location will be LocalMachine for Windows and MacOS while on Linux it will be CurrentUser.

    .OUTPUTS
    List of certificates from the My store or `$null` if none are currently installed.

    .EXAMPLE
    Get-LocalCertificate

    Gets the list of certificates from the My store.
    #>

    $location = 'LocalMachine'
    if(Test-COperatingSystem -IsLinux){
        $location = 'CurrentUser'
    }

    $store = [Security.Cryptography.X509Certificates.X509Store]::New('My',$location)
    try
    {
        $store.Open('ReadOnly')
        $store.Certificates | Write-Output
        return $store.Certificates | Sort-Object -Property 'NotAfter' -Descending
    }
    catch
    {
        Write-Error -Message ("Invalid Store Location: " + $location)
    }
    finally
    {
        if( $store )
        {
            $store.Dispose()
        }
    }
}