
function Get-CCertificate
{
    <#
    .SYNOPSIS
    Gets a certificate from a file or the Windows certificate store.

    .DESCRIPTION
    The `Get-CCertificate` function gets an X509 certificate from a file or the Windows certificate store. When you 
    want to get a certificate from a file, pass the path to the `Path` parameter (wildcards allowed). If the certificate
    is password-protected, pass its password, as a `[securestring]`, to the `Password` parameter. If you plan on
    installing the certificate in a Windows certificate store, and you want to customize the key storage flags, pass
    the flags to the `KeyStorageFlags` parameter.

    If the path is to a certificate in PowerShell's certificate drive (i.e. the path begins with `cert:\`), the 
    `Password` and `KeyStorageFlags` are ignored. The certificate is returned. Wildcards allowed.

    You can search the Windows certificate stores for a certificate a specific thumbprint or friendly name by passing
    with the `Thumbprint` and `FriendlyName` parameters, respectively. `Get-CCertificate` will search all stores for all
    locations. If you know the store or location of the certificate, pass those to the `StoreName` and `StoreLocation`
    parameters, respectively. If the certificate is in a custom store, pass the store's name to the `CustomStoreName`
    parameter.

    `Get-CCertificate` adds a `Path` parameter which is the path where the certificate was loaded from the file system
    or the `cert:` path to the certificate in the Windows certificate store.

    .OUTPUTS
    System.Security.Cryptography.x509Certificates.X509Certificate2. The X509Certificate2 certificates that were found, or `$null`.

    .EXAMPLE
    Get-CCertificate -Path C:\Certificates\certificate.cer -Password MySuperSecurePassword
    
    Gets an X509Certificate2 object representing the certificate.cer file. Wildcards *not* supported when using a file
    system path.
    
    .EXAMPLE
    Get-CCertificate -Thumbprint a909502dd82ae41433e6f83886b00d4277a32a7b -StoreName My -StoreLocation LocalMachine
    
    Gets an X509Certificate2 object for the certificate in the Personal store with a specific thumbprint under the Local
    Machine.
    
    .EXAMPLE
    Get-CCertificate -FriendlyName 'Development Certificate' -StoreLocation CurrentUser -StoreName TrustedPeople
    
    Gets the X509Certificate2 whose friendly name is Development Certificate from the Current User's Trusted People
    certificate store.
    
    .EXAMPLE
    Get-CCertificate -Thumbprint $thumbprint -CustomStoreName 'SharePoint' -StoreLocation LocalMachine

    Demonstrates how to get a certificate from a custom store, i.e. one that is not part of the standard `StoreName`
    enumeration.

    .EXAMPLE
    Get-CCertificate -Path 'cert:\CurrentUser\a909502dd82ae41433e6f83886b00d4277a32a7b'

    Demonstrates how to get a certificate out of a Windows certificate store with its certificate path. Wildcards
    supported.
    #>
    [CmdletBinding(DefaultParameterSetName='ByFriendlyName')]
    [OutputType([Security.Cryptography.X509Certificates.X509Certificate2])]
    param(
        [Parameter(Mandatory, ParameterSetName='ByPath')]
        # The path to the certificate. Can be a file system path or a certificate path, e.g. `cert:\`. Wildcards supported.
        [String]$Path,
        
        [Parameter(ParameterSetName='ByPath')]
        # The password to the certificate. Can be plaintext or a [SecureString](http://msdn.microsoft.com/en-us/library/system.securestring.aspx).
        [securestring]$Password,

        [Parameter(ParameterSetName='ByPath')]
        # The storage flags to use when loading a certificate file. This controls where/how you can store the certificate in the certificate stores later. Use the `-bor` operator to combine flags.
        [Security.Cryptography.X509Certificates.X509KeyStorageFlags]$KeyStorageFlags,

        [Parameter(Mandatory, ParameterSetName='ByThumbprint')]
        [Parameter(Mandatory, ParameterSetName='ByThumbprintCustomStoreName')]
        # The certificate's thumbprint.
        [String]$Thumbprint,
        
        [Parameter(Mandatory, ParameterSetName='ByFriendlyName')]
        [Parameter(Mandatory, ParameterSetName='ByFriendlyNameCustomStoreName')]
        # The friendly name of the certificate.
        [String]$FriendlyName,
        
        [Parameter(Mandatory, ParameterSetName='ByFriendlyName')]
        [Parameter(Mandatory, ParameterSetName='ByFriendlyNameCustomStoreName')]
        [Parameter(Mandatory, ParameterSetName='ByThumbprint')]
        [Parameter(Mandatory, ParameterSetName='ByThumbprintCustomStoreName')]
        # The location of the certificate's store.
        [Security.Cryptography.X509Certificates.StoreLocation]$StoreLocation,
        
        [Parameter(Mandatory, ParameterSetName='ByFriendlyName')]
        [Parameter(Mandatory, ParameterSetName='ByThumbprint')]
        # The name of the certificate's store.
        [Security.Cryptography.X509Certificates.StoreName]$StoreName,

        [Parameter(Mandatory, ParameterSetName='ByFriendlyNameCustomStoreName')]
        [Parameter(Mandatory, ParameterSetName='ByThumbprintCustomStoreName')]
        # The name of the non-standard, custom store.
        [String]$CustomStoreName
    )

    Set-StrictMode -Version 'Latest'
    Use-CallerPreference -Cmdlet $PSCmdlet -Session $ExecutionContext.SessionState

    function Add-PathMember
    {
        param(
            [Parameter(Mandatory,VAlueFromPipeline=$true)]
            [Security.Cryptography.X509Certificates.X509Certificate2]
            $Certificate,

            [Parameter(Mandatory)]
            [string]
            $Path
        )

        process
        {
            $Certificate | Add-Member -MemberType NoteProperty -Name 'Path' -Value $Path -PassThru
        }
    }

    function Resolve-CertificateProviderFriendlyPath
    {
        param(
            [Parameter(Mandatory,ValueFromPipelineByPropertyName)]
            [string]
            $PSPath,

            [Parameter(Mandatory,ValueFromPipelineByPropertyName)]
            [Management.Automation.PSDriveInfo]
            $PSDrive
        )

        process
        {
            $qualifier = '{0}:' -f $PSDrive.Name
            $path = $PSPath | Split-Path -NoQualifier
            Join-Path -Path $qualifier -ChildPath $path
        }
    }
    
    if( $PSCmdlet.ParameterSetName -eq 'ByPath' )
    {
        if( -not (Test-Path -Path $Path -PathType Leaf) )
        {
            Write-Error ('Certificate ''{0}'' not found.' -f $Path)
            return
        }

        Get-Item -Path $Path | 
            ForEach-Object {
                $item = $_
                if( $item -is [Security.Cryptography.X509Certificates.X509Certificate2] )
                {
                    $certFriendlyPath = $item | Resolve-CertificateProviderFriendlyPath
                    return $item | Add-PathMember -Path $certFriendlyPath
                }
                elseif( $item -is [IO.FileInfo] )
                {
                    try
                    {
                        $ctorParams = @( $item.FullName, $Password )
                        if( $KeyStorageFlags )
                        {
                            $ctorParams += $KeyStorageFlags
                        }
                        return New-Object 'Security.Cryptography.X509Certificates.X509Certificate2' $ctorParams | Add-PathMember -Path $item.FullName
                    }
                    catch
                    {
                        $ex = $_.Exception
                        while( $ex.InnerException )
                        {
                            $ex = $ex.InnerException
                        }
                        Write-Error -Message ('Failed to create X509Certificate2 object from file ''{0}'': {1}' -f $item.FullName,$ex.Message)
                    }
                }
            }
    }
    else
    {
        $storeLocationPath = '*'
        if( $StoreLocation )
        {
            $storeLocationPath = $StoreLocation
        }
        
        $storeNamePath = '*'
        if( $PSCmdlet.ParameterSetName -like '*CustomStoreName' )
        {
            $storeNamePath = $CustomStoreName
        }
        else
        {
            $storeNamePath = $StoreName
            if( $StoreName -eq [Security.Cryptography.X509Certificates.StoreName]::CertificateAuthority )
            {
                $storeNamePath = 'CA'
            }
        }
        
        if( $pscmdlet.ParameterSetName -like 'ByThumbprint*' )
        {
            $certPath = 'cert:\{0}\{1}\{2}' -f $storeLocationPath,$storeNamePath,$Thumbprint
            if( (Test-Path -Path $certPath) )
            {
                foreach( $certPathItem in (Get-ChildItem -Path $certPath) )
                {
                    $path = $certPathItem | Resolve-CertificateProviderFriendlyPath
                    $certPathItem | Add-PathMember -Path $path
                }
            }
            return
        }
        elseif( $PSCmdlet.ParameterSetName -like 'ByFriendlyName*' )
        {
            $certPath = Join-Path -Path 'cert:' -ChildPath $storeLocationPath
            $certPath = Join-Path -Path $certPath -ChildPath $storeNamePath
            $certPath = Join-Path -Path $certPath -ChildPath '*'
            return Get-ChildItem -Path $certPath | 
                        Where-Object { $_.FriendlyName -eq $FriendlyName } |
                        ForEach-Object {
                            $friendlyPath = $_ | Resolve-CertificateProviderFriendlyPath
                            $_ | Add-PathMember -Path $friendlyPath
                        }
        }
        Write-Error "Unknown parameter set '$($pscmdlet.ParameterSetName)'."
    }
}

