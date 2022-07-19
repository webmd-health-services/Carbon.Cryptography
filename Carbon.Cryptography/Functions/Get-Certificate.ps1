
function Get-Certificate
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

    On Windows, the path can also be a path to a certificate in PowerShell's certificate drive (i.e. the path begins
    with `cert:\`). When getting a path in the `cert:` drive, the `Password` and `KeyStorageFlags` parameters are
    ignored. The certificate is returned. Wildcards allowed.

    When called with no parameters, `Get-CCertificate` returns all certificates in all certificate locations and stores
    (except stores with custom names). You can filter what certificates to return using any combination of these
    parameters. A certificate must match all filters to be returned.

    * `StoreLocation`: only return certificates in one of the store locations, `CurrentUser` or `LocalMachine`.
    * `StoreName`: only return certificates from this store. Can't be used with `CustomStoreName`.
    * `CustomStoreName`: only return certificates from this custom store name. Can't be used with `StoreName`.
    * `Subject`: only return certificates with this subject. Wildcards allowed.
    * `LiteralSubject`: only return certificates with this exact subject.
    * `Thumbprint`: only return certificates with this thumbprint. Wildcards allowed.
    * `FriendlyName`: only return certificates with this friendly name. Wildcards allowed. Friendly names are
      Windows-only. If you pass a friendly name on other platforms, you'll get no certificates back.
    * `LiteralFriendlyName`: only return certificates with this exact friendly name. Friendly names are Windows-only. If
      you pass a friendly name on other platforms, you'll get no certificates back.

    `Get-CCertificate` adds a `Path` property to the returned objects that is the file system path where the certificate
    was loaded from, or, if loaded from a Windows certificate store, the path to the certificate in the `cert:` drive.

    When loading certificates from a certificate store, `Get-CCertificate` adds `StoreLocation` and `StoreName`
    properties for the store where the certificate was found.

    .OUTPUTS
    System.Security.Cryptography.x509Certificates.X509Certificate2. The X509Certificate2 certificates that were found,
    or `$null`.

    .EXAMPLE
    Get-CCertificate -Path C:\Certificates\certificate.cer -Password MySuperSecurePassword

    Gets an X509Certificate2 object representing the certificate.cer file.

    .EXAMPLE
    Get-CCertificate -Thumbprint a909502dd82ae41433e6f83886b00d4277a32a7b -StoreName My -StoreLocation LocalMachine

    Gets an X509Certificate2 object for the certificate in the Personal store with a specific thumbprint under the Local
    Machine.

    .EXAMPLE
    Get-CCertificate

    Demonstrates how to get all certificates in all current user and local machine stores.

    .EXAMPLE
    Get-CCertificate -Thumbprint a909502dd82ae41433e6f83886b00d4277a32a7b

    Demonstrates how to find certificates with a given thumbprints.

    .EXAMPLE
    Get-CCertificate -StoreLocation CurrentUser

    Demonstrates how to get all certificates for a specific location.

    .EXAMPLE
    Get-CCertificate -StoreName My

    Demonstrates how to get all certificates from a specific store.

    .EXAMPLE
    Get-CCertificate -Subject 'CN=Carbon.Cryptography'

    Demonstrates how to find all certificates in all stores that have a specific subject.

    .EXAMPLE
    Get-CCertificate -LiteralSubject 'CN=*.example.com'

    Demonstrates how to find a certificate that has wildcards in its subject using the `LiteralSubject` parameter.

    .EXAMPLE
    Get-CCertificate -Thumbprint $thumbprint -CustomStoreName 'SharePoint' -StoreLocation LocalMachine

    Demonstrates how to get a certificate from a custom store, i.e. one that is not part of the standard `StoreName`
    enumeration.

    .EXAMPLE
    Get-CCertificate -FriendlyName 'My Friendly Name'

    Demonstrates how to get all certificates with a specific friendly name. Friendly names are Windows-only. No
    certificates will be returned when using this parameter on non-Windows platforms.

    .EXAMPLE
    Get-CCertificate -LiteralFriendlyName '*My Friendly Name'

    Demonstrates how to find a certificate that has wildcards in its subject using the `LiteralFriendlyName` parameter.

    .EXAMPLE
    Get-CCertificate -Path 'cert:\CurrentUser\a909502dd82ae41433e6f83886b00d4277a32a7b'

    Demonstrates how to get a certificate out of a Windows certificate store with its certificate path. Wildcards
    supported. The `cert:` drive only exists on Windows. If you use a `cert:` path on non-Windows platforms, you'll get
    an error.
    #>
    [CmdletBinding(DefaultParameterSetName='FromCertificateStore')]
    [OutputType([Security.Cryptography.X509Certificates.X509Certificate2])]
    param(
        # The path to the certificate. On Windows, this can also be a certificate path, e.g. `cert:\`. Wildcards
        # supported.
        [Parameter(Mandatory, ParameterSetName='ByPath', Position=0)]
        [String] $Path,

        # The password to the certificate. Must be a `[securestring]`.
        [Parameter(ParameterSetName='ByPath')]
        [securestring] $Password,

        # The storage flags to use when loading a certificate file. This controls where/how you can store the
        # certificate in the certificate stores later. Use the `-bor` operator to combine flags.
        [Parameter(ParameterSetName='ByPath')]
        [Security.Cryptography.X509Certificates.X509KeyStorageFlags] $KeyStorageFlags,

        # The certificate's thumbprint. Wildcards allowed.
        [Parameter(ParameterSetName='FromCertificateStore')]
        [Parameter(ParameterSetName='FromCertificateStoreCustomStore')]
        [String] $Thumbprint,

        # The subject of the certificate. Wildcards allowed.
        [Parameter(ParameterSetName='FromCertificateStore')]
        [Parameter(ParameterSetName='FromCertificateStoreCustomStore')]
        [String] $Subject,

        # The literal subject of the certificate.
        [Parameter(ParameterSetName='FromCertificateStore')]
        [Parameter(ParameterSetName='FromCertificateStoreCustomStore')]
        [String] $LiteralSubject,

        # The friendly name of the certificate. Wildcards allowed. Friendly name is Windows-only. If you search by
        # friendly name on other platforms, you'll never get any certificates back.
        [Parameter(ParameterSetName='FromCertificateStore')]
        [Parameter(ParameterSetName='FromCertificateStoreCustomStore')]
        [String] $FriendlyName,

        # The literal friendly name of the certificate. Friendly name is Windows-only. If you search by friendly name on
        # other platforms, you'll never get any certificates back.
        [Parameter(ParameterSetName='FromCertificateStore')]
        [Parameter(ParameterSetName='FromCertificateStoreCustomStore')]
        [String] $LiteralFriendlyName,

        # The location of the certificate's store.
        [Parameter(ParameterSetName='FromCertificateStore')]
        [Parameter(ParameterSetName='FromCertificateStoreCustomStore')]
        [Security.Cryptography.X509Certificates.StoreLocation] $StoreLocation,

        # The name of the certificate's store.
        [Parameter(ParameterSetName='FromCertificateStore')]
        [Security.Cryptography.X509Certificates.StoreName] $StoreName,

        # The name of the non-standard, custom store.
        [Parameter(Mandatory, ParameterSetName='FromCertificateStoreCustomStore')]
        [String] $CustomStoreName
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
            Write-Error -Message "Certificate ""$($Path)"" not found." -ErrorAction $ErrorActionPreference
            return
        }

        foreach( $item in (Get-Item -Path $Path) )
        {
            Write-Debug -Message $PSCmdlet.GetUnresolvedProviderPathFromPSPath($item.PSPath)
            if( $item -is [Security.Cryptography.X509Certificates.X509Certificate2] )
            {
                $certFriendlyPath = $item | Resolve-CertificateProviderFriendlyPath
                $item | Add-PathMember -Path $certFriendlyPath | Write-Output
            }
            elseif( $item -is [IO.FileInfo] )
            {
                try
                {
                    $ctorParams = @($item.FullName, $Password )
                    if( $PSBoundParameters.ContainsKey('KeyStorageFlags') )
                    {
                        # macOS doesn't allow ephemeral key storage, which is kind of weird but whatever.
                        if( (Test-COperatingSystem -MacOS) )
                        {
                            $KeyStorageFlags = 
                                $KeyStorageFlags -band -bnot [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet
                        }
                        $ctorParams += $KeyStorageFlags
                    }
                    New-Object 'Security.Cryptography.X509Certificates.X509Certificate2' -ArgumentList $ctorParams | 
                        Add-PathMember -Path $item.FullName |
                        Write-Output
                }
                catch
                {
                    $ex = $_.Exception
                    while( $ex.InnerException )
                    {
                        $ex = $ex.InnerException
                    }
                    $msg = "[$($ex.GetType().FullName)] exception creating X509Certificate2 object from file " +
                           """$($item.FullName)"": $($ex)"
                    Write-Error -Message $msg -ErrorAction $ErrorActionPreference
                }
            }
        }
        return
    }

    $foundCerts = @{}
    Write-Debug -Message "[$($MyInvocation.MyCommand.Name)]"
    $locationWildcard = '*'
    if( $StoreLocation )
    {
        $locationWildcard = $StoreLocation.ToString()
    }

    $storeNameWildcard = '*'
    if( $StoreName )
    {
        $storeNameWildcard = $StoreName.ToString()
    }
    Write-Debug -Message "  $($locationWildcard)\$($storeNameWildcard)"

    # If we're searching for a certificate, don't write an error if one isn't found. Only write an error if the user
    # is looking for a specific certificate in a specific location and store.
    $searching = [Management.Automation.WildcardPattern]::ContainsWildcardCharacters($Thumbprint) -or `
                 [Management.Automation.WildcardPattern]::ContainsWildcardCharacters($FriendlyName) -or `
                 [Management.Automation.WildcardPattern]::ContainsWildcardCharacters($Subject) -or `
                 $locationWildcard -eq '*' -or `
                 ($storeNameWildcard -eq '*' -and -not $CustomStoreName)
                 
    [Security.Cryptography.X509Certificates.StoreLocation] $currentUserLocation =
        [Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
    [Security.Cryptography.X509Certificates.StoreLocation] $localMachineLocation =
        [Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine

    $result = @()
    @($currentUserLocation, $localMachineLocation) |
        Where-Object { $_.ToString() -like $locationWildcard } |
        ForEach-Object {
            $location = $_
            Write-Debug -Message "  $($location)"

            if( $CustomStoreName )
            {
                try
                {
                    Write-Debug -Message "    $($CustomStoreName)"
                    [Security.Cryptography.X509Certificates.X509Store]::New($CustomStoreName, $location) |
                        Write-Output
                }
                catch
                {
                    $msg = "Failed to open ""$($location)\$($CustomStoreName)"" custom store: $($_)"
                    Write-Error -Message $msg -ErrorAction $ErrorActionPreference
                }
                return
            }

            Write-Debug -Message "    $($storeNameWildcard)"

            [Enum]::GetValues([Security.Cryptography.X509Certificates.StoreName]) |
                Where-Object { $_.ToString() -like $storeNameWildcard } |
                ForEach-Object {
                    $name = $_
                    try
                    {
                        [Security.Cryptography.X509Certificates.X509Store]::New($name, $location) |
                            Write-Output
                    }
                    catch
                    {
                        $ex = $_.Exception
                        while( $ex.InnerException )
                        {
                            $ex = $ex.InnerException
                        }
                        $msg = "Exception opening ""$($location)\$($name)"" store: " +
                               "[$($ex.GetType().FullName)]: $($ex)"
                        Write-Error -Message $msg -ErrorAction $ErrorActionPreference
                    }
                }
        } |
        Foreach-Object {
            $openFlags = [Security.Cryptography.X509Certificates.OpenFlags]::OpenExistingOnly -bor `
                         [Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly

            [Security.Cryptography.X509Certificates.X509Store] $store = $_
            try
            {
                $store.Open($openFlags)
                $storeNamePropValue = $store.Name
                if( -not $CustomStoreName )
                {
                    if( $storeNamePropValue -eq 'CA' )
                    {
                        $storeNamePropValue = [Security.Cryptography.X509Certificates.StoreName]::CertificateAuthority
                    }
                    else
                    {
                        $storeNamePropValue = [Security.Cryptography.X509Certificates.StoreName]$storeNamePropValue
                    }
                }
                Write-Debug "      $($store.Location)  $($store.Name)"
                $store.Certificates |
                    Add-Member -MemberType NoteProperty -Name 'StoreLocation' -Value $store.Location -PassThru |
                    Add-Member -MemberType NoteProperty -Name 'StoreName' -Value $storeNamePropValue -PassThru |
                    Add-Member -MemberType ScriptProperty -Name 'Path' -Value {
                        if( -not (Test-Path -Path 'cert:') )
                        {
                            return
                        }

                        $storeNamePath = $this.StoreName
                        if( $storeNamePath.ToString() -eq 'CertificateAuthority' )
                        {
                            $storeNamePath = 'CA'
                        }

                        $path = Join-Path -Path 'cert:' -ChildPath $this.StoreLocation
                        $path = Join-Path -Path $path -ChildPath $storeNamePath
                        $path = Join-Path -Path $path -ChildPath $this.Thumbprint
                        return $path
                    } -PassThru
            }
            # Store doesn't exist.
            catch [Security.Cryptography.CryptographicException]
            {
                $Global:Error.RemoveAt(0)
            }
            catch
            {
                $ex = $_.Exception
                while( $ex.InnerException )
                {
                    $ex = $ex.InnerException
                }
                $msg = "[$($ex.GetType().FullName)] exception opening and iterating certificates in " +
                       """$($store.Location)\$($store.Name)"" store: $($ex)"
                Write-Error -Message $msg -ErrorAction $ErrorActionPreference
            }
            finally
            {
                $store.Dispose()
            }
        } |
        Where-Object {
            $key = "$($_.StoreLocation)\$($_.StoreName)\$($_.Thumbprint)"
            if( $foundCerts.ContainsKey($key) )
            {
                return $false
            }
            $foundCerts[$key] = $_
            return $true
        } |
        Where-Object {
            if( -not $Subject )
            {
                return $true
            }
            return $_.Subject -like $Subject
        } |
        Where-Object {
            if( -not $LiteralSubject )
            {
                return $true
            }

            return $_.Subject -eq $LiteralSubject
        } |
        Where-Object {
            if( -not $Thumbprint )
            {
                return $true
            }
            return $_.Thumbprint -like $Thumbprint
        } |
        Where-Object {
            if( -not $FriendlyName )
            {
                return $true
            }
            return $_.FriendlyName -like $FriendlyName
        } |
        Where-Object {
            if( -not $LiteralFriendlyName )
            {
                return $true
            }
            return $_.FriendlyName -eq $LiteralFriendlyName
        } |
        ForEach-Object { $_.pstypenames.Insert(0, 'Carbon.Cryptography.X509Certificate2') ; $_ } |
        Tee-Object -Variable 'result' |
        Write-Output

    if( -not $searching -and -not $result )
    {
        $fields = [Collections.ArrayList]::New()
        if( $Subject )
        {
            $field = "Subject like ""$($Subject)"""
            [void]$fields.Add($field)
        }

        if( $LiteralSubject )
        {
            $field = "Subject equal ""$($LiteralSubject)"""
            [void]$fields.Add($field)
        }

        if( $Thumbprint )
        {
            $field = "Thumbprint like ""$($Thumbprint)"""
            [void]$fields.Add($field)
        }

        if( $FriendlyName )
        {
            $field = "Friendly Name like ""$($FriendlyName)"""
            [void]$fields.Add($field)
        }

        if( $LiteralFriendlyName )
        {
            $field = "Friendly Name equal ""$($LiteralFriendlyName)"""
            [void]$fields.Add($field)
        }

        if( $StoreName )
        {
            $storeDisplayName = $StoreName.ToString()
        }
        elseif( $CustomStoreName )
        {
            $storeDisplayName = "$($CustomStoreName) custom"
        }

        $lastField = ''
        if( $fields.Count -gt 1 )
        {
            $lastField = ", and $($fields[-1])"
            $fields = $fields[0..($fields.Count - 2)]
        }

        $msg = "Certificate with $($fields -join ', ')$($lastField) does not exist in the $($StoreLocation)\" +
               "$($storeDisplayName) store."
        Write-Error -Message $msg -ErrorAction $ErrorActionPreference
    }
}

