
function Install-CCertificate
{
    <#
    .SYNOPSIS
    Installs an X509 certificate.
    
    .DESCRIPTION
    The `Install-CCertificate` function installs an X509 certificate. It uses the .NET X509 certificates API. The user 
    performing the action must have permission to modify the store or the installation will fail. You can install from
    a file (pass the path to the file to the `-Path` parameter), or from an `X509Certificate2` object (pass it to the
    `-Certificate` parameter). Pass the store location (LocalMachine or CurrentUser) to the `-StoreLocation` parameter.
    Pass the store name (e.g. My, Root) to the `-StoreName` parameter. If the certificate has a private key and you want
    the private key exportable, use the `-Exportable` switch.

    If the certificate already exists in the store, nothing happens. If you want to re-install the certificate over any
    existing certificates, use the `-Force` switch.

    If installing a certificate from a file, and the file is password-protected, use the `-Password` parameter to pass
    the certificate's password. The password must be a `[securestring]`.

    This function only works on Windows.

    To install a certificate on a remote computer, create a remoting session with the `New-PSSession` cmdlet, and pass
    the session object to this function's `Session` parameter. When installing to a remote computer, the certificate's
    binary data is converted to a base64 encoded string and sent to the remote computer, where it is converted back
    into a certificate. If installing a certificate from a file, the file's bytes are converted to base64, sent to the
    remote computer, saved as a temporary file, installed, and the temporary file is removed.

    .OUTPUTS
    System.Security.Cryptography.X509Certificates.X509Certificate2. An X509Certificate2 object representing the newly installed certificate.
    
    .EXAMPLE
    Install-CCertificate -Path 'C:\Users\me\certificate.cer' -StoreLocation LocalMachine -StoreName My -Exportable -Password $securePassword
    
    Demonstrates how to install a password-protected certificate from a file and to allow its private key to be
    exportable.
    
    .EXAMPLE
    Install-CCertificate -Path C:\Users\me\certificate.cer -StoreLocation LocalMachine -StoreName My -Session $session
    
    Demonstrates how to install a certificate from a file on the local computer into the local machine's personal store
    on a remote cmoputer. You can pass multiple sessions to the `Session` parameter.
    #>
    [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName='FromFileInWindowsStore')]
    [OutputType([Security.Cryptography.X509Certificates.X509Certificate2])]
    param(
        # The path to the certificate file.
        [Parameter(Mandatory, Position=0, ParameterSetName='FromFileInWindowsStore')]
        [Parameter(Mandatory, Position=0, ParameterSetName='FromFileInCustomStore')]
        [String] $Path,
        
        # The certificate to install.
        [Parameter(Mandatory, Position=0, ParameterSetName='FromCertificateInWindowsStore')]
        [Parameter(Mandatory, Position=0, ParameterSetName='FromCertificateInCustomStore')]
        [Security.Cryptography.X509Certificates.X509Certificate2] $Certificate,
        
        # The location of the certificate's store.  To see a list of acceptable values, run:
        #
        #   > [Enum]::GetValues([Security.Cryptography.X509Certificates.StoreLocation])
        [Parameter(Mandatory)]
        [Security.Cryptography.X509Certificates.StoreLocation] $StoreLocation,
        
        # The name of the certificate's store.  To see a list of acceptable values run:
        #
        #  > [Enum]::GetValues([Security.Cryptography.X509Certificates.StoreName])
        [Parameter(Mandatory, ParameterSetName='FromFileInWindowsStore')]
        [Parameter(Mandatory, ParameterSetName='FromCertificateInWindowsStore')]
        [Security.Cryptography.X509Certificates.StoreName] $StoreName,

        # The name of the non-standard, custom store where the certificate should be installed.
        [Parameter(Mandatory, ParameterSetName='FromFileInCustomStore')]
        [Parameter(Mandatory, ParameterSetName='FromCertificateInCustomStore')]
        [String] $CustomStoreName,

        # Mark the private key as exportable. Only valid if loading the certificate from a file.
        [Parameter(ParameterSetName='FromFileInWindowsStore')]
        [Parameter(ParameterSetName='FromFileInCustomStore')]
        [switch] $Exportable,
        
        # The password for the certificate.  Should be a `System.Security.SecureString`.
        [Parameter(ParameterSetName='FromFileInWindowsStore')]
        [Parameter(ParameterSetName='FromFileInCustomStore')]
        [securestring] $Password,

        # Use the `Session` parameter to install a certificate on remote computer(s) using PowerShell remoting. Use
        # `New-PSSession` to create a session.
        [Management.Automation.Runspaces.PSSession[]] $Session,

        # Re-install the certificate, even if it is already installed. Calls the `Add()` method for store even if the
        # certificate is in the store. This function assumes that the `Add()` method replaces existing certificates.
        [switch] $Force,

        # Return the installed certificate.
        [switch] $PassThru
    )
    
    Set-StrictMode -Version 'Latest'
    Use-CallerPreference -Cmdlet $PSCmdlet -Session $ExecutionContext.SessionState

    $ephemeralKeyFlag = [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet
    $defaultKeyFlag = [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet

    if( $PSCmdlet.ParameterSetName -like 'FromFile*' )
    {   
        $resolvedPath = Resolve-Path -Path $Path
        if( -not $resolvedPath )
        {
            return
        }

        $Path = $resolvedPath.ProviderPath
        
        $fileBytes = [IO.File]::ReadAllBytes($Path)
        $encodedCert = [Convert]::ToBase64String($fileBytes)
        $keyFlags = $ephemeralKeyFlag
        if( (Test-COperatingSystem -MacOS) )
        {
            $keyFlags = $defaultKeyFlag
        }

        # We need the certificate thumbprint so we can check if the certificate exists or not.
        $Certificate = [Security.Cryptography.X509Certificates.X509Certificate]::New($Path, $Password, $keyFlags)
        try
        {
            $thumbprint = $Certificate.Thumbprint
        }
        finally
        {
            $Certificate.Reset()
        }
        $Certificate = $null
    }
    else
    {
        $thumbprint = $Certificate.Thumbprint
        $encodedCert = [Convert]::ToBase64String( $Certificate.RawData )
    }

    $keyFlags = [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet
    if( $StoreLocation -eq [Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser )
    {
        $keyFlags = [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::UserKeySet
    }

    $keyFlags = $keyFlags -bor [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet

    if( $Exportable )
    {
        $keyFlags = $keyFlags -bor [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
    }

    $invokeCommandArgs = @{ }
    if( $Session )
    {
        $invokeCommandArgs['Session'] = $Session
    }

    Invoke-Command @invokeCommandArgs -ScriptBlock {
        [CmdletBinding()]
        param(
            # The base64 encoded certificate to install.
            [Parameter(Mandatory)]
            [String] $EncodedCertificate,

            # The password for the certificate.
            [securestring] $Password,

            [Parameter(Mandatory)]
            [Security.Cryptography.X509Certificates.StoreLocation] $StoreLocation,
        
            $StoreName,

            [string] $CustomStoreName,

            [Security.Cryptography.X509Certificates.X509KeyStorageFlags] $KeyStorageFlags,

            [bool] $Force,

            [bool] $WhatIf,

            [Management.Automation.ActionPreference] $Verbosity,
            
            [String] $Thumbprint
        )

        Set-StrictMode -Version 'Latest'

        $WhatIfPreference = $WhatIf
        $VerbosePreference = $Verbosity

        $certFilePath = Join-Path -Path ([IO.Path]::GetTempPath()) -ChildPath ([IO.Path]::GetRandomFileName())

        [Security.Cryptography.X509Certificates.X509Certificate2] $cert = $null
        [Security.Cryptography.X509Certificates.X509Store] $store = $null
        if( $CustomStoreName )
        {
            $storeNameDisplay = $CustomStoreName
            $store = [Security.Cryptography.X509Certificates.X509Store]::New($CustomStoreName, $StoreLocation)
        }
        else
        {
            $StoreName = [Security.Cryptography.X509Certificates.StoreName]$StoreName
            $storeNameDisplay = $StoreName.ToString()
            $store = [Security.Cryptography.X509Certificates.X509Store]::New($StoreName, $StoreLocation)
        }

        if( -not $Force )
        {
            try
            {
                $store.Open( ([Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly) )
                if( $store.Certificates | Where-Object 'Thumbprint' -eq $Thumbprint )
                {
                    return
                }
            }
            catch
            {
                $msg = "Exception reading certificates from $($StoreLocation)\$($storeNameDisplay) store: $($_)"
                Write-Error -Message $msg -ErrorAction $ErrorActionPreference
                return
            }
            finally
            {
                $store.Close()
            }
        }

        $certBytes = [Convert]::FromBase64String( $EncodedCertificate )
        [IO.File]::WriteAllBytes( $certFilePath, $certBytes )

        # Make sure the key isn't persisted if we're not going to store it. 
        if( $WhatIf )
        {
            # We don't use EphemeralKeySet because it isn't supported on macOS.
            $KeyStorageFlags = [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet
        }

        try
        {
            $cert = 
                [Security.Cryptography.X509Certificates.X509Certificate2]::New($certFilePath, $Password, $KeyStorageFlags)
        }
        catch
        {
            $msg = "Exception reading certificate from file: $($_)"
            Write-Error -Message $msg -ErrorAction $ErrorActionPreference
            return
        }
        
        $description = $cert.FriendlyName
        if( -not $description )
        {
            $description = $cert.Subject
        }

        try
        {
            $store.Open( ([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite) )

            $action = "install into $($StoreLocation)\$($storeNameDisplay) store"
            $target = "$($description) ($($cert.Thumbprint))"
            if( $PSCmdlet.ShouldProcess($target, $action) )
            {
                $msg = "Installing certificate ""$($description)"" ($($cert.Thumbprint)) into $($StoreLocation)\" +
                    "$($storeNameDisplay) store."
                Write-Verbose -Message $msg 
                $store.Add( $cert )
            }
        }
        catch
        {
            if( (Test-COperatingSystem -MacOS) -and ($cert.HasPrivateKey -and -not $Exportable) )
            {
                $msg = "Exception installing certificate ""$($description)"" ($($cert.Thumbprint)) into " +
                       "$($StoreLocation)\$($storeNameDisplay): $($_). On macOS, certificates with private keys " +
                       "must be exportable. Update $($MyInvocation.MyCommand.Name) with the ""-Exportable"" switch."
                Write-Error -Message $msg -ErrorAction $ErrorActionPreference
                return
            }

            $msg = "Exception installing certificate in $($StoreLocation)\$($storeNameDisplay) store: $($_)"
            Write-Error -Message $msg -ErrorAction $ErrorActionPreference
            return
        }
        finally
        {
            Remove-Item -Path $certFilePath -ErrorAction Ignore -WhatIf:$false -Force

            if( $cert )
            {
                $cert.Reset()
            }

            if( $store )
            {
                $store.Close()
            }
        }
    } -ArgumentList $encodedCert,
                    $Password,
                    $StoreLocation,
                    $StoreName,
                    $CustomStoreName,
                    $keyFlags,
                    $Force,
                    $WhatIfPreference,
                    $VerbosePreference,
                    $thumbprint

    if( $PassThru )
    {
        # Don't return a certificate object created by this function. It may have been loaded from a file and stored
        # in a temp file on disk. If that certificate object isn't properly disposed, the temp file can stick around
        # slowly filling up disks.
        $storeParam = @{ StoreName = $StoreName }
        if( $CustomStoreName )
        {
            $storeParam = @{ CustomStoreName = $CustomStoreName }
        }
        return Get-CCertificate -Thumbprint $thumbprint -StoreLocation $StoreLocation @storeParam
    }
}

