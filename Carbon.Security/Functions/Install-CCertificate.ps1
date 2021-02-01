
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
    binary data is converted to a base-64 encoded string and sent to the remote computer, where it is converted back
    into a certificate. If installing a certificate from a file, the file's bytes are converted to base-64, sent to the
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
        [Parameter(Mandatory, Position=0, ParameterSetName='FromFileInWindowsStore')]
        [Parameter(Mandatory, Position=0, ParameterSetName='FromFileInCustomStore')]
        # The path to the certificate file.
        [String]$Path,
        
        [Parameter(Mandatory, Position=0, ParameterSetName='FromCertificateInWindowsStore')]
        [Parameter(Mandatory, Position=0, ParameterSetName='FromCertificateInCustomStore')]
        # The certificate to install.
        [Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        
        [Parameter(Mandatory)]
        # The location of the certificate's store.  To see a list of acceptable values, run:
        #
        #   > [Enum]::GetValues([Security.Cryptography.X509Certificates.StoreLocation])
        [Security.Cryptography.X509Certificates.StoreLocation]$StoreLocation,
        
        [Parameter(Mandatory, ParameterSetName='FromFileInWindowsStore')]
        [Parameter(Mandatory, ParameterSetName='FromCertificateInWindowsStore')]
        # The name of the certificate's store.  To see a list of acceptable values run:
        #
        #  > [Enum]::GetValues([Security.Cryptography.X509Certificates.StoreName])
        [Security.Cryptography.X509Certificates.StoreName]$StoreName,

        [Parameter(Mandatory, ParameterSetName='FromFileInCustomStore')]
        [Parameter(Mandatory, ParameterSetName='FromCertificateInCustomStore')]
        # The name of the non-standard, custom store where the certificate should be installed.
        [String]$CustomStoreName,

        [Parameter(ParameterSetName='FromFileInWindowsStore')]
        [Parameter(ParameterSetName='FromFileInCustomStore')]
        # Mark the private key as exportable. Only valid if loading the certificate from a file.
        [switch]$Exportable,
        
        [Parameter(ParameterSetName='FromFileInWindowsStore')]
        [Parameter(ParameterSetName='FromFileInCustomStore')]
        # The password for the certificate.  Should be a `System.Security.SecureString`.
        [securestring]$Password,

        # Use the `Session` parameter to install a certificate on remote computer(s) using PowerShell remoting. Use
        # `New-PSSession` to create a session.
        [Management.Automation.Runspaces.PSSession[]]$Session,

        # Re-install the certificate, even if it is already installed. Calls the `Add()` method for store even if the
        # certificate is in the store. This function assumes that the `Add()` method replaces existing certificates.
        [switch]$Force,

        # Return the installed certificate.
        [switch]$PassThru
    )
    
    Set-StrictMode -Version 'Latest'
    Use-CallerPreference -Cmdlet $PSCmdlet -Session $ExecutionContext.SessionState

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

        $Certificate = Get-CCertificate -Path $Path -Password $Password -KeyStorageFlags $keyFlags
    }
    else
    {
        $encodedCert = [Convert]::ToBase64String( $Certificate.RawData )
        $keyFlags = 0
    }

    $invokeCommandArgs = @{ }
    if( $Session )
    {
        $invokeCommandArgs['Session'] = $Session
    }

    Invoke-Command @invokeCommandArgs -ScriptBlock {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            # The base-64 encoded certificate to install.
            [String]$EncodedCertificate,

            # The password for the certificate.
            [securestring]$Password,

            [Parameter(Mandatory)]
            [Security.Cryptography.X509Certificates.StoreLocation]$StoreLocation,
        
            $StoreName,

            [string]$CustomStoreName,

            [Security.Cryptography.X509Certificates.X509KeyStorageFlags]$KeyStorageFlags,

            [bool]$Force,

            [bool]$WhatIf,

            [Management.Automation.ActionPreference]$Verbosity
        )

        Set-StrictMode -Version 'Latest'

        $WhatIfPreference = $WhatIf
        $VerbosePreference = $Verbosity

        $certFilePath = Join-Path -Path ([IO.Path]::GetTempPath()) -ChildPath ([IO.Path]::GetRandomFileName())

        try
        {
            $certBytes = [Convert]::FromBase64String( $EncodedCertificate )
            [IO.File]::WriteAllBytes( $certFilePath, $certBytes )

            $cert = 
                [Security.Cryptography.X509Certificates.X509Certificate2]::New($certFilePath, $Password, $KeyStorageFlags)

            if( $CustomStoreName )
            {
                $store = [Security.Cryptography.X509Certificates.X509Store]::New($CustomStoreName, $StoreLocation)
            }
            else
            {
                $StoreName = [Security.Cryptography.X509Certificates.StoreName]$StoreName
                $store = [Security.Cryptography.X509Certificates.X509Store]::New($StoreName, $StoreLocation)
            }

            if( -not $Force )
            {
                $store.Open( ([Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly) )
                try
                {
                    if( $store.Certificates | Where-Object { $_.Thumbprint -eq $cert.Thumbprint } )
                    {
                        return
                    }
                }
                finally
                {
                    $store.Close()
                }
            }

            $store.Open( ([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite) )

            $description = $cert.FriendlyName
            if( -not $description )
            {
                $description = $cert.Subject
            }

            $action = "install into $($StoreLocation)'s $($StoreName) store"
            $target = "$($description) ($($cert.Thumbprint))"
            if( $PSCmdlet.ShouldProcess($action, $target) )
            {
                $msg = "Installing certificate ""$($description)"" ($($cert.Thumbprint)) into $($StoreLocation)'s " +
                       "$($StoreName) store."
                Write-Verbose -Message $msg 
                $store.Add( $cert )
            }
            $store.Close()
        }
        finally
        {
            Remove-Item -Path $certFilePath -ErrorAction Ignore -WhatIf:$false -Force
        }

    } -ArgumentList $encodedCert,$Password,$StoreLocation,$StoreName,$CustomStoreName,$keyFlags,$Force,$WhatIfPreference,$VerbosePreference

    if( $PassThru )
    {
        return $Certificate
    }
}

