
function Install-CCertificate
{
    <#
    .SYNOPSIS
    Installs a certificate in a given store.
    
    .DESCRIPTION
    Uses the .NET certificates API to add a certificate to a store for the machine or current user.  The user performing the action must have permission to modify the store or the installation will fail.

    To install a certificate on a remote computer, create a remoting session with the `New-PSSession` cmdlet, and pass the session object to this function's `Session` parameter. When installing to a remote computer, the certificate's binary data is converted to a base-64 encoded string and sent to the remote computer, where it is converted back into a certificate. If installing a certificate from a file, the file's bytes are converted to base-64, sent to the remote computer, saved as a temporary file, installed, and the temporary file is removed.

    The ability to install a certificate on a remote computer was added in Carbon 2.1.0.
    
    .OUTPUTS
    System.Security.Cryptography.X509Certificates.X509Certificate2. An X509Certificate2 object representing the newly installed certificate.
    
    .EXAMPLE
    > Install-CCertificate -Path C:\Users\me\certificate.cer -StoreLocation LocalMachine -StoreName My -Exportable -Password My5up3r53cur3P@55w0rd
    
    Installs the certificate (which is protected by a password) at C:\Users\me\certificate.cer into the local machine's Personal store.  The certificate is marked exportable.
    
    .EXAMPLE
    Install-CCertificate -Path C:\Users\me\certificate.cer -StoreLocation LocalMachine -StoreName My -ComputerName remote1,remote2
    
    Demonstrates how to install a certificate from a file on the local computer into the local machine's personal store on two remote cmoputers, remote1 and remote2. Use the `Credential` parameter to connect as a specific principal.
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
        [Management.Automation.Runspaces.PSSession[]]$Session
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
        $encodedCert = [Convert]::ToBase64String( $fileBytes )

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

            [bool]$WhatIf,

            [Management.Automation.ActionPreference]$Verbosity
        )

        Set-StrictMode -Version 'Latest'

        $WhatIfPreference = $WhatIf
        $VerbosePreference = $Verbosity

        $tempDir = 'Carbon+Install-CCertificate+{0}' -f [IO.Path]::GetRandomFileName()
        $tempDir = Join-Path -Path ([IO.Path]::GetTempPath()) -ChildPath $tempDir
        New-Item -Path $tempDir -ItemType 'Directory' -WhatIf:$false | Out-Null

        try
        {
            $certBytes = [Convert]::FromBase64String( $EncodedCertificate )
            $certFilePath = Join-Path -Path $tempDir -ChildPath ([IO.Path]::GetRandomFileName())
            [IO.File]::WriteAllBytes( $certFilePath, $certBytes )

            $cert = New-Object 'Security.Cryptography.X509Certificates.X509Certificate2' ($certFilePath, $Password, $KeyStorageFlags)

            if( $CustomStoreName )
            {
                $store = New-Object 'Security.Cryptography.X509Certificates.X509Store' $CustomStoreName,$StoreLocation
            }
            else
            {
                $store = New-Object 'Security.Cryptography.X509Certificates.X509Store'  ([Security.Cryptography.X509Certificates.StoreName]$StoreName),$StoreLocation
            }

            $store.Open( ([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite) )

            $description = $cert.FriendlyName
            if( -not $description )
            {
                $description = $cert.Subject
            }

            if( $PSCmdlet.ShouldProcess( ('install into {0}''s {1} store' -f $StoreLocation,$StoreName), ('{0} ({1})' -f $description,$cert.Thumbprint) ) )
            {
                Write-Verbose ('Installing certificate ''{0}'' ({1}) into {2}''s {3} store.' -f $description,$cert.Thumbprint,$StoreLocation,$StoreName)
                $store.Add( $cert )
            }
            $store.Close()
        }
        finally
        {
            Remove-Item -Path $tempDir -Recurse -ErrorAction Ignore -WhatIf:$false -Force
        }

    } -ArgumentList $encodedCert,$Password,$StoreLocation,$StoreName,$CustomStoreName,$keyFlags,$WhatIfPreference,$VerbosePreference

    return $Certificate
}

