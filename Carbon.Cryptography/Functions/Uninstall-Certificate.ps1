
function Uninstall-Certificate
{
    <#
    .SYNOPSIS
    Removes a certificate from a certificate store.
    
    .DESCRIPTION
    The `Uninstall-CCertificate` function uses .NET's certificates API to remove a certificate from a certificate store
    for the machine or current user. Use the thumbprint to identify which certificate to remove. The thumbprint is
    unique to each certificate. The user performing the removal must have read and write permission on the store where
    the certificate is located.

    If the certificate isn't in the store, nothing happens, not even an error.

    To uninstall a certificate from a remote computer, use the `Session`parameter. You can create a new session with the
    `New-PSSession` cmdlet. You can pass multiple sessions.

    You can uninstall a certificate using just its thumbprint. `Uninstall-CCertificate` will search through all
    certificate locations and stores and uninstall all certificates that have the thumbprint. When you enumerate all
    certificates over a remoting session, you get a terminating `The system cannot open the device or file specified`
    error, so you can't delete a certificate with just a thumbprint over remoting.

    .EXAMPLE
    Uninstall-CCertificate -Thumbprint '570895470234023dsaaefdbcgbefa'

    Demonstrates how to delete a certificate from all stores it is installed in. `Uninstall-CCertificate` searches every
    certificate stores and deletes all certificates with the given thumbprint.

    .EXAMPLE
    '570895470234023dsaaefdbcgbefa' | Uninstall-CCertificate

    Demonstrates that you can pipe a thumbprint to `Uninstall-CCertificate`. The certificate is uninstall from all
    stores it is in.

    .EXAMPLE
    Get-Item -Path 'cert:\LocalMachine\My\570895470234023dsaaefdbcgbefa' | Uninstall-CCertificate

    Demonstrates that you can pipe a certificate `Uninstall-CCertificate`. The certificate is uninstalled from all
    stores it is in.

    .EXAMPLE
    Uninstall-CCertificate -Thumbprint 570895470234023dsaaefdbcgbefa -StoreLocation CurrentUser -StoreName My
    
    Removes the 570895470234023dsaaefdbcgbefa certificate from the current user's Personal certificate store.
    
    .EXAMPLE
    Uninstall-CCertificate -Certificate $cert -StoreLocation LocalMachine -StoreName Root
    
    Demonstrates how you can remove a certificate by passing it to the `Certificate` parameter.

    .EXAMPLE
    Uninstall-CCertificate -Thumbprint 570895470234023dsaaefdbcgbefa -StoreLocation LocalMachine -StoreName 'SharePoint'

    Demonstrates how to uninstall a certificate from a custom, non-standard store.

    .EXAMPLE
    Uninstall-CCertificate -Thumbprint 570895470234023dsaaefdbcgbefa -StoreLocation CurrentUser -StoreName My -Session $session
    
    Demonstrates how to uninstall a certificate from a remote computer.
    #>
    [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName='ByThumbprint')]
    param(
        [Parameter(Mandatory, ParameterSetName='ByThumbprint',ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [Parameter(Mandatory, ParameterSetName='ByThumbprintAndStoreName')]
        [Parameter(Mandatory, ParameterSetName='ByThumbprintAndCustomStoreName')]
        # The thumbprint of the certificate to remove.
        #
        # If you want to uninstall the certificate from all stores it is installed in, you can pipe the thumbprint to this parameter or you can pipe a certificate object. (This functionality was added in Carbon 2.5.0.)
        [String]$Thumbprint,
        
        [Parameter(Mandatory, ParameterSetName='ByCertificateAndStoreName')]
        [Parameter(Mandatory, ParameterSetName='ByCertificateAndCustomStoreName')]
        # The certificate to remove
        [Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        
        [Parameter(Mandatory, ParameterSetName='ByThumbprintAndStoreName')]
        [Parameter(Mandatory, ParameterSetName='ByThumbprintAndCustomStoreName')]
        [Parameter(Mandatory, ParameterSetName='ByCertificateAndStoreName')]
        [Parameter(Mandatory, ParameterSetName='ByCertificateAndCustomStoreName')]
        # The location of the certificate's store.
        [Security.Cryptography.X509Certificates.StoreLocation]$StoreLocation,
        
        [Parameter(Mandatory, ParameterSetName='ByThumbprintAndStoreName')]
        [Parameter(Mandatory, ParameterSetName='ByCertificateAndStoreName')]
        # The name of the certificate's store.
        [Security.Cryptography.X509Certificates.StoreName]$StoreName,

        [Parameter(Mandatory, ParameterSetName='ByThumbprintAndCustomStoreName')]
        [Parameter(Mandatory, ParameterSetName='ByCertificateAndCustomStoreName')]
        # The name of the non-standard, custom store where the certificate should be un-installed.
        [String]$CustomStoreName,

        [Parameter(ParameterSetName='ByThumbprintAndStoreName')]
        [Parameter(ParameterSetName='ByThumbprintAndCustomStoreName')]
        [Parameter(ParameterSetName='ByCertificateAndStoreName')]
        [Parameter(ParameterSetName='ByCertificateAndCustomStoreName')]
        # Use the `Session` parameter to uninstall a certificate on remote computer(s) using PowerShell remoting. Use
        # `New-PSSession` to create a session.
        #
        # Due to a bug in PowerShell, you can't remove a certificate by just its thumbprint over remoting. Using just a
        # thumbprint requires us to enumerate through all installed certificates. When you do this over remoting,
        # PowerShell throws a terminating `The system cannot open the device or file specified` error.
        [Management.Automation.Runspaces.PSSession[]]$Session
    )
    
    process
    {
        Set-StrictMode -Version 'Latest'
        Use-CallerPreference -Cmdlet $PSCmdlet -Session $ExecutionContext.SessionState

        if( $PSCmdlet.ParameterSetName -like 'ByCertificate*' )
        {
            $Thumbprint = $Certificate.Thumbprint
        }
    
        $invokeCommandParameters = @{}
        if( $Session )
        {
            $invokeCommandParameters['Session'] = $Session
        }

        if( $PSCmdlet.ParameterSetName -eq 'ByThumbprint' )
        {
            # Must be in this order. Delete LocalMachine certs *first* so they don't show
            # up in CurrentUser stores. If you delete a certificate that "cascades" into 
            # the CurrentUser store first, you'll get errors when running non-
            # interactively as SYSTEM.
            if( (Test-Path -Path 'cert:') )
            {
                Get-ChildItem -Path 'Cert:\LocalMachine','Cert:\CurrentUser' -Recurse |
                    Where-Object { -not $_.PsIsContainer } |
                    Where-Object { $_.Thumbprint -eq $Thumbprint } |
                    ForEach-Object {
                        $cert = $_
                        $description = $cert.FriendlyName
                        if( -not $description )
                        {
                            $description = $cert.Subject
                        }

                        $certPath = $_.PSPath | Split-Path -NoQualifier
                        Write-Verbose ('Uninstalling certificate ''{0}'' ({1}) at {2}.' -f $description,$cert.Thumbprint,$certPath)
                        $_
                    } |
                    Remove-Item
            }
            return
        }

        Invoke-Command @invokeCommandParameters -ScriptBlock {
            [CmdletBinding()]
            param(
                # The thumbprint of the certificate to remove.
                [String]$Thumbprint,
        
                # The location of the certificate's store.
                [Security.Cryptography.X509Certificates.StoreLocation]$StoreLocation,
        
                # The name of the certificate's store.
                $StoreName,

                # The name of the non-standard, custom store where the certificate should be un-installed.
                [String]$CustomStoreName
            )

            Set-StrictMode -Version 'Latest'

            if( $CustomStoreName )
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

            $certPath = Join-Path -Path 'Cert:\' -ChildPath $StoreLocation
            $certPath = Join-Path -Path $certPath -ChildPath $storeNamePath
            $certPath = Join-Path -Path $certPath -ChildPath $Thumbprint

            if( -not (Test-Path -Path $certPath -PathType Leaf) )
            {
                Write-Debug -Message ('Certificate {0} not found.' -f $certPath)
                return
            }

            $cert = Get-Item -Path $certPath

            if( $CustomStoreName )
            {
                $store = New-Object 'Security.Cryptography.X509Certificates.X509Store' $CustomStoreName,$StoreLocation
            }
            else
            {
                $store = New-Object 'Security.Cryptography.X509Certificates.X509Store' ([Security.Cryptography.X509Certificates.StoreName]$StoreName),$StoreLocation
            }

            $store.Open( ([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite) )

            try
            {
                $target = $cert.FriendlyName
                if( -not $target )
                {
                    $target = $cert.Subject
                }

                if( $PSCmdlet.ShouldProcess( ("certificate {0} ({1})" -f $certPath,$target), "remove" ) )
                {
                    Write-Verbose ('Uninstalling certificate ''{0}'' ({1}) at {2}.' -f $target,$cert.Thumbprint,$certPath)
                    $store.Remove( $cert )
                }
            }
            finally
            {
                $store.Close()
            }
        } -ArgumentList $Thumbprint,$StoreLocation,$StoreName,$CustomStoreName
    }
}
