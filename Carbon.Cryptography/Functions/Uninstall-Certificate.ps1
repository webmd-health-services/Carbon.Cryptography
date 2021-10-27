
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
        # The thumbprint of the certificate to remove.
        #
        # If you want to uninstall the certificate from all stores it is installed in, you can pipe the thumbprint to this parameter or you can pipe a certificate object. (This functionality was added in Carbon 2.5.0.)
        [Parameter(Mandatory, ParameterSetName='ByThumbprint', ValueFromPipelineByPropertyName, ValueFromPipeline)]
        [Parameter(Mandatory, ParameterSetName='ByThumbprintAndStoreName')]
        [Parameter(Mandatory, ParameterSetName='ByThumbprintAndCustomStoreName')]
        [String] $Thumbprint,
        
        # The certificate to remove
        [Parameter(Mandatory, ParameterSetName='ByCertificateAndStoreName')]
        [Parameter(Mandatory, ParameterSetName='ByCertificateAndCustomStoreName')]
        [Security.Cryptography.X509Certificates.X509Certificate2] $Certificate,
        
        # The location of the certificate's store.
        [Parameter(Mandatory, ParameterSetName='ByThumbprintAndStoreName')]
        [Parameter(Mandatory, ParameterSetName='ByThumbprintAndCustomStoreName')]
        [Parameter(Mandatory, ParameterSetName='ByCertificateAndStoreName')]
        [Parameter(Mandatory, ParameterSetName='ByCertificateAndCustomStoreName')]
        [Security.Cryptography.X509Certificates.StoreLocation] $StoreLocation,
        
        # The name of the certificate's store.
        [Parameter(Mandatory, ParameterSetName='ByThumbprintAndStoreName')]
        [Parameter(Mandatory, ParameterSetName='ByCertificateAndStoreName')]
        [Security.Cryptography.X509Certificates.StoreName] $StoreName,

        [Parameter(Mandatory, ParameterSetName='ByThumbprintAndCustomStoreName')]
        [Parameter(Mandatory, ParameterSetName='ByCertificateAndCustomStoreName')]
        [String] $CustomStoreName,

        # Use the `Session` parameter to uninstall a certificate on remote computer(s) using PowerShell remoting. Use
        # `New-PSSession` to create a session.
        #
        # Due to a bug in PowerShell, you can't remove a certificate by just its thumbprint over remoting. Using just a
        # thumbprint requires us to enumerate through all installed certificates. When you do this over remoting,
        # PowerShell throws a terminating `The system cannot open the device or file specified` error.
        [Parameter(ParameterSetName='ByThumbprintAndStoreName')]
        [Parameter(ParameterSetName='ByThumbprintAndCustomStoreName')]
        [Parameter(ParameterSetName='ByCertificateAndStoreName')]
        [Parameter(ParameterSetName='ByCertificateAndCustomStoreName')]
        [Management.Automation.Runspaces.PSSession[]] $Session
    )
    
    process
    {
        Set-StrictMode -Version 'Latest'
        Use-CallerPreference -Cmdlet $PSCmdlet -Session $ExecutionContext.SessionState

        if( $PSCmdlet.ParameterSetName -eq 'ByThumbprint' )
        {
            # Must be in this order. Delete LocalMachine certs *first* so they don't show
            # up in CurrentUser stores. If you delete a certificate that "cascades" into 
            # the CurrentUser store first, you'll get errors when running non-
            # interactively as SYSTEM.
            $certsToDelete = & {
                Get-Certificate -StoreLocation LocalMachine -Thumbprint $Thumbprint
                Get-Certificate -StoreLocation CurrentUser -Thumbprint $Thumbprint
            }
            foreach( $certToDelete in $certsToDelete )
            {
                Uninstall-Certificate -Thumbprint $Thumbprint `
                                      -StoreLocation $certToDelete.StoreLocation `
                                      -StoreName $certToDelete.StoreName
            }
            return
        }

        if( $PSCmdlet.ParameterSetName -like 'ByCertificate*' )
        {
            $Thumbprint = $Certificate.Thumbprint
        }
    
        $invokeCommandParameters = @{}
        if( $Session )
        {
            $invokeCommandParameters['Session'] = $Session
        }

        if( $CustomStoreName )
        {
            # This is just so we can pass a value to the Invoke-Command script block. The store name enum doesn't have a
            # "not set" value so when it is "$null", the call to Invoke-Command fails.
            $StoreName = [Security.Cryptography.X509Certificates.StoreName]::My
        }

        Invoke-Command @invokeCommandParameters -ScriptBlock {
            [CmdletBinding()]
            param(
                # The thumbprint of the certificate to remove.
                [String] $Thumbprint,
        
                # The location of the certificate's store.
                [Security.Cryptography.X509Certificates.StoreLocation] $StoreLocation,
        
                # The name of the certificate's store.
                [Security.Cryptography.X509Certificates.StoreName] $StoreName,

                # The name of the non-standard, custom store where the certificate should be un-installed.
                [String] $CustomStoreName
            )

            Set-StrictMode -Version 'Latest'

            if( $CustomStoreName )
            {
                $storeNameDisplay = $CustomStoreName
                $store = [Security.Cryptography.X509Certificates.X509Store]::New($CustomStoreName, $StoreLocation)
            }
            else
            {
                $storeNameDisplay = $StoreName.ToString()
                $store = [Security.Cryptography.X509Certificates.X509Store]::New($StoreName, $StoreLocation)
            }

            $certToRemove = $null
            try
            {
                $store.Open( ([Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly) )
                $certToRemove = $store.Certificates | Where-Object { $_.Thumbprint -eq $Thumbprint }
                if( -not $certToRemove )
                {
                    return
                }
            }
            catch
            {
                $ex = $_.Exception.InnerException
                while( $ex.InnerException )
                {
                    $ex = $ex.InnerException
                }
                $msg = "[$($ex.GetType().FullName)] exception reading certificates from $($StoreLocation)\" +
                       "$($storeNameDisplay) store: $($ex)"
                Write-Error -Message $msg -ErrorAction $ErrorActionPreference
                return
            }
            finally
            {
                $store.Close()
            }

            try
            {
                $store.Open( ([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite) )
                $target = $certToRemove.FriendlyName
                if( -not $target )
                {
                    $target = $certToRemove.Subject
                }

                $shouldProcessTarget = "$($target) in $($StoreLocation)\$($storeNameDisplay)"
                if( $PSCmdlet.ShouldProcess($shouldProcessTarget, 'remove') )
                {
                    $msg = "Uninstalling certificate ""$($target)"" ($($Thumbprint)) from $($StoreLocation)\" +
                           "$($storeNameDisplay) store."
                    Write-Verbose $msg
                    $certToRemove | ForEach-Object { $store.Remove($_) }
                }
            }
            catch
            {
                $ex = $_.Exception.InnerException
                while( $ex.InnerException )
                {
                    $ex = $ex.InnerException
                }
                $msg = "[$($ex.GetType().FullName)] exception uninstalling certificate in $($StoreLocation)\" +
                       "$($storeNameDisplay) store: $($ex)"
                Write-Error -Message $msg -ErrorAction $ErrorActionPreference
                return
            }
            finally
            {
                $store.Close()
            }
        } -ArgumentList $Thumbprint,$StoreLocation,$StoreName,$CustomStoreName
    }
}
