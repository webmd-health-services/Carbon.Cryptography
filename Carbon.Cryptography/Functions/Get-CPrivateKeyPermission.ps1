
function Get-CPrivateKeyPermission
{
    <#
    .SYNOPSIS
    Gets the permissions (access control rules) for an X509 certificate's private key. Windows only.

    .DESCRIPTION
    The `Get-CPrivateKeyPermission` gets the permissions on an X509 certificate's private key. Pass the path to the X509
    certificate in the PowerShell `cert:` drive to the `Path` parameter (wildcards supported). All non-inherited
    permissions are returned.

    To get a specific user or group's permissions, pass the user/group name to the `Identity` parameter. If the
    user/group doesn't exist, the function writes an error then returns nothing.

    To also get inherited permissions, use the `Inherited` switch.

    This function only supports the Windows operating system. If you run on a non-Windows operating system, the function
    writes an error then returns nothing.

    If the certificate doesn't exist, the function writes an error then returns nothing.

    If the certificate doesn't have a private key, the function writes a warning and returns. If the
    certificate's private key is inaccessible, the function writes an error then returns nothing.

    If running under Windows PowerShell and the .NET framework uses the
    [RSACryptoServiceProvider](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.rsacryptoserviceprovider)
    or the
    [DSACryptoServiceProvider](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.dsacryptoserviceprovider)
    class to manage the private key, the function returns `System.Security.AccessRule.CryptoKeyAccessRule` objects.
    Otherwise, it returns `System.Security.AccessRule.FileSystemAccessRule` objects.

    .OUTPUTS
    System.Security.AccessControl.AccessRule.

    .LINK
    Get-CPrivateKey

    .LINK
    Grant-CPrivateKeyPermission

    .LINK
    Resolve-CPrivateKeyPermission

    .LINK
    Revoke-CPrivateKeyPermission

    .LINK
    Test-CPrivateKeyPermission

    .EXAMPLE
    Get-CPrivateKeyPermission -Path 'Cert:\LocalMachine\1234567890ABCDEF1234567890ABCDEF12345678'

    Demonstrates how to use this function to return non-inherited access rules for an X509 certificate's private key. In
    this example, the `Cert:\LocalMachine\1234567890ABCDEF1234567890ABCDEF12345678` certificate's private key
    permissions are returned.
    #>
    [CmdletBinding()]
    [OutputType([System.Security.AccessControl.AccessRule])]
    param(
        # The path whose permissions (i.e. access control rules) to return. Must be a path on the `cert:` drive.
        # Wildcards supported.
        [Parameter(Mandatory)]
        [String] $Path,

        # The user/group name whose permissiosn (i.e. access control rules) to return. By default, all permissions are
        # returned.
        [String] $Identity,

        # Return inherited permissions in addition to explicit permissions.
        [switch] $Inherited
    )

    Set-StrictMode -Version 'Latest'
    Use-CallerPreference -Cmdlet $PSCmdlet -Session $ExecutionContext.SessionState

    if (-not (Test-Path -Path $Path))
    {
        $msg = "Failed to get permissions on ""${Path}"" certificate's private key because the certificate does not " +
               'exist.'
        Write-Error -Message $msg -ErrorAction $ErrorActionPreference
        return
    }

    if ($Identity)
    {
        if( -not (Test-CIdentity -Name $Identity) )
        {
            $msg = "Failed to get permissions on ""${Path}"" for ""${Identity}"" because that user/group does not " +
                   'exist.'
            Write-Error -Message $msg -ErrorAction $ErrorActionPreference
            return
        }

        $Identity = Resolve-CIdentityName -Name $Identity
    }

    foreach ($certificate in (Get-Item -Path $Path -Force))
    {
        if ($certificate -isnot [X509Certificate2])
        {
            $msg = "Failed to get permissions on ""${certificate}"" because it is not an X509 certificate."
            Write-Error -Message $msg -ErrorAction $ErrorActionPreference
            continue
        }

        $certPath = Join-Path -Path 'cert:' -ChildPath ($certificate.PSPath | Split-Path -NoQualifier)
        $subject = $certificate.Subject
        Write-Debug -Message "${certPath}  ${subject}" -Verbose

        if (-not $certificate.HasPrivateKey)
        {
            $msg = "Unable to get permissions on ""${subject}"" (thumbprint: ${thumbprint}; path ${certPath}) " +
                   'certificate''s private key because the certificate doesn''t have a private key.'
            Write-Warning $msg -WarningAction $WarningPreference
            continue
        }

        $pk = $certificate | Get-CPrivateKey
        if (-not $pk)
        {
            continue
        }

        $usesCryptoKeyRights = $pk | Test-CCryptoKeyAvailable
        if (-not $usesCryptoKeyRights)
        {
            $getPermArgs = [Collections.Generic.Dictionary[[String], [Object]]]::New($PSBoundParameters)
            [void]$getPermArgs.Remove('Path')

            $pkPaths = $certificate | Resolve-CPrivateKeyPath
            if (-not $pkPaths)
            {
                continue
            }

            foreach ($pkPath in $pkPaths)
            {
                Get-CPermission -Path $pkPath @getPermArgs
            }
            continue
        }

        $certificate.PrivateKey.CspKeyContainerInfo.CryptoKeySecurity |
            Select-Object -ExpandProperty 'Access' |
            Where-Object {
                if( $Inherited )
                {
                    return $true
                }

                return (-not $_.IsInherited)
            } |
            Where-Object {
                if( $Identity )
                {
                    return ($_.IdentityReference.Value -eq $Identity)
                }

                return $true
            }
    }
}
