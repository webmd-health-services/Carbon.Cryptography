
function Revoke-CPrivateKeyPermission
{
    <#
    .SYNOPSIS
    Removes a user or group's permissions on an X509 certificate's private key. Windows only.

    .DESCRIPTION
    The `Revoke-CPrivateKeyPermission` removes a user or group's non-inherited permissions on an X509 certificate's
    private key. Pass the path to the X509 certificate object to the `Path` parameter. The path must be in PowerShell's
    "cert:" drive. Wildcards supported. Pass the user/group whose permission to remove to the `Identity` permission. The
    function removes all the user/group's permissions on the given private key.

    If the certificate doesn't exist, or the path is not to an X509 certificate object in PowerShell's "cert:" drive,
    the function writes an error and returns.

    If the user/group doesn't exist, the function writes an error and returns.

    If the user/group doesn't have any permissions, nothing happens.

    If the certificate doesn't have a private key, the function writes a warning then returns.

    .LINK
    Get-CPrivateKey

    .LINK
    Get-CPrivateKeyPermission

    .LINK
    Grant-CPrivateKeyPermission

    .LINK
    Resolve-CPrivateKeyPath

    .LINK
    Test-CPrivateKeyPermission

    .EXAMPLE
    Revoke-CPrivateKeyPermission -Identity ENTERPRISE\LowerDecks -Path 'cert:\LocalMachine\My\1234567890ABCDEF1234567890ABCDEF12345678'

    Demonstrates how to revoke the Lower Deck crew's permission to the
    "cert:\LocalMachine\My\1234567890ABCDEF1234567890ABCDEF12345678" certificate's private key.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessage('PSShouldProcess', '')]
    [CmdletBinding(SupportsShouldProcess)]
    param(
        # The path to the X509 certificate. Must be a path on PowerShell's "cert:" drive.
        [Parameter(Mandatory)]
        [String] $Path,

        # The user/group name whose permissions to remove.
        [Parameter(Mandatory)]
        [String] $Identity
    )

    Set-StrictMode -Version 'Latest'
    Use-CallerPreference -Cmdlet $PSCmdlet -Session $ExecutionContext.SessionState

    if (-not $IsWindows)
    {
        Write-Error -Message 'Revoke-CPrivateKeyPermission only supports Windows.' -ErrorAction $ErrorActionPreference
        return
    }

    if (-not (Test-Path -Path $Path))
    {
        $msg = "Failed to revoke permissions on ""${Path}"" certificate's private key because the certificate does " +
               'not exist.'
        Write-Error -Message $msg -ErrorAction $ErrorActionPreference
        return
    }

    if (-not (Test-CPrincipal -Name $Identity))
    {
        $msg = "Failed to revoke ""${Permission}"" rights on ""${Path}"" to ""${Identity}"" because that user/group " +
               'does not exist.'
        Write-Error -Message $msg -ErrorAction $ErrorActionPreference
        return
    }

    $Identity = Resolve-CPrincipalName -Name $Identity

    $rulesToRemove = Get-CPrivateKeyPermission -Path $Path -Identity $Identity
    if (-not $rulesToRemove)
    {
        return
    }

    foreach ($certificate in (Get-Item -Path $Path -Force))
    {
        if ($certificate -isnot [X509Certificate2])
        {
            $msg = "Failed to revoke permissions on ""${certificate}"" because it is not an X509 certificate."
            Write-Error -Message $msg -ErrorAction $ErrorActionPreference
            continue
        }

        $certPath = Join-Path -Path 'cert:' -ChildPath ($certificate.PSPath | Split-Path -NoQualifier)
        $subject = $certificate.Subject
        $thumbprint = $certificate.Thumbprint
        if (-not $certificate.HasPrivateKey)
        {
            $msg = "Unable to revoke permissions on ""${subject}"" (thumbprint: ${thumbprint}; path ${certPath}) " +
                   'certificate''s private key because the certificate doesn''t have a private key.'
            Write-Warning $msg -WarningAction $WarningPreference
            continue
        }

        $description = "${certPath} ${subject}"

        $pk = $certificate | Get-CPrivateKey
        $usesCryptoKeyRights = $pk | Test-CCryptoKeyAvailable
        if (-not $usesCryptoKeyRights)
        {
            $pkPaths = $certificate | Resolve-CPrivateKeyPath
            if (-not $pkPaths)
            {
                continue
            }

            $revokePermArgs = [Collections.Generic.Dictionary[[String], [Object]]]::New($PSBoundParameters)
            [void]$revokePermArgs.Remove('Path')

            foreach ($pkPath in $pkPaths)
            {
                Revoke-CPermission -Path $pkPath @revokePermArgs -Description $description
            }

            continue
        }

        [Security.AccessControl.CryptoKeySecurity] $keySecurity = $pk.CspKeyContainerInfo.CryptoKeySecurity

        foreach ($ruleToRemove in $rulesToRemove)
        {
            $rmIdentity = $ruleToRemove.IdentityReference
            $rmType = $ruleToRemove.AccessControlType.ToString().ToLowerInvariant()
            $rmRights = $ruleToRemove.CryptoKeyRights
            Write-Information "${description}  ${rmIdentity}  - ${rmType} ${rmRights}"
            [void] $keySecurity.RemoveAccessRule($ruleToRemove)
        }

        $action = "revoke ${Identity}'s permissions"
        Set-CryptoKeySecurity -Certificate $certificate -CryptoKeySecurity $keySecurity -Action $action
    }
}

