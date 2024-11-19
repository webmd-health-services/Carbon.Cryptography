function Grant-CPrivateKeyPermission
{
    <#
    .SYNOPSIS
    Grants permissions on an X509 certificate's private key. Windows only.

    .DESCRIPTION
    The `Grant-CPrivateKeyPermission` functions grants permissions to an X509 certificatte's private key to a user or
    group. Pass the path to the certificate to the `Path` parameter. The path must be to an item on the PowerShell
    `cert:` drive. Wildcards supported. Pass the user/group name to the `Identity` parameter. Pass the permission to the
    `Permission` parameter. The function grants the identity the given permissions.

    If the certificate doesn't exist or is not to an item in the cert: drive, the function writes an error and returns.

    If the user/group does not exist, the function writes an error and returns.

    If the certificate doesn't have a private key, or the private key is inaccessible, the function writes an error and
    returns.

    If the user already has the given permission on the private key, nothing happens. Use the `-Force` switch to replace
    the existing access rule with a new and identital access rule.

    To clear all other non-inherited permissions on the private key, use the `-Clear` switch.

    To have the permission returned as an access rule object, use the `-PassThru` switch. If running under Windows
    PowerShell and the .NET framework uses the
    [RSACryptoServiceProvider](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.rsacryptoserviceprovider)
    or the
    [DSACryptoServiceProvider](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.dsacryptoserviceprovider)
    class to manage the private key, the function returns `System.Security.AccessRule.CryptoKeyAccessRule` objects.
    Otherwise, it returns `System.Security.AccessRule.FileSystemAccessRule` objects.

    To add a deny rule, pass `Deny` to the the `Type` parameter.

    .OUTPUTS
    System.Security.AccessControl.AccessRule.

    .LINK
    Get-CPrivateKey

    .LINK
    Get-CPrivateKeyPermission

    .LINK
    Resolve-CPrivateKeyPath

    .LINK
    Revoke-CPrivateKeyPermission

    .LINK
    Test-CPrivateKeyPermission

    .LINK
    http://msdn.microsoft.com/en-us/library/system.security.accesscontrol.filesystemrights.aspx

    .LINK
    http://msdn.microsoft.com/en-us/library/system.security.accesscontrol.registryrights.aspx

    .LINK
    http://msdn.microsoft.com/en-us/library/system.security.accesscontrol.cryptokeyrights.aspx

    .LINK
    http://msdn.microsoft.com/en-us/magazine/cc163885.aspx#S3

    .EXAMPLE
    Grant-CPrivateKeyPermission -Identity ENTERPRISE\Engineers -Permission FullControl -Path 'cert:\LocalMachine\My\1234567890ABCDEF1234567890ABCDEF12345678'

    Demonstrates how to grant permissions to an X509 certificate's private key. In this example, the
    `Enterprise\Engineers` group will get full control to the private key of the certificate at
    `cert:\LocalMachine\My\1234567890ABCDEF1234567890ABCDEF12345678`.

    .EXAMPLE
    Grant-CPrivateKeyPermission -Identity BORG\Locutus -Permission FullControl -Type Deny -Path 'cert:\LocalMachine\My\1234567890ABCDEF1234567890ABCDEF12345678'

    Demonstrates how to grant deny permissions on an objecy with the `Type` parameter.

    .EXAMPLE
    Grant-CPrivateKeyPermission -Identity ENTERPRISE\Engineers -Permission FullControl -Clear -Path 'cert:\LocalMachine\My\1234567890ABCDEF1234567890ABCDEF12345678'

    Demonstrates how to clear all other permissions on the private key by using the `-Clear` switch.

    .EXAMPLE
    Grant-CPrivateKeyPermission -Identity ENTERPRISE\Engineers -Permission FullControl -Force -Path 'cert:\LocalMachine\My\1234567890ABCDEF1234567890ABCDEF12345678'

    Demonstrates how to always force granting the permission using the `-Force` switch. By default, if an identity
    already has permissions, the function does nothing. When using the `-Force` switch, the function will remove any
    existing permissions and then grant the requested permission.

    .EXAMPLE
    Grant-CPrivateKeyPermission -Identity ENTERPRISE\Engineers -Permission FullControl -PassThru -Path 'cert:\LocalMachine\My\1234567890ABCDEF1234567890ABCDEF12345678'

    Demonstrates how to have the permission granted returned by using the `-PassThru` switch. If running under Windows
    PowerShell and the .NET framework uses the
    [RSACryptoServiceProvider](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.rsacryptoserviceprovider)
    or the
    [DSACryptoServiceProvider](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.dsacryptoserviceprovider)
    class to manage the private key, the function returns `System.Security.AccessRule.CryptoKeyAccessRule` objects.
    Otherwise, it returns `System.Security.AccessRule.FileSystemAccessRule` objects.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessage('PSShouldProcess', '')]
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([Security.AccessControl.AccessRule])]
    param(
        # The path on which the permissions should be granted. Must be the path to an X509 certificate, i.e. an item in
        # the PowerShell `cert:` drive.
        [Parameter(Mandatory)]
        [String] $Path,

        # The user or group name getting the permissions.
        [Parameter(Mandatory)]
        [String] $Identity,

        # The permission to grant. The Windows UI only allows Read and FullControl access, so
        # `Grant-CPrivateKeyPermission` also only allows `Read` and `FullControl` permissions.
        [Parameter(Mandatory)]
        [ValidateSet('Read', 'FullControl')]
        [String] $Permission,

        # The type of rule to grant, either `Allow` or `Deny`. The default is `Allow`, which will allow access to the
        # item. The other option is `Deny`, which will deny access to the item.
        [Security.AccessControl.AccessControlType] $Type = [Security.AccessControl.AccessControlType]::Allow,

        # Removes all non-inherited permissions on the item.
        [switch] $Clear,

        # Returns an object representing the permission created or set on the `Path`. The returned object will have a
        # `Path` propery added to it so it can be piped to any cmdlet that uses a path.
        [switch] $PassThru,

        # Grants permissions, even if they are already present.
        [switch] $Force
    )

    Set-StrictMode -Version 'Latest'
    Use-CallerPreference -Cmdlet $PSCmdlet -Session $ExecutionContext.SessionState

    if (-not $IsWindows)
    {
        Write-Error -Message 'Grant-CPrivateKeyPermission only supports Windows.' -ErrorAction $ErrorActionPreference
        return
    }

    if (-not (Test-Path -Path $Path))
    {
        $msg = "Failed to grant permissions on ""${Path}"" certificate's private key because the certificate does " +
               'not exist.'
        Write-Error -Message $msg -ErrorAction $ErrorActionPreference
        return
    }

    if (-not (Test-CPrincipal -Name $Identity))
    {
        $msg = "Failed to grant ""${Permission}"" permissions on ""${Path}"" to ""${Identity}"" because that " +
               'user/group does not exist.'
        Write-Error -Message $msg -ErrorAction $ErrorActionPreference
        return
    }

    $Identity = Resolve-CPrincipalName -Name $Identity

    foreach ($certificate in (Get-Item -Path $Path -Force))
    {
        if ($certificate -isnot [X509Certificate2])
        {
            $msg = "Failed to grant permissions on ""${certificate}"" because it is not an X509 certificate."
            Write-Error -Message $msg -ErrorAction $ErrorActionPreference
            continue
        }

        $certPath = Join-Path -Path 'cert:' -ChildPath ($certificate.PSPath | Split-Path -NoQualifier)
        $subject = $certificate.Subject
        $thumbprint = $certificate.Thumbprint
        if (-not $certificate.HasPrivateKey)
        {
            $msg = "Unable to grant permission on ""${subject}"" (thumbprint: ${thumbprint}; path ${certPath}) " +
                   'certificate''s private key because the certificate doesn''t have a private key.'
            Write-Warning $msg -WarningAction $WarningPreference
            continue
        }

        $description = "${certPath} ${subject}"

        $pk = $certificate | Get-CPrivateKey
        if (-not $pk)
        {
            continue
        }

        $useCryptoKeyRights = ($pk | Test-CCryptoKeyAvailable)
        if (-not $useCryptoKeyRights)
        {
            $grantPermArgs = [Collections.Generic.Dictionary[[String], [Object]]]::New($PSBoundParameters)
            [void]$grantPermArgs.Remove('Path')

            $pkPaths = $certificate | Resolve-CPrivateKeyPath
            if (-not $pkPaths)
            {
                continue
            }

            foreach ($pkPath in $pkPaths)
            {
                Grant-CPermission -Path $pkPath @grantPermArgs -Description $description
            }

            continue
        }

        [Security.AccessControl.CryptoKeySecurity] $keySecurity =
            $certificate.PrivateKey.CspKeyContainerInfo.CryptoKeySecurity
        if (-not $keySecurity)
        {
            $msg = "Failed to grant permission to ""${subject}"" (thumbprint: ${thumbprint}; path: ${certPath}) " +
                   'certificate''s private key because the private key has no security information. Make sure ' +
                   'you''re running with administrative rights.'
            Write-Error -Message $msg -ErrorAction $ErrorActionPreference
            continue
        }

        $rulesToRemove = @()
        if ($Clear)
        {
            $rulesToRemove =
                $keySecurity.Access |
                Where-Object { $_.IdentityReference.Value -ne $Identity } |
                # Don't remove Administrators access.
                Where-Object { $_.IdentityReference.Value -ne 'BUILTIN\Administrators' }
            if ($rulesToRemove)
            {
                foreach ($ruleToRemove in $rulesToRemove)
                {
                    $rmIdentity = $ruleToRemove.IdentityReference.ToString()
                    $rmType = $ruleToRemove.AccessControlType.ToString().ToLowerInvariant()
                    $rmRights = $ruleToRemove.CryptoKeyRights
                    Write-Information "${description}  ${rmIdentity}  - ${rmType} ${rmRights}"
                    if (-not $keySecurity.RemoveAccessRule($ruleToRemove))
                    {
                        $msg = "Failed to remove ""${rmIdentity}"" identity's ${rmType} ""${rmRights}"" permissions " +
                               "to ${subject} (thumbprint: ${thumbprint}; path: ${certPath}) certificate's private key."
                        Write-Error -Message $msg -ErrorAction $ErrorActionPreference
                        continue
                    }
                }
            }
        }

        $rights = $Permission | ConvertTo-CryptoKeyRights

        $accessRule =
            New-Object -TypeName 'Security.AccessControl.CryptoKeyAccessRule' `
                        -ArgumentList $Identity, $rights, $Type |
            Add-Member -MemberType NoteProperty -Name 'Path' -Value $certPath -PassThru

        if ($Force -or `
            $rulesToRemove -or `
            -not (Test-CPrivateKeyPermission -Path $certPath -Identity $Identity -Permission $Permission -Strict))
        {
            $currentPerm = Get-CPrivateKeyPermission -Path $certPath -Identity $Identity
            if ($currentPerm)
            {
                $curType = $currentPerm.AccessControlType.ToString().ToLowerInvariant()
                $curRights = $currentPerm.CryptoKeyRights
                Write-Information "${description}  ${Identity}  - ${curType} ${curRights}"
            }
            $newType = $Type.ToString().ToLowerInvariant()
            Write-Information "${description}  ${Identity}  + ${newType} ${rights}"
            $keySecurity.SetAccessRule($accessRule)
            $action = "grant ""${Identity} ${newType} ${rights} permission(s)"
            Set-CryptoKeySecurity -Certificate $certificate -CryptoKeySecurity $keySecurity -Action $action
        }

        if( $PassThru )
        {
            return $accessRule
        }
    }
}

