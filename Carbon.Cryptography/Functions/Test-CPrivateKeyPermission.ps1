
function Test-CPrivateKeyPermission
{
    <#
    .SYNOPSIS
    Tests if a user/group has permissions on an X509 certificate's private key.

    .DESCRIPTION
    The `Test-CPrivateKeyPermission` function tests if a user/group has permission on an X509 certificate's private key.
    Pass the path to the X509 certificate to the `Path` parameter. The path must be in PowerShell's "cert:" drive.  Pass
    the user/group name to the `Identity` parameter. Pass the permission to check to the `Permission` parameter. The
    function returns `$true` if the user/group has the given permission, `$false` otherwise.

    To check that the user has exactly the permissions give, use the `-Strict` switch. If a user has full control, and
    you pass `Read` as the permission to check, the function will return `$true` because read permissions are part of
    full control permissions.

    By default, only non-inherited permissions are used. To also consider inherited permissions, use the `-Inherited`
    switch.

    If the certificate doesn't have a private key, a warning is written and `$true` returned.

    .OUTPUTS
    System.Boolean.

    .LINK
    Get-CPrivateKey

    .LINK
    Get-CPrivateKeyPermission

    .LINK
    Grant-CPrivateKeyPermission

    .LINK
    Resolve-CPrivateKeyPermission

    .LINK
    Revoke-CPrivateKeyPermission

    .EXAMPLE
    Test-CPrivateKeyPermission -Identity 'STARFLEET\Data' -Permission 'FullControl' -Path 'cert:\LocalMachine\My\1234567890ABCDEF1234567890ABCDEF12345678'

    Demonstrates how to test for permissions on an X509 certificate's private key.

    .EXAMPLE
    Test-CPrivateKeyPermission -Identity 'ENT\LowerDecks' -Permission 'Read' -Strict -Path 'cert:\LocalMachine\My\1234567890ABCDEF1234567890ABCDEF12345678'

    Demonstrates how to test for exact permissions. In this example, we're checking that the lower decks crew only has
    read permissions and no more.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        # The path on which the permissions should be checked.  Can be a file system or registry path.
        [Parameter(Mandatory)]
        [String] $Path,

        # The user or group whose permissions to check.
        [Parameter(Mandatory)]
        [String] $Identity,

        # The permission to test for: e.g. FullControl, Read, etc.  For file system items, use values from
        # [System.Security.AccessControl.FileSystemRights](http://msdn.microsoft.com/en-us/library/system.security.accesscontrol.filesystemrights.aspx).
        # For registry items, use values from
        # [System.Security.AccessControl.RegistryRights](http://msdn.microsoft.com/en-us/library/system.security.accesscontrol.registryrights.aspx).
        [Parameter(Mandatory)]
        [ValidateSet('Read', 'FullControl')]
        [String] $Permission,

        # Include inherited permissions in the check.
        [switch] $Inherited,

        # Check for the exact permissions, inheritance flags, and propagation flags, i.e. make sure the identity has
        # *only* the permissions you specify.
        [switch] $Strict
    )

    Set-StrictMode -Version 'Latest'
    Use-CallerPreference -Cmdlet $PSCmdlet -Session $ExecutionContext.SessionState

    if (-not (Test-Path -Path $Path))
    {
        $msg = "Failed to test permissions on ""${Path}"" because that path does not exist."
        Write-Error -Message $msg -ErrorAction $ErrorActionPreference
        return
    }

    if( -not (Test-CIdentity -Name $Identity ) )
    {
        $msg = "Failed to test permissions on ""${Path}"" for ""${Identity}"" because that user/group does not exist."
        Write-Error -Message $msg -ErrorAction $ErrorActionPreference
        return
    }

    $Identity = Resolve-CIdentityName -Name $Identity

    foreach ($certificate in (Get-Item -Path $Path -Force))
    {
        if ($certificate -isnot [X509Certificate2])
        {
            $msg = "Failed to test if ""${Identity}} has ${Permission} permissions on ""${certificate}"" because " +
                   "the item is not an X509 certificate but a [$($certificate.GetType().FullName)]."
            Write-Error -Message $msg -ErrorAction $ErrorActionPreference
            continue
        }

        if (-not $certificate.HasPrivateKey)
        {
            $msg = "Failed to check if ""${Identity}"" has ${Permission} permissions on ${Path} because that " +
                   'certificate doesn''t have a private key.'
            Write-Warning -Message $msg -WarningAction $WarningPreference
            continue
        }

        $pk = $certificate | Get-CPrivateKey
        if (-not $pk)
        {
            return $true
        }

        $useCryptoKeyRights = ($pk | Test-CCryptoKeyAvailable)
        if (-not $useCryptoKeyRights)
        {
            $pkPaths = $certificate | Resolve-CPrivateKeyPath
            if (-not $pkPaths)
            {
                continue
            }

            $testPermArgs = [Collections.Generic.Dictionary[[String], [Object]]]::New($PSBoundParameters)
            [void]$testPermArgs.Remove('Path')

            foreach ($pkPath in $pkPaths)
            {
                Test-CPermission -Path $pkPath @testPermArgs
            }

            continue
        }

        $rights = $Permission | ConvertTo-CryptoKeyRights -Strict:$Strict

        $acl =
            Get-CPrivateKeyPermission -Path $Path -Identity $Identity -Inherited:$Inherited |
            Where-Object { $_.AccessControlType -eq 'Allow' } |
            Where-Object { $_.IsInherited -eq $Inherited } |
            Where-Object {
                if (-not $rights)
                {
                    return $true
                }

                if( $Strict )
                {
                    return ($_.CryptoKeyRights -eq $rights)
                }
                else
                {
                    return ($_.CryptoKeyRights -band $rights) -eq $rights
                }
            }

        if( $acl )
        {
            return $true
        }
        return $false
    }
}

