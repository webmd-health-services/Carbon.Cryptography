
function ConvertTo-CryptoKeyRights
{
    <#
    .SYNOPSIS
    Converts standard Read and FullControl permissions to equivalent `System.Security.AccessControl.CryptoKeyRights`
    rights.

    .DESCRIPTION
    The Windows UI only allows two permissions to be granted on a private key: Read and FullControl, so the
    `Carbon.Cryptography` module behaves the same when. When setting permissions on a key that supports
    `CryptoKeyRights`, the rights flags should actually `GenericRead` when granting `Read` permissions and `GenericAll
    -bor GenericRead`  when granting `FullControl` permissions. This was determined by setting permissions on a private
    key using the Windows UI then checking the rights Windows set. This function converts the `Read` and `FullControl`
    permissions allowed by Windows an the `Carbon.Cryptogrpahy` module into the actual CryptoKeyRights flags needed by
    the .NET frameworks crypto service provider API.

    Windows also automatically sets the `Synchronize` flag. If you want the `Synchronize` right flag set, use the
    `-Strict` switch. This is usually ony necessary when comparing rights flags.

    .EXAMPLE
    ConvertTo-CryptoKeyRights -InputObject 'Read'

    Demonstrates how to use this function by passing the permission to the `InputObject` parameter.

    .EXAMPLE
    'FullControl' | ConvertTo-CryptoKeyRights

    Demonstrates how to use this function by piping the permission to the `InputObject` parameter.

    .EXAMPLE
    'Read' | ConvertTo-CryptoKeyRights -Strict

    Demonstrates how to include *all* crypto key
    #>
    [CmdletBinding()]
    param(
        # The values to convert.
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateSet('Read', 'FullControl')]
        [String] $InputObject,

        [switch] $Strict
    )

    process
    {
        Set-StrictMode -Version 'Latest'
        Use-CallerPreference -Cmdlet $PSCmdlet -Session $ExecutionContext.SessionState

        # CryptoKeyRights
        # Read          0x80100000  GenericRead, Synchronize
        # FullControl   0x90100000  GenericRead, GenericAll, Synchronize
        $rights = [Security.AccessControl.CryptoKeyRights]::GenericRead
        if ($InputObject -eq 'FullControl')
        {
            $rights = $rights -bor [Security.AccessControl.CryptoKeyRights]::GenericAll
        }

        if ($Strict)
        {
            $rights = $rights -bor [Security.AccessControl.CryptoKeyRights]::Synchronize
        }

        return $rights
    }
}
