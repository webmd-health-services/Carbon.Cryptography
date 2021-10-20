
function Convert-SecureStringToByte
{
    <#
    .SYNOPSIS
    Converts a secure string to an array of bytes.

    .DESCRIPTION
    The `Convert-CSecureStringToByte` converts a `[securestring]` to an array of bytes that represents the original
    decrypted string. The secure string is never left in memory as a string, but is kept as an array of bytes during
    the conversion, and all arrays used during the conversion are cleared.

    The decrypted secure string is returned as an array of bytes. You are resonsible for clearing the array when 
    you're done, otherwise you risk exposing your secret in memory or on the file system.

    .EXAMPLE
    Convert-CSecureStringToByte -SecureString $credential.Password

    Demonstrates how to convert a secure string into an array of bytes representing the original password.
    #>
    [CmdletBinding()]
    [OutputType([Byte[]])]
    param(
        [Parameter(Mandatory)]
        [securestring]$SecureString
    )

    Set-StrictMode -Version 'Latest'
    Use-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

    $ptrDecryptedString = [Runtime.Interopservices.Marshal]::SecureStringToGlobalAllocUnicode($SecureString);
    try
    {
        [byte[]]$bytes = [byte[]]::New($SecureString.Length * 2)
        for( $idx = 0; $idx -lt $bytes.Length; ++$idx )
        {
            $bytes[$idx] = [Runtime.InteropServices.Marshal]::ReadByte($ptrDecryptedString, $idx)
        }
        return $bytes
    }
    finally
    {
        [Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($ptrDecryptedString)
    }
}