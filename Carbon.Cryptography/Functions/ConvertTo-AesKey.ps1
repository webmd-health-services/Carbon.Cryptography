
function ConvertTo-AesKey
{
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)]
        [String]$From,

        [Parameter(Mandatory)]
        [Object]$InputObject
    )

    Set-StrictMode -Version 'Latest'
    Use-CallerPreference -Cmdlet $PSCmdlet -Session $ExecutionContext.SessionState    

    $Key = $InputObject

    $bytesKey = $true
    if( $InputObject -isnot [byte[]] )
    {
        $bytesKey = $false
        if( $InputObject -is [SecureString] )
        {
            $unicodeKey = Convert-SecureStringToByte -SecureString $InputObject
            try
            {
                # SecureString is two bytes per char. We need an encoding that is typically one byte per char, otherwise
                # the key will be twice as big as it should be. In the end, the user is responsible for ensuring the
                # key is the property size (in bytes).
                $Key = [Text.Encoding]::Convert([Text.Encoding]::Unicode, [Text.Encoding]::UTF8, $unicodeKey)
            }
            finally
            {
                $unicodeKey.Clear() # Keep it out of memory!
            }
        }
        else
        {
            $msg = "An encryption key must be a [securestring] or an array of bytes, but $($From) got passed a " +
                   """$($InputObject.GetType().FullName)"". If you are passing an array of bytes, make sure you " +
                   "explicitly cast it as a ``byte[]`, e.g. `([byte[]])@( ... )` when passing to $($From)."
            Write-Error -Message $msg
            return
        }
    }

    if( $Key.Length -ne 128/8 -and $Key.Length -ne 192/8 -and $Key.Length -ne 256/8 )
    {
        $commonMsg = "Key is the wrong length. The $($From) function is using AES, which requires a 128-bit, " +
                     '192-bit, or 256-bit key (16, 24, or 32 bytes, respectively). '
        # Did we receive an array of bytes for a key or a secure string?
        if( $bytesKey )
        {
            $msg = "$($commonMsg) Make sure your byte array key is 16, 24, or 32 bytes long."
        }
        # Got a secure string.
        else
        {
            $msg = "$($commonMsg) Make sure that when the secure string key is UTF-8 encoded and converted to a byte " +
                   "array, that array is 16, 32, or 64 bytes long. $($From) received a secure string key that is " +
                   "$($Key.Length) bytes long."
        }
        Write-Error -Message $msg
        return
    }

    return $Key
}
