
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

    if( $InputObject -isnot [byte[]] )
    {
        if( $InputObject -is [SecureString] )
        {
            $unicodeKey = Convert-CSecureStringToByte -SecureString $InputObject
            try
            {
                # SecureString is two bytes per char. We need an encoding that is one byte per char, otherwise the key
                # will be twice as big as it should be.
                $Key = [Text.Encoding]::Convert([Text.Encoding]::Unicode, [Text.Encoding]::ASCII, $unicodeKey)
            }
            finally
            {
                $unicodeKey.Clear() # Keep it out of memory!
            }
        }
        else
        {
            $msg = 'An encryption key must be a [securestring] or an array of bytes, but we got passed a ' +
                   """$($InputObject.GetType().FullName)"". If you are passing an array of bytes, make sure you " +
                   'explicitly cast it as a `byte[]`, e.g. `([byte[]])@( ... )`.'
            Write-Error -Message $msg
            return
        }
    }

    if( $Key.Length -ne 128/8 -and $Key.Length -ne 192/8 -and $Key.Length -ne 256/8 )
    {
        $msg = "Key is the wrong length. The $($From) function is using AES, which requires a 128-bit, 192-bit, or " +
               "256-bit key (16, 24, or 32 bytes, respectively). We received a key of $($Key.Length * 8) bits " +
               "($($Key.Length) bytes)."
        Write-Error -Message $msg
        return
    }

    return $Key
}
