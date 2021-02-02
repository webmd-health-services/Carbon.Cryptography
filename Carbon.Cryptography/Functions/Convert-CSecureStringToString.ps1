
function Convert-CSecureStringToString
{
    <#
    .SYNOPSIS
    Converts a secure string into a plain text string.

    .DESCRIPTION
    The `Convert-CSecureStringToString` function converts a secure string to a plaintexxt string. Try really, really,
    really hard not to do this. Once you do, the plaintext string will be *all over memory* and, perhaps, the file
    system.
    
    The function creates a new `[pscredential]` with the password and uses it to convert the password to plaintext 
    (i.e. it calls `$credential.GetNetworkCredential().Password`).

    .OUTPUTS
    System.String.

    .EXAMPLE
    Convert-CSecureStringToString -SecureString $mySuperSecretPasswordIAmAboutToExposeToEveryone

    Returns the plain text/decrypted value of the secure string.

    .EXAMPLE
    $ISureHopeIKnowWhatIAmDoing | Convert-CSecureStringToString

    Demonstrates that you can pipe a secure string to `Convert-CSecureStringToString`.
    #>
    [CmdletBinding()]
    [OutputType([String])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        # The secure string to convert.
        [securestring]$SecureString
    )
    
    process
    {
        Set-StrictMode -Version 'Latest'
        Use-CallerPreference -Cmdlet $PSCmdlet -Session $ExecutionContext.SessionState

        $bytes = Convert-CSecureStringToByte -SecureString $SecureString
        try
        {
            return [Text.Encoding]::Unicode.GetString($bytes)
        }
        finally
        {
            $bytes.Clear()
        }
    }
}

