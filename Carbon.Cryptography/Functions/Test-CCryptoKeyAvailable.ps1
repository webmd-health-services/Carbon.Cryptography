
function Test-CCryptoKeyAvailable
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [Object] $InputObject
    )

    begin
    {
        $cryptoKeyRightsExists = $null -ne [Type]::GetType('System.Security.AccessControl.CryptoKeyRights')
    }

    process
    {
        return ($cryptoKeyRightsExists -and ($InputObject | Get-Member -Name 'CspKeyContainerInfo'))
    }
}
