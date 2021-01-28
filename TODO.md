# Using This Template

Click the "Use this template" button above. Clone the new repository. Run the `.\Initialize-Repository.ps1` script.
Pass the name of the module to the `ModuleName` parameter. The script will:

* Rename this file to TODO.md (there are additional steps to take afterward)
* Puts the default README.md file in place.
* Rename every file that has `Carbon.Security` in its name, replacing `Carbon.Security` with the module name.
* Replaces `Carbon.Security` in every file with the module name.
* Installs and enables [Whiskey](https://github.com/webmd-health-services/Whiskey/wiki).
* Removes this script.
* If Git is installed, adds all the changes, and amends the initial commit with them so all traces of the template are
  removed.

# Manual Steps

Things you'll still need to do after creating your repository:

* Turn on branch protections.
* Create "develop" and "release" branches.
* Create a build in AppVeyor.
* Create a feature branch.
* Update the build.ps1 script to add the API keys necessary to publish the module to GitHub and the PowerShell Gallery.
Look at the bottom, where `New-WhiskeyContext` and `Invoke-WhiskeyBuild` are called. Change those two lines to this:

```powershell
$context = New-WhiskeyContext -Environment 'Dev' -ConfigurationPath $configPath
$apiKeys = @{
    'AppVeyorBearerToken' = 'WHS_APPVEYOR_BEARER_TOKEN';
    'GitHubAccessToken' = 'WHS_GITHUB_ACCESS_TOKEN';
    'PowerShellGalleryApiKey' = 'WHS_POWERSHELL_GALLERY_API_KEY';
}
foreach( $apiKeyName in $apiKeys.Keys )
{
    $envVarName = $apiKeys[$apiKeyName]
    $path = "env:$($envVarName)"
    if( -not (Test-Path -Path $path) )
    {
        continue
    }
    Add-WhiskeyApiKey -Context $context -ID $apiKeyName -Value (Get-Item -Path $path).Value
}
Invoke-WhiskeyBuild -Context $context @optionalArgs
```

* Commit and push your new branch. A build should run in AppVeyor and finish successfully after a minute or so. The
default build will run using:
    * Windows PowerShell 5.1 on:
        * Windows Server 2012 R2
        * Windows Server 2016
    * PowerShell Core 6 on:
        * Windows 2012 R2
        * Windows Server 2016
    * PowerShell Core 7 on:
        * Windows Server 2019
        * Ubuntu 18.04 (Bionic Beaver)
        * macOS 10.15 "Catalina"
