# Copyright WebMD Health Services
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License

@{

    # Script module or binary module file associated with this manifest.
    RootModule = 'Carbon.Security.psm1'

    # Version number of this module.
    ModuleVersion = '1.0.0'

    # ID used to uniquely identify this module
    GUID = '225b9f63-3e3e-406c-87a0-33d34f30cd8e'

    # Author of this module
    Author = 'WebMD Health Services'

    # Company or vendor of this module
    CompanyName = 'WebMD Health Services'

    # If you want to support .NET Core, add 'Core' to this list.
    CompatiblePSEditions = @( 'Desktop', 'Core' )

    # Copyright statement for this module
    Copyright = '(c) WebMD Health Services.'

    # Description of the functionality provided by this module
    Description = 'Makes encrypting and decrypting strings and other security work easy.'

    # Minimum version of the Windows PowerShell engine required by this module
    PowerShellVersion = '5.1'

    # Name of the Windows PowerShell host required by this module
    # PowerShellHostName = ''

    # Minimum version of the Windows PowerShell host required by this module
    # PowerShellHostVersion = ''

    # Minimum version of Microsoft .NET Framework required by this module
    # DotNetFrameworkVersion = ''

    # Minimum version of the common language runtime (CLR) required by this module
    # CLRVersion = ''

    # Processor architecture (None, X86, Amd64) required by this module
    # ProcessorArchitecture = ''

    # Modules that must be imported into the global environment prior to importing this module
    # RequiredModules = @()

    # Assemblies that must be loaded prior to importing this module
    # RequiredAssemblies = @( )

    # Script files (.ps1) that are run in the caller's environment prior to importing this module.
    # ScriptsToProcess = @()

    # Type files (.ps1xml) to be loaded when importing this module
    # TypesToProcess = @()

    # Format files (.ps1xml) to be loaded when importing this module
    # FormatsToProcess = @( )

    # Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
    # NestedModules = @()

    # Functions to export from this module. Only list public function here.
    FunctionsToExport = @(
        'Convert-CSecureStringToString'
        'Get-CCertificate',
        'Install-CCertificate',
        'Uninstall-CCertificate'
    )

    # Cmdlets to export from this module. By default, you get a script module, so there are no cmdlets.
    # CmdletsToExport = @()

    # Variables to export from this module. Don't export variables except in RARE instances.
    VariablesToExport = @()

    # Aliases to export from this module. Don't create/export aliases. It can pollute your user's sessions.
    AliasesToExport = @()

    # DSC resources to export from this module
    # DscResourcesToExport = @()

    # List of all modules packaged with this module
    # ModuleList = @()

    # List of all files packaged with this module
    # FileList = @()

    # HelpInfo URI of this module
    # HelpInfoURI = ''

    # Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
    # DefaultCommandPrefix = ''

    # Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
    PrivateData = @{

        PSData = @{

            # Tags applied to this module. These help with module discovery in online galleries.
            Tags = @( 
                'Desktop', 'Core', 'security', 'convert', 'securestring', 'string', 'certificate', 'certificates',
                'x509', 'x509certificate', 'x509certificates', 'install', 'uninstall'
             )

            # A URL to the license for this module.
            LicenseUri = 'http://www.apache.org/licenses/LICENSE-2.0'

            # A URL to the main website for this project.
            ProjectUri = 'https://github.com/webmd-health-services/Carbon.Security'

            # A URL to an icon representing this module.
            # IconUri = ''

            Prerelease = ''

            # ReleaseNotes of this module
            ReleaseNotes = @'
# Upgrade Instructions

If upgrading from Carbon 2, you should do the following:

* `Get-CCertificate` and `Install-CCertificate` no longer accept plaintext passwords. Ensure the value passed to the 
  `Password` parameter of the `Get-CCertificate` and `Install-CCertificate` functions is a `[securestring]`.
* `Install-CCertificate` no longer installs a certificate if it is already installed. Add a `-Force` switch to all
  usages of `Install-CCertificate` where you need existing certificates to be replaced.
* `Install-CCertificate` no longer returns the installed certificate. Add a `-PassThru` switch to all usages of
  `Install-CCertificate` where your code expects a return value.

# Changes

* Migrated `Convert-CSecureStringToString` from Carbon.
* `Convert-CSecureStringToString` now accepts piping in secure strings.
* Migrated `Get-CCertificate`, `Install-CCertificate`, and `Uninstall-CCertificate` from Carbon.
* Changed the `Password` parameter on the `Get-CCertificate` and `Install-CCertificate` functions to be a
  `[securestring]`. Plain text passwords are no longer allowed.
* `Install-CCertificate` no longer installs a certificate if it is already installed. Use the new `-Force` switch to
  always re-install a certificate.
* `Install-CCertificate` no longer always returns the installed certificate. If you want the certificate returned, use
  the new `-PassThru` switch.
* The `Get-CCertificate` function's default parameter set is now loading a certificate by path and you no longer have
  to explicitly provide the `-Path` parameter.
'@
        } # End of PSData hashtable

    } # End of PrivateData hashtable
}
