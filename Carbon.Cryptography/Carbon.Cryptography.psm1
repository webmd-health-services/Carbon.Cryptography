
using namespace System.Security.AccessControl
using namespace System.Security.Cryptography.X509Certificates

# Copyright Aaron Jensen and WebMD Health Services
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

#Requires -Version 5.1
Set-StrictMode -Version 'Latest'

if( -not (Test-Path 'variable:IsWindows') )
{
    [Diagnostics.CodeAnalysis.SuppressMessage('PSAvoidAssignmentToAutomaticVariable', '')]
    $IsWindows = $true
    [Diagnostics.CodeAnalysis.SuppressMessage('PSAvoidAssignmentToAutomaticVariable', '')]
    $IsLinux = $false
    [Diagnostics.CodeAnalysis.SuppressMessage('PSAvoidAssignmentToAutomaticVariable', '')]
    $IsMacOS = $false
}

Add-Type -AssemblyName 'System.Security'

# Functions should use $script:moduleRoot as the relative root from which to find
# things. A published module has its function appended to this file, while a
# module in development has its functions in the Functions directory.
$script:moduleRoot = $PSScriptRoot
$moduleBinRoot = Join-Path -Path $script:moduleRoot -ChildPath 'bin'
$moduleBinRoot | Out-Null # To make the PSScriptAnalyzer squiggle go away.

$psModulesDirPath = Join-Path -Path $script:moduleRoot -ChildPath 'Modules' -Resolve

Import-Module -Name (Join-Path -Path $psModulesDirPath -ChildPath 'Carbon.Core') `
              -Function @(
                    'ConvertTo-CBase64',
                    'Get-CPathProvider',
                    'Invoke-CPowerShell',
                    'Test-COperatingSystem'
                ) `
              -Verbose:$false

Import-Module -Name (Join-Path -Path $psModulesDirPath -ChildPath 'Carbon.Accounts') `
              -Function @('Resolve-CPrincipal', 'Resolve-CPrincipalName', 'Test-CPrincipal') `
              -Verbose:$false

Import-Module -Name (Join-Path -Path $psModulesDirPath -ChildPath 'Carbon.Security') `
              -Function @(
                    'Get-CAcl',
                    'Get-CPermission',
                    'Grant-CPermission',
                    'Revoke-CPermission',
                    'Test-CPermission'
                ) `
              -Verbose:$false

# Store each of your module's functions in its own file in the Functions
# directory. On the build server, your module's functions will be appended to
# this file, so only dot-source files that exist on the file system. This allows
# developers to work on a module without having to build it first. Grab all the
# functions that are in their own files.
$functionsPath = Join-Path -Path $moduleRoot -ChildPath 'Functions\*.ps1'
if( (Test-Path -Path $functionsPath) )
{
    foreach( $functionPath in (Get-Item $functionsPath) )
    {
        . $functionPath.FullName
    }
}
