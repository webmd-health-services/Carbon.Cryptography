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

<#
.SYNOPSIS
Imports the Carbon.Cryptography module into the current session.

.DESCRIPTION
The `Import-Carbon.Cryptography.ps1` script imports the Carbon.Cryptography module into the current session. If the module is already
loaded, it is removed, then reloaded.

.EXAMPLE
.\Import-Carbon.Cryptography.ps1

Demonstrates how to use this script to import the Carbon.Cryptography module  into the current PowerShell session.
#>
[CmdletBinding()]
param(
)

#Requires -Version 5.1
Set-StrictMode -Version 'Latest'

$originalVerbosePref = $Global:VerbosePreference
$originalWhatIfPref = $Global:WhatIfPreference

$Global:VerbosePreference = $VerbosePreference = 'SilentlyContinue'
$Global:WhatIfPreference = $WhatIfPreference = $false

try
{
    if( (Get-Module -Name 'Carbon.Cryptography') )
    {
        Remove-Module -Name 'Carbon.Cryptography' -Force
    }

    Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath 'Carbon.Cryptography.psd1' -Resolve)
}
finally
{
    $Global:VerbosePreference = $originalVerbosePref
    $Global:WhatIfPreference = $originalWhatIfPref
}
