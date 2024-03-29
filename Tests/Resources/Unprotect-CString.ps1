<#
.SYNOPSIS
**INTERNAL. DO NOT USE** Standalone wrapper script for Carbon's `Unprotect-CString` function to make it easier to decrypt a string as a custom user.
#>
param(
    [Parameter(Mandatory)]
    # A base64 encoded string that was protected with Carbon's `Protect-CString`.
    [String]$ProtectedString
)

#Requires -Version 5.1
Set-StrictMode -Version 'Latest'

Add-Type -AssemblyName 'System.Security'

Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath '..\..\Carbon.Cryptography\Carbon.Cryptography.psd1' -Resolve)

Unprotect-CString -ProtectedString $ProtectedString -AsPlainText
