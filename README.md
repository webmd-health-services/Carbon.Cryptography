# Overview

The "Carbon.Cryptography" module has functions that help manage X509 certificates and working with secure strings.

It started out as part of the [Carbon](http://get-carbon.org) module. But when that module become too big and unwieldy,
its security-related functionality was moved into this module.

# System Requirements

* Windows PowerShell 5.1 and .NET 4.6.1+
* PowerShell Core 6+

# Installing

To install globally:

```powershell
Install-Module -Name 'Carbon.Cryptography'
Import-Module -Name 'Carbon.Cryptography'
```

To install privately:

```powershell
Save-Module -Name 'Carbon.Cryptography' -Path '.'
Import-Module -Name '.\Carbon.Cryptography'
```

# Commands

* `Convert-CSecureStringToByte`: converts a secure string into an array of bytes (that can be easily cleared from from
memory, unlike strings, who hang out forever).
* `Convert-CSecureStringToString`: converts secure strings to strings.
* `Get-CCertificate`: reads X509 certificates from files or, on Windows, from the Windows certificate stores.
* `Install-CCertificate`: Installs X509 certificates into the Windows certificate store.
* `Protect-CString`: Encrypt a string using the Windows Data Protection API (DPAPI; Windows only), public/private key
cryptography, or symmetric cryptography.
* `Uninstall-CCertificate`: Removes X509 certificates from the Windows certificate store.
* `Unprotect-CString`: Decrypt a string that was encrypted with `Protect-CString`.
