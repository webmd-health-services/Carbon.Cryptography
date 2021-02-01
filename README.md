# Overview

The "Carbon.Security" module has functions that help manage X509 certificates and working with secure strings.

It started out as part of the [Carbon](http://get-carbon.org) module. But when that module become too big and unwieldy,
its security-related functionality was moved into this module.

# System Requirements

* Windows PowerShell 5.1 and .NET 4.6.1+
* PowerShell Core 6+

# Installing

To install globally:

```powershell
Install-Module -Name 'Carbon.Security'
Import-Module -Name 'Carbon.Security'
```

To install privately:

```powershell
Save-Module -Name 'Carbon.Security' -Path '.'
Import-Module -Name '.\Carbon.Security'
```

# Commands

* `Convert-CSecureStringToString`: converts secure strings to strings.
* `Get-CCertificate`: reads X509 certificates from files or, on Windows, from the Windows certificate stores.
* `Install-CCertificate`: Installs X509 certificates into the Windows certificate store.
* `Uninstall-CCertificate`: Removes X509 certificates from the Windows certificate store.
