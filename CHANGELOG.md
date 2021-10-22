
# 2.1.0

* `Install-CCertificate` now works on Linux and macOS.
* `Uninstall-CCertificate` now works on Linux and macOS.
* Fixed: `Get-CCertificate` only returns one instance of a certificate even if that certificate exists in multiple
  stores and/or locations.
* `Uninstall-CCertificate` no longer opens a store for writing if the certificate to delete isn't installed.


# 2.0.0

## Upgrade Instructions

`Carbon.Cryptography` now uses the `DefaultCommandPrefix` module manifest metadata to add the `C` prefix to its
commands. If you're using the `Import-Module` cmdlet's `-Function` parameter when importing `Carbon.Cryptography`,
remove the `C` prefix from the function names.

The `Get-LocalCertificate` function was removed. Replace any usages of `Get-LocalCertificate` with `Get-CCertificate`. 

The `Remove-Certificate` alias was removed. Replace usages of the `Remove-Certificate` alias with 
`Uninstall-CCertificatte`.

## Changes

* `Carbon.Cryptography` now uses the `DefaultCommandPrefix` module manifest metadata to add the `C` prefix to its
  commands.
* Removed `Get-LocalCertificate` function (it was an internal function that was accidentally exported from the module).
* Removed `Remove-Certificate` alias to `Uninstall-CCertificate`.


# 1.1.0

* Added `Find-CTlsCertificate` function that finds an HTTPS certificate that matches a given hostname, searching the My
  store for the local machine or current user.
* Fixed: On Linux and macOS, `Get-CCertificate` doesn't return certificates from X509 certificate stores.
* When getting a certificate out of the certificate stores, `Get-CCertificate` no longer requires a location, store
  name, and thumbprint. When called with no parameters, `Get-CCertificate` returns *all* certificates in all certificate
  stores (except stores with custom names). The `StoreLocation`, `StoreName`, `Thumbprint`, and `FriendlyName`
  parameters now act as filters for what certificates to return. A certificate must match *all* filters to be returned.
* Added a `Subject` parameter to `Get-CCertificate` to find certificates by subject.


# 1.0.4

* Fixed: `Unprotect-CString `sometimes fails to decrypt a secret if the decryption key certificate is installed in
  multiple certificate stores but some of those times without the private key.


# 1.0.3

* Fixed: When installing certificates with private keys, the `Install-CCertificate` function causes Windows API to write
  extra files to the directories where private keys are saved.
* Fixed: In some situations, the `Install-CCertificate` function, when passed a certificate object to install with a
  private key, would fail to install the private key.


# 1.0.2

* Fixed: `Unprotect-CString` error handling fails when encryption fails.


# 1.0.1

* Fixed: `Protect-CString` incorrectly marked as a filter instead of a function.
* Fixed: `Protect-CString` and `Unprotect-CString` failed to handle encryption exceptions.

# 1.0.0

## Upgrade Instructions

If upgrading from Carbon 2, you should do the following:

* `Get-CCertificate` and `Install-CCertificate` no longer accept plaintext passwords. Ensure the value passed to the 
  `Password` parameter of the `Get-CCertificate` and `Install-CCertificate` functions is a `[securestring]`.
* `Install-CCertificate` no longer installs a certificate if it is already installed. Add a `-Force` switch to all
  usages of `Install-CCertificate` where you need existing certificates to be replaced.
* `Install-CCertificate` no longer returns the installed certificate. Add a `-PassThru` switch to all usages of
  `Install-CCertificate` where your code expects a return value.
* `Unprotect-CString` now returns decrypted text as a `[securestring]`. Add the `-AsPlainText` to use the old behavior
  and get back a plain text string. Remove the `-AsSecureString` parameter if you were previously requesting a secure
  string.

## Changes

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
* The `Unprotect-CString` function now returns the decrypted text as a `[securestring]` by default instead of a
  `[String]`. Use the `-AsPlainText` switch to get a plain text string back (not recommended).