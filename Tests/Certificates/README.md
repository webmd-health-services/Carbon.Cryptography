# Test Certificates

## Creating

Generate new public/private key pairs with this command:

```powershell
New-CRsaKeyPair -KeyUsage DocumentEncryption -Subject 'CN=FUNCTION_BEING_TESTED'
```

Don't enter a password to leave the private key .pfx file unprotected. If you need both a protected and unprotected
.pfx file, generate an unprotected private key, import it into your My certificate store as exportable, then export
with a password.

To create a CNG (cryptographic next-generation) public/private key pair, use the "Microsoft Software Key Storage
Provider" provider:

```powershell
New-CRsaKeyPair -KeyUsage DocumentEncryption -ProviderName 'Microsoft Software Key Storage Provider' -Subject 'CN=FUNCTION_BEING_TESTED'
```

You must change the header/footer in the public key, .pem file, to be:

```
-----BEGIN CERTIFICATE-----
-----END CERTIFICATE-----
```

for it to be loadable on non-Windows platforms.
