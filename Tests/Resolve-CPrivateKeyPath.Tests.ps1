
#Requires -Version 5.1
Set-StrictMode -Version 'Latest'

$script:rsaCertThumbprint = '44A7C2F73353BC53F82318C14490D7E2500B6DE9'
$script:cngCertThumbprint = '6CF94E242624811F7E12A5340502C1ECE88F1B18'

BeforeAll {
    Set-StrictMode -Version 'Latest'

    & (Join-Path -Path $PSScriptRoot -ChildPath 'Initialize-Test.ps1' -Resolve)

    $script:rsaCertThumbprint = '44A7C2F73353BC53F82318C14490D7E2500B6DE9'
    $script:cngCertThumbprint = '6CF94E242624811F7E12A5340502C1ECE88F1B18'

}

Describe 'Resolve-CPrivateKeyPath' {
    Context '<_>' -ForEach 'CurrentUser', 'LocalMachine' {

        $location = $_

        $testCases = @(
            @{ Description = 'RSA' ; CertPath = "Cert:\${location}\My\${script:rsaCertThumbprint}" },
            @{ Description = 'CNG' ; CertPath = "Cert:\${location}\My\${script:cngCertThumbprint}" }
        )

        Context '<Description>' -ForEach $testCases {
            It 'gets a single path' {
                Get-Item -Path $CertPath | Resolve-CPrivateKeyPath | Should -HaveCount 1
            }
        }
    }
}