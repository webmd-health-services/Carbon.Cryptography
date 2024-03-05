
#Requires -Version 5.1
Set-StrictMode -Version 'Latest'

BeforeAll {
    Set-StrictMode -Version 'Latest'

    & (Join-Path -Path $PSScriptRoot -ChildPath 'Initialize-Test.ps1' -Resolve)
}

Describe 'Get-CPrivateKey' {
    BeforeEach {
        $Global:Error.Clear()
    }

    $testCases = @(
        @{ CertFilePath = 'CarbonRsaCng.pfx' ; Description = 'CNG' ; },
        @{ CertFilePath = 'CarbonTestPrivateKey.pfx' ; Description = 'RSA' ; }
    )

    Context '<Description>' -ForEach $testCases {
        It 'gets the private key' {
            $certFileFullPath = Join-Path -Path $PSScriptRoot -ChildPath $CertFilePath
            $pk = Get-CCertificate -Path $certFileFullPath | Get-CPrivateKey
            $pk | Should -Not -BeNullOrEmpty
            $Global:Error | Should -BeNullOrEmpty
        }

    }
}