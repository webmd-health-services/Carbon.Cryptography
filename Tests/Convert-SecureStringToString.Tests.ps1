
#Requres -Version 5.1
Set-StrictMode -Version 'Latest'

& (Join-Path -Path $PSScriptRoot -ChildPath 'Initialize-Test.ps1' -Resolve)

Describe 'Convert-SecureStringToString.when passed a secure string' {
    It 'should convert it to plaintext' {
        $secret = "Hello World!"
        $secureString = ConvertTo-SecureString -String $secret -AsPlainText -Force
        $notSoSecret = Convert-CSecureStringToString $secureString
        $notSoSecret | Should -Be $secret
    }
}

Describe 'Convert-SecureStringToString.when piping secure strings' {
    It 'should convert each secure string' {
        $plaintexts = 
            & {
                ConvertTo-SecureString -String 'password1' -AsPlainText -Force
                ConvertTo-SecureString -String '1wordpass' -AsPlainText -Force
                ConvertTo-SecureString -String 'word1pass' -AsPlainText -Force
            } |
            Convert-CSecureStringToString
        $plaintexts | Select-Object -First 1 | Should -Be 'password1'
        $plaintexts | Select-Object -Skip 1 | Select-Object -First 1 | Should -Be '1wordpass'
        $plaintexts | Select-Object -Last 1 | Should -Be 'word1pass'
    }
}
