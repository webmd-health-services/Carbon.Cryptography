Set-StrictMode -Version 'Latest'

& (Join-Path -Path $PSScriptRoot -ChildPath 'Initialize-Test.ps1' -Resolve)

Describe 'Find-CTlsCertificate.when there is a match between hostname and a certificate`s subject alternative name'{
    It 'should return a certificate with Subject Alternate Name matching hostname'{
        $certificate = Find-CTlsCertificate ("2.5.29.17")
        $certificate | Should -Not -BeNullOrEmpty
    }
}

Describe 'Find-CTlsCertificate.when there is no match between hostname and a certificate`s subject alternative name'{
    It 'should return null with an error message'{
        $certificate = Find-CTlsCertificate ("Invalid.Name")
        $certificate | Should -BeNullOrEmpty
    }
}

Describe 'Find-CTlsCertificate.when passed no arguments'{
    It 'should return null with an error message'{
        $certificate = Find-CTlsCertificate ("Invalid.Name")
        $certificate | Should -BeNullOrEmpty
    }
}