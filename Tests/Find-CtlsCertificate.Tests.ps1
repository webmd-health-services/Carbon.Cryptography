Set-StrictMode -Version 'Latest'

& (Join-Path -Path $PSScriptRoot -ChildPath 'Initialize-Test.ps1' -Resolve)

$ipProperties = [Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
$serverFqdn = "$($ipProperties.HostName).$($ipProperties.DomainName)"
$machineName = [Environment]::MachineName
$foundCert = $null
$mockedCertificates = [Collections.ArrayList]::new()

function Init {
    $script:foundCert = $null
    $script:mockedCertificates = [Collections.ArrayList]::new()
}

function GivenCertificate
{
    param(
        [Parameter(Mandatory)]
        [String]$For,
        [Parameter(Mandatory)]
        [String]$WithThumbprint,
        [switch]$NoPrivateKey,
        [String[]]$WithDnsNames = @(),
        [String[]]$WithUsages,
        [switch]$ThatFailsVerify,
        [String]$ExtensionFriendlyName,
        [datetime] $NotBefore,
        [datetime] $NotAfter
    )

    $fullDnsList = & {
        $For
        if( $WithDnsNames )
        {
            $WithDnsNames
        }
    }
    $extensions = [PSCustomObject]@{
        'Oid' = [PSCustomObject]@{
            'Value' = $For
            'FriendlyName' = 'Subject Alternative Name'
        }
    }
    $certificate = [pscustomobject]@{
        'Thumbprint' = $WithThumbprint
        'SubjectName' = [pscustomobject]@{
            'Name' = "CN=$($For)"
        }
        'DnsNameList' = $fullDnsList
        'EnhancedKeyUsageList' = $WithUsages | ForEach-Object { [pscustomobject]@{ 'FriendlyName' = $_ } }
        'HasPrivateKey' = -not $NoPrivateKey
        'Extensions' = $extensions
        'NotBefore' = $NotBefore
        'NotAfter' = $NotAfter
    }
    $verify = { $true }
    if( $ThatFailsVerify )
    {
        $verify = { $false }
    }
    $certificate | Add-Member -MemberType ScriptMethod -Name 'Verify' -Value $verify
    [void]$mockedCertificates.Add($certificate)
}

function WhenFindingTlsCertificate
{
    param(
        [String]$Name
    )

    $installedCertificates = $script:mockedCertificates

    Mock -CommandName 'Get-LocalCertificates' `
         -ModuleName 'Carbon.Cryptography' `
         -MockWith { $installedCertificates }.GetNewClosure()
    
    $script:foundCert = Find-CTlsCertificate -HostName $Name -ErrorAction SilentlyContinue
}

function ThenFoundCertificate {
    param(
        [String]$HostName
    )

    $foundCert | Should -Not -BeNullOrEmpty
    $foundCert.DnsNameList | Should -Contain $HostName
}

function ThenNoCertificateFound{
    $foundCert | Should -BeNullOrEmpty
}

Describe 'Find-CTlsCertificate' {
    It 'should find a certificate' {
        Init
        GivenCertificate -For $machineName `
                         -WithThumbprint 'This one should find certificate matching hostname' `
                         -WithDnsNames ($serverFqdn) `
                         -WithUsages ('Server Authentication') `
                         -NotBefore (Get-Date) `
                         -NotAfter (Get-Date).AddYears(1)
        Start-Sleep -Seconds 1
        WhenFindingTlsCertificate $machineName
        ThenFoundCertificate $machineName
    }
}

Describe 'Find-CTlsCertificate' {
    It 'should not find a certificate (due to no certificates matching hostname)' {
        Init
        GivenCertificate -For $machineName `
                         -WithThumbprint 'No certificate matching hostname' `
                         -WithDnsNames ($serverFqdn) `
                         -WithUsages ('Server Authentication') `
                         -NotBefore (Get-Date) `
                         -NotAfter (Get-Date).AddYears(1)
        Start-Sleep -Seconds 1
        WhenFindingTlsCertificate 'NotFound'
        ThenNoCertificateFound 
    }
}

Describe 'Find-CTlsCertificate' {
    It 'should not find a certificate (due to no private key)' {
        Init
        GivenCertificate -For $machineName `
                         -WithThumbprint 'No private key' `
                         -NoPrivateKey $true `
                         -WithDnsNames ($serverFqdn) `
                         -WithUsages ('Server Authentication') `
                         -NotBefore (Get-Date) `
                         -NotAfter (Get-Date).AddYears(1)
        Start-Sleep -Seconds 1
        WhenFindingTlsCertificate $machineName
        ThenNoCertificateFound 
    }
}

Describe 'Find-CTlsCertificate' {
    It 'should not find a certificate (due to no matching dns name)' {
        Init
        GivenCertificate -For $machineName `
                         -WithThumbprint 'No matching dns name' `
                         -WithDnsNames ($machineName, 'fake.net') `
                         -WithUsages ('Server Authentication') `
                         -NotBefore (Get-Date) `
                         -NotAfter (Get-Date).AddYears(1)
        Start-Sleep -Seconds 1
        WhenFindingTlsCertificate $machineName
        ThenNoCertificateFound 
    }
}

Describe 'Find-CTlsCertificate' {
    It 'should not find a certificate (due to unsupported usages)' {
        Init
        GivenCertificate -For $machineName `
                         -WithThumbprint 'Unsupported usages' `
                         -WithDnsNames ($serverFqdn) `
                         -WithUsages ('Remote Desktop Authentication', 'Client Authentication') `
                         -NotBefore (Get-Date) `
                         -NotAfter (Get-Date).AddYears(1)
        Start-Sleep -Seconds 1
        WhenFindingTlsCertificate $machineName
        ThenNoCertificateFound 
    }
}

Describe 'Find-CTlsCertificate' {
    It 'should not find a certificate (due to failing validation)' {
        Init
        GivenCertificate -For $machineName `
                         -WithThumbprint 'Fails validation' `
                         -WithDnsNames ($serverFqdn) `
                         -WithUsages ('Server Authentication') `
                         -ThatFailsVerify `
                         -NotBefore (Get-Date) `
                         -NotAfter (Get-Date).AddYears(1)
        Start-Sleep -Seconds 1
        WhenFindingTlsCertificate $machineName
        ThenNoCertificateFound 
    }
}

Describe 'Find-CTlsCertificate' {
    It 'should not find a certificate (due to expired certificate)' {
        Init
        GivenCertificate -For $machineName `
                         -WithThumbprint 'Expired certificate' `
                         -WithDnsNames ($serverFqdn) `
                         -WithUsages ('Server Authentication') `
                         -NotBefore (Get-Date).AddDays(-2) `
                         -NotAfter (Get-Date).AddDays(-1)
        Start-Sleep -Seconds 1
        WhenFindingTlsCertificate $machineName
        ThenNoCertificateFound 
    }
}