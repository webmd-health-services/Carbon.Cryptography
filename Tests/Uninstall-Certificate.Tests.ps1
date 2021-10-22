
#Requires -Version 5.1
Set-StrictMode -Version 'Latest'

& (Join-Path -Path $PSScriptRoot -ChildPath 'Initialize-Test.ps1' -Resolve)

$TestCertPath = Join-Path -Path $PSScriptRoot -ChildPath 'Resources\CarbonTestCertificate.pfx' -Resolve
$TestCert = New-Object Security.Cryptography.X509Certificates.X509Certificate2 $TestCertPath

function Init
{
    # Make sure there's no local machine cert "inheriting" down to the current user's store.
    Uninstall-CCertificate -Thumbprint $TestCert.Thumbprint
    Install-CCertificate -Path $TestCertPath `
                         -StoreLocation CurrentUser `
                         -StoreName My `
                         -Exportable:(Test-TCertificate -MustBeExportable)
    $Global:Error.Clear()
}

function ThenFailed
{
    [CmdletBinding()]
    param(
        [String] $WithErrorMatching
    )
    $Global:Error | Should -Not -BeNullOrEmpty

    if( $WithErrorMatching )
    {
        $Global:Error | Should -Match $WithErrorMatching
    }
}

Describe 'Uninstall-Certificate' {

    It 'should remove certificate by certificate' {
        Init
        Uninstall-CCertificate -Certificate $TestCert -StoreLocation CurrentUser -StoreName My
        $cert = Get-CCertificate -Thumbprint $TestCert.Thumbprint -StoreLocation CurrentUser -StoreName My
        $cert | Should -BeNullOrEmpty
    }

    It 'should remove certificate by thumbprint' {
        Init
        Uninstall-CCertificate -Thumbprint $TestCert.Thumbprint -StoreLocation CurrentUser -StoreName My
        $maxTries = 10
        $tryNum = 0
        do
        {
            $cert = Get-CCertificate -Thumbprint $TestCert.Thumbprint -StoreLocation CurrentUser -StoreName My
            if( -not $cert )
            {
                break
            }
            Start-Sleep -Milliseconds 100
        }
        while( $tryNum++ -lt $maxTries )
        $cert | Should -BeNullOrEmpty
    }

    It 'should support WhatIf' {
        Init
        Uninstall-CCertificate -Thumbprint $TestCert.Thumbprint -StoreLocation CurrentUser -StoreName My -WhatIf
        $cert = Get-CCertificate -Thumbprint $TestCert.Thumbprint -StoreLocation CurrentUser -StoreName My
        $cert | Should -Not -BeNullOrEmpty
    }

    It 'should uninstall certificate from custom store' {
        Init
        $errorActionParam = @{}
        if( -not (Test-CustomStore -IsSupported -Location CurrentUser) )
        {
            $errorActionParam['ErrorAction'] = 'SilentlyContinue'
        }
        # Make sure there's no local machine cert "inheriting" down to the current user's store.
        if( (Test-IsAdministrator) -and (Test-MyStore -IsSupported -Location LocalMachine) )
        {
            Uninstall-CCertificate -Thumbprint $TestCert.Thumbprint -StoreLocation LocalMachine -CustomStoreName 'Carbon'
        }
        $cert = Install-CCertificate -Path $TestCertPath -StoreLocation CurrentUser -CustomStoreName 'Carbon' -PassThru
        $cert | Should -Not -BeNullOrEmpty
        Get-CCertificate -StoreLocation CurrentUser -CustomStoreName 'Carbon' -Thumbprint $cert.Thumbprint |
            Should -Not -BeNullOrEmpty
        Uninstall-CCertificate -Thumbprint $cert.Thumbprint `
                               -StoreLocation CurrentUser `
                               -CustomStoreName 'Carbon' `
                               @errorActionParam
        if( (Test-CustomStore -IsSupported -Location CurrentUser) )
        {
            while( (Get-CCertificate -StoreLocation CurrentUser -CustomStoreName 'Carbon' -Thumbprint $cert.Thumbprint) )
            {
                Write-Verbose -Message ('Waiting for "{0}" to get deleted.' -f $certPath)
                Start-Sleep -Seconds 1
            }
            Get-CCertificate -StoreLocation CurrentUser -CustomStoreName 'Carbon' -Thumbprint $cert.Thumbprint |
                Should -BeNullOrEmpty    
        }
        else
        {
            ThenFailed -WithErrorMatching 'exception reading certificates'
        }
    }

    It 'should uninstall certificate from remote computer' -Skip:(-not (Test-Remoting -IsAvailable)) {
        Init
        $Global:Error.Clear()

        [int32]$timeout = [TimeSpan]::New(0, 0, 10).TotalMilliseconds
        $sessionOptions = New-PSSessionOption -OpenTimeout $timeout -CancelTimeout $timeout -OperationTimeout $timeout
        $session = New-PSSession -ComputerName $env:COMPUTERNAME -SessionOption $sessionOptions
        try
        {
            Uninstall-CCertificate -Thumbprint $TestCert.Thumbprint `
                                   -StoreLocation CurrentUser `
                                   -StoreName My `
                                   -Session $session
            $Global:Error.Count | Should -Be 0

            $cert = Get-CCertificate -Thumbprint $TestCert.Thumbprint -StoreLocation CurrentUser -StoreName My
            $cert | Should -BeNullOrEmpty
        }
        finally
        {
            Remove-PSSession -Session $session
        }
    }
}

function GivenARemotingSession
{
    [int32]$timeout = [TimeSpan]::New(0, 0, 10).TotalMilliseconds
    $sessionOptions = New-PSSessionOption -OpenTimeout $timeout -CancelTimeout $timeout -OperationTimeout $timeout
    $script:session = New-PSSession -ComputerName $env:COMPUTERNAME -SessionOption $sessionOptions
}

function GivenAnInstalledCertificate
{
    param(
        $StoreLocation = 'CurrentUser',
        $StoreName = 'My'
    )
    Install-CCertificate -Path $TestCertPath -StoreLocation $StoreLocation -StoreName $StoreName
}

function WhenPipedMultipleThumbprints
{
    $TestCert.Thumbprint,$TestCert.Thumbprint | Uninstall-CCertificate
}

function WhenUninstallingViaRemoting
{
    try
    {
        $TestCert | Uninstall-CCertificate -Session $session
    }
    finally
    {
        $session | Remove-PSSession
    }
}

function WhenUninstallPipedCertificate
{
    $TestCert | Uninstall-CCertificate
}

function WhenUninstallingByThumbprint
{
    Uninstall-CCertificate -Thumbprint $TestCert.Thumbprint
}

function WhenUninstallPipedThumbprint
{
    $TestCert.Thumbprint | Uninstall-CCertificate
}

function ThenCertificateUninstalled
{
    $certs = Get-CCertificate -Thumbprint $TestCert.Thumbprint
    if( $certs )
    {
        $certs | Format-Table -AutoSize | Out-String | Write-Verbose -Verbose
    }
    $certs | Should -BeNullOrEmpty
}

Describe 'Uninstall-Certificate.when given just the certificate thumbprint' {
    It 'should find and uninstall the certificate' {
        Init
        GivenAnInstalledCertificate
        WhenUninstallingByThumbprint
        ThenCertificateUninstalled
    }
}

Describe 'Uninstall-Certificate.when given just the certificate thumbprint and installed in multiple stores' {
    It 'should find and uninstall the certificate from all stores' {
        Init
        GivenAnInstalledCertificate -StoreLocation 'CurrentUser' -StoreName 'My'
        $location = 'CurrentUser'
        if( (Test-IsAdministrator) -and -not (Test-LocalMachineStore -IsReadOnly) )
        {
            $location = 'LocalMachine'
        }
        GivenAnInstalledCertificate -StoreLocation $location -StoreName 'CertificateAuthority'
        WhenUninstallingByThumbprint
        ThenCertificateUninstalled
    }
}

Describe 'Uninstall-Certificate.when piped thumbprint' {
    It 'should uninstall the certificate with that thumbprint' {
        Init
        GivenAnInstalledCertificate
        WhenUninstallPipedThumbprint
        ThenCertificateUninstalled
    }
}

Describe 'Uninstall-Certificate.when piped certificate object' {
    It 'should uninstall that certificate' {
        Init
        GivenAnInstalledCertificate
        WhenUninstallPipedCertificate
        ThenCertificateUninstalled
    }
}

Describe 'Uninstall-Certificate.when piped multiple thumbprints' {
    It 'should uninstall all the certificates' {
        Init
        GivenAnInstalledCertificate
        WhenPipedMultipleThumbprints
        ThenCertificateUninstalled
    }
}
