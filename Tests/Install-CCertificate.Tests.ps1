
#Requires -Version 5.1
Set-StrictMode -Version 'Latest'

& (Join-Path -Path $PSScriptRoot -ChildPath 'Initialize-Test.ps1' -Resolve)

$testCertPath = Join-Path -Path $PSScriptRoot -ChildPath 'Resources\CarbonTestCertificate.cer' -Resolve
$testCert = New-Object 'Security.Cryptography.X509Certificates.X509Certificate2' $testCertPath
$TestCertProtectedPath = Join-Path -Path $PSScriptRoot -ChildPath 'Resources\CarbonTestCertificateWithPassword.cer' -Resolve
$testCertProtected = New-Object 'Security.Cryptography.X509Certificates.X509Certificate2' $TestCertProtectedPath,'password'

$onWindows = Test-COperatingSystem -IsWindows

if( -not $onWindows )
{
    Write-Warning -Message ('TODO: Get Install-CCertificate working on non-Windows platforms.')
    return
}

$skipRemotingTests = (Test-RunningUnderBuildServer) -or -not (Test-IsAdministrator)
$skipRemotingParam = @{
    'Skip' = $skipRemotingTests;
}

$output = $null

function Init
{
    $Global:Error.Clear()

    $script:output = $null

    if( (Get-CCertificate -Thumbprint $testCert.Thumbprint -StoreLocation CurrentUser -StoreName My) )
    {
        Uninstall-CCertificate -Certificate $testCert -StoreLocation CurrentUser -StoreName My
    }

    if( (Get-CCertificate -Thumbprint $testCertProtected.Thumbprint -StoreLocation CurrentUser -StoreName My) )
    {
        Uninstall-CCertificate -Certificate $testCertProtected -StoreLocation CurrentUser -StoreName My
    }
}

function Reset
{
    Uninstall-CCertificate -Certificate $testCert -StoreLocation CurrentUser -StoreName My
    Uninstall-CCertificate -Certificate $testCertProtected -StoreLocation CurrentUser -StoreName My

    # Local Machine store is read-only on non-Windows operating systems.
    if( $onWindows )
    {
        Uninstall-CCertificate -Certificate $testCert -StoreLocation LocalMachine -StoreName My
        Uninstall-CCertificate -Certificate $testCertProtected -StoreLocation LocalMachine -StoreName My
    }
}

function ThenCertificateInstalled
{
    param(
        [Parameter(Mandatory)]
        [String]$WithThumbprint,

        $For = 'CurrentUser', 

        $In = 'My'
    )

    $cert = Get-CCertificate -Thumbprint $WithThumbprint -StoreLocation $For -StoreName $In
    $cert | Should -Not -BeNullOrEmpty | Out-Null
    $cert.Thumbprint | Should -Be $WithThumbprint | Out-Null
    return $cert
}

function ThenCertificateReturned
{
    param(
        [String]$WithThumbprint
    )
    $output | Should -Not -BeNullOrEmpty
    $output | Should -BeOfType ([Security.Cryptography.X509Certificates.X509Certificate2])
    $output.Thumbprint | Should -Be $WithThumbprint
}

function ThenNoError
{
    $Global:Error | Should -BeNullOrEmpty
}

function ThenNothingReturned
{
    $output | Should -BeNullOrEmpty
}

function WhenInstalling
{
    [CmdletBinding(DefaultParameterSetName='FromX509Certificate2Object')]
    param(
        [Parameter(Mandatory, ParameterSetName='FromX509Certificate2Object', Position=0)]
        [Security.Cryptography.X509Certificates.X509Certificate2]$FromX509Certificate2Object,

        [Parameter(Mandatory, ParameterSetName='FromFile')]
        [String]$FromFile,

        [Parameter(Mandatory)]
        $For,
        
        [Parameter(Mandatory)]
        $In,

        [switch]$WithForce,

        [switch]$ReturningCertificate,

        [switch]$ThatIsExportable,

        [Management.Automation.Runspaces.PSSession]$OverSession,

        [switch]$WhatIf
    )

    $conditionalParams = @{}
    if( $WithForce )
    {
        $conditionalParams['Force'] = $WithForce
    }

    if( $FromX509Certificate2Object )
    {
        $conditionalParams['Certificate'] = $FromX509Certificate2Object
    }

    if( $FromFile )
    {
        $conditionalParams['Path'] = $FromFile
    }

    if( $ReturningCertificate )
    {
        $conditionalParams['PassThru'] = $true
    }

    if( $ThatIsExportable )
    {
        $conditionalParams['Exportable'] = $true
    }

    [Security.Cryptography.X509Certificates.StoreName]$storeName = 1
    if( ([Enum]::TryParse($In, [ref]$storeName)) )
    {
        $conditionalParams['StoreName'] = $In
    }
    else
    {
        $conditionalParams['CustomStoreName'] = $In
    }

    if( $OverSession )
    {
        $conditionalParams['Session'] = $OverSession
    }

    if( $WhatIf )
    {
        $conditionalParams['WhatIf'] = $true
    }

    $output = $null
    Install-CCertificate -StoreLocation $For @conditionalParams |
        Tee-Object -Variable 'output'
    $script:output = $output
}

Describe "Install-CCertificate" {
    BeforeEach { Init }
    AfterEach { Reset }

    It 'should install certificate to local machine' {
        WhenInstalling -FromFile $testCertPath -For 'CurrentUser' -In 'My'
        ThenCertificateInstalled $testCert.Thumbprint -For 'CurrentUser' -In 'My' 
        ThenNothingReturned
        $cert = Get-CCertificate -Thumbprint $testCert.Thumbprint -StoreLocation 'CurrentUser' -StoreName 'My'
        {
            $cert.Export( [Security.Cryptography.X509Certificates.X509ContentType]::Pfx ) | Out-Null
        } | Should -Throw
    }

    It 'should install certificate to local machine with relative path' {
        Push-Location -Path $PSScriptRoot
        try
        {
            $path = '.\Resources\{0}' -f (Split-Path -Leaf -Path $testCertPath)
            WhenInstalling -FromFile $path -For 'CurrentUser' -In 'My'
            ThenNothingReturned
            ThenCertificateInstalled $testCert.Thumbprint -For 'CurrentUser' -In 'My' 
        }
        finally
        {
            Pop-Location
        }
    }

    It 'should install certificate to local machine as exportable' {
        WhenInstalling -FromFile $testCertPath -For 'CurrentUser' -In 'My' -ThatIsExportable
        ThenNothingReturned
        ThenCertificateInstalled $testCert.Thumbprint -For 'CurrentUser' -In 'My' 
        $cert = Get-CCertificate -Thumbprint $testCert.Thumbprint -StoreLocation 'CurrentUser' -StoreName 'My'
        $cert | Should -Not -BeNullOrEmpty
        $bytes = $cert.Export( [Security.Cryptography.X509Certificates.X509ContentType]::Pfx )
        $bytes | Should -Not -BeNullOrEmpty
    }

    It 'should install certificate' {
        WhenInstalling $testCert -For 'CurrentUser' -In 'My'
        ThenNothingReturned
        ThenCertificateInstalled $testCert.Thumbprint -For 'CurrentUser' -In 'My'
    }

    It 'should install password protected certificate' {
        WhenInstalling $testCertProtected -For 'CurrentUser' -In 'My'
        ThenNothingReturned
        ThenCertificateInstalled $testCertProtected.Thumbprint -For 'CurrentUser' -In 'My'
    }

    It 'should install certificate in remote computer' @skipRemotingParam {
        $session = New-PSSession -ComputerName $env:COMPUTERNAME
        try
        {
            WhenInstalling $testCert -For 'CurrentUser' -In 'My' -OverSession $session
            ThenNothingReturned
            ThenCertificateInstalled $testCert.Thumbprint -For 'CurrentUser' -In 'My'
        }
        finally
        {
            Remove-PSSession -Session $session
        }
    }

    It 'should support ShouldProcess' {
        WhenInstalling -FromFile $testCertPath -For 'CurrentUser' -In 'My' -WhatIf
        ThenNothingReturned
        Join-Path -Path 'cert:\CurrentUser\My' -ChildPath $testCert.Thumbprint |
            Should -Not -Exist
    }
}

Describe 'Install-CCertificate.when installing in custom store' {
    AfterEach { Reset }
    It 'should install certificate in the custom store' {
        Init
        $certInstallPath = Join-Path -Path 'cert:\CurrentUser\SharePoint' -ChildPath $testCert.Thumbprint
        Uninstall-CCertificate -Thumbprint $testCert.Thumbprint -StoreLocation 'CurrentUser' -CustomStoreName 'SharePoint'
        $certInstallPath | Should -Not -Exist
        WhenInstalling -FromFile $testCertPath -For 'CurrentUser' -In 'SharePoint'
        ThenNothingReturned
        $certInstallPath | Should -Exist
    }
}

Describe 'Install-CCertificate.when certificate is already installed' {
    AfterEach { Reset }
    It 'should not re-install it' {
        Init
        $output =
            WhenInstalling $testCert -For 'CurrentUser' -In 'My' -Verbose 4>&1 |
            Where-Object { $_ -is [Management.Automation.VerboseRecord] }
        $output | Should -HaveCount 1
        $output.Message | Should -Match 'Installing certificate'
        ThenCertificateInstalled $testCert.Thumbprint -For 'CurrentUser' -In 'My'
        ThenNoError

        # Install it again.
        $output = 
            WhenInstalling $testCert -For 'CurrentUser' -In 'My' -Verbose 4>&1 |
            Where-Object { $_ -is [Management.Automation.VerboseRecord] }
        $output | Should -BeNullOrEmpty -Because 'certificates shouldn''t get re-installed'
        ThenNoError
        ThenCertificateInstalled $testCert.Thumbprint -For 'CurrentUser' -In 'My'
    }
}

Describe 'Install-CCertificate.when certificate is already installed and forcing install' {
    AfterEach { Reset }
    It 'should not re-install it' {
        Init
        $output =
            WhenInstalling $testCert -For 'CurrentUser' -In 'My' -Verbose 4>&1 |
            Where-Object { $_ -is [Management.Automation.VerboseRecord] }
        ThenNoError
        $output | Should -HaveCount 1
        $output.Message | Should -Match 'Installing certificate'
        ThenCertificateInstalled $testCert.Thumbprint -For 'CurrentUser' -In 'My'

        # Install it again.
        $output = 
            WhenInstalling $testCert -For 'CurrentUser' -In 'My' -WithForce -Verbose 4>&1 |
            Where-Object { $_ -is [Management.Automation.VerboseRecord] }
        ThenNoError
        $output | Should -HaveCount 1
        $output.Message | Should -Match 'Installing certificate'
        ThenCertificateInstalled $testCert.Thumbprint -For 'CurrentUser' -In 'My'
    }
}

Describe 'Install-CCertificate.when requesting the installed certificate be returned' {
    AfterEach { Reset }
    Context 'certificate is not installed' {
        It 'should return the certificate' {
            Init
            WhenInstalling $testCert -For 'CurrentUser' -In 'My' -ReturningCertificate
            ThenCertificateReturned $testCert.Thumbprint
        }
    }
    Context 'certificate is installed' {
        It 'should return the certificate' {
            Init
            WhenInstalling $testCert -For 'CurrentUser' -In 'My'
            ThenNothingReturned
            WhenInstalling $testCert -For 'CurrentUser' -In 'My' -ReturningCertificate
            ThenCertificateReturned $testCert.Thumbprint
        }
    }
}

if( $skipRemotingTests )
{
    $msg = 'Tests to ensure Install-CCertificate works over remoting were not run. Remoting tests require ' +
            'administrator rights. Make sure to run these tests as an administrator.'
    Write-Warning -Message $msg
}
