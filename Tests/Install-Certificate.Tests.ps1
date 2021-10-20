
#Requires -Version 5.1
Set-StrictMode -Version 'Latest'

& (Join-Path -Path $PSScriptRoot -ChildPath 'Initialize-Test.ps1' -Resolve)

$testCertPath = Join-Path -Path $PSScriptRoot -ChildPath 'Resources\CarbonTestCertificate.pfx' -Resolve
$testCert = New-Object 'Security.Cryptography.X509Certificates.X509Certificate2' $testCertPath
$password = ConvertTo-SecureString -String 'password' -AsPlainText -Force
$TestCertProtectedPath = Join-Path -Path $PSScriptRoot -ChildPath 'Resources\CarbonTestCertificateWithPassword.pfx' -Resolve
$testCertProtected = New-Object 'Security.Cryptography.X509Certificates.X509Certificate2' $TestCertProtectedPath, $password

$onWindows = Test-TCOperatingSystem -IsWindows

if( -not $onWindows )
{
    Write-Warning -Message ('TODO: Get Install-Certificate working on non-Windows platforms.')
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
    Reset
}

function Measure-PhysicalStore
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [Security.Cryptography.X509Certificates.StoreLocation]$Location
    )

    $path = Join-Path -Path $env:APPDATA -ChildPath 'Microsoft\Crypto\RSA\*\*'
    if( $Location -eq [Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine )
    {
        $path = Join-Path -Path $env:ProgramData -ChildPath 'Microsoft\Crypto\RSA\MachineKeys'
    }
    Get-ChildItem -Path $path -ErrorAction Ignore | Measure-Object | Select-Object -ExpandProperty 'Count'
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

    $tries = 100
    $cert = $null
    for( $tryNum = 0; $tryNum -lt $tries; ++$tryNum )
    {
        $cert = Get-CCertificate -Thumbprint $WithThumbprint -StoreLocation $For -StoreName $In
        if( $cert )
        {
            break
        }
        Start-Sleep -Milliseconds 100
    }
    $cert | Should -Not -BeNullOrEmpty
    $cert.Thumbprint | Should -Be $WithThumbprint
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

        [switch]$WhatIf,

        [Parameter(ParameterSetName='FromFile')]
        [securestring]$WithPassword
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

    if( $WithPassword )
    {
        $conditionalParams['Password'] = $WithPassword
    }

    $output = $null
    Install-CCertificate -StoreLocation $For @conditionalParams |
        Tee-Object -Variable 'output'
    $script:output = $output
}

$locations = & {
    'CurrentUser'
    if( (Test-IsAdministrator) -and $onWindows )
    {
        'LocalMachine'
    }
}

Describe 'Install-Certificate' {
    BeforeEach { Init }
    AfterEach { Reset }

    foreach( $location in $locations )
    {
        Context "for $($location)" {
            It 'should install certificate from a file' {
                WhenInstalling -FromFile $testCertPath -For $location -In 'My'
                ThenCertificateInstalled $testCert.Thumbprint -For $location -In 'My' 
                ThenNothingReturned
                $cert = Get-CCertificate -Thumbprint $testCert.Thumbprint -StoreLocation $location -StoreName 'My'
                {
                    $cert.Export( [Security.Cryptography.X509Certificates.X509ContentType]::Pfx ) | Out-Null
                } | Should -Throw
            }

            It 'should install certificate from a file with relative path' {
                Push-Location -Path $PSScriptRoot
                try
                {
                    $path = '.\Resources\{0}' -f (Split-Path -Leaf -Path $testCertPath)
                    WhenInstalling -FromFile $path -For $location -In 'My'
                    ThenNothingReturned
                    ThenCertificateInstalled $testCert.Thumbprint -For $location -In 'My' 
                }
                finally
                {
                    Pop-Location
                }
            }

            It 'should install certificate as exportable' {
                WhenInstalling -FromFile $testCertPath -For $location -In 'My' -ThatIsExportable
                ThenNothingReturned
                ThenCertificateInstalled $testCert.Thumbprint -For $location -In 'My' 
                $cert = Get-CCertificate -Thumbprint $testCert.Thumbprint -StoreLocation $location -StoreName 'My'
                $cert | Should -Not -BeNullOrEmpty
                $bytes = $cert.Export( [Security.Cryptography.X509Certificates.X509ContentType]::Pfx )
                $bytes | Should -Not -BeNullOrEmpty
            }

            It 'should install certificate' {
                WhenInstalling $testCert -For $location -In 'My'
                ThenNothingReturned
                ThenCertificateInstalled $testCert.Thumbprint -For $location -In 'My'
            }

            It 'should install password protected certificate' {
                $fileCount = Measure-PhysicalStore -Location $location
                WhenInstalling -FromFile $TestCertProtectedPath -WithPassword $password -For $location -In 'My'
                ThenNothingReturned
                ThenCertificateInstalled $testCertProtected.Thumbprint -For $location -In 'My'
                Measure-PhysicalStore -Location $location | Should -Be ($fileCount + 1)
            }

            It 'should install certificate in remote computer' @skipRemotingParam {
                $session = New-PSSession -ComputerName $env:COMPUTERNAME
                try
                {
                    WhenInstalling $testCert -For $location -In 'My' -OverSession $session
                    ThenNothingReturned
                    ThenCertificateInstalled $testCert.Thumbprint -For $location -In 'My'
                }
                finally
                {
                    Remove-PSSession -Session $session
                }
            }

            It 'should support ShouldProcess' {
                WhenInstalling -FromFile $testCertPath -For $location -In 'My' -WhatIf
                ThenNothingReturned
                Join-Path -Path "cert:\$($location)\My" -ChildPath $testCert.Thumbprint |
                    Should -Not -Exist
            }
        }
    }
}

foreach( $location in $locations )
{
    Describe "Install-Certificate.$($location).when installing in custom store" {
        AfterEach { Reset }
        It 'should install certificate in the custom store' {
            Init
            $certInstallPath = Join-Path -Path "cert:\$($location)\Carbon" -ChildPath $testCert.Thumbprint
            # Certs in local machine stores (except "My") are inherited into user stores, so delete any certs in the
            # local machine store first.
            Uninstall-CCertificate -Thumbprint $testCert.Thumbprint `
                                   -StoreLocation 'LocalMachine' `
                                   -CustomStoreName 'Carbon'
            Uninstall-CCertificate -Thumbprint $testCert.Thumbprint `
                                   -StoreLocation 'CurrentUser' `
                                   -CustomStoreName 'Carbon'
            $certInstallPath | Should -Not -Exist
            WhenInstalling -FromFile $testCertPath -For $location -In 'Carbon'
            ThenNothingReturned

            $duration = [Diagnostics.Stopwatch]::StartNew()
            $timeout = [TimeSpan]::New(0, 0, 10)
            do
            {
                if( (Test-Path -Path $certInstallPath) )
                {
                    break
                }

                Write-Verbose "Couldn't find $($location)\Carbon\$($ExpectedCertificate.Thumbprint). Trying again in 100ms." -Verbose
                Start-Sleep -Milliseconds 100
            }
            while( $duration.Elapsed -lt $timeout )
            $duration.Stop()
            $duration = $null

            $certInstallPath | Should -Exist
        }
    }

    Describe "Install-Certificate.$($location).when certificate is already installed" {
        AfterEach { Reset }
        It 'should not re-install it' {
            $fileCount = Measure-PhysicalStore -Location $location
            Init
            $output =
                WhenInstalling -FromFile $testCertPath -For $location -In 'My' -Verbose 4>&1 |
                Where-Object { $_ -is [Management.Automation.VerboseRecord] }
            $output | Should -HaveCount 1
            $output.Message | Should -Match 'Installing certificate'
            ThenCertificateInstalled $testCert.Thumbprint -For $location -In 'My'
            ThenNoError

            # Install it again.
            $output = 
                WhenInstalling -FromFile $testCertPath -For $location -In 'My' -Verbose 4>&1 |
                Where-Object { $_ -is [Management.Automation.VerboseRecord] }
            $output | Should -BeNullOrEmpty -Because 'certificates shouldn''t get re-installed'
            ThenNoError
            ThenCertificateInstalled $testCert.Thumbprint -For $location -In 'My'
            Measure-PhysicalStore -Location $location | Should -Be ($fileCount + 1)
        }
    }

    Describe "Install-Certificate.$($location).when certificate is already installed and forcing install" {
        AfterEach { Reset }
        It 'should not re-install it' {
            $fileCount = Measure-PhysicalStore -Location $location
            Init
            $output =
                WhenInstalling -FromFile $testCertPath -For $location -In 'My' -Verbose 4>&1 |
                Where-Object { $_ -is [Management.Automation.VerboseRecord] }
            ThenNoError
            $output | Should -HaveCount 1
            $output.Message | Should -Match 'Installing certificate'
            ThenCertificateInstalled $testCert.Thumbprint -For $location -In 'My'

            # Install it again.
            $output = 
                WhenInstalling -FromFile $testCertPath -For $location -In 'My' -WithForce -Verbose 4>&1 |
                Where-Object { $_ -is [Management.Automation.VerboseRecord] }
            ThenNoError
            $output | Should -HaveCount 1
            $output.Message | Should -Match 'Installing certificate'
            ThenCertificateInstalled $testCert.Thumbprint -For $location -In 'My'
            Measure-PhysicalStore -Location $location | Should -Be ($fileCount + 2)
        }
    }

    Describe "Install-Certificate.$($location).when requesting the installed certificate be returned" {
        AfterEach { Reset }
        Context 'certificate is not installed' {
            It 'should return the certificate' {
                Init
                WhenInstalling $testCert -For $location -In 'My' -ReturningCertificate
                ThenCertificateReturned $testCert.Thumbprint
            }
        }
        Context 'certificate is installed' {
            It 'should return the certificate' {
                Init
                WhenInstalling $testCert -For $location -In 'My'
                ThenNothingReturned
                WhenInstalling $testCert -For $location -In 'My' -ReturningCertificate
                ThenCertificateReturned $testCert.Thumbprint
            }
        }
    }
}

if( $skipRemotingTests )
{
    $msg = 'Tests to ensure Install-Certificate works over remoting were not run. Remoting tests require ' +
            'administrator rights. Make sure to run these tests as an administrator.'
    Write-Warning -Message $msg
}
