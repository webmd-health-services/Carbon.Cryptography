
#Requires -Version 5.1
Set-StrictMode -Version 'Latest'

& (Join-Path -Path $PSScriptRoot -ChildPath 'Initialize-Test.ps1' -Resolve)

$testCertPath = Join-Path -Path $PSScriptRoot -ChildPath 'Resources\CarbonTestCertificate.pfx' -Resolve
$testCert = New-Object 'Security.Cryptography.X509Certificates.X509Certificate2' $testCertPath
$password = ConvertTo-SecureString -String 'password' -AsPlainText -Force
$TestCertProtectedPath = Join-Path -Path $PSScriptRoot -ChildPath 'Resources\CarbonTestCertificateWithPassword.pfx' -Resolve
$testCertProtected = New-Object 'Security.Cryptography.X509Certificates.X509Certificate2' $TestCertProtectedPath, $password

# $isAdmin = Test-IsAdministrator
# $localMachineLocationAvailable = -not $onWindows -or $isAdmin
# $remotingAvailable = (Test-RunningUnderBuildServer) -or $isAdmin 

$onWindows = Test-TCOperatingSystem -Windows
$isAdmin = Test-IsAdministrator
$localMachineLocationAvailable = (Test-TCOperatingSystem -Windows) -and $isAdmin
$isCustomStoreAvailable = -not (Test-TCOperatingSystem -Windows) -or $isAdmin
$isRemotingAvailable = -not (Test-RunningUnderBuildServer) -and $isAdmin
$physicalStorePathKnown = $onWindows
$canExportPrivateKeyByDefault = Test-TCOperatingSystem -Linux

if( $isRemotingAvailable )
{
    Start-Service 'WinRM'
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

    # Physical stores are unknown on non-Windows operating systems.
    if( -not $physicalStorePathKnown )
    {
        return -1
    }

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

    if( $localMachineLocationAvailable )
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

function ThenPhysicalStoreHasCount
{
    param(
        [Parameter(Mandatory)]
        [int] $ExpectedCount,

        [Parameter(Mandatory)]
        [Security.Cryptography.X509Certificates.StoreLocation] $ForLocation
    )

    if( -not $physicalStorePathKnown )
    {
        return
    }

    Measure-PhysicalStore -Location $ForLocation | Should -Be $ExpectedCount
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
    'LocalMachine'
}

Describe 'Install-Certificate' {
    BeforeEach { Init }
    AfterEach { Reset }

    foreach( $location in $locations )
    {
        $skip = $false
        if( $location -eq 'LocalMachine' -and -not $localMachineLocationAvailable )
        {
            $skip = $true
        }

        Context "for $($location)" {
            It 'should install certificate from a file' -Skip:$skip {
                WhenInstalling -FromFile $testCertPath -For $location -In 'My'
                ThenCertificateInstalled $testCert.Thumbprint -For $location -In 'My' 
                ThenNothingReturned
                $cert = Get-CCertificate -Thumbprint $testCert.Thumbprint -StoreLocation $location -StoreName 'My'
                {
                    $cert.Export( [Security.Cryptography.X509Certificates.X509ContentType]::Pfx ) | Out-Null
                } | Should -Not:($canExportPrivateKeyByDefault) -Throw
            }

            It 'should install certificate from a file with relative path' -Skip:$skip {
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

            It 'should install certificate as exportable' -Skip:$skip {
                WhenInstalling -FromFile $testCertPath -For $location -In 'My' -ThatIsExportable
                ThenNothingReturned
                ThenCertificateInstalled $testCert.Thumbprint -For $location -In 'My' 
                $cert = Get-CCertificate -Thumbprint $testCert.Thumbprint -StoreLocation $location -StoreName 'My'
                $cert | Should -Not -BeNullOrEmpty
                $bytes = $cert.Export( [Security.Cryptography.X509Certificates.X509ContentType]::Pfx )
                $bytes | Should -Not -BeNullOrEmpty
            }

            It 'should install certificate' -Skip:$skip {
                WhenInstalling $testCert -For $location -In 'My'
                ThenNothingReturned
                ThenCertificateInstalled $testCert.Thumbprint -For $location -In 'My'
            }

            It 'should install password protected certificate' -Skip:$skip {
                $fileCount = Measure-PhysicalStore -Location $location
                WhenInstalling -FromFile $TestCertProtectedPath -WithPassword $password -For $location -In 'My'
                ThenNothingReturned
                ThenCertificateInstalled $testCertProtected.Thumbprint -For $location -In 'My'
                ThenPhysicalStoreHasCount ($fileCount + 1) -ForLocation $location
            }

            It 'should install certificate in remote computer' -Skip:($skip -or -not $isRemotingAvailable) {
                [int32]$timeout = [TimeSpan]::New(0, 0, 10).TotalMilliseconds
                $sessionOptions =
                    New-PSSessionOption -OpenTimeout $timeout  -CancelTimeout $timeout  -OperationTimeout $timeout
                $session = New-PSSession -ComputerName $env:COMPUTERNAME -SessionOption $sessionOptions
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

            It 'should support ShouldProcess' -Skip:$skip {
                WhenInstalling -FromFile $testCertPath -For $location -In 'My' -WhatIf
                ThenNothingReturned
                Get-CCertificate -StoreLocation $location -StoreName My -Thumbprint $testCert.Thumbprint |
                    Should -BeNullOrEmpty
            }
        }
    }
}

foreach( $location in $locations )
{
    $skip = $false
    if( $location -eq 'LocalMachine' -and -not $localMachineLocationAvailable )
    {
        $skip = $true
    }

    Describe "Install-Certificate.$($location).when installing in custom store" {
        AfterEach { Reset }
        It 'should install certificate in the custom store' -Skip:($skip -or -not $isCustomStoreAvailable) {
            Init
            Uninstall-CCertificate -Thumbprint $testCert.Thumbprint
            Get-CCertificate -Thumbprint $testCert.Thumbprint | Should -BeNullOrEmpty
            WhenInstalling -FromFile $testCertPath -For $location -In 'Carbon'
            ThenNothingReturned

            $duration = [Diagnostics.Stopwatch]::StartNew()
            $timeout = [TimeSpan]::New(0, 0, 10)
            do
            {
                $cert = Get-CCertificate -StoreLocation $location `
                                         -CustomStoreName 'Carbon' `
                                         -Thumbprint $testCert.Thumbprint
                if( $cert )
                {
                    break
                }

                $msg = "Couldn't find $($testCert.Thumbprint) in $($location)\Carbon store. Trying again " +
                       'in 100ms.'
                Write-Verbose $msg -Verbose
                Start-Sleep -Milliseconds 100
            }
            while( $duration.Elapsed -lt $timeout )
            $duration.Stop()
            $duration = $null

            Get-CCertificate -StoreLocation $location -CustomStoreName 'Carbon' -Thumbprint $testCert.Thumbprint |
                Should -Not -BeNullOrEmpty
        }
    }

    Describe "Install-Certificate.$($location).when certificate is already installed" {
        AfterEach { Reset }
        It 'should not re-install it' -Skip:$skip {
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
            ThenPhysicalStoreHasCount ($fileCount + 1) -ForLocation $location
        }
    }

    Describe "Install-Certificate.$($location).when certificate is already installed and forcing install" {
        AfterEach { Reset }
        It 'should not re-install it' -Skip:$skip {
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
            ThenPhysicalStoreHasCount  ($fileCount + 2) -ForLocation $location
        }
    }

    Describe "Install-Certificate.$($location).when requesting the installed certificate be returned" {
        AfterEach { Reset }
        Context 'certificate is not installed' {
            It 'should return the certificate' -Skip:$skip {
                Init
                WhenInstalling $testCert -For $location -In 'My' -ReturningCertificate
                ThenCertificateReturned $testCert.Thumbprint
            }
        }
        Context 'certificate is installed' {
            It 'should return the certificate' -Skip:$skip {
                Init
                WhenInstalling $testCert -For $location -In 'My'
                ThenNothingReturned
                WhenInstalling $testCert -For $location -In 'My' -ReturningCertificate
                ThenCertificateReturned $testCert.Thumbprint
            }
        }
    }
}
