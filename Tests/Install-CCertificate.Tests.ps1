
#Requires -Version 5.1
Set-StrictMode -Version 'Latest'

BeforeAll {
    & (Join-Path -Path $PSScriptRoot -ChildPath 'Initialize-Test.ps1' -Resolve)

    $resourcesPath = Join-Path -Path $PSScriptRoot -ChildPath 'Resources' -Resolve
    $script:testCertPath = Join-Path -Path $resourcesPath -ChildPath 'CarbonTestCertificate.pfx' -Resolve
    $script:testCert = [Security.Cryptography.X509Certificates.X509Certificate2]::New($script:testCertPath)
    $script:password = ConvertTo-SecureString -String 'password' -AsPlainText -Force
    $script:TestCertProtectedPath = Join-Path -Path $resourcesPath -ChildPath 'CarbonTestCertificateWithPassword.pfx' -Resolve
    $script:testCertProtected = [Security.Cryptography.X509Certificates.X509Certificate2]::New($script:TestCertProtectedPath, $script:password)
    $script:output = $null

    function Measure-PhysicalStore
    {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [Security.Cryptography.X509Certificates.StoreLocation]$Location
        )

        # Physical stores are unknown on non-Windows operating systems.
        if( -not (Test-PhysicalStore -IsReadable) )
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
        $script:output | Should -Not -BeNullOrEmpty
        $script:output | Should -BeOfType ([Security.Cryptography.X509Certificates.X509Certificate2])
        $script:output.Thumbprint | Should -Be $WithThumbprint
    }

    function ThenFailed
    {
        param(
            [String] $WithErrorMatching,

            [int] $AtIndex = 0
        )
        $Global:Error | Should -Not -BeNullOrEmpty
        $Global:Error | Select-Object -Index $AtIndex | Should -Match $WithErrorMatching
    }

    function ThenNoError
    {
        $Global:Error | Should -BeNullOrEmpty
    }

    function ThenNothingReturned
    {
        $script:output | Should -BeNullOrEmpty
    }

    function ThenPhysicalStoreHasCount
    {
        param(
            [Parameter(Mandatory)]
            [int] $ExpectedCount,

            [Parameter(Mandatory)]
            [Security.Cryptography.X509Certificates.StoreLocation] $ForLocation
        )

        if( -not (Test-PhysicalStore -IsReadable) )
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
        Install-CCertificate -StoreLocation $For @conditionalParams | Tee-Object -Variable 'output'
        $script:output = $output
    }
}

Describe 'Install-CCertificate' {
    & (Join-Path -Path $PSScriptRoot -ChildPath 'Initialize-Test.ps1' -Resolve)

    $isRemotingAvailable = Test-Remoting -IsAvailable
    $currentUserHasMyStore = Test-MyStore -IsSupported -Location 'CurrentUser'
    $currentUserNotMsg = ''
    $currentUserErrorActionArg = @{}
    if (-not $currentUserHasMyStore)
    {
        $currentUserErrorActionArg['ErrorAction'] = 'SilentlyContinue'
        $currentUserNotMsg = 'not '
    }

    $localMachineHasMyStore = Test-MyStore -IsSupported -Location 'CurrentUser'
    $localMachineNotMsg = ''
    $localMachineErrorActionArg = @{}
    if (-not $localMachineHasMyStore)
    {
        $localMachineErrorActionArg['ErrorAction'] = 'SilentlyContinue'
        $localMachineNotMsg = 'not '
    }

    Context "<location> Store" -ForEach @(
        @{
            'Location' = 'CurrentUser';
            'Skip' = $false;
            'HasMyStore' = $currentUserHasMyStore;
            'ErrorActionArg' = $currentUserErrorActionArg;
            'NotMsg' = $currentUserNotMsg;
            'IsRemotingAvailable' = $isRemotingAvailable;
        },
        @{
            'Location' = 'LocalMachine';
            'Skip' = -not (Test-IsAdministrator);
            'HasMyStore' = $localMachineHasMyStore;
            'ErrorActionArg' = $localMachineErrorActionArg;
            'NotMsg' = $localMachineNotMsg;
            'IsRemotingAvailable' = $isRemotingAvailable;
        }
    ) {
        BeforeEach {
            $Global:Error.Clear()
            $script:script:output = $null
        }

        AfterEach {
            Uninstall-CCertificate -Certificate $script:testCert -StoreLocation CurrentUser -StoreName My
            Uninstall-CCertificate -Certificate $script:testCertProtected -StoreLocation CurrentUser -StoreName My

            if( (Test-IsAdministrator) -and -not (Test-LocalMachineStore -IsReadOnly) )
            {
                Uninstall-CCertificate -Certificate $script:testCert -StoreLocation LocalMachine -StoreName My
                Uninstall-CCertificate -Certificate $script:testCertProtected -StoreLocation LocalMachine -StoreName My
            }
        }

        It "should $($notMsg)install certificate from file" -Skip:$skip {
            WhenInstalling -FromFile $script:testCertPath `
                           -For $location `
                           -In 'My' `
                           -ThatIsExportable:(Test-TCertificate -MustBeExportable) `
                           @errorActionArg
            if( -not $hasMyStore )
            {
                ThenFailed 'Exception reading certificates'
                return
            }
            ThenCertificateInstalled $script:testCert.Thumbprint -For $location -In 'My'
            ThenNothingReturned
            $not = (Test-TCertificate -MustBeExportable) -or (Test-TCertificate -AutomaticallyExportable)
            $cert = Get-CCertificate -Thumbprint $script:testCert.Thumbprint -StoreLocation $location -StoreName 'My'
            {
                $cert.Export( [Security.Cryptography.X509Certificates.X509ContentType]::Pfx ) | Out-Null
            } | Should -Not:$not -Throw
        }

        It "should $($notMsg)install certificate using relative file path" -Skip:$skip {
            Push-Location -Path $PSScriptRoot
            try
            {
                $path = '.\Resources\{0}' -f (Split-Path -Leaf -Path $script:testCertPath)
                WhenInstalling -FromFile $path `
                            -For $location `
                            -In 'My' `
                            -ThatIsExportable:(Test-TCertificate -MustBeExportable) `
                            @errorActionArg
                if( -not $hasMyStore )
                {
                    ThenFailed 'Exception reading certificates'
                    return
                }
                ThenNothingReturned
                ThenCertificateInstalled $script:testCert.Thumbprint -For $location -In 'My'
            }
            finally
            {
                Pop-Location
            }
        }

        It "should $($notMsg)install certificate as exportable" -Skip:$skip {
            WhenInstalling -FromFile $script:testCertPath -For $location -In 'My' -ThatIsExportable @errorActionArg
            if( -not $hasMyStore )
            {
                ThenFailed 'Exception reading certificates'
                return
            }
            ThenNothingReturned
            ThenCertificateInstalled $script:testCert.Thumbprint -For $location -In 'My'
            $cert = Get-CCertificate -Thumbprint $script:testCert.Thumbprint -StoreLocation $location -StoreName 'My'
            $cert | Should -Not -BeNullOrEmpty
            $bytes = $cert.Export( [Security.Cryptography.X509Certificates.X509ContentType]::Pfx )
            $bytes | Should -Not -BeNullOrEmpty
        }

        It "should $($notMsg)install certificate from X509Certificate2 object" -Skip:$skip {
            WhenInstalling $script:testCert -For $location -In 'My' @errorActionArg
            if( -not $hasMyStore )
            {
                ThenFailed 'Exception reading certificates'
                return
            }
            ThenNothingReturned
            ThenCertificateInstalled $script:testCert.Thumbprint -For $location -In 'My'
        }

        It "should $($notMsg)install password protected certificate" -Skip:$skip {
            $fileCount = Measure-PhysicalStore -Location $location
            WhenInstalling -FromFile $script:TestCertProtectedPath `
                            -WithPassword $script:password `
                            -For $location `
                            -In 'My' `
                            -ThatIsExportable:(Test-TCertificate -MustBeExportable) `
                            @errorActionArg
            if( -not $hasMyStore )
            {
                ThenFailed 'Exception reading certificates'
                return
            }
            ThenNothingReturned
            ThenCertificateInstalled $script:testCertProtected.Thumbprint -For $location -In 'My'
            ThenPhysicalStoreHasCount ($fileCount + 1) -ForLocation $location
        }

        It "should $($notMsg)install certificate on remote computer" -Skip:($skip -or -not $isRemotingAvailable) {
            [int32]$timeout = [TimeSpan]::New(0, 0, 10).TotalMilliseconds
            $sessionOptions =
                New-PSSessionOption -OpenTimeout $timeout  -CancelTimeout $timeout  -OperationTimeout $timeout
            $session = New-PSSession -ComputerName $env:COMPUTERNAME -SessionOption $sessionOptions
            try
            {
                WhenInstalling $script:testCert -For $location -In 'My' -OverSession $session @errorActionArg
                if( -not $hasMyStore )
                {
                    ThenFailed 'Exception reading certificates'
                    return
                }
                ThenNothingReturned
                ThenCertificateInstalled $script:testCert.Thumbprint -For $location -In 'My'
            }
            finally
            {
                Remove-PSSession -Session $session
            }
        }

        It 'should support WhatIf' -Skip:$skip {
            WhenInstalling -FromFile $script:testCertPath -For $location -In 'My' -WhatIf @errorActionArg
            if( -not $hasMyStore )
            {
                ThenFailed 'Exception reading certificates'
                return
            }
            ThenNothingReturned
            Get-CCertificate -StoreLocation $location `
                                -StoreName My `
                                -Thumbprint $script:testCert.Thumbprint `
                                -ErrorAction Ignore |
                Should -BeNullOrEmpty
        }

        It 'should not re-install a certificate' -Skip:$skip {
            $fileCount = Measure-PhysicalStore -Location $location
            $script:output =
                WhenInstalling -FromFile $script:testCertPath `
                                -For $location `
                                -In 'My' `
                                -ThatIsExportable:(Test-TCertificate -MustBeExportable) `
                                -Verbose `
                                @errorActionArg `
                                4>&1 |
                Where-Object { $_ -is [Management.Automation.VerboseRecord] }
            if( -not $hasMyStore )
            {
                ThenFailed 'Exception reading certificates'
                return
            }

            $script:output | Should -HaveCount 1
            $script:output.Message | Should -Match 'Installing certificate'
            ThenCertificateInstalled $script:testCert.Thumbprint -For $location -In 'My'
            ThenNoError

            # Install it again.
            $script:output =
                WhenInstalling -FromFile $script:testCertPath -For $location -In 'My' -Verbose 4>&1 |
                Where-Object { $_ -is [Management.Automation.VerboseRecord] }
            $script:output | Should -BeNullOrEmpty -Because 'certificates shouldn''t get re-installed'
            ThenNoError
            ThenCertificateInstalled $script:testCert.Thumbprint -For $location -In 'My'
            ThenPhysicalStoreHasCount ($fileCount + 1) -ForLocation $location
        }

        It 'should reinstall already installed certificate' -Skip:$skip {
            $fileCount = Measure-PhysicalStore -Location $location
            $script:output =
                WhenInstalling -FromFile $script:testCertPath `
                                -For $location `
                                -In 'My' `
                                -ThatIsExportable:(Test-TCertificate -MustBeExportable) `
                                -Verbose `
                                @errorActionArg `
                                4>&1 |
                Where-Object { $_ -is [Management.Automation.VerboseRecord] }

            if( -not $hasMyStore )
            {
                ThenFailed 'Exception reading certificates'
                return
            }

            ThenNoError
            $script:output | Should -HaveCount 1
            $script:output.Message | Should -Match 'Installing certificate'
            ThenCertificateInstalled $script:testCert.Thumbprint -For $location -In 'My'

            # Install it again.
            $script:output =
                WhenInstalling -FromFile $script:testCertPath -For $location -In 'My' -WithForce -Verbose 4>&1 |
                Where-Object { $_ -is [Management.Automation.VerboseRecord] }
            ThenNoError
            $script:output | Should -HaveCount 1
            $script:output.Message | Should -Match 'Installing certificate'
            ThenCertificateInstalled $script:testCert.Thumbprint -For $location -In 'My'
            ThenPhysicalStoreHasCount  ($fileCount + 2) -ForLocation $location
        }

        Context 'certificate is not installed' {
            It "should $($notMsg)return the certificate" -Skip:$skip {
                WhenInstalling $script:testCert -For $location -In 'My' -ReturningCertificate @errorActionArg
                if( -not $hasMyStore )
                {
                    ThenNothingReturned
                    ThenFailed 'Exception reading certificates' -AtIndex 1
                    return
                }
                ThenCertificateReturned $script:testCert.Thumbprint
            }
        }
        Context 'certificate is installed' {
            It 'should not return the certificate' -Skip:$skip {
                WhenInstalling $script:testCert -For $location -In 'My' @errorActionArg
                ThenNothingReturned
                if( -not $hasMyStore )
                {
                    ThenFailed 'Exception reading certificates'
                    return
                }
                WhenInstalling $script:testCert -For $location -In 'My' -ReturningCertificate
                ThenCertificateReturned $script:testCert.Thumbprint
            }
        }

        It "should $($notMsg)install certificate in the custom store" -Skip:$skip {
            Uninstall-CCertificate -Thumbprint $script:testCert.Thumbprint
            Get-CCertificate -Thumbprint $script:testCert.Thumbprint | Should -BeNullOrEmpty
            $Global:Error.Clear()
            $shouldFail = -not (Test-CustomStore -IsSupported -Location $location)
            $errorActionArg = @{}
            if( $shouldFail )
            {
                $errorActionArg['ErrorAction'] = 'SilentlyContinue'
            }
            WhenInstalling -FromFile $script:testCertPath `
                            -For $location `
                            -In 'Carbon' `
                            -ThatIsExportable:(Test-TCertificate -MustBeExportable) `
                            @errorActionArg
            ThenNothingReturned

            if( $shouldFail )
            {
                ThenFailed 'exception reading'
                return
            }

            $duration = [Diagnostics.Stopwatch]::StartNew()
            $timeout = [TimeSpan]::New(0, 0, 10)
            do
            {
                $cert = Get-CCertificate -StoreLocation $location `
                                        -CustomStoreName 'Carbon' `
                                        -Thumbprint $script:testCert.Thumbprint
                if( $cert )
                {
                    break
                }

                $msg = "Couldn't find $($script:testCert.Thumbprint) in $($location)\Carbon store. Trying again " +
                    'in 100ms.'
                Write-Verbose $msg -Verbose
                Start-Sleep -Milliseconds 100
            }
            while( $duration.Elapsed -lt $timeout )
            $duration.Stop()
            $duration = $null

            Get-CCertificate -StoreLocation $location -CustomStoreName 'Carbon' -Thumbprint $script:testCert.Thumbprint |
                Should -Not -BeNullOrEmpty
            ThenNoError
        }
    }
}
