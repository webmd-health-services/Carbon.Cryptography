
#Requires -Version 5.1
#Requires -RunAsAdministrator
Set-StrictMode -Version 'Latest'

BeforeDiscovery {
    $script:testCertPath = Join-Path -Path $PSScriptRoot -ChildPath 'Resources\CarbonTestCertificate.pfx' -Resolve
    $script:TestCert = [Security.Cryptography.X509Certificates.X509Certificate2]::New($script:testCertPath)
    $script:testCertificateThumbprint = '7D5CE4A8A5EC059B829ED135E9AD8607977691CC'
    $script:testCertFriendlyName = 'Pup Test Certificate'
    $script:testCertSubject = 'CN=example.com'

    Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath 'Carbon.CryptographyTestHelper')
}

BeforeAll {
    Set-StrictMode -Version 'Latest'

    & (Join-Path -Path $PSScriptRoot -ChildPath 'Initialize-Test.ps1' -Resolve)

    $script:certsToUninstall = [Collections.ArrayList]::New()

    Get-CCertificate -Path (Join-Path -Path $PSScriptRoot -ChildPath 'Resources\*') -ErrorAction Ignore |
        Where-Object { Get-CCertificate -Thumbprint $_.Thumbprint  } |
        ForEach-Object {
            Write-Error "Certificate $($_.Subject) $($_.Thumbprint) is still installed."
            Uninstall-CCertificate -Thumbprint $_.Thumbprint
        }

    function Assert-TestCert
    {
        param(
            $actualCert
        )

        $actualCert | Should -Not -BeNullOrEmpty
        $actualCert.Thumbprint | Should -Be $TestCert.Thumbprint
    }

    function ConvertTo-Parameter
    {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory, ValueFromPipeline)]
            [hashtable] $InputObject
        )

        process
        {
            $params = @{}
            foreach( $key in $InputObject.Keys )
            {
                if( $key -like 'Expected*' )
                {
                    continue
                }

                $value = $InputObject[$key]
                if( -not $value )
                {
                    continue
                }

                $params[$key] = $value
            }

            return ,$params
        }
    }

    function GivenCertificateInStore
    {
        param(
            [String] $FromFile,

            [String] $InCustomStore,

            [Security.Cryptography.X509Certificates.StoreName] $InStore =
                [Security.Cryptography.X509Certificates.StoreName]::My
        )

        if( -not [IO.Path]::IsPathRooted($FromFile) )
        {
            $FromFile = Join-Path -Path $PSScriptRoot -ChildPath $FromFile
        }

        $optionalParams = @{ StoreName = $InStore }
        if( $InCustomStore )
        {
            $optionalParams = @{ CustomStoreName = $InCustomStore }
        }

        if( (Test-TCertificate -MustBeExportable) )
        {
            $optionalParams['Exportable'] = $true
        }

        $cert = Install-CCertificate -Path $FromFile -StoreLocation CurrentUser @optionalParams -PassThru

        # $cert | Format-List * | Out-String | Write-Verbose -Verbose

        $script:certsToUninstall.Add($cert)
    }

    function ThenReturnedCert
    {
        [CmdletBinding()]
        param(
            [Parameter(Position=0)]
            [Object] $Certificate = $script:result,

            [Parameter(Mandatory, ParameterSetName='ByHashtable')]
            [hashtable] $WithProperties,

            [Parameter(ParameterSetName='ByParameter')]
            [String] $WithPath,

            [Parameter(ParameterSetName='ByParameter')]
            [Security.Cryptography.X509Certificates.StoreLocation] $For,

            [Parameter(ParameterSetName='ByParameter')]
            [Security.Cryptography.X509Certificates.StoreName] $FromStore,

            [Parameter(ParameterSetName='ByParameter')]
            [String] $FromCustomStore
        )

        $Certificate | Should -Not -BeNullOrEmpty
        $Certificate | Should -HaveCount 1
        $Certificate | Should -BeOfType [Security.Cryptography.X509Certificates.X509Certificate2]

        if( $WithProperties )
        {
            $Certificate | Should -Not -BeNullOrEmpty
            foreach( $propertyName in $WithProperties.Keys )
            {
                $Certificate | Get-Member -Name $propertyName | Should -Not -BeNullOrEmpty
                $Certificate.$propertyName | Should -Be $WithProperties[$propertyName]
            }
            return
        }

        if( (Test-Path -Path 'cert:') )
        {
            $Certificate.Path | Should -Be $WithPath
        }
        else
        {
            $Certificate.Path | Should -BeNullOrEmpty
        }

        $Certificate.StoreLocation | Should -Be $For
        if( $FromStore )
        {
            $Certificate.StoreName | Should -BeOfType [Security.Cryptography.X509Certificates.StoreName]
            $Certificate.StoreName | Should -Be $FromStore
        }
        else
        {
            $Certificate.StoreName | Should -BeOfType [String]
            $Certificate.StoreName | Should -Be $FromCustomStore
        }
    }

    function WhenGettingCertificate
    {
        [CmdletBinding()]
        param(
            [hashtable]$By = @{}
        )

        $script:result = Get-CCertificate @By
    }
}

Describe 'Get-CCertificate' {
    BeforeEach {
        if( (Get-Module 'Carbon') )
        {
            Write-Warning 'Removing Carbon. How did it get imported?'
            Remove-Module 'Carbon' -Force
        }

        $Global:Error.Clear()

        $script:certsToUninstall.Clear()
    }

    AfterEach {
        foreach( $cert in $script:certsToUninstall)
        {
            $storeNameArg = @{ StoreName = $cert.StoreName }
            [Security.Cryptography.X509Certificates.StoreName] $storeName = 'My'
            if (-not [Enum]::TryParse($cert.StoreName, [ref]$storeName))
            {
                $storeNameArg = @{ CustomStoreName = $cert.StoreName }
            }
            Uninstall-CCertificate -Thumbprint $cert.Thumbprint -StoreLocation $cert.StoreLocation @storeNameArg
        }
    }

    Context 'when getting certificate from a file' {
        It ('should have Path property') {
            $cert = Get-CCertificate -Path $testCertPath
            $cert.Path | Should -Be $testCertPath
        }
    }

    Context 'when getting certificate by path from certificate store' {
        It ('should have Path property') {
            GivenCertificateInStore -FromFile $testCertPath
            $errorActionParam = @{ 'ErrorAction' = 'SilentlyContinue' }
            $testCertCertProviderPath = "cert:\CurrentUser\My\$($testCertificateThumbprint)"
            if( (Test-Path -Path 'cert:') )
            {
                $errorActionParam = @{}
            }
            $cert = Get-CCertificate -Path $testCertCertProviderPath @errorActionParam
            if( (Test-Path -Path 'cert:') )
            {
                $cert.Path | Should -Be $testCertCertProviderPath
            }
            else
            {
                $cert | Should -BeNullOrEmpty
                $Global:Error | Should -Match '"cert:.*" not found'
            }
        }
    }

    function Search
    {
        param(
            [Parameter(Mandatory, Position=0)]
            [AllowEmptyString()]
            [String] $Description,

            [switch] $ForCurrentUser,
            [switch] $InMyStore,
            [switch] $InCustomStore,
            [switch] $ByThumbprint,
            [switch] $BySubject,
            [switch] $ByLiteralSubject,
            [switch] $ByFriendlyName,
            [switch] $ByLiteralFriendlyName,
            [switch] $UsingWildcard,
            [switch] $ThatDoesNotExist,
            [String] $ExpectedErrorMessage
        )

        $testCase = @{
            Description = $Description;
            ExpectedStore = 'My';
            Exists = -not $ThatDoesNotExist;
        }

        if( $InCustomStore )
        {
            $testCase['ExpectedStore'] = 'Carbon'
        }

        if( (Test-Path -Path 'cert:') )
        {
            $testCase['ExpectedPath'] = Join-Path -Path 'cert:\CurrentUser' -ChildPath $testCase['ExpectedStore']
            $testCase['ExpectedPath'] = Join-Path -Path $testCase['ExpectedPath'] -ChildPath $testCertificateThumbprint
        }

        if( $ForCurrentUser )
        {
            $testCase['StoreLocation'] = 'CurrentUser'
        }

        if( $InMyStore )
        {
            $testCase['StoreName'] = 'My'
        }

        if( $InCustomStore )
        {
            $testCase['CustomStoreName'] = 'Carbon'
        }

        if( $ByThumbprint )
        {
            $searchKey = 'Thumbprint'
            $searchValue = $TestCert.Thumbprint
            $errPrefix = 'thumbprint like ".*"'
        }

        if( $BySubject )
        {
            $searchKey = 'Subject'
            $searchValue = $testCertSubject
            $errPrefix = 'subject like ".*"'
        }

        if( $ByLiteralSubject )
        {
            $searchKey = 'LiteralSubject'
            $searchValue = $testCertSubject
            $errPrefix = 'Subject equal ".*"'
        }

        if( $ByFriendlyName )
        {
            $searchKey = 'FriendlyName'
            $searchValue = $testCertFriendlyName
            $errPrefix = 'Friendly Name like ".*"'
        }

        if( $ByLiteralFriendlyName )
        {
            $searchKey = 'LiteralFriendlyName'
            $searchValue = $testCertFriendlyName
            $errPrefix = 'Friendly Name equal ".*"'
        }

        if( $ThatDoesNotExist )
        {
            $searchValue = 'doesnotexist'
        }

        if( $searchValue )
        {
            if( $UsingWildcard )
            {
                $searchValue = $searchValue.Substring(0, $searchValue.Length -1)
                $searchValue = "$($searchValue)*"
            }

            $testCase[$searchKey] = $searchValue
        }

        if( $ExpectedErrorMessage )
        {
            $testCase['ExpectedErrorMessage'] = "$($errPrefix) does not exist in $($ExpectedErrorMessage)"
        }

        return $testCase
    }

    Context 'when searching for a certificate' {
        $searchTestCases = & {
            # Search in all stores.
            Search 'by thumbprint' -ByThumbprint
            Search 'by wildcard thumbprint' -ByThumbprint -UsingWildcard
            Search 'by subject' -BySubject
            Search 'by wildcard subject' -BySubject -UsingWildcard
            Search 'by literal subject' -ByLiteralSubject
            Search 'by friendly name' -ByFriendlyName
            Search 'by wildcard friendly name' -ByFriendlyName -UsingWildcard
            Search 'by literal friendly name' -ByLiteralFriendlyName

            # Search all stores for single location.
            Search 'for current user by thumbprint' -ForCurrentUser -ByThumbprint
            Search 'for current user by wildcard thumbprint' -ForCurrentUser -ByThumbprint -UsingWildcard
            Search 'for current user by subject' -ForCurrentUser -BySubject
            Search 'for current user by wildcard subject' -ForCurrentUser -BySubject -UsingWildcard
            Search 'for current user by literal subject' -ForCurrentUser -ByLiteralSubject
            Search 'for current user by friendly name' -ForCurrentUser -ByFriendlyName
            Search 'for current user by wildcard friendly name' -ForCurrentUser -ByFriendlyName -UsingWildcard
            Search 'for current user by literal friendly name' -ForCurrentUser -ByLiteralFriendlyName

            # Search single store in all locations.
            Search 'in my store by thumbprint' -InMyStore -ByThumbprint
            Search 'in my store by wildcard thumbprint' -InMyStore -ByThumbprint -UsingWildcard
            Search 'in my store by subject' -InMyStore -BySubject
            Search 'in my store by wildcard subject' -InMyStore -BySubject -UsingWildcard
            Search 'in my store by literal subject' -InMyStore -ByLiteralSubject
            Search 'in my store by friendly name' -InMyStore -ByFriendlyName
            Search 'in my store by wildcard friendly name' -InMyStore -ByFriendlyName -UsingWildcard
            Search 'in my store by literal friendly name' -InMyStore -ByLiteralFriendlyName

            # Search a single store for a single location.
            $in = 'in currentuser my store by '
            Search "${in}thumbprint" -ForCurrentUser -InMyStore -ByThumbprint
            Search "${in}wildcard thumbprint" -ForCurrentUser -InMyStore -ByThumbprint -UsingWildcard
            Search "${in}subject" -ForCurrentUser -InMyStore -BySubject
            Search "${in}wildcard subject" -ForCurrentUser -InMyStore -BySubject -UsingWildcard
            Search "${in}literal subject" -ForCurrentUser -InMyStore -ByLiteralSubject
            Search "${in}friendly name" -ForCurrentUser -InMyStore -ByFriendlyName
            Search "${in}wildcard friendly name" -ForCurrentUser -InMyStore -ByFriendlyName -UsingWildcard
            Search "${in}literal friendly name" -ForCurrentUser -InMyStore -ByLiteralFriendlyName

            if( (Test-CustomStore -IsSupported -Location CurrentUser) -and `
                -not (Test-CustomStore -IsReadOnly -Location CurrentUser) )
            {
                # Search a custom store in all locations.
                Search 'in custom store by thumbprint' -InCustomStore -ByThumbprint
                Search 'in custom store by wildcard thumbprint' -InCustomStore -ByThumbprint -UsingWildcard
                Search 'in custom store by subject' -InCustomStore -BySubject
                Search 'in custom store by wildcard subject' -InCustomStore -BySubject -UsingWildcard
                Search 'in custom store by literal subject' -InCustomStore -ByLiteralSubject
                Search 'in custom store by friendly name' -InCustomStore -ByFriendlyName
                Search 'in custom store by wildcard friendly name' -InCustomStore -ByFriendlyName -UsingWildcard
                Search 'in custom store by literal friendly name' -InCustomStore -ByLiteralFriendlyName

                # Search a custom store for a single location.
                $in = 'in currentuser custom store by '
                Search "${in}thumbprint" -ForCurrentUser -InCustomStore -ByThumbprint
                Search "${in}wildcard thumbprint" -ForCurrentUser -InCustomStore -ByThumbprint -UsingWildcard
                Search "${in}subject" -ForCurrentUser -InCustomStore -BySubject
                Search "${in}wildcard subject" -ForCurrentUser -InCustomStore -BySubject -UsingWildcard
                Search "${in}literal subject" -ForCurrentUser -InCustomStore -ByLiteralSubject
                Search "${in}wildcard subject" -ForCurrentUser -InCustomStore -ByFriendlyName -UsingWildcard
                Search "${in}friendly name" -ForCurrentUser -InCustomStore -ByFriendlyName
                Search "${in}literal friendly name" -ForCurrentUser -InCustomStore -ByLiteralFriendlyName

            }
        }

        It 'finds certificate searching <description>' -ForEach $searchTestCases {

            $usingCustomStore = Test-Path -Path 'variable:CustomStoreName'
            $installParams = @{}
            if ($usingCustomStore)
            {
                $installParams['InCustomStore'] = $CustomStoreName
            }
            GivenCertificateInStore -FromFile $testCertPath @installParams

            $getArgs = @{}

            Get-Command -Name 'Get-CCertificate' |
                Select-Object -ExpandProperty 'Parameters' |
                ForEach-Object { $_.Keys } |
                Where-Object { Test-Path -Path "variable:${_}" } |
                ForEach-Object { $getArgs[$_] = Get-Variable -Name $_ -ValueOnly }

            $cert = Get-CCertificate @getArgs -ErrorAction SilentlyContinue

            # Friendly names are Windows-only.
            if (((Test-Path -Path 'variable:FriendlyName') -or (Test-Path -Path 'variable:LiteralFriendlyName')) -and `
               (-not (Test-FriendlyName -IsSupported)) )
            {
                $cert | Should -BeNullOrEmpty
                return
            }

            $thenArgs = @{ 'FromStore' = $ExpectedStore }
            if ($usingCustomStore)
            {
                $thenArgs = @{ 'FromCustomStore' = $ExpectedStore }
            }

            if ((Test-Path -Path 'cert:') -and (Test-Path -Path 'variable:ExpectedPath'))
            {
                $thenArgs['WithPath'] = $ExpectedPath
            }
            ThenReturnedCert $cert -For 'CurrentUser' @thenArgs
        }
    }

    Context 'when there are no results searching for certificates' {
        $notFoundTestCases = & {
                @{ Description = 'by wildcard thumbprint' ; 'Thumbprint' = 'deadbee*' }
                @{ Description = 'in My store by wildcard thumbprint' ; 'Thumbprint' = 'deadbee*' ; 'StoreName' = 'My' ; }
                @{ Description = 'for current user by wildcard thumbprint' ; 'Thumbprint' = 'deadbee*' ; 'StoreLocation' = 'CurrentUser' ; }
                @{ Description = 'in current user''s My store by wildcard thumbprint' ; 'Thumbprint' = 'deadbee*' ; 'StoreLocation' = 'CurrentUser' ; 'StoreName' = 'My' }

                @{ Description = 'by wildcard subject' ; 'Subject' = "CN=$($PSCommandPath)*" }
                @{ Description = 'in My store by wildcard subject' ; 'Subject' = "CN=$($PSCommandPath)*"; 'StoreName' = 'My' ; }
                @{ Description = 'for current user by wildcard subject' ; 'Subject' = "CN=$($PSCommandPath)*"; 'StoreLocation' = 'CurrentUser' ; }
                @{ Description = 'in current user''s My store by wildcard subject' ; 'Subject' = "CN=$($PSCommandPath)*"; 'StoreLocation' = 'CurrentUser' ; 'StoreName' = 'My' }

                @{ Description = 'by wildcard friendly name' ; 'FriendlyName' = "$($PSCommandPath)*" }
                @{ Description = 'in My store by wildcard friendly name' ; 'FriendlyName' = "$($PSCommandPath)*"; 'StoreName' = 'My' ; }
                @{ Description = 'for current user by wildcard friendly name' ; 'FriendlyName' = "$($PSCommandPath)*"; 'StoreLocation' = 'CurrentUser' ; }
                @{ Description = 'in current user''s My store by wildcard friendly name' ; 'FriendlyName' = "$($PSCommandPath)*"; 'StoreLocation' = 'CurrentUser' ; 'StoreName' = 'My' }

                if( -not (Test-CustomStore -IsSupported -Location CurrentUser) )
                {
                    # Search a custom store in all locations.
                    Search '' -InCustomStore -ByThumbprint -UsingWildcard
                    Search '' -InCustomStore -BySubject -UsingWildcard
                    Search '' -InCustomStore -ByFriendlyName -UsingWildcard

                    # Search a custom store for a single location.
                    Search '' -ForCurrentUser -InCustomStore -ByThumbprint -UsingWildcard
                    Search '' -ForCurrentUser -InCustomStore -BySubject -UsingWildcard
                    Search '' -ForCurrentUser -InCustomStore -ByFriendlyName -UsingWildcard

                }
            } |
            ForEach-Object { $_['Exists'] = $false ; $_ | Write-Output }

        It 'finds no certificates when searching <description>' -ForEach $notFoundTestCases {
            $getArgs = @{}

            Get-Command -Name 'Get-CCertificate' |
                Select-Object -ExpandProperty 'Parameters' |
                ForEach-Object { $_.Keys } |
                Where-Object { Test-Path -Path "variable:${_}" } |
                ForEach-Object { $getArgs[$_] = Get-Variable -Name $_ -ValueOnly }

            $cert = Get-CCertificate @getArgs

            $cert | Should -BeNullOrEmpty
            $Global:Error | Should -BeNullOrEmpty
        }
    }

    Context 'when specific certificate does not exist' {
        $failedSearchTestCases = & {
            # Search a single store for a single location.
            $expectedErrorMsg = 'the CurrentUser\\My store'
            $searchArgs =@{
                ForCurrentUser = $true;
                InMyStore = $true;
                ThatDoesNotExist = $true;
                ExpectedErrorMessage = $expectedErrorMsg;
            }
            $inMsg = 'in current user''s My store by '
            Search "${inMsg}by thumbprint" -ByThumbprint @searchArgs
            Search "${inMsg}by subject" -BySubject @searchArgs
            Search "${inMsg}by friendly name" -ByFriendlyName @searchArgs
            Search "${inMsg}by literal subject" -ByLiteralSubject @searchArgs
            Search "${inMsg}by literal friendly name" -ByLiteralFriendlyName @searchArgs

            if( -not (Test-CustomStore -IsSupported -Location CurrentUser) -or `
                (Test-CustomStore -IsReadOnly -Location CurrentUser) )
            {
                $expectedErrorMsg = 'the CurrentUser\\Carbon custom store'
                $searchArgs =
                    @{ ForCurrentUser = $true ; InCustomStore = $true ; ExpectedErrorMessage = $expectedErrorMsg; }
                $inMsg = 'in current user''s custom store by '
                Search "${inMsg}by thumprint" -ByThumbprint @searchArgs
                Search "${inMsg}by subject" -BySubject @searchArgs
                Search "${inMsg}by literal subject" -ByLiteralSubject @searchArgs
                Search "${inMsg}by friendly name" -ByFriendlyName @searchArgs
                Search "${inMsg}by literal friendly name" -ByLiteralFriendlyName @searchArgs
            }
        }

        It 'fails search <description>' -ForEach $failedSearchTestCases {
            $getArgs = @{}

            Get-Command -Name 'Get-CCertificate' |
                Select-Object -ExpandProperty 'Parameters' |
                ForEach-Object { $_.Keys } |
                Where-Object { Test-Path -Path "variable:${_}" } |
                ForEach-Object { $getArgs[$_] = Get-Variable -Name $_ -ValueOnly }

            $cert = Get-CCertificate @getArgs -ErrorAction SilentlyContinue
            $cert | Should -BeNullOrEmpty
            $Global:Error | Should -HaveCount 1
            $Global:Error | Should -Match $ExpectedErrorMessage
        }
    }

    Context 'when certificate does not exist but ignoring errors' {
        It 'should not write an error' {
            $cert = Get-CCertificate -Thumbprint 'deadbee' -StoreLocation CurrentUser -StoreName My -ErrorAction Ignore
            $cert | Should -BeNullOrEmpty
            $Global:Error | Should -BeNullOrEmpty
        }
    }

    if( (Test-Path -Path 'Cert:\CurrentUser\CA') )
    {
        Context 'when searching with CertificateAuthority store name' {
            It 'should get certificates in CA store' {
                GivenCertificateInStore -FromFile $testCertPath -InStore 'CertificateAuthority'
                $foundACert = $false
                foreach( $expectedCert in (Get-ChildItem -Path 'Cert:\CurrentUser\CA') )
                {
                    $actualCert = Get-CCertificate -Thumbprint $expectedCert.Thumbprint `
                                                -StoreLocation CurrentUser `
                                                -StoreName CertificateAuthority
                    $actualCert | Should -Not -BeNullOrEmpty
                    $actualCert.Thumbprint | Should -Be $expectedCert.Thumbprint
                    $foundACert = $true
                }
                $foundACert | Should -BeTrue
            }
        }
    }

    Context 'when getting certificate with relative path' {
        It 'should get certificate' {
            Push-Location -Path $PSScriptRoot
            try
            {
                $cert = Get-CCertificate -Path ('.\Resources\{0}' -f (Split-Path -Leaf -Path $testCertPath))
                Assert-TestCert $cert
            }
            finally
            {
                Pop-Location
            }
        }
    }

    Context 'when certificate file is password protected' {
        It 'should get certificate' {
            $certPath = Join-Path -Path $PSScriptRoot -ChildPath 'Resources\CarbonTestCertificateWithPassword.pfx' -Resolve
            [Security.Cryptography.X509Certificates.X509Certificate2]$cert =
                Get-CCertificate -Path $certPath -Password (ConvertTo-SecureString 'password' -AsPlainText -Force)
            $Global:Error.Count | Should -Be 0
            $cert | Should -Not -BeNullOrEmpty
            $cert.Thumbprint | Should -Be 'DE32D78122C2B5136221DE51B33A2F65A98351D2'
            if( (Test-FriendlyName -IsSupported) )
            {
                $cert.FriendlyName | Should -Be 'Carbon Test Certificate - Password Protected'
            }
        }
    }

    Context 'when certificate fails to load' {
        It 'should include exception in error message' {
            $cert = Get-CCertificate -Path (Join-Path -Path $PSScriptRoot -ChildPath 'Resources\CarbonTestCertificateWithPassword.pfx') -ErrorAction SilentlyContinue
            $Global:Error.Count | Should -BeGreaterThan 0
            $Global:Error[0] | Should -Match 'password'
            $cert | Should -BeNullOrEmpty
            $Error[1].Exception | Should -Not -BeNullOrEmpty
            $Error[1].Exception | Should -BeOfType ([Management.Automation.MethodInvocationException])
        }
    }

    Context 'when not using parameter name' {
        It 'should load by path' {
            $cert = Get-CCertificate $testCertPath
            $cert | Should -Not -BeNullOrEmpty
            $cert.Thumbprint | Should -Be $testCertificateThumbprint
            $cert.Path | Should -Be $testCertPath
        }
    }

    Context 'when certificate has wildcard character in subject' {
        It 'should return certificate by literal subject' {
            GivenCertificateInStore -FromFile 'Resources\CarbonIisDevelopmentCertificate.pfx'
            GivenCertificateInStore -FromFile 'Resources\CarbonIisDevelopmentCertificate2.pfx'
            WhenGettingCertificate -By @{ LiteralSubject = 'CN=*.get-carbon.org' }
            ThenReturnedCert -WithProperties @{ Subject = 'CN=*.get-carbon.org' }
        }
    }

    Context 'when certificate has wildcard character in friendly name' {
        It 'should return certificate by literal friendly name' {
            GivenCertificateInStore -FromFile 'Resources\CarbonIisDevelopmentCertificate.pfx'
            GivenCertificateInStore -FromFile 'Resources\CarbonIisDevelopmentCertificate2.pfx'
            WhenGettingCertificate -By @{ LiteralFriendlyName = '*get-carbon.org test certificate' }
            if( (Test-FriendlyName -IsSupported) )
            {
                ThenReturnedCert -WithProperties @{ Subject = 'CN=*.get-carbon.org' }
            }
            else
            {
                $script:result | Should -BeNullOrEmpty
                $Global:Error | Should -BeNullOrEmpty
            }
        }
    }

    Context 'when searching for a specific certificate that does not exist using all the search options' {
        It 'should fail' {
            WhenGettingCertificate -By @{
                StoreLocation = 'CurrentUser';
                StoreName = 'My';
                Thumbprint = 'doesnotexist';
                Subject = 'doesnotexist';
                LiteralSubject = 'doesnotexist';
                FriendlyName = 'doesnotexist';
                LiteralFriendlyName = 'doesnotexist';
            } -ErrorAction SilentlyContinue
            $script:result | Should -BeNullOrEmpty
            $regex = 'Subject like "doesnotexist", Subject equal "doesnotexist", Thumbprint like "doesnotexist", ' +
                    'Friendly Name like "doesnotexist", and Friendly Name equal "doesnotexist"'
            $Global:Error | Should -Match $regex
        }
    }
}
