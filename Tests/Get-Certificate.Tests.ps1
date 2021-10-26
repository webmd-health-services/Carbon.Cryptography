
#Requres -Version 5.1
Set-StrictMode -Version 'Latest'

& (Join-Path -Path $PSScriptRoot -ChildPath 'Initialize-Test.ps1' -Resolve)

$testCertPath = Join-Path -Path $PSScriptRoot -ChildPath 'Resources\CarbonTestCertificate.pfx' -Resolve
$TestCert = New-Object Security.Cryptography.X509Certificates.X509Certificate2 $testCertPath
$testCertificateThumbprint = '7D5CE4A8A5EC059B829ED135E9AD8607977691CC'
$testCertFriendlyName = 'Pup Test Certificate'
$testCertSubject = 'CN=example.com'

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
    Install-CCertificate -Path $FromFile -StoreLocation CurrentUser @optionalParams
}

function Init
{
    if( (Get-Module 'Carbon') )
    {
        Write-Warning 'Removing Carbon. How did it get imported?'
        Remove-Module 'Carbon' -Force
    }

    $Global:Error.Clear()
}

function Reset
{
    Get-CCertificate -Path (Join-Path -Path $PSScriptRoot -ChildPath 'Resources\*') -ErrorAction Ignore |
        ForEach-Object { Uninstall-CCertificate -Thumbprint $_.Thumbprint }

    if( (Test-CustomStore -IsSupported -Location LocalMachine) -and `
        -not (Test-CustomStore -IsReadOnly -Location LocalMachine) )
    {
        Uninstall-CCertificate -Thumbprint $testCertificateThumbprint `
                               -CustomStoreName 'Carbon' `
                               -StoreLocation LocalMachine `
                               -ErrorAction Stop
    }

    Uninstall-CCertificate -Certificate $TestCert -StoreLocation CurrentUser -StoreName My
    if( -not (Test-CustomStore -IsReadOnly -Location CurrentUser) )
    {
        Uninstall-CCertificate -Certificate $TestCert -StoreLocation CurrentUser -CustomStoreName 'Carbon'
    }
}

function Search
{
    param(
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
        StoreLocation = '';
        StoreName = '';
        CustomStoreName = '';
        Thumbprint = '';
        Subject = '';
        LiteralSubject = '';
        FriendlyName = '';
        LiteralFriendlyName = '';
        ExpectedPath = '';
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


Describe 'Get-Certificate.when getting certificate from a file' {
    AfterEach { Reset }
    It ('should have Path property') {
        Init
        $cert = Get-CCertificate -Path $testCertPath
        $cert.Path | Should -Be $testCertPath
    }
}

Describe 'Get-Certificate.when getting certificate by path from certificate store' {
    AfterEach { Reset }
    It ('should have Path property') {
        Init
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

$searchTestCases = & {
    # Search in all stores.
    Search -ByThumbprint
    Search -ByThumbprint -UsingWildcard
    Search -BySubject
    Search -BySubject -UsingWildcard
    Search -ByLiteralSubject
    Search -ByFriendlyName
    Search -ByFriendlyName -UsingWildcard
    Search -ByLiteralFriendlyName

    # Search all stores for single location.
    Search -ForCurrentUser -ByThumbprint
    Search -ForCurrentUser -ByThumbprint -UsingWildcard
    Search -ForCurrentUser -ByThumbprint -UsingWildcard
    Search -ForCurrentUser -BySubject
    Search -ForCurrentUser -BySubject -UsingWildcard
    Search -ForCurrentUser -ByLiteralSubject
    Search -ForCurrentUser -ByFriendlyName
    Search -ForCurrentUser -ByFriendlyName -UsingWildcard
    Search -ForCurrentUser -ByLiteralFriendlyName

    # Search single store in all locations.
    Search -InMyStore -ByThumbprint
    Search -InMyStore -ByThumbprint -UsingWildcard
    Search -InMyStore -BySubject
    Search -InMyStore -BySubject -UsingWildcard
    Search -InMyStore -ByLiteralSubject
    Search -InMyStore -ByFriendlyName
    Search -InMyStore -ByFriendlyName -UsingWildcard
    Search -InMyStore -ByLiteralFriendlyName

    # Search a single store for a single location.
    Search -ForCurrentUser -InMyStore -ByThumbprint
    Search -ForCurrentUser -InMyStore -ByThumbprint -UsingWildcard
    Search -ForCurrentUser -InMyStore -BySubject
    Search -ForCurrentUser -InMyStore -BySubject -UsingWildcard
    Search -ForCurrentUser -InMyStore -ByLiteralSubject
    Search -ForCurrentUser -InMyStore -ByFriendlyName
    Search -ForCurrentUser -InMyStore -ByFriendlyName -UsingWildcard
    Search -ForCurrentUser -InMyStore -ByLiteralFriendlyName

    if( (Test-CustomStore -IsSupported -Location CurrentUser) -and `
        -not (Test-CustomStore -IsReadOnly -Location CurrentUser) )
    {
        # Search a custom store in all locations.
        Search -InCustomStore -ByThumbprint -UsingWildcard
        Search -InCustomStore -BySubject -UsingWildcard
        Search -InCustomStore -ByLiteralSubject
        Search -InCustomStore -ByFriendlyName -UsingWildcard
        Search -InCustomStore -ByLiteralFriendlyName

        # Search a custom store for a single location.
        Search -ForCurrentUser -InCustomStore -ByThumbprint -UsingWildcard
        Search -ForCurrentUser -InCustomStore -BySubject -UsingWildcard
        Search -ForCurrentUser -InCustomStore -ByLiteralSubject
        Search -ForCurrentUser -InCustomStore -ByFriendlyName -UsingWildcard
        Search -ForCurrentUser -InCustomStore -ByLiteralFriendlyName

        Search -InCustomStore -ByThumbprint
        Search -InCustomStore -BySubject
        Search -InCustomStore -ByLiteralSubject
        Search -InCustomStore -ByFriendlyName
        Search -InCustomStore -ByLiteralFriendlyName
    
        Search -ForCurrentUser -InCustomStore -ByThumbprint
        Search -ForCurrentUser -InCustomStore -BySubject
        Search -ForCurrentUser -InCustomStore -ByLiteralSubject
        Search -ForCurrentUser -InCustomStore -ByFriendlyName
        Search -ForCurrentUser -InCustomStore -ByLiteralFriendlyName
    
    }
}

$itMsg = 'in { Location = <StoreLocation>; Store = <StoreName>; CustomStoreName = <CustomStoreName> } by { Thumbprint = ' +
         '<Thumbprint> ; Subject = <Subject> ; LiteralSubject = <LiteralSubject> ; FriendlyName = <FriendlyName> ; ' +
         'LiteralFriendlyName = <LiteralFriendlyName> } that { Exists = <Exists> }'
Describe 'Get-Certificate.when searching for a certificate' {
    AfterEach { Reset }
    It $itMsg -TestCases $searchTestCases {
        param(
            $StoreLocation,
            $StoreName,
            $CustomStoreName,
            $Thumbprint,
            $Subject,
            $LiteralSubject,
            $FriendlyName,
            $LiteralFriendlyName,
            $ExpectedPath,
            $ExpectedStore,
            $Exists
        )
        
        Init

        $installParams = @{}
        if( $CustomStoreName )
        {
            $installParams['InCustomStore'] = $CustomStoreName
        }
        GivenCertificateInStore -FromFile $testCertPath @installParams

        $params = ,$PSBoundParameters | ConvertTo-Parameter
        $params.Remove('Exists')
        $params.Remove('ExpectedPath')
        $params.Remove('ExpectedStore')
        $cert = Get-CCertificate @params -ErrorAction SilentlyContinue

        # Friendly names are Windows-only.
        if( ($FriendlyName -or $LiteralFriendlyName) -and (-not (Test-FriendlyName -IsSupported)) )
        {
            $cert | Should -BeNullOrEmpty
            return
        }

        $storeParam = @{ 'FromStore' = $ExpectedStore }
        if( $CustomStoreName )
        {
            $storeParam = @{ 'FromCustomStore' = $ExpectedStore }
        }
        ThenReturnedCert $cert -WithPath $ExpectedPath -For 'CurrentUser' @storeParam
    }
}

$notFoundTestCases = & {
    @{ 'Thumbprint' = 'deadbee*' }
    @{ 'Thumbprint' = 'deadbee*' ; 'StoreName' = 'My' ; }
    @{ 'Thumbprint' = 'deadbee*' ; 'StoreLocation' = 'CurrentUser' ; }
    @{ 'Thumbprint' = 'deadbee*' ; 'StoreLocation' = 'CurrentUser' ; 'StoreName' = 'My' }

    @{ 'Subject' = "CN=$($PSCommandPath)*" }
    @{ 'Subject' = "CN=$($PSCommandPath)*"; 'StoreName' = 'My' ; }
    @{ 'Subject' = "CN=$($PSCommandPath)*"; 'StoreLocation' = 'CurrentUser' ; }
    @{ 'Subject' = "CN=$($PSCommandPath)*"; 'StoreLocation' = 'CurrentUser' ; 'StoreName' = 'My' }

    @{ 'FriendlyName' = "$($PSCommandPath)*" }
    @{ 'FriendlyName' = "$($PSCommandPath)*"; 'StoreName' = 'My' ; }
    @{ 'FriendlyName' = "$($PSCommandPath)*"; 'StoreLocation' = 'CurrentUser' ; }
    @{ 'FriendlyName' = "$($PSCommandPath)*"; 'StoreLocation' = 'CurrentUser' ; 'StoreName' = 'My' }

    if( -not (Test-CustomStore -IsSupported -Location CurrentUser) )
    {
        # Search a custom store in all locations.
        Search -InCustomStore -ByThumbprint -UsingWildcard
        Search -InCustomStore -BySubject -UsingWildcard
        Search -InCustomStore -ByFriendlyName -UsingWildcard

        # Search a custom store for a single location.
        Search -ForCurrentUser -InCustomStore -ByThumbprint -UsingWildcard
        Search -ForCurrentUser -InCustomStore -BySubject -UsingWildcard
        Search -ForCurrentUser -InCustomStore -ByFriendlyName -UsingWildcard

    }
} |
    ForEach-Object { $_['Exists'] = $false ; $_ | Write-Output }

Describe 'Get-Certificate.when there are no results searching for certificates' {
    It $itMsg -TestCases $notFoundTestCases {
        param(
            $StoreLocation,
            $StoreName,
            $CustomStoreName,
            $Thumbprint,
            $Subject,
            $LiteralSubject,
            $FriendlyName,
            $LiteralFriendlyName,
            $ExpectedPath,
            $ExpectedStore,
            $Exists
        )
        
        Init

        $params = ,$PSBoundParameters | ConvertTo-Parameter
        $params.Remove('Exists')
        $params.Remove('ExpectedPath')
        $params.Remove('ExpectedStore')
        $cert = Get-CCertificate @params

        $cert | Should -BeNullOrEmpty
        $Global:Error | Should -BeNullOrEmpty
    }
}

$failedSearchTestCases = & {
    # Search a single store for a single location.
    $expectedErrorMsg = 'the CurrentUser\\My store'
    Search -ForCurrentUser -InMyStore -ByThumbprint -ThatDoesNotExist -ExpectedErrorMessage $expectedErrorMsg
    Search -ForCurrentUser -InMyStore -BySubject -ThatDoesNotExist -ExpectedErrorMessage $expectedErrorMsg
    Search -ForCurrentUser -InMyStore -ByFriendlyName -ThatDoesNotExist -ExpectedErrorMessage $expectedErrorMsg
    Search -ForCurrentUser -InMyStore -ByLiteralSubject -ThatDoesNotExist -ExpectedErrorMessage $expectedErrorMsg
    Search -ForCurrentUser -InMyStore -ByLiteralFriendlyName -ThatDoesNotExist -ExpectedErrorMessage $expectedErrorMsg

    if( -not (Test-CustomStore -IsSupported -Location CurrentUser) -or `
        (Test-CustomStore -IsReadOnly -Location CurrentUser) )
    {
        $expectedErrorMsg = 'the CurrentUser\\Carbon custom store'
        Search -ForCurrentUser -InCustomStore -ByThumbprint -ExpectedErrorMessage $expectedErrorMsg
        Search -ForCurrentUser -InCustomStore -BySubject -ExpectedErrorMessage $expectedErrorMsg
        Search -ForCurrentUser -InCustomStore -ByLiteralSubject -ExpectedErrorMessage $expectedErrorMsg
        Search -ForCurrentUser -InCustomStore -ByFriendlyName -ExpectedErrorMessage $expectedErrorMsg
        Search -ForCurrentUser -InCustomStore -ByLiteralFriendlyName -ExpectedErrorMessage $expectedErrorMsg
    }
}

Describe 'Get-Certificate.when specific certificate does not exist' {
    AfterEach { Reset }
    It $itMsg -TestCases $failedSearchTestCases {
        param(
            $StoreLocation,
            $StoreName,
            $CustomStoreName,
            $Thumbprint,
            $Subject,
            $LiteralSubject,
            $FriendlyName,
            $LiteralFriendlyName,
            $ExpectedPath,
            $ExpectedStore,
            $Exists,
            $ExpectedErrorMessage
        )

        $params = ,$PSBoundParameters | ConvertTo-Parameter
        $params.Remove('Exists')
        $params.Remove('ExpectedPath')
        $params.Remove('ExpectedStore')
        $params.Remove('ExpectedErrorMessage')

        Init
        $cert = Get-CCertificate @params -ErrorAction SilentlyContinue
        $cert | Should -BeNullOrEmpty
        $Global:Error | Should -HaveCount 1
        $Global:Error | Should -Match $ExpectedErrorMessage
    }
}

Describe 'Get-Certificate.when certificate does not exist but ignoring errors' {
    AfterEach { Reset }
    It 'should not write an error' {
        Init
        $cert = Get-CCertificate -Thumbprint 'deadbee' -StoreLocation CurrentUser -StoreName My -ErrorAction Ignore
        $cert | Should -BeNullOrEmpty
        $Global:Error | Should -BeNullOrEmpty
    }
}

if( (Test-Path -Path 'Cert:\CurrentUser\CA') )
{
    Describe 'Get-Certificate.when searching with CertificateAuthority store name' {
        AfterEach { Reset }
        It 'should get certificates in CA store' {
            Init
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

Describe 'Get-Certificate.when getting certificate with relative path' {
    AfterEach { Reset }
    It 'should get certificate' {
        Init
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

Describe 'Get-Certificate.when certificate file is password protected' {
    AfterEach { Reset }
    It 'should get certificate' {
        Init
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

Describe 'Get-Certificate.when certificate fails to load' {
    AfterEach { Reset }
    It 'should include exception in error message' {
        Init
        $cert = Get-CCertificate -Path (Join-Path -Path $PSScriptRoot -ChildPath 'Resources\CarbonTestCertificateWithPassword.pfx') -ErrorAction SilentlyContinue
        $Global:Error.Count | Should -BeGreaterThan 0
        $Global:Error[0] | Should -Match 'password'
        $cert | Should -BeNullOrEmpty
        $Error[1].Exception | Should -Not -BeNullOrEmpty
        $Error[1].Exception | Should -BeOfType ([Management.Automation.MethodInvocationException])
    }
}

Describe 'Get-Certificate.when not using parameter name' {
    AfterEach { Reset }
    It 'should load by path' {
        Init
        $cert = Get-CCertificate $testCertPath
        $cert | Should -Not -BeNullOrEmpty
        $cert.Thumbprint | Should -Be $testCertificateThumbprint
        $cert.Path | Should -Be $testCertPath
    }
}

Describe 'Get-Certificate.when certificate has wildcard character in subject' {
    AfterEach { Reset }
    It 'should return certificate by literal subject' {
        Init
        GivenCertificateInStore -FromFile 'Resources\CarbonIisDevelopmentCertificate.pfx'
        GivenCertificateInStore -FromFile 'Resources\CarbonIisDevelopmentCertificate2.pfx'
        WhenGettingCertificate -By @{ LiteralSubject = 'CN=*.get-carbon.org' }
        ThenReturnedCert -WithProperties @{ Subject = 'CN=*.get-carbon.org' }
    }
}

Describe 'Get-Certificate.when certificate has wildcard character in friendly name' {
    AfterEach { Reset }
    It 'should return certificate by literal friendly name' {
        Init
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

Describe 'Get-Certificate.when searching for a specific certificate that does not exist using all the search options' {
    AfterEach { Reset }
    It 'should fail' {
        Init
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

