
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

function Init
{
    if( (Get-Module 'Carbon') )
    {
        Write-Warning 'Removing Carbon. How did it get imported?'
        Remove-Module 'Carbon' -Force
    }

    $Global:Error.Clear()

    if( -not (Get-CCertificate -Thumbprint $TestCert.Thumbprint `
                               -StoreLocation CurrentUser `
                               -StoreName My `
                               -ErrorAction Ignore) ) 
    {
        Install-CCertificate -Path $testCertPath `
                             -StoreLocation CurrentUser `
                             -StoreName My `
                             -Exportable:(Test-TCertificate -MustBeExportable)
    }

    if( (Test-CustomStore -IsSupported -Location LocalMachine) -and `
        -not (Test-CustomStore -IsReadOnly -Location LocalMachine) )
    {
        Uninstall-CCertificate -Thumbprint $testCertificateThumbprint `
                               -CustomStoreName 'Carbon' `
                               -StoreLocation LocalMachine `
                               -ErrorAction Stop
    }

    if( (Test-CustomStore -IsSupported -Location CurrentUser) -and `
        -not (Test-CustomStore -IsReadOnly -Location CurrentUser) )
    {
        Install-CCertificate -Path $testCertPath `
                             -StoreLocation CurrentUser `
                             -CustomStoreName 'Carbon' `
                             -Exportable:(Test-TCertificate -MustBeExportable)
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
        [switch] $ByFriendlyName,
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
        FriendlyName = '';
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
        $errPrefix = 'thumbprint ".*"'
    }

    if( $BySubject )
    {
        $searchKey = 'Subject'
        $searchValue = $testCertSubject
        $errPrefix = 'subject ".*"'
    }

    if( $ByFriendlyName )
    {
        $searchKey = 'FriendlyName'
        $searchValue = $testCertFriendlyName
        $errPrefix = 'friendly name ".*"'
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
        [Parameter(Mandatory)]
        [Security.Cryptography.X509Certificates.X509Certificate2] $Certificate,

        [String] $WithPath,

        [Security.Cryptography.X509Certificates.StoreLocation] $For,

        [Security.Cryptography.X509Certificates.StoreName] $FromStore,

        [String] $FromCustomStore
    )

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

Describe 'Get-Certificate.when getting certificate from a file' {
    It ('should have Path property') {
        Init
        $cert = Get-CCertificate -Path $testCertPath
        $cert.Path | Should -Be $testCertPath
    }
}

Describe 'Get-Certificate.when getting certificate by path from certificate store' {
    It ('should have Path property') {
        Init
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
    Search -ByFriendlyName
    Search -ByFriendlyName -UsingWildcard

    # Search all stores for single location.
    Search -ForCurrentUser -ByThumbprint
    Search -ForCurrentUser -ByThumbprint -UsingWildcard
    Search -ForCurrentUser -ByThumbprint -UsingWildcard
    Search -ForCurrentUser -BySubject
    Search -ForCurrentUser -BySubject -UsingWildcard
    Search -ForCurrentUser -ByFriendlyName
    Search -ForCurrentUser -ByFriendlyName -UsingWildcard

    # Search single store in all locations.
    Search -InMyStore -ByThumbprint
    Search -InMyStore -ByThumbprint -UsingWildcard
    Search -InMyStore -BySubject
    Search -InMyStore -BySubject -UsingWildcard
    Search -InMyStore -ByFriendlyName
    Search -InMyStore -ByFriendlyName -UsingWildcard

    # Search a single store for a single location.
    Search -ForCurrentUser -InMyStore -ByThumbprint
    Search -ForCurrentUser -InMyStore -ByThumbprint -UsingWildcard
    Search -ForCurrentUser -InMyStore -BySubject
    Search -ForCurrentUser -InMyStore -BySubject -UsingWildcard
    Search -ForCurrentUser -InMyStore -ByFriendlyName
    Search -ForCurrentUser -InMyStore -ByFriendlyName -UsingWildcard

    if( (Test-CustomStore -IsSupported -Location CurrentUser) -and `
        -not (Test-CustomStore -IsReadOnly -Location CurrentUser) )
    {
        # Search a custom store in all locations.
        Search -InCustomStore -ByThumbprint -UsingWildcard
        Search -InCustomStore -BySubject -UsingWildcard
        Search -InCustomStore -ByFriendlyName -UsingWildcard

        # Search a custom store for a single location.
        Search -ForCurrentUser -InCustomStore -ByThumbprint -UsingWildcard
        Search -ForCurrentUser -InCustomStore -BySubject -UsingWildcard
        Search -ForCurrentUser -InCustomStore -ByFriendlyName -UsingWildcard

        Search -InCustomStore -ByThumbprint
        Search -InCustomStore -BySubject
        Search -InCustomStore -ByFriendlyName
    
        Search -ForCurrentUser -InCustomStore -ByThumbprint
        Search -ForCurrentUser -InCustomStore -BySubject
        Search -ForCurrentUser -InCustomStore -ByFriendlyName
    
    }
}

$itMsg = 'in { Location = <StoreLocation>; Store = <StoreName>; CustomStoreName = <CustomStoreName> } by { Thumbprint = ' +
         '<Thumbprint> ; Subject = <Subject> ; FriendlyName = <FriendlyName> } that { Exists = <Exists> }'
Describe 'Get-Certificate.when searching for a certificate' {
    It $itMsg -TestCases $searchTestCases {
        param(
            $StoreLocation,
            $StoreName,
            $CustomStoreName,
            $Thumbprint,
            $Subject,
            $FriendlyName,
            $ExpectedPath,
            $ExpectedStore,
            $Exists
        )
        
        Init

        $params = ,$PSBoundParameters | ConvertTo-Parameter
        $params.Remove('Exists')
        $params.Remove('ExpectedPath')
        $params.Remove('ExpectedStore')
        $cert = Get-CCertificate @params -ErrorAction SilentlyContinue

        # Friendly names are Windows-only.
        if( $FriendlyName -and (-not (Test-FriendlyName -IsSupported)) )
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

Describe 'Get-Certificate.when searching for certificates that do not exist using wildcards' {
    It $itMsg -TestCases $notFoundTestCases {
        param(
            $StoreLocation,
            $StoreName,
            $CustomStoreName,
            $Thumbprint,
            $Subject,
            $FriendlyName,
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

    # Search a custom store for a single location.
    $expectedErrorMsg = 'the CurrentUser\\Carbon custom store'
    Search -ForCurrentUser -InCustomStore -ByThumbprint -ThatDoesNotExist -ExpectedErrorMessage $expectedErrorMsg
    Search -ForCurrentUser -InCustomStore -BySubject -ThatDoesNotExist -ExpectedErrorMessage $expectedErrorMsg
    Search -ForCurrentUser -InCustomStore -ByFriendlyName -ThatDoesNotExist -ExpectedErrorMessage $expectedErrorMsg

    if( -not (Test-CustomStore -IsSupported -Location CurrentUser) -or `
        (Test-CustomStore -IsReadOnly -Location CurrentUser) )
    {
        $expectedErrorMsg = 'the CurrentUser\\Carbon custom store'
        Search -InCustomStore -ByThumbprint -ExpectedErrorMessage $expectedErrorMsg
        Search -InCustomStore -BySubject -ExpectedErrorMessage $expectedErrorMsg
        Search -InCustomStore -ByFriendlyName -ExpectedErrorMessage $expectedErrorMsg
    
        Search -ForCurrentUser -InCustomStore -ByThumbprint -ExpectedErrorMessage $expectedErrorMsg
        Search -ForCurrentUser -InCustomStore -BySubject -ExpectedErrorMessage $expectedErrorMsg
        Search -ForCurrentUser -InCustomStore -ByFriendlyName -ExpectedErrorMessage $expectedErrorMsg
    }
}

Describe 'Get-Certificate.when certificate does not exist' {
    It $itMsg -TestCases $failedSearchTestCases {
        param(
            $StoreLocation,
            $StoreName,
            $CustomStoreName,
            $Thumbprint,
            $Subject,
            $FriendlyName,
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
        It 'should get certificates in CA store' {
            Init
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
    It 'should load by path' {
        $cert = Get-CCertificate $testCertPath
        $cert | Should -Not -BeNullOrEmpty
        $cert.Thumbprint | Should -Be $testCertificateThumbprint
        $cert.Path | Should -Be $testCertPath
    }
}

Uninstall-CCertificate -Certificate $TestCert -StoreLocation CurrentUser -StoreName My
if( -not (Test-CustomStore -IsReadOnly -Location CurrentUser) )
{
    Uninstall-CCertificate -Certificate $TestCert -StoreLocation CurrentUser -CustomStoreName 'Carbon'
}
