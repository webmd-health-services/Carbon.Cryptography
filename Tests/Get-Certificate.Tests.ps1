
#Requres -Version 5.1
Set-StrictMode -Version 'Latest'

& (Join-Path -Path $PSScriptRoot -ChildPath 'Initialize-Test.ps1' -Resolve)

$testCertPath = Join-Path -Path $PSScriptRoot -ChildPath 'Resources\CarbonTestCertificate.pfx' -Resolve
$TestCert = New-Object Security.Cryptography.X509Certificates.X509Certificate2 $testCertPath
$testCertificateThumbprint = '7D5CE4A8A5EC059B829ED135E9AD8607977691CC'
$testCertFriendlyName = 'Pup Test Certificate'
$testCertSubject = 'CN=example.com'
$testCertCertProviderPath = 'cert:\CurrentUser\My\{0}' -f $testCertificateThumbprint
# macOS requires all certificates with private keys to be marked exportable.
$mustBeExportable = (Test-TCOperatingSystem -MacOS)
$supportsCustomStores = -not (Test-TCOperatingSystem -MacOS)

$supportsFriendlyName = Test-TCOperatingSystem -IsWindows

function Assert-TestCert
{
    param(
        $actualCert
    )
        
    $actualCert | Should -Not -BeNullOrEmpty
    $actualCert.Thumbprint | Should -Be $TestCert.Thumbprint
}

function Init
{
    if( (Get-Module 'Carbon') )
    {
        Write-Warning 'Removing Carbon. How did it get imported?'
        Remove-Module 'Carbon' -Force
    }

    $Global:Error.Clear()

    if( -not (Get-CCertificate -Thumbprint $TestCert.Thumbprint -StoreLocation CurrentUser -StoreName My) ) 
    {
        Install-CCertificate -Path $testCertPath `
                             -StoreLocation CurrentUser `
                             -StoreName My `
                             -Exportable:$mustBeExportable
    }


    if( $supportsCustomStores -and `
        -not (Get-CCertificate -Thumbprint $TestCert.Thumbprint -StoreLocation CurrentUser -CustomStoreName 'Carbon') )
    {
        Install-CCertificate -Path $testCertPath `
                             -StoreLocation CurrentUser `
                             -CustomStoreName 'Carbon' `
                             -Exportable:$mustBeExportable
    }
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
    It ('should have Path property') -Skip:(-not (Test-Path -Path 'cert:')) {
        Init
        $cert = Get-CCertificate -Path $testCertCertProviderPath
        $cert.Path | Should -Be $testCertCertProviderPath
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
        [switch] $UsingWildcard
    )

    $testCase = @{
        StoreLocation = '';
        StoreName = '';
        CustomStoreName = '';
        Thumbprint = '';
        Subject = '';
        FriendlyName = '';
        ExpectedPath = '';
        ExpectedStore = 'My'
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
    }

    if( $BySubject )
    {
        $searchKey = 'Subject'
        $searchValue = $testCertSubject
    }

    if( $ByFriendlyName )
    {
        $searchKey = 'FriendlyName'
        $searchValue = $testCertFriendlyName
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

    return $testCase
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

    # Search a custom store in all locations.
    Search -InCustomStore -ByThumbprint
    Search -InCustomStore -ByThumbprint -UsingWildcard
    Search -InCustomStore -BySubject
    Search -InCustomStore -BySubject -UsingWildcard
    Search -InCustomStore -ByFriendlyName
    Search -InCustomStore -ByFriendlyName -UsingWildcard

    # Search a custom store for a single location.
    Search -ForCurrentUser -InCustomStore -ByThumbprint
    Search -ForCurrentUser -InCustomStore -ByThumbprint -UsingWildcard
    Search -ForCurrentUser -InCustomStore -BySubject
    Search -ForCurrentUser -InCustomStore -BySubject -UsingWildcard
    Search -ForCurrentUser -InCustomStore -ByFriendlyName
    Search -ForCurrentUser -InCustomStore -ByFriendlyName -UsingWildcard
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

$itMsg = 'in { Location = <StoreLocation>; Store = <StoreName>; CustomStoreName = <CustomStoreName> } by { Thumbprint = ' +
         '<Thumbprint> ; Subject = <Subject> ; FriendlyName = <FriendlyName> }'
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
            $ExpectedStore
        )
        
        Init
        $params = ,$PSBoundParameters | ConvertTo-Parameter
        $cert = Get-CCertificate @params

        # Friendly names are Windows-only.
        if( (-not $supportsFriendlyName -and $FriendlyName) )
        {
            $cert | Should -BeNullOrEmpty
            return
        }

        $storeParam = @{ 'FromStore' = $ExpectedStore }
        if( $CustomStoreName )
        {
            $storeParam = @{ 'FromCustomStore' = $ExpectedStore }

            if( -not $supportsCustomStores )
            {
                $cert | Should -BeNullOrEmpty
                if( $StoreLocation )
                {
                    $Global:Error | Should -Match 'store does not exist|keychain could not be found'
                }
                return
            }
        }
        ThenReturnedCert $cert -WithPath $ExpectedPath -For 'CurrentUser' @storeParam
    }
}

Describe 'Get-Certificate.when certificate does not exist' {
    It 'should not throw error when certificate does not exist' {
        Init
        $cert = Get-CCertificate -Thumbprint '1234567890abcdef1234567890abcdef12345678' -StoreLocation CurrentUser -StoreName My -ErrorAction SilentlyContinue
        $Global:Error.Count | Should -Be 0
        $cert | Should -BeNullOrEmpty
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
        if( $supportsFriendlyName )
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

Uninstall-CCertificate -Certificate $TestCert -storeLocation CurrentUser -StoreName My
Uninstall-CCertificate -Certificate $TestCert -storeLocation CurrentUser -CustomStoreName 'Carbon'
