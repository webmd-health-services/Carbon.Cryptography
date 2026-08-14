
function Find-CCertificate
{
    <#
    .SYNOPSIS
    Searches certificate stores for certificates.

    .DESCRIPTION
    The `Find-CCertificate` function searches through the My/Personal certificate store for the local machine and
    current user accounts for certificates that match search criteria. Use the following parameters to search:

    * `Subject`: return certificates with the given subject. Wildcards accepted.
    * `LiteralSubject`: return certificates whose subjects exactly match the given subject.
    * `Active`: return certificates that are active and not expired.
    * `HasPrivateKey`: return certificates that have a private key.
    * `HostName`: return certificates that authenticate the given hostname. Wildcards supported. Matches against the
      subject's common name and the certificate's subject alternate names.
    * `LiteralHostName`: return certificates that authenticate the given hostname. Matches against the subject's common
      name and the certificate's subject alternate names.
    * `KeyUsageName`: return certificates that have the given enhanced key usage, searching each usage's friendly name.
    * `KeyUsageOId`: return certificates that have the given enhanced key usage, searching each usage's object ID.
    * `Trusted`: return certificates that are trusted/verified.

    You can search in the local machine or current user accounts (not both) by passing the account to the
    `StoreLocation` parameter. You can search in different stores by passing the store name to the `StoreName`
    parameter.

    Enable debug messages to see detailed information about why a certificate isn't or isn't being found. You'll see
    messages for each selection criteria and if a criterium isn't met, you'll see a `!` flag. For example, this debug
    output from `Find-CCertificate -HostName 'example.com' -Active -HasPrivateKey -Trusted`:

        CN=sub.example.com
        FCD157FCB753E2B388183C19021301B1739DF1E2
            private key      True
            start date       2021-10-18 15:43:23
            expiration date  2023-10-19 15:43:23
          ! hostname         ['sub.example.com']

        CN=example.com
        7F660D4F7201B8EB8F7F6AC2A0906253C240584F
            private key      True
            start date       2021-10-18 15:43:23
            expiration date  2022-10-19 15:43:23
            hostname         ['example.com']
            trusted          True
        ^--------------------------------------^

    shows that certificate `FCD157FCB753E2B388183C19021301B1739DF1E2` wasn't selected because its hostname didn't match
    the `example.com` hostname, but that certificate `7F660D4F7201B8EB8F7F6AC2A0906253C240584F` was selected because it
    matched six criteria.

    If a certificate isn't found and debug messages are off, the search log is written to the verbose
    stream instead of the debug stream.

    .EXAMPLE
    Find-CCertificate -Active -HostName 'dev.example.com' -KeyUsageName 'Server Authentication' -Trusted -HasPrivateKey

    Demonstrates how to search for a certificate using multiple criteria. In this example, we're looking for a TLS
    certificate that can be used with the `dev.example.com` hostname.
    #>
    [CmdletBinding()]
    param(
        [String] $Subject,

        [String] $LiteralSubject,

        [switch] $Active,

        [switch] $HasPrivateKey,

        [String] $HostName,

        [String] $LiteralHostName,

        [String] $KeyUsageName,

        [String] $KeyUsageOid,

        [switch] $Trusted,

        [Security.Cryptography.X509Certificates.StoreLocation] $StoreLocation,

        [Security.Cryptography.X509Certificates.StoreName] $StoreName =
            [Security.Cryptography.X509Certificates.StoreName]::My
    )

    begin
    {
        Set-StrictMode -Version 'Latest'
        Use-CallerPreference -Cmdlet $PSCmdlet -Session $ExecutionContext.SessionState

        $foundACert = $false

        $searchLog = [Text.StringBuilder]::New()

        $actionPrefEnabledValues = @('Inquire', 'Continue', 'Suspend')
        $debugEnabled = $DebugPreference -in $actionPrefEnabledValues
        $searchLogEnabled = -not $debugEnabled -and $VerbosePreference -in $actionPrefEnabledValues

        function Write-SearchLog
        {
            param(
                [Parameter(Mandatory)]
                [AllowEmptyString()]
                [String] $Message
            )

            if ($searchLogEnabled)
            {
                [void]$searchLog.AppendLine($Message)
                return
            }

            Write-Debug $Message
        }

        function Test-Object
        {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory, ValueFromPipeline)]
                [AllowEmptyString()]
                [AllowNull()]
                [Object] $InputObject,

                [Parameter(Mandatory, ParameterSetName='Equals')]
                [AllowEmptyString()]
                [AllowNull()]
                [switch] $Equals,

                [Parameter(Mandatory, ParameterSetName='LessThan')]
                [switch] $LessThan,

                [Parameter(Mandatory, ParameterSetName='GreaterThan')]
                [switch] $GreaterThan,

                [Parameter(Mandatory, ParameterSetName='Contains')]
                [switch] $Contains,

                [Parameter(Mandatory, ParameterSetName='ContainsLike')]
                [switch] $ContainsLike,

                [Parameter(Mandatory, ParameterSetName='Matches')]
                [switch] $Match,

                [Parameter(Mandatory, ParameterSetName='Like')]
                [switch] $Like,

                [Parameter(Mandatory, Position=0)]
                [Object] $Value,

                [Parameter(Mandatory)]
                [String] $Name,

                [String] $DisplayValue
            )

            process
            {
                $success = $false

                if( $Equals )
                {
                    if( $null -eq $InputObject )
                    {
                        if( $null -eq $Value )
                        {
                            $success = $true
                        }
                    }
                    elseif( $InputObject -eq $Value )
                    {
                        $success = $true
                    }
                }
                elseif( $LessThan )
                {
                    $success = $InputObject -lt $Value
                }
                elseif( $GreaterThan )
                {
                    $success = $InputObject -gt $Value
                }
                elseif( $Contains )
                {
                    $success = $InputObject -contains $Value
                }
                elseif( $ContainsLike )
                {
                    $success = $false

                    foreach ($nameItem in $InputObject)
                    {
                        # If the first character of the item is a wildcard character.
                        if ($nameItem[0] -eq '*')
                        {
                            # Wildcards in certificates only ever match one "level" of a domain name and must be on the very left.
                            # Therefore the wildcard can match any character except for "."
                            $wildcardRegex = '[^\.]+'
                            $baseName = $nameItem.Substring(1)               # *.example.com  ➔ .example.com
                            $escapedBaseName = [Regex]::Escape($baseName)    #  .example.com  ➔ \.example\.com
                            $regex = "^${wildcardRegex}$($escapedBaseName)$" # \.example\.com ➔ ^[^\.]+\.example\.com$
                            $success = $Value -match $regex
                        }
                        else
                        {
                            $success = $nameItem -like $Value
                        }

                        # Found a match.
                        if ($success)
                        {
                            break
                        }
                    }
                }
                elseif( $Match )
                {
                    $success = $InputObject -match $Value
                }
                elseif( $Like )
                {
                    $success = $InputObject -like $Value
                }

                $flag = '!'
                if( $success )
                {
                    $flag = ' '
                }

                if( -not $DisplayValue )
                {
                    $displayValues =
                        $InputObject |
                        Where-Object { $null -ne $_ } |
                        ForEach-Object { $_ } |
                        Where-Object { $null -ne $_ } |
                        ForEach-Object {
                            if( $_ -is [DateTime] )
                            {
                                return $_.ToString('yyyy-MM-dd HH:mm:ss')
                            }
                            return $_.ToString()
                        }
                    $DisplayValue = $displayValues -join ', '
                }

                $name = '{0,-22}' -f $Name
                $msg = "  $($flag) $($Name)  $($DisplayValue)"
                if( $longestLineLength -lt $msg.Length )
                {
                    $script:longestLineLength = $msg.Length
                }
                Write-SearchLog $msg
                return $success
            }
        }
    }

    process
    {
        Write-SearchLog 'Find-CCertificate search criteria:'
        if( $Subject )
        {
            Write-SearchLog "  Subject        like  $($Subject)"
        }
        if( $LiteralSubject )
        {
            Write-SearchLog "  Subject        eq    $($LiteralSubject)"
        }
        if( $Active )
        {
            Write-SearchLog '  Active         True'
        }
        if( $HasPrivateKey )
        {
            Write-SearchLog '  HasPrivateKey  True'
        }
        if( $HostName )
        {
            Write-SearchLog "  HostName       like  $($HostName)"
        }
        if( $LiteralHostName )
        {
            Write-SearchLog "  HostName       eq    $($LiteralHostName)"
        }
        if( $KeyUsageName )
        {
            Write-SearchLog "  Key Usage      $($KeyUsageName)"
        }
        if( $KeyUsageOid )
        {
            Write-SearchLog "  Key Usage OID  $($KeyUsageOid)"
        }
        if( $Trusted )
        {
            Write-SearchLog "  Trusted        True"
        }
        if( $StoreLocation )
        {
            Write-SearchLog "  StoreLocation  $($StoreLocation)"
        }
        if( $StoreName )
        {
            Write-SearchLog "  StoreName      $($StoreName)"
        }
        Write-SearchLog ''

        $getCertArgs = @{}

        if( $StoreLocation )
        {
            $getCertArgs['StoreLocation'] = $StoreLocation
        }

        $certs = Get-CCertificate @getCertArgs -StoreName $StoreName
        $isFirstCert = $true
        foreach( $certificate in $certs )
        {
            if( $isFirstCert )
            {
                $isFirstCert = $false
            }
            else
            {
                Write-SearchLog ''
            }

            Write-SearchLog $certificate.Subject
            Write-SearchLog $certificate.Thumbprint

            $script:longestLineLength = $certificate.Subject.Length
            if( $script:longestLineLength -lt $certificate.Thumbprint.Length )
            {
                $script:longestLineLength = $certificate.Thumbprint.Length
            }

            if( $Subject )
            {
                if( -not ($certificate.Subject | Test-Object -Like $Subject -Name 'subject') )
                {
                    continue
                }
            }

            if( $LiteralSubject )
            {
                if( -not ($certificate.Subject | Test-Object -Equals $LiteralSubject -Name 'subject') )
                {
                    continue
                }
            }

            if( $HasPrivateKey.IsPresent )
            {
                if( -not ($certificate.HasPrivateKey | Test-Object -Equals $HasPrivateKey -Name 'private key') )
                {
                    continue
                }
            }

            if( $Active )
            {
                if( -not ($certificate.NotBefore | Test-Object -LessThan (Get-Date) -Name 'start date') )
                {
                    continue
                }

                if( -not ($certificate.NotAfter | Test-Object -GreaterThan (Get-Date) -Name 'expiration date') )
                {
                    continue
                }
            }

            $subjectHostName = ''
            if( $certificate.Subject -match '^CN=([^,]+),?.*$' )
            {
                $subjectHostName = $Matches[1]
            }

            if( $HostName )
            {
                $inSubject = $subjectHostName | Test-Object -Like $HostName -Name 'subject common name'
                if( -not $inSubject )
                {
                    $found =
                        (,$certificate.DnsNameList | Test-Object -ContainsLike $HostName -Name 'subject alternate name')
                    if( -not $found )
                    {
                        continue
                    }
                }
            }

            if( $LiteralHostName )
            {
                $inSubject = $subjectHostName | Test-Object -Equals $LiteralHostName -Name 'subject common name'
                if( -not $inSubject )
                {
                    $found =
                        (,$certificate.DnsNameList | Test-Object -Contains $LiteralHostName -Name 'subject alternate name')
                    if( -not $found )
                    {
                        continue
                    }
                }
            }

            if( $KeyUsageName -or $KeyUsageOid )
            {
                if( $certificate.EnhancedKeyUsageList.Count -eq 0 )
                {
                    $certificate.EnhancedKeyUsageList.Count |
                        Test-Object -Equals 0 -Name 'key usage' -DisplayValue 'Any' |
                        Out-Null
                }
                else
                {
                    if( $KeyUsageName )
                    {
                        $names = $certificate.EnhancedKeyUsageList | Select-Object -ExpandProperty 'FriendlyName'
                        if( -not (,$names | Test-Object -Contains $KeyUsageName -Name 'key usage') )
                        {
                            continue
                        }
                    }

                    if( $KeyUsageOid )
                    {
                        $oids = $certificate.EnhancedKeyUsageList | Select-Object -ExpandProperty 'ObjectId'
                        if( -not (,$oids | Test-Object -Contains $KeyUsageOid -Name 'key usage') )
                        {
                            continue
                        }
                    }
                }
            }

            if( $Trusted )
            {
                if( -not $certificate.Verify() | Test-Object -Equals $true -Name 'trusted' )
                {
                    continue
                }
            }

            $foundACert = $true
            Write-SearchLog "^$('-' * ($longestLineLength - 2))^"

            $certificate | Write-Output
        }
    }

    end
    {
        if (-not $foundACert -and $searchLogEnabled)
        {
            [void]$searchLog.Insert(0, [Environment]::NewLine)
            Write-Verbose -Message $searchLog.ToString()
        }
    }
}
