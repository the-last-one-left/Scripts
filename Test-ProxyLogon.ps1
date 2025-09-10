#################################################################################
#
# The sample scripts are not supported under any Microsoft standard support 
# program or service. The sample scripts are provided AS IS without warranty 
# of any kind. Microsoft further disclaims all implied warranties including, without 
# limitation, any implied warranties of merchantability or of fitness for a particular 
# purpose. The entire risk arising out of the use or performance of the sample scripts 
# and documentation remains with you. In no event shall Microsoft, its authors, or 
# anyone else involved in the creation, production, or delivery of the scripts be liable 
# for any damages whatsoever (including, without limitation, damages for loss of business 
# profits, business interruption, loss of business information, or other pecuniary loss) 
# arising out of the use of or inability to use the sample scripts or documentation, 
# even if Microsoft has been advised of the possibility of such damages.
#
#################################################################################

# Version 21.03.08.2119

# Checks for signs of exploit from CVE-2021-26855, 26858, 26857, and 27065.
#
# Examples
#
# Check the local Exchange server only and save the report:
# .\Test-ProxyLogon.ps1 -OutPath $home\desktop\logs
#
# Check all Exchange servers and save the reports:
# Get-ExchangeServer | .\Test-ProxyLogon.ps1 -OutPath $home\desktop\logs
#
# Check all Exchange servers, but only display the results, don't save them:
# Get-ExchangeServer | .\Test-ProxyLogon.ps1
#
#Requires -Version 4

[CmdletBinding()]
param (
    [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [string[]]
    $ComputerName,

    [Parameter()]
    [string]
    $OutPath = "$PSScriptRoot\Test-ProxyLogonLogs",

    [Parameter()]
    [switch]
    $DisplayOnly
)

process {

    function Test-ExchangeProxyLogon {
        <#
	.SYNOPSIS
		Checks targeted exchange servers for signs of ProxyLogon vulnerability compromise.

	.DESCRIPTION
		Checks targeted exchange servers for signs of ProxyLogon vulnerability compromise.
		Will do so in parallel if more than one server is specified, so long as names aren't provided by pipeline.

		The vulnerabilities are described in CVE-2021-26855, 26858, 26857, and 27065

	.PARAMETER ComputerName
		The list of server names to scan for signs of compromise.
		Do not provide these by pipeline if you want parallel processing.

	.PARAMETER Credential
		Credentials to use for remote connections.

	.EXAMPLE
		PS C:\> Test-ExchangeProxyLogon

		Scans the current computer for signs of ProxyLogon vulnerability compromise.

	.EXAMPLE
		PS C:\> Test-ExchangeProxyLogon -ComputerName (Get-ExchangeServer).Fqdn

		Scans all exchange servers in the organization for ProxyLogon vulnerability compromises
#>
        [CmdletBinding()]
        param (
            [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
            [string[]]
            $ComputerName,

            [pscredential]
            $Credential
        )
        begin {
            #region Remoting Scriptblock
            $scriptBlock = {
                #region Functions
                function Get-ExchangeInstallPath {
                    return (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\v15\Setup -ErrorAction SilentlyContinue).MsiInstallPath
                }

                function Get-Cve26855 {
                    [CmdletBinding()]
                    param ()

                    $exchangePath = Get-ExchangeInstallPath
                    if ($null -eq $exchangePath) {
                        Write-Host "  Exchange 2013 or later not found. Skipping CVE-2021-26855 test."
                        return
                    }

                    Write-Progress -Activity "Checking for CVE-2021-26855 in the HttpProxy logs"

                    $files = (Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy" -Filter '*.log').FullName
                    $count = 0
                    $allResults = @()
                    $sw = New-Object System.Diagnostics.Stopwatch
                    $sw.Start()
                    $files | ForEach-Object {
                        $count++

                        if ($sw.ElapsedMilliseconds -gt 500) {
                            Write-Progress -Activity "Checking for CVE-2021-26855 in the HttpProxy logs" -Status "$count / $($files.Count)" -PercentComplete ($count * 100 / $files.Count)
                            $sw.Restart()
                        }

                        if ((Get-ChildItem $_ -ErrorAction SilentlyContinue | Select-String "ServerInfo~").Count -gt 0) {
                            $fileResults = @(Import-Csv -Path $_ -ErrorAction SilentlyContinue | Where-Object { $_.AuthenticatedUser -eq '' -and $_.AnchorMailbox -Like 'ServerInfo~*/*' } | Select-Object -Property DateTime, RequestId, ClientIPAddress, UrlHost, UrlStem, RoutingHint, UserAgent, AnchorMailbox, HttpStatus)
                            $fileResults | ForEach-Object {
                                $allResults += $_
                            }
                        }
                    }

                    Write-Progress -Activity "Checking for CVE-2021-26855 in the HttpProxy logs" -Completed

                    return $allResults
                }

                function Get-Cve26857 {
                    [CmdletBinding()]
                    param ()

                    Get-WinEvent -FilterHashtable @{
                        LogName      = 'Application'
                        ProviderName = 'MSExchange Unified Messaging'
                        Level        = '2'
                    } -ErrorAction SilentlyContinue | Where-Object { $_.Message -Like "*System.InvalidCastException*" }
                }

                function Get-Cve26858 {
                    [CmdletBinding()]
                    param ()

                    $exchangePath = Get-ExchangeInstallPath
                    if ($null -eq $exchangePath) {
                        Write-Host "  Exchange 2013 or later not found. Skipping CVE-2021-26858 test."
                        return
                    }

                    Get-ChildItem -Recurse -Path "$exchangePath\Logging\OABGeneratorLog" | Select-String "Download failed and temporary file" -List | Select-Object -ExpandProperty Path
                }

                function Get-Cve27065 {
                    [CmdletBinding()]
                    param ()

                    $exchangePath = Get-ExchangeInstallPath
                    if ($null -eq $exchangePath) {
                        Write-Host "  Exchange 2013 or later not found. Skipping CVE-2021-27065 test."
                        return
                    }

                    Get-ChildItem -Recurse -Path "$exchangePath\Logging\ECP\Server\*.log" -ErrorAction SilentlyContinue | Select-String "Set-.+VirtualDirectory" -List | Select-Object -ExpandProperty Path
                }

                function Get-SuspiciousFile {
                    [CmdletBinding()]
                    param ()

                    foreach ($file in Get-ChildItem -Recurse -Path "$env:WINDIR\temp\lsass.*dmp") {
                        [PSCustomObject]@{
                            ComputerName = $env:COMPUTERNAME
                            Type         = 'LsassDump'
                            Path         = $file.FullName
                            Name         = $file.Name
                        }
                    }
                    foreach ($file in Get-ChildItem -Recurse -Path "c:\root\lsass.*dmp" -ErrorAction SilentlyContinue) {
                        [PSCustomObject]@{
                            ComputerName = $env:COMPUTERNAME
                            Type         = 'LsassDump'
                            Path         = $file.FullName
                            Name         = $file.Name
                        }
                    }
                    foreach ($file in Get-ChildItem -Recurse -Path $env:ProgramData -ErrorAction SilentlyContinue | Where-Object { $_.Extension -Match "\.7z$|\.zip$|\.rar$" }) {
                        [PSCustomObject]@{
                            ComputerName = $env:COMPUTERNAME
                            Type         = 'SuspiciousArchive'
                            Path         = $file.FullName
                            Name         = $file.Name
                        }
                    }
                }

                function Get-AgeInDays {
                    param (
                        [string]
                        $dateString
                    )

                    $date = [DateTime]::MinValue
                    if ([DateTime]::TryParse($dateString, [ref]$date)) {
                        $age = [DateTime]::Now - $date
                        return $age.TotalDays.ToString("N1")
                    }

                    return ""
                }

                function Get-LogAge {
                    [CmdletBinding()]
                    param ()

                    $exchangePath = Get-ExchangeInstallPath
                    if ($null -eq $exchangePath) {
                        Write-Host "  Exchange 2013 or later not found. Skipping log age checks."
                        return $null
                    }

                    [PSCustomObject]@{
                        Oabgen           = (Get-AgeInDays (Get-ChildItem -Recurse -Path "$exchangePath\Logging\OABGeneratorLog" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime)
                        Ecp              = (Get-AgeInDays (Get-ChildItem -Recurse -Path "$exchangePath\Logging\ECP\Server\*.log" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime)
                        AutodProxy       = (Get-AgeInDays (Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy\Autodiscover" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime)
                        EasProxy         = (Get-AgeInDays (Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy\Eas" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime)
                        EcpProxy         = (Get-AgeInDays (Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy\Ecp" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime)
                        EwsProxy         = (Get-AgeInDays (Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy\Ews" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime)
                        MapiProxy        = (Get-AgeInDays (Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy\Mapi" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime)
                        OabProxy         = (Get-AgeInDays (Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy\Oab" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime)
                        OwaProxy         = (Get-AgeInDays (Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy\Owa" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime)
                        OwaCalendarProxy = (Get-AgeInDays (Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy\OwaCalendar" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime)
                        PowershellProxy  = (Get-AgeInDays (Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy\PowerShell" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime)
                        RpcHttpProxy     = (Get-AgeInDays (Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy\RpcHttp" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime)
                    }
                }
                #endregion Functions

                [PSCustomObject]@{
                    ComputerName = $env:COMPUTERNAME
                    Cve26855     = @(Get-Cve26855)
                    Cve26857     = @(Get-Cve26857)
                    Cve26858     = @(Get-Cve26858)
                    Cve27065     = @(Get-Cve27065)
                    Suspicious   = @(Get-SuspiciousFile)
                    LogAgeDays   = Get-LogAge
                }
            }
            #endregion Remoting Scriptblock
            $parameters = @{
                ScriptBlock = $scriptBlock
            }
            if ($Credential) { $parameters.Credential = $Credential }
        }
        process {
            if ($null -ne $ComputerName) {
                Invoke-Command @parameters -ComputerName $ComputerName
            } else {
                Invoke-Command @parameters
            }
        }
    }

    function Write-ProxyLogonReport {
        <#
	.SYNOPSIS
		Processes output of Test-ExchangeProxyLogon for reporting on the console screen.

	.DESCRIPTION
		Processes output of Test-ExchangeProxyLogon for reporting on the console screen.

	.PARAMETER InputObject
		The reports provided by Test-ExchangeProxyLogon

	.PARAMETER OutPath
		Path to a FOLDER in which to generate output logfiles.
		This command will only write to the console screen if no path is provided.

	.EXAMPLE
		PS C:\> Test-ExchangeProxyLogon -ComputerName (Get-ExchangeServer).Fqdn | Write-ProxyLogonReport -OutPath C:\logs

		Gather data from all exchange servers in the organization and write a report to C:\logs
#>
        [CmdletBinding()]
        param (
            [parameter(ValueFromPipeline = $true)]
            $InputObject,

            [string]
            $OutPath,

            [switch]
            $DisplayOnly
        )

        begin {
            if ($OutPath -and -not $DisplayOnly) {
                New-Item $OutPath -ItemType Directory -Force | Out-Null
            }
        }

        process {
            foreach ($report in $InputObject) {
                Write-Host "ProxyLogon Status: Exchange Server $($report.ComputerName)"

                if ($null -ne $report.LogAgeDays) {
                    Write-Host ("  Log age days: Oabgen {0} Ecp {1} Autod {2} Eas {3} EcpProxy {4} Ews {5} Mapi {6} Oab {7} Owa {8} OwaCal {9} Powershell {10} RpcHttp {11}" -f `
                            $report.LogAgeDays.Oabgen, `
                            $report.LogAgeDays.Ecp, `
                            $report.LogAgeDays.AutodProxy, `
                            $report.LogAgeDays.EasProxy, `
                            $report.LogAgeDays.EcpProxy, `
                            $report.LogAgeDays.EwsProxy, `
                            $report.LogAgeDays.MapiProxy, `
                            $report.LogAgeDays.OabProxy, `
                            $report.LogAgeDays.OwaProxy, `
                            $report.LogAgeDays.OwaCalendarProxy, `
                            $report.LogAgeDays.PowershellProxy, `
                            $report.LogAgeDays.RpcHttpProxy)

                    if (-not $DisplayOnly) {
                        $newFile = Join-Path -Path $OutPath -ChildPath "$($report.ComputerName)-LogAgeDays.csv"
                        $report.LogAgeDays | Export-Csv -Path $newFile
                        Write-Host "  Report exported to: $newFile"
                    }
                }

                if (-not ($report.Cve26855.Count -or $report.Cve26857.Count -or $report.Cve26858.Count -or $report.Cve27065.Count -or $report.Suspicious.Count)) {
                    Write-Host "  Nothing suspicious detected" -ForegroundColor Green
                    Write-Host ""
                    continue
                }

                if ($report.Cve26855.Count -gt 0) {
                    Write-Host "  [CVE-2021-26855] Suspicious activity found in Http Proxy log!" -ForegroundColor Red
                    if (-not $DisplayOnly) {
                        $newFile = Join-Path -Path $OutPath -ChildPath "$($report.ComputerName)-Cve-2021-26855.csv"
                        $report.Cve26855 | Export-Csv -Path $newFile
                        Write-Host "  Report exported to: $newFile"
                    } else {
                        $report.Cve26855 | Format-Table DateTime, AnchorMailbox -AutoSize | Out-Host
                    }
                    Write-Host ""
                }
                if ($report.Cve26857.Count -gt 0) {
                    Write-Host "  [CVE-2021-26857] Suspicious activity found in Eventlog!" -ForegroundColor Red
                    Write-Host "  $(@($report.Cve26857).Count) events found"
                    if (-not $DisplayOnly) {
                        $newFile = Join-Path -Path $OutPath -ChildPath "$($report.ComputerName)-Cve-2021-26857.csv"
                        $report.Cve26857 | Select-Object TimeCreated, MachineName, Message | Export-Csv -Path $newFile
                        Write-Host "  Report exported to: $newFile"
                    }
                    Write-Host ""
                }
                if ($report.Cve26858.Count -gt 0) {
                    Write-Host "  [CVE-2021-26858] Suspicious activity found in OAB generator logs!" -ForegroundColor Red
                    Write-Host "  Please review the following files for 'Download failed and temporary file' entries:"
                    foreach ($entry in $report.Cve26858) {
                        Write-Host "   $entry"
                    }
                    if (-not $DisplayOnly) {
                        $newFile = Join-Path -Path $OutPath -ChildPath "$($report.ComputerName)-Cve-2021-26858.log"
                        $report.Cve26858 | Set-Content -Path $newFile
                        Write-Host "  Report exported to: $newFile"
                    }
                    Write-Host ""
                }
                if ($report.Cve27065.Count -gt 0) {
                    Write-Host "  [CVE-2021-27065] Suspicious activity found in ECP logs!" -ForegroundColor Red
                    Write-Host "  Please review the following files for 'Set-*VirtualDirectory' entries:"
                    foreach ($entry in $report.Cve27065) {
                        Write-Host "   $entry"
                    }
                    if (-not $DisplayOnly) {
                        $newFile = Join-Path -Path $OutPath -ChildPath "$($report.ComputerName)-Cve-2021-27065.log"
                        $report.Cve27065 | Set-Content -Path $newFile
                        Write-Host "  Report exported to: $newFile"
                    }
                    Write-Host ""
                }
                if ($report.Suspicious.Count -gt 0) {
                    Write-Host "  Other suspicious files found: $(@($report.Suspicious).Count)"
                    if (-not $DisplayOnly) {
                        $newFile = Join-Path -Path $OutPath -ChildPath "$($report.ComputerName)-other.csv"
                        $report.Suspicious | Export-Csv -Path $newFile
                        Write-Host "  Report exported to: $newFile"
                    } else {
                        foreach ($entry in $report.Suspicious) {
                            Write-Host "   $($entry.Type) : $($entry.Path)"
                        }
                    }
                }
            }
        }
    }

    if ($DisplayOnly) {
        $ComputerName | Test-ExchangeProxyLogon | Write-ProxyLogonReport -DisplayOnly
    } else {
        $ComputerName | Test-ExchangeProxyLogon | Write-ProxyLogonReport -OutPath $OutPath
    }
}

# SIG # Begin signature block
# MIIjtwYJKoZIhvcNAQcCoIIjqDCCI6QCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDvSxQzQBLEqsZe
# dsUaMUajL/jb7u8pqPif8yvJXblwGaCCDYEwggX/MIID56ADAgECAhMzAAAB32vw
# LpKnSrTQAAAAAAHfMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjAxMjE1MjEzMTQ1WhcNMjExMjAyMjEzMTQ1WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQC2uxlZEACjqfHkuFyoCwfL25ofI9DZWKt4wEj3JBQ48GPt1UsDv834CcoUUPMn
# s/6CtPoaQ4Thy/kbOOg/zJAnrJeiMQqRe2Lsdb/NSI2gXXX9lad1/yPUDOXo4GNw
# PjXq1JZi+HZV91bUr6ZjzePj1g+bepsqd/HC1XScj0fT3aAxLRykJSzExEBmU9eS
# yuOwUuq+CriudQtWGMdJU650v/KmzfM46Y6lo/MCnnpvz3zEL7PMdUdwqj/nYhGG
# 3UVILxX7tAdMbz7LN+6WOIpT1A41rwaoOVnv+8Ua94HwhjZmu1S73yeV7RZZNxoh
# EegJi9YYssXa7UZUUkCCA+KnAgMBAAGjggF+MIIBejAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUOPbML8IdkNGtCfMmVPtvI6VZ8+Mw
# UAYDVR0RBEkwR6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMRYwFAYDVQQFEw0yMzAwMTIrNDYzMDA5MB8GA1UdIwQYMBaAFEhu
# ZOVQBdOCqhc3NyK1bajKdQKVMFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY0NvZFNpZ1BDQTIwMTFfMjAxMS0w
# Ny0wOC5jcmwwYQYIKwYBBQUHAQEEVTBTMFEGCCsGAQUFBzAChkVodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY0NvZFNpZ1BDQTIwMTFfMjAx
# MS0wNy0wOC5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAnnqH
# tDyYUFaVAkvAK0eqq6nhoL95SZQu3RnpZ7tdQ89QR3++7A+4hrr7V4xxmkB5BObS
# 0YK+MALE02atjwWgPdpYQ68WdLGroJZHkbZdgERG+7tETFl3aKF4KpoSaGOskZXp
# TPnCaMo2PXoAMVMGpsQEQswimZq3IQ3nRQfBlJ0PoMMcN/+Pks8ZTL1BoPYsJpok
# t6cql59q6CypZYIwgyJ892HpttybHKg1ZtQLUlSXccRMlugPgEcNZJagPEgPYni4
# b11snjRAgf0dyQ0zI9aLXqTxWUU5pCIFiPT0b2wsxzRqCtyGqpkGM8P9GazO8eao
# mVItCYBcJSByBx/pS0cSYwBBHAZxJODUqxSXoSGDvmTfqUJXntnWkL4okok1FiCD
# Z4jpyXOQunb6egIXvkgQ7jb2uO26Ow0m8RwleDvhOMrnHsupiOPbozKroSa6paFt
# VSh89abUSooR8QdZciemmoFhcWkEwFg4spzvYNP4nIs193261WyTaRMZoceGun7G
# CT2Rl653uUj+F+g94c63AhzSq4khdL4HlFIP2ePv29smfUnHtGq6yYFDLnT0q/Y+
# Di3jwloF8EWkkHRtSuXlFUbTmwr/lDDgbpZiKhLS7CBTDj32I0L5i532+uHczw82
# oZDmYmYmIUSMbZOgS65h797rj5JJ6OkeEUJoAVwwggd6MIIFYqADAgECAgphDpDS
# AAAAAAADMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0
# ZSBBdXRob3JpdHkgMjAxMTAeFw0xMTA3MDgyMDU5MDlaFw0yNjA3MDgyMTA5MDla
# MH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMT
# H01pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTEwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCr8PpyEBwurdhuqoIQTTS68rZYIZ9CGypr6VpQqrgG
# OBoESbp/wwwe3TdrxhLYC/A4wpkGsMg51QEUMULTiQ15ZId+lGAkbK+eSZzpaF7S
# 35tTsgosw6/ZqSuuegmv15ZZymAaBelmdugyUiYSL+erCFDPs0S3XdjELgN1q2jz
# y23zOlyhFvRGuuA4ZKxuZDV4pqBjDy3TQJP4494HDdVceaVJKecNvqATd76UPe/7
# 4ytaEB9NViiienLgEjq3SV7Y7e1DkYPZe7J7hhvZPrGMXeiJT4Qa8qEvWeSQOy2u
# M1jFtz7+MtOzAz2xsq+SOH7SnYAs9U5WkSE1JcM5bmR/U7qcD60ZI4TL9LoDho33
# X/DQUr+MlIe8wCF0JV8YKLbMJyg4JZg5SjbPfLGSrhwjp6lm7GEfauEoSZ1fiOIl
# XdMhSz5SxLVXPyQD8NF6Wy/VI+NwXQ9RRnez+ADhvKwCgl/bwBWzvRvUVUvnOaEP
# 6SNJvBi4RHxF5MHDcnrgcuck379GmcXvwhxX24ON7E1JMKerjt/sW5+v/N2wZuLB
# l4F77dbtS+dJKacTKKanfWeA5opieF+yL4TXV5xcv3coKPHtbcMojyyPQDdPweGF
# RInECUzF1KVDL3SV9274eCBYLBNdYJWaPk8zhNqwiBfenk70lrC8RqBsmNLg1oiM
# CwIDAQABo4IB7TCCAekwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFEhuZOVQ
# BdOCqhc3NyK1bajKdQKVMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1Ud
# DwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFHItOgIxkEO5FAVO
# 4eqnxzHRI4k0MFoGA1UdHwRTMFEwT6BNoEuGSWh0dHA6Ly9jcmwubWljcm9zb2Z0
# LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcmwwXgYIKwYBBQUHAQEEUjBQME4GCCsGAQUFBzAChkJodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcnQwgZ8GA1UdIASBlzCBlDCBkQYJKwYBBAGCNy4DMIGDMD8GCCsGAQUFBwIB
# FjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2RvY3MvcHJpbWFyeWNw
# cy5odG0wQAYIKwYBBQUHAgIwNB4yIB0ATABlAGcAYQBsAF8AcABvAGwAaQBjAHkA
# XwBzAHQAYQB0AGUAbQBlAG4AdAAuIB0wDQYJKoZIhvcNAQELBQADggIBAGfyhqWY
# 4FR5Gi7T2HRnIpsLlhHhY5KZQpZ90nkMkMFlXy4sPvjDctFtg/6+P+gKyju/R6mj
# 82nbY78iNaWXXWWEkH2LRlBV2AySfNIaSxzzPEKLUtCw/WvjPgcuKZvmPRul1LUd
# d5Q54ulkyUQ9eHoj8xN9ppB0g430yyYCRirCihC7pKkFDJvtaPpoLpWgKj8qa1hJ
# Yx8JaW5amJbkg/TAj/NGK978O9C9Ne9uJa7lryft0N3zDq+ZKJeYTQ49C/IIidYf
# wzIY4vDFLc5bnrRJOQrGCsLGra7lstnbFYhRRVg4MnEnGn+x9Cf43iw6IGmYslmJ
# aG5vp7d0w0AFBqYBKig+gj8TTWYLwLNN9eGPfxxvFX1Fp3blQCplo8NdUmKGwx1j
# NpeG39rz+PIWoZon4c2ll9DuXWNB41sHnIc+BncG0QaxdR8UvmFhtfDcxhsEvt9B
# xw4o7t5lL+yX9qFcltgA1qFGvVnzl6UJS0gQmYAf0AApxbGbpT9Fdx41xtKiop96
# eiL6SJUfq/tHI4D1nvi/a7dLl+LrdXga7Oo3mXkYS//WsyNodeav+vyL6wuA6mk7
# r/ww7QRMjt/fdW1jkT3RnVZOT7+AVyKheBEyIXrvQQqxP/uozKRdwaGIm1dxVk5I
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIVjDCCFYgCAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAd9r8C6Sp0q00AAAAAAB3zAN
# BglghkgBZQMEAgEFAKCBxjAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgRNB+az2J
# LEuk4cLbIZWgZ+KzwHj1697nlhqND99Of+8wWgYKKwYBBAGCNwIBDDFMMEqgGoAY
# AEMAUwBTACAARQB4AGMAaABhAG4AZwBloSyAKmh0dHBzOi8vZ2l0aHViLmNvbS9t
# aWNyb3NvZnQvQ1NTLUV4Y2hhbmdlIDANBgkqhkiG9w0BAQEFAASCAQB/JOHnjaW+
# mIfSZDH1jHFwbvywpsW/62akfUtF60VkTx34VtF7rXMXL8b+KQo8+rQJMGIvq0cz
# Dowd0AKTTQWrPlNwWnTLxv7n5L0QxO4fGq0GfQIbX6Ztdfk/zzb+hhSXrPoThbnW
# llikNdLNMJpP3Gyp4Vpz3LJ1f7oCxL8yFGVLLUcMaeUxVc80wqrMUn599YdSFpSp
# UXSasuXxpPUwUul2oLeH8q1wvFhcRWIbZxlyTzgSuGi1xQdC8qDS351Nz+Vz/gMC
# PebU4tV3h8WBQbLbIfCl2ikbTmiw9tNVZfmuvlpSs3TZU6pInijvPyCL5gTNlj/k
# RfbDobmdi5WIoYIS/jCCEvoGCisGAQQBgjcDAwExghLqMIIS5gYJKoZIhvcNAQcC
# oIIS1zCCEtMCAQMxDzANBglghkgBZQMEAgEFADCCAVkGCyqGSIb3DQEJEAEEoIIB
# SASCAUQwggFAAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZIAWUDBAIBBQAEIDcjWPrA
# uz/Fg7btnD8t2TDJW+NWGEpLeQyOcYLzMRN2AgZgPN/61wkYEzIwMjEwMzA4MjMy
# ODU1LjkwMlowBIACAfSggdikgdUwgdIxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
# YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlv
# bnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046RTA0MS00QkVFLUZB
# N0UxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2Wggg5NMIIE
# +TCCA+GgAwIBAgITMwAAATdBj0PnWltvpwAAAAABNzANBgkqhkiG9w0BAQsFADB8
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1N
# aWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0yMDEwMTUxNzI4MTRaFw0y
# MjAxMTIxNzI4MTRaMIHSMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVyYXRpb25zIExpbWl0
# ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkUwNDEtNEJFRS1GQTdFMSUwIwYD
# VQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIIBIjANBgkqhkiG9w0B
# AQEFAAOCAQ8AMIIBCgKCAQEAxBHuadElm3G5tikhTzjSDB0+9sXmUhUyDVRj0Y4v
# z9rZ9sykNobL5/6At5zOkeB2bl9IXvVdyS/ZJNZT373knzrQ347z30Mmw7++VU/C
# E+4x4w9kb5bqQHfSzbJQt6KmWsuMmJLzg4R5MeJs5MY5YdPLxoMoDRcTi//KoMFR
# 0KzS1/324D2/4KkHD1Xt+s0xY0DICUOK1RbmJCKEgBP1/GDZjuZQBS9Di89yTnvL
# JV+Lr1QtriH4EqmRoAdmV3zJ0GJsr5vhGPmKfOPCRSk7Q8igX7goFnCLzpYcfHGC
# qoR/mw95gfQpwymVwxZB0PkGMrQw+LKVPa/FHP4C4KO+QQIDAQABo4IBGzCCARcw
# HQYDVR0OBBYEFA1gsHMM+udgY7rEne66OyzxlE9lMB8GA1UdIwQYMBaAFNVjOlyK
# MZDzQ3t8RhvFM2hahW1VMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwubWlj
# cm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1RpbVN0YVBDQV8yMDEwLTA3
# LTAxLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljVGltU3RhUENBXzIwMTAtMDctMDEu
# Y3J0MAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcN
# AQELBQADggEBAJ32U9d90RVuAUb9NsnXBG1K42qjhU+jHvwBdbipIcX4Wg7dH5Zd
# uQZj3gWgKADZ5z+TehX7GnBbi265VI7xDRsFe2CjkTm4JIoisdKwYBDruS+YRRBG
# 4B1ERuWi54XGwx+lSA+iQNrIi6Jm0CL/MfQLvwsqPJSGP69OEHCyaExos486+X3J
# TuGV11CBl/BO7r8UHbx/rE6fZrlZZYabIF6aeahvTL14LvZLV/bMzYSODsbjHHsT
# m9QaGm1ijhagCdbkAqr8+7HAgYEar8XPlzxUhVI4ShVB5ZGd9gZ2yBkwxdA0oFc7
# 45TdOPrbP79vd0ePqgvJDH5tkOhTRNI55XQwggZxMIIEWaADAgECAgphCYEqAAAA
# AAACMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0ZSBB
# dXRob3JpdHkgMjAxMDAeFw0xMDA3MDEyMTM2NTVaFw0yNTA3MDEyMTQ2NTVaMHwx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1p
# Y3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMIIBIjANBgkqhkiG9w0BAQEFAAOC
# AQ8AMIIBCgKCAQEAqR0NvHcRijog7PwTl/X6f2mUa3RUENWlCgCChfvtfGhLLF/F
# w+Vhwna3PmYrW/AVUycEMR9BGxqVHc4JE458YTBZsTBED/FgiIRUQwzXTbg4CLNC
# 3ZOs1nMwVyaCo0UN0Or1R4HNvyRgMlhgRvJYR4YyhB50YWeRX4FUsc+TTJLBxKZd
# 0WETbijGGvmGgLvfYfxGwScdJGcSchohiq9LZIlQYrFd/XcfPfBXday9ikJNQFHR
# D5wGPmd/9WbAA5ZEfu/QS/1u5ZrKsajyeioKMfDaTgaRtogINeh4HLDpmc085y9E
# uqf03GS9pAHBIAmTeM38vMDJRF1eFpwBBU8iTQIDAQABo4IB5jCCAeIwEAYJKwYB
# BAGCNxUBBAMCAQAwHQYDVR0OBBYEFNVjOlyKMZDzQ3t8RhvFM2hahW1VMBkGCSsG
# AQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTAD
# AQH/MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1UdHwRPME0w
# S6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3Rz
# L01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEFBQcBAQROMEwwSgYI
# KwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWlj
# Um9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0MIGgBgNVHSABAf8EgZUwgZIwgY8GCSsG
# AQQBgjcuAzCBgTA9BggrBgEFBQcCARYxaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L1BLSS9kb2NzL0NQUy9kZWZhdWx0Lmh0bTBABggrBgEFBQcCAjA0HjIgHQBMAGUA
# ZwBhAGwAXwBQAG8AbABpAGMAeQBfAFMAdABhAHQAZQBtAGUAbgB0AC4gHTANBgkq
# hkiG9w0BAQsFAAOCAgEAB+aIUQ3ixuCYP4FxAz2do6Ehb7Prpsz1Mb7PBeKp/vpX
# bRkws8LFZslq3/Xn8Hi9x6ieJeP5vO1rVFcIK1GCRBL7uVOMzPRgEop2zEBAQZvc
# XBf/XPleFzWYJFZLdO9CEMivv3/Gf/I3fVo/HPKZeUqRUgCvOA8X9S95gWXZqbVr
# 5MfO9sp6AG9LMEQkIjzP7QOllo9ZKby2/QThcJ8ySif9Va8v/rbljjO7Yl+a21dA
# 6fHOmWaQjP9qYn/dxUoLkSbiOewZSnFjnXshbcOco6I8+n99lmqQeKZt0uGc+R38
# ONiU9MalCpaGpL2eGq4EQoO4tYCbIjggtSXlZOz39L9+Y1klD3ouOVd2onGqBooP
# iRa6YacRy5rYDkeagMXQzafQ732D8OE7cQnfXXSYIghh2rBQHm+98eEA3+cxB6ST
# OvdlR3jo+KhIq/fecn5ha293qYHLpwmsObvsxsvYgrRyzR30uIUBHoD7G4kqVDmy
# W9rIDVWZeodzOwjmmC3qjeAzLhIp9cAvVCch98isTtoouLGp25ayp0Kiyc8ZQU3g
# hvkqmqMRZjDTu3QyS99je/WZii8bxyGvWbWu3EQ8l1Bx16HSxVXjad5XwdHeMMD9
# zOZN+w2/XU/pnR4ZOC+8z1gFLu8NoFA12u8JJxzVs341Hgi62jbb01+P3nSISRKh
# ggLXMIICQAIBATCCAQChgdikgdUwgdIxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
# YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlv
# bnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046RTA0MS00QkVFLUZB
# N0UxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAH
# BgUrDgMCGgMVAOq7qDk4iVz8ITuZbUFrAG7ecxqcoIGDMIGApH4wfDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEFBQACBQDj8JiVMCIYDzIw
# MjEwMzA4MjAzNTMzWhgPMjAyMTAzMDkyMDM1MzNaMHcwPQYKKwYBBAGEWQoEATEv
# MC0wCgIFAOPwmJUCAQAwCgIBAAICE1gCAf8wBwIBAAICEWswCgIFAOPx6hUCAQAw
# NgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgC
# AQACAwGGoDANBgkqhkiG9w0BAQUFAAOBgQAyfDgC3vPVBMc0JdAT5bYlQixlM90t
# G0u+j+zWWvV3np72NKvue2+KP8JQaMaRs6tgyE5H2pkDdgrY0dHy3HmFc+Z5kQMg
# Fa40t6/q2DWVRZnHJNiEHQLAN0btqEy6XkCj3DJVFlu+QWv8DEKVRtnNdzfbCuXZ
# Xl1O+BFdPj9RQjGCAw0wggMJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBD
# QSAyMDEwAhMzAAABN0GPQ+daW2+nAAAAAAE3MA0GCWCGSAFlAwQCAQUAoIIBSjAa
# BgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEIH/hfa+W
# 2wyvGSwqIWCzCGR2+8xQP9MxRUiRbGxDoiicMIH6BgsqhkiG9w0BCRACLzGB6jCB
# 5zCB5DCBvQQgHVl+r8CeBJ0iyX/aGZD2YbQ7gk+U7N7BQiTDKAYSHBAwgZgwgYCk
# fjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQD
# Ex1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAATdBj0PnWltvpwAA
# AAABNzAiBCAg0ttsCxQ8U6gHRTJObOH+Oo03tZq6kmpet2aXV4YW4jANBgkqhkiG
# 9w0BAQsFAASCAQAG23ME4O0iW+YPP9PHDMY5cLflUPC+GwUPYPV1I9WsTTM32SaN
# h+x1PGV5j7pWi3o1Cv75DpWYBYBSMgjCR4DeVmIAgCSU0SQ1BNenQopFH45YsK3M
# fGCxWLmHHH/ckME43e+C3ehiIlLD074biN1SubcCAZQv0ellZepwTq6XSInh+Br9
# OTZRyJMuvXcd0D2FDVTcBFVmO3C+Dd61N9tvlFEF2HCDyzJmjOg/JQXrO2kL/Mew
# fgDSJHyr+VmgoaX5JOaitncWkVBPDizrTw16BE4iOaKGjvCPcrWHYEqFfOIwM+6C
# nQPbj0CS2WZbPW+xt8+pfKmrtqolQBivJVwv
# SIG # End signature block
