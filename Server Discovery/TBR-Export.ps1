# Import required modules
Import-Module MSOnline
Import-Module ExchangeOnlineManagement
Import-Module AzureADPreview

#Courtesy of Joshua Honig (https://social.technet.microsoft.com/profile/joshua%20honig) - directly stolen from his Technet Post
function Blink-Message {
 param([String]$Message,[int]$Delay,[int]$Count,[ConsoleColor[]]$Colors) 
    $startColor = [Console]::ForegroundColor
    $startLeft  = [Console]::CursorLeft
    $startTop   = [Console]::CursorTop
    $colorCount = $Colors.Length
    for($i = 0; $i -lt $Count; $i++) {
        [Console]::CursorLeft = $startLeft
        [Console]::CursorTop  = $startTop
        [Console]::ForegroundColor = $Colors[$($i % $colorCount)]
        [Console]::WriteLine($Message)
        Start-Sleep -Milliseconds $Delay
    }
    [Console]::ForegroundColor = $startColor
}

#Checks and Installs MSOL
function Check-MSOModule {
	Write-Host 'Checking for MSOL Module' -ForegroundColor Yellow
    $module = Get-Module -Name msonline -ListAvailable | Select-Object -Last 1
    if ($null -ne $module) {
         Write-Host 'MSOL Module Exists!' -ForegroundColor Green
    }
    else {
		Write-Host "MSOL Module Not Installed!" -ForegroundColor Red
		$Selection = Read-Host "Install? (Y/N)"
		If ($Selection -eq "Y") {
			if ($null -eq $installedModule) {
				Write-Host 'Installing the required modules please hang tight.'
				Write-Host 'This WILL fail you did not run the script as admin' -ForegroundColor Yellow
				Install-Module -Name msonline -Force
				$module = Get-Module -Name msonline -ListAvailable | Select-Object -Last 1
				if ($null -ne $module) { }
				else { Write-Host 'FAILED!' -ForegroundColor Red }
			}
		}
		ElseIf ($Selection -eq "N") {
			exit
		}  
		Else {
			Clear-Host
			Write-Host "Please make a proper selection" -ForegroundColor Red
			Pause
			Check-MSOModule
		}     
    }
}

#Checks and Installs EXO
function Check-EXOModule {
	Write-Host 'Checking for EXO Module' -ForegroundColor Yellow
    $module = Get-Module -Name ExchangeOnlineManagement -ListAvailable | Select-Object -Last 1
    if ($null -ne $module) {
         Write-Host 'EXO Module Exists!' -ForegroundColor Green
    }
    else {
		Write-Host "EXO Module Not Installed!" -ForegroundColor Red
		$Selection = Read-Host "Install? (Y/N)"
		If ($Selection -eq "Y") {
			if ($null -eq $installedModule) {
				Write-Host 'Installing the required modules please hang tight.'
				Write-Host 'This WILL fail you did not run the script as admin' -ForegroundColor Yellow
				Install-Module -Name ExchangeOnlineManagement -Force
				$module = Get-Module -Name ExchangeOnlineManagement -ListAvailable | Select-Object -Last 1
				if ($null -ne $module) { }
				else { Write-Host 'FAILED!' -ForegroundColor Red }
			}
		}
		ElseIf ($Selection -eq "N") {
			exit
		}  
		Else {
			Clear-Host
			Write-Host "Please make a proper selection" -ForegroundColor Red
			Pause
			Check-EXOModule
		}     
    }
}

#Checks and Installs AADP
function Check-AADModule {
	Write-Host 'Checking for AAD Module' -ForegroundColor Yellow
    $module = Get-Module -Name AzureADPreview -ListAvailable | Select-Object -Last 1
    if ($null -ne $module) {
         Write-Host 'AAD Module Exists!' -ForegroundColor Green
    }
    else {
		Write-Host "AAD Module Not Installed!" -ForegroundColor Red
		$Selection = Read-Host "Install? (Y/N)"
		If ($Selection -eq "Y") {
			if ($null -eq $installedModule) {
				Write-Host 'Installing the required modules please hang tight.'
				Write-Host 'This WILL fail you did not run the script as admin' -ForegroundColor Yellow
				Uninstall-Module azuread 
				Install-Module -Name AzureADPreview -Force
				$module = Get-Module -Name AzureADPreview -ListAvailable | Select-Object -Last 1
				if ($null -ne $module) { }
				else { Write-Host 'FAILED!' -ForegroundColor Red }
			}
		}
		ElseIf ($Selection -eq "N") {
			exit
		}  
		Else {
			Clear-Host
			Write-Host "Please make a proper selection" -ForegroundColor Red
			Pause
			Check-AADModule
		}     
    }
}

#Now lets make this very clear
Clear
Blink-Message "This script is still in development.  I have controls in place to validate compatability"  250 10 Red, White, DarkRed, Green
Write-Host ''
Write-Host 'The script needs Exchange Online, Azure AD and MSOL Service - we will try to install'
Write-Host ''
Write-Host 'Compiled by Zachary Child, please submit complaints to TBR-Script@awesomazing.com'
Pause
Check-AADModule
Check-EXOModule
Check-MSOModule


# Connect to Exchange Online and MSOL Service
Connect-ExchangeOnline -ShowBanner:$false
Connect-MsolService 
AzureADPreview\Connect-AzureAD

# Get user information
$users = Get-MsolUser -All
$exchangeUsers = Get-ExoMailbox -ResultSize Unlimited

# Collect and export user information
$results = @()
foreach ($user in $users) {
    $exchangeUser = $exchangeUsers | Where-Object { $_.UserPrincipalName -eq $user.UserPrincipalName }
    $results += [PSCustomObject]@{
        'First Name'                = $user.FirstName
        'Last Name'                 = $user.LastName
        'Email'                     = $user.UserPrincipalName
        'Licenses Applied'          = ($user.Licenses.AccountSkuId -join ", ")
        'Last Password Change'      = $user.LastPasswordChangeTimestamp
        'User Type'                 = $user.UserType
        'Per User MFA Enabled'      = $user.StrongAuthenticationRequirements.State
        'Conditional Access MFA Enabled' = $user.ConditionalAccessPolicy -ne $null
		'Strong Authentication Methods' = ($user.StrongAuthenticationMethods.MethodType -join ", ")
        'Is Sign In Blocked'        = $user.BlockCredential
    }
}

# Export user data to CSV
$results | Export-Csv -Path "Office365UserData.csv" -NoTypeInformation

# Get license information
$licenses = Get-MsolAccountSku
$licenseData = @()
foreach ($license in $licenses) {
    $licenseData += [PSCustomObject]@{
        'License Name'  = $license.AccountSkuId
        'Total Licenses' = $license.ActiveUnits
        'Licenses In Use' = $license.ConsumedUnits
    }
}

# Export license data to CSV
$licenseData | Export-Csv -Path "Office365LicenseData.csv" -NoTypeInformation

# Check Security Defaults and Azure AD license
$directorySettings = Get-AzureADDirectorySetting -All $true
$securityDefaults = $directorySettings | Where-Object { $_.DisplayName -eq "SecurityDefaults" }
$securityDefaultsEnabled = $securityDefaults.Values -contains "true"

Blink-Message "Security Defaults Enabled: $securityDefaultsEnabled" 250 10 Red, White, DarkRed, Green

$companyInfo = Get-MsolCompanyInformation
$companySku = $companyInfo.AccountSkuId

if ($companySku -match "AAD_PREMIUM") {
    if ($companySku -match "P1") {
        Blink-Message "Azure AD License: P1" 250 10 Red, White, DarkRed, Green
    } elseif ($companySku -match "P2") {
        Blink-Message "Azure AD License: P2" 250 10 Red, White, DarkRed, Green
    } else {
        Blink-Message "Azure AD License: Unknown" 250 10 Red, White, DarkRed, Green
    }
} else {
    Blink-Message "Azure AD License: Not  Premium (P1 or P2)" 250 10 Red, White, DarkRed, Green
}
pause

# Disconnect from Exchange Online and MSOL Service
Disconnect-ExchangeOnline -Confirm:$false

#Let everyone know
Clear
Blink-Message "Export complete, you will find 2 CSV files in the directory you ran this from"  250 10 Red, White, DarkRed, Green
pause