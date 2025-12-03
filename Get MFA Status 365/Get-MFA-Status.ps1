#Requires -Version 5.0


#Preference Variables
$Env:ProgressPreference = "SilentlyContinue"
$Env:WarningPreference = "SilentlyContinue"
$Env:ErrorActionPreference = "SilentlyContinue"

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
function Check-MSOL {
	Write-Host 'Checking for MSOnline Module' -ForegroundColor Yellow
    $module = Get-Module -Name MSOnline -ListAvailable | Select-Object -Last 1
    if ($null -ne $module) {
         Write-Host 'MSOnline Module Exists!' -ForegroundColor Green
    }
    else {
		Write-Host "MSOnline Module Not Installed!" -ForegroundColor Red
		$Selection = Read-Host "Install? (Y/N)"
		If ($Selection -eq "Y") {
			if ($null -eq $installedModule) {
				Write-Host 'Installing the required modules please hang tight.'
				Write-Host 'This WILL fail you did not run the script as admin' -ForegroundColor Yellow
				Install-Module -Name MSOnline -Force
				$module = Get-Module -Name MSOnline -ListAvailable | Select-Object -Last 1
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
			Check-HawkModule
		}     
    }
}

#Now lets make this very clear
Clear
Blink-Message "This script will grab all usersr MFA status and save a CSV in C:\Temp\"  250 10 Red, White, DarkRed, Green
Pause
Check-MSOL
Connect-MsolService
$TenantDomain = Get-MsolDomain | Select-Object -ExpandProperty  Name -Last 1 
Get-MsolUser -All | select DisplayName,BlockCredential,UserPrincipalName,@{N="MFA Status"; E={ if( $_.StrongAuthenticationRequirements.State -ne $null){ $_.StrongAuthenticationRequirements.State} else { "Disabled"}}} | Export-Csv -NoTypeInformation -Path c:\Temp\$TenantDomain-Users.csv



