

Function ListServices {
	Write-Host "The following services are set to Automatically start but are not running:" -ForegroundColor Yellow
	Get-Service -Exclude WaaSMedicSvc, NPSMSvc* | Select-Object -Property DisplayName,Status,StartType  | Where-Object {$_.Status -eq "Stopped" -and $_.StartType -eq "Automatic"} | foreach { $_.DisplayName } 	
	$Selection = Read-Host "Attempt to start them? (Y/N)"
	If ($Selection -eq "Y") {
		Get-Service -Exclude WaaSMedicSvc, NPSMSvc* | Select-Object -Property Name,Status,StartType  | Where-Object {$_.Status -eq "Stopped" -and $_.StartType -eq "Automatic"} | foreach { $_.Name } | Start-Service -PassThru 
	}
	ElseIf ($Selection -eq "N") {
		Write-Host "Continuing without starting..." -ForegroundColor Green
		Pause
	}  
	Else {
		Clear-Host
		Write-Host "Please make a proper selection" -ForegroundColor Red
		Pause
		ListServices
	} 
	
}

Function GetFirewallProfile {
	$profile = Get-NetFirewallSetting -PolicyStore ActiveStore | Select-Object -ExpandProperty ActiveProfile
	If ($profile -like '*Public*') {
		Write-Host "The firewall is currently using $profile profile(s)....  There may be an issue with DNS or the Network Location Awareness Service." -ForegroundColor Red
		Pause
	}
	Else {
		Write-Host "The firewall is currently using $profile profile(s)...." -ForegroundColor Green
		Pause
	}
}

Function DiskSpace {
	Write-Host "Calculating Disk Space..." -ForegroundColor Green
	Get-WmiObject -Class win32_logicaldisk | Format-Table DeviceId, MediaType, @{n="Size";e={[math]::Round($_.Size/1GB,2)}},@{n="FreeSpace";e={[math]::Round($_.FreeSpace/1GB,2)}}
	Pause
}

Function Logs {
	Write-Host "Last 10 Application Errors:" -ForegroundColor Green
	Get-EventLog -Newest 10 -EntryType Error -LogName Application | Select-Object Source, EventID, Message | Out-Host
	Pause
	Write-Host "Last 10 System Errors:" -ForegroundColor Green
	Get-EventLog -Newest 10 -EntryType Error -LogName System | Select-Object Source, EventID, Message| Out-Host
	Pause
}
	
Function GetDNS {
	Write-Host "DNS Servers:" -ForegroundColor Green
	Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object {$_.ServerAddresses -ne $null} | Out-Host
}



Write-Host "Basic discovery for servers having issues" -ForegroundColor Green
Pause
ListServices
GetFirewallProfile
DiskSpace
Logs
GetDNS
Write-host "Ummmm.....  Shit -Jameson Taylor (Thomas)" -ForegroundColor Magenta
Pause