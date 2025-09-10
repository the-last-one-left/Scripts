#Pulls latest elevate to $WorkDir and installs for current user, then installs outlook integration

$ElevateUrl         = "https://cp.serverdata.net/voice/pbx/softphonereleases/default/latest-win/elevate-uc.exe"
$WorkDir            = "C:\Temp"
$ProgressPreference = 'SilentlyContinue'

New-Item -ItemType Directory -Force -Path "$WorkDir" | out-null

Write-Host "Downloading latest Elevate Client to $WorkDir"
Invoke-WebRequest $ElevateUrl -OutFile $WorkDir\elevate-uc.exe | out-null

Write-Host "Silently installing Elevate for current user"
Start-Process -Wait -FilePath "$WorkDir\elevate-uc.exe" -ArgumentList '/S','/currentuser' -passthru | out-null

$ElevateOutlook    = "C:\Users\$Env:UserName\AppData\Local\Programs\Elevate UC\OfficeIntegrationServer\ElevateOfficeIntegration.exe"

Write-Host "Enabling Outlook Integration"
Start-Process -Wait -FilePath "$ElevateOutlook" -ArgumentList '-silentinstall' -passthru | out-null


$RegistryPath      = 'HKCU:\Software\IM Providers'
$Name     	   = 'DefaultIMApp'
$Value    	   = 'DesktopCommunicator'

New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -Force | out-null
