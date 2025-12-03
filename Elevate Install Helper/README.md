# Elevate UC Client Installer

## Overview
Automated installation script for Elevate UC (Unified Communications) client with Outlook integration. Downloads the latest version, performs a silent installation for the current user, and enables Outlook integration.

## Purpose
Streamlines deployment of Elevate UC client in enterprise environments by automating the download, installation, and Outlook integration configuration process.

## Requirements
- Windows operating system
- Internet connectivity to reach cp.serverdata.net
- Appropriate permissions to install software for current user
- Outlook installed (for integration features)

## Features
- Downloads latest Elevate UC client from official source
- Silent installation for current user (no GUI prompts)
- Automatic Outlook integration setup
- Sets Elevate as default IM provider via registry modification
- Creates temporary working directory automatically

## Usage
```powershell
.\Elevate - End User.ps1
```

## Technical Details
- **Download URL**: https://cp.serverdata.net/voice/pbx/softphonereleases/default/latest-win/elevate-uc.exe
- **Installation Path**: `%LOCALAPPDATA%\Programs\Elevate UC\`
- **Working Directory**: `C:\Temp`
- **Registry Modification**: Sets `HKCU:\Software\IM Providers\DefaultIMApp` to `DesktopCommunicator`

## Installation Process
1. Creates `C:\Temp` directory if it doesn't exist
2. Downloads latest Elevate UC executable
3. Installs silently for current user
4. Executes Outlook integration installer
5. Configures registry for default IM provider

## Notes
- Script suppresses progress indicators for cleaner execution
- All installation output is suppressed using `out-null`
- Installation is user-specific, not system-wide
- No reboot required

## Troubleshooting
- Ensure network access to cp.serverdata.net
- Verify user has permission to write to C:\Temp
- Check if Outlook is installed before running
- Review Event Viewer for installation errors if issues occur

## Author
Pacific Office Automation - Problem Solved
