# Server Discovery & Diagnostics

## Overview
Collection of PowerShell scripts for Windows Server troubleshooting and Microsoft 365 tenant assessment.

## Scripts Included
1. **ServerDisco.ps1** - Server health and diagnostic checks
2. **TBR-Export.ps1** - Comprehensive Microsoft 365 tenant baseline report

---

# ServerDisco.ps1

## Purpose
Interactive diagnostic script for Windows Servers experiencing issues. Performs common health checks including service status, firewall profile, disk space, event logs, and DNS configuration.

## Features
- Service status check (identifies auto-start services that aren't running)
- Optional service restart functionality
- Firewall profile detection with Public profile warning
- Disk space calculation for all drives
- Recent event log error review (Application and System)
- DNS server configuration display

## Usage
```powershell
.\ServerDisco.ps1
```

## Diagnostic Checks Performed

### 1. Service Status
- Lists auto-start services that are currently stopped
- Excludes: WaaSMedicSvc, NPSMSvc*
- Offers option to attempt starting stopped services
- Useful for identifying service failures after updates or reboots

### 2. Firewall Profile Detection
- Checks active firewall profile (Domain/Private/Public)
- **Warning**: Public profile often indicates DNS or Network Location Awareness issues
- Common cause of connectivity problems in domain environments

### 3. Disk Space Analysis
- Displays all logical disks
- Shows total size and free space in GB
- Quick identification of storage capacity issues

### 4. Event Log Review
- Last 10 Application errors
- Last 10 System errors
- Includes Source, EventID, and Message
- Helps identify recent system issues

### 5. DNS Configuration
- Lists DNS servers for all IPv4 adapters
- Only shows adapters with configured DNS
- Useful for identifying DNS misconfiguration

## Common Issues Detected

### Public Firewall Profile
If the server shows Public profile:
- Check DNS server settings
- Verify domain connectivity
- Restart Network Location Awareness service
- Check network adapter configuration
- Review domain controller accessibility

### Stopped Auto-Start Services
Common scenarios:
- Service dependencies failed
- Service crashed after update
- Permissions issues
- Corrupted service configuration

## Requirements
- Windows Server OS
- PowerShell 5.0 or later
- Administrative privileges recommended
- Must be run locally on the server

## Limitations
- Does not modify system configuration (except optional service starts)
- Event log review limited to 10 most recent errors
- No automatic remediation beyond service restart

## Use Cases
- Initial server health assessment
- Troubleshooting RDP connectivity issues
- Post-reboot verification
- Network connectivity diagnostics
- Pre-patch health validation

---

# TBR-Export.ps1

## Purpose
Comprehensive Microsoft 365 tenant baseline report generator. Exports user data, license information, MFA status, and security configuration to CSV files for assessment and documentation.

**Note**: Script is flagged as "still in development" but includes full functionality.

## Features
- Automated module installation and validation
- User account export with license and MFA details
- License consumption reporting
- Security Defaults status check
- Azure AD Premium license detection
- Dual MFA detection (per-user and Conditional Access)

## Requirements
- PowerShell 5.0 or later
- Administrator rights (for module installation)
- Microsoft 365 Global Admin permissions
- Required Modules (auto-installed if missing):
  - MSOnline
  - ExchangeOnlineManagement
  - AzureADPreview

## Usage
```powershell
.\TBR-Export.ps1
```

## Module Installation
Script automatically checks for required modules:
- Prompts for installation if missing
- Uninstalls conflicting AzureAD module before installing AzureADPreview
- Validates installation success
- **Must run as Administrator for module installation**

## Authentication
Requires three separate connections:
1. Exchange Online (`Connect-ExchangeOnline`)
2. MSOnline Service (`Connect-MsolService`)
3. Azure AD (`Connect-AzureAD`)

Interactive authentication prompts appear for each service.

## Output Files

### Office365UserData.csv
Includes per-user details:
- **First Name**
- **Last Name**
- **Email** (UserPrincipalName)
- **Licenses Applied** (comma-separated list)
- **Last Password Change**
- **User Type** (Member/Guest)
- **Per User MFA Enabled** (Enabled/Enforced/Disabled)
- **Conditional Access MFA Enabled** (True/False)
- **Strong Authentication Methods** (SMS/Phone/App)
- **Is Sign In Blocked** (True/False)

### Office365LicenseData.csv
License consumption summary:
- **License Name** (SKU ID)
- **Total Licenses**
- **Licenses In Use**

### Console Output
Blinking messages display:
- Security Defaults status (Enabled/Disabled)
- Azure AD license level (None/P1/P2)

## Technical Details

### MFA Detection
- **Per-User MFA**: Checks `StrongAuthenticationRequirements.State`
- **Conditional Access MFA**: Checks for Conditional Access policies
- **Authentication Methods**: Lists configured methods (SMS, Phone App, etc.)

### Security Assessment
- Security Defaults status from Azure AD directory settings
- Azure AD Premium license detection (P1/P2)
- Helps determine available security features

## Common Issues

### Module Conflicts
**AzureAD vs AzureADPreview**: Script automatically removes AzureAD module if AzureADPreview installation is needed. These modules conflict.

### Legacy Authentication
- Uses MSOnline and legacy authentication methods
- May fail if legacy authentication is disabled in tenant
- Consider Conditional Access policies that block PowerShell

### Permission Issues
Requires Global Admin or equivalent permissions:
- User Administrator
- Exchange Administrator
- Security Administrator (for Conditional Access check)

## Use Cases
- Tenant security assessment
- Pre-migration baseline documentation
- MFA rollout planning
- License optimization analysis
- Compliance auditing
- Security posture review

## Module Deprecation Notice
**MSOnline** and **AzureADPreview** modules are deprecated. Microsoft recommends Microsoft Graph PowerShell SDK for new implementations. This script maintains legacy modules for compatibility with existing MSP workflows.

## Recommended Analysis
After export, review for:
1. Users without MFA enabled
2. Over-licensed/under-licensed accounts
3. Blocked accounts that should be removed
4. Guest accounts without MFA
5. Shared mailboxes with licenses
6. Security Defaults disabled without Conditional Access policies

## Author
Compiled by Zachary Child  
Pacific Office Automation - Problem Solved

Credits: Blink-Message function courtesy of Joshua Honig

---

## Support
For issues or questions, contact: TBR-Script@awesomazing.com
