# Get MFA Status - Microsoft 365

## Overview
PowerShell script that audits Multi-Factor Authentication (MFA) status for all users in a Microsoft 365 tenant and exports results to CSV.

## Purpose
Provides comprehensive MFA compliance reporting for Microsoft 365 environments, helping administrators identify users without MFA enabled and support security audits.

## Requirements
- PowerShell 5.0 or later
- MSOnline PowerShell module
- Microsoft 365 Global Admin or User Admin permissions
- Internet connectivity to Microsoft 365

## Features
- Automatic module installation check and installation
- MFA status detection for all users
- Tenant domain auto-detection for file naming
- CSV export to standardized location
- Visual blinking message notifications
- Displays BlockCredential status alongside MFA status

## Prerequisites
Run PowerShell as Administrator if MSOnline module needs to be installed.

## Usage
```powershell
.\Get-MFA-Status.ps1
```

## Installation Process
If MSOnline module is not installed:
1. Script detects missing module
2. Prompts for installation
3. Installs module (requires admin rights)
4. Validates installation success

## Authentication
- Interactive authentication to Microsoft 365
- Uses `Connect-MsolService` (legacy authentication)
- Requires Global Admin or User Admin role

## Output
CSV file saved to: `C:\Temp\<TenantDomain>-Users.csv`

### CSV Columns
- **DisplayName**: User's display name
- **BlockCredential**: Whether sign-in is blocked (True/False)
- **UserPrincipalName**: User's email/UPN
- **MFA Status**: Current MFA state (Enabled/Enforced/Disabled)

## MFA Status Values
- **Enabled**: MFA is enabled but not enforced (user prompted during sign-in)
- **Enforced**: MFA is required for all sign-ins
- **Disabled**: MFA is not configured (shown as "Disabled" in output)

## Technical Details
- Retrieves all users with `Get-MsolUser -All`
- Checks `StrongAuthenticationRequirements.State` property
- Auto-detects tenant domain using `Get-MsolDomain`
- Suppresses progress bars and warnings for cleaner execution

## Output Location
The script creates output in: `C:\Temp\`

Ensure this directory exists or the script will fail. Consider modifying the path for different output locations.

## Common Issues

### Module Installation Failures
- Must run PowerShell as Administrator
- Requires internet connectivity
- May need to set execution policy: `Set-ExecutionPolicy RemoteSigned`

### Authentication Issues
- Verify account has appropriate admin permissions
- Check for Conditional Access policies blocking PowerShell access
- Legacy authentication may be disabled in tenant

### MSOnline Module Deprecation
**Important**: MSOnline module is deprecated. Consider migrating to Microsoft Graph PowerShell for future-proofing. This script uses MSOnline for compatibility with existing environments.

## Use Cases
- MFA compliance auditing
- Security assessment preparation
- Identifying users without MFA before enforcement
- Documenting current security posture
- Pre-migration MFA status baseline

## Limitations
- Uses legacy MSOnline module (deprecated)
- Checks per-user MFA only (not Conditional Access MFA)
- Requires admin credentials
- No Conditional Access policy detection

## Recommended Follow-Up
After running this script:
1. Review users with "Disabled" MFA status
2. Plan MFA rollout for identified users
3. Consider Conditional Access policies for modern MFA enforcement
4. Document exceptions for accounts that cannot use MFA

## Author
Pacific Office Automation - Problem Solved

Credits: Blink-Message function courtesy of Joshua Honig
