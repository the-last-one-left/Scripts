# SharePoint Site Permissions Auditor

## Overview
Comprehensive PowerShell script that audits and exports SharePoint Online permissions for all sites, lists, libraries, and folders within a Microsoft 365 tenant using PnP.PowerShell.

## Purpose
Provides detailed permission reporting across entire SharePoint Online tenants for security audits, compliance requirements, and permission management. Identifies unique permissions at site, list, library, and folder levels.

## Requirements
- **PowerShell 7.0 or later** (enforced by script)
- PnP.PowerShell module (auto-installed if missing)
- SharePoint Administrator or Global Administrator permissions
- Microsoft 365 tenant with SharePoint Online

## Features
- Interactive URL and path configuration via GUI dialogs
- Automatic PowerShell version validation
- Automatic PnP.PowerShell module installation
- Tenant-wide site collection enumeration
- Recursive sub-site scanning
- Folder-level permission detection
- Unique permission identification
- SharePoint group membership expansion
- CSV export per site collection
- Excludes system sites automatically

## Usage
```powershell
.\SharepointSitePermissions-PNPOnline.ps1
```

## Initial Prompts
Script will request:
1. **Tenant Admin URL** (e.g., `https://contoso-admin.sharepoint.com/`)
2. **Report Root Directory** (where CSV files will be saved)

Both prompts use GUI dialogs for easy input.

## Authentication
- Uses modern authentication (`-Interactive` parameter)
- Two connection stages:
  1. SharePoint Admin Center (for site discovery)
  2. Individual site connections (for permission auditing)

## Excluded Site Templates
The script automatically excludes system/special-purpose sites:
- SRCHCEN#0 (Search Center)
- REDIRECTSITE#0 (Redirect Sites)
- SPSMSITEHOST#0 (SharePoint Home)
- APPCATALOG#0 (App Catalog)
- POINTPUBLISHINGHUB#0 (Publishing Hub)
- EDISC#0 (eDiscovery Center)
- STS#-1 (System/Hidden Sites)

## Excluded Lists and Libraries
The script automatically skips system libraries:
- Access Requests, App Packages, Apps in Testing
- Cache Profiles, Composed Looks, Device Channels
- Form Templates, Master Page Gallery, Site Assets
- Style Library, Theme Gallery, User Information List
- Web Part Gallery, Workflow History, Workflow Tasks
- All hidden lists

## Output Format

### CSV File Naming
`<TenantURL_SiteURL>.CSV`  
Example: `contoso.sharepoint.com_sites_Finance.CSV`

### CSV Columns
- **Object**: Type (Site Collection/Site/List/Folder)
- **Title**: Display name of the object
- **URL**: Full URL to the object
- **HasUniquePermissions**: True/False
- **Users**: Semicolon-separated list of users
- **Type**: Permission type (User/SharePointGroup/SecurityGroup)
- **Permissions**: Permission levels (Read; Contribute; Full Control, etc.)
- **GrantedThrough**: How permission was granted (Direct/Group)

### SharePoint Group Handling
When permissions are granted through SharePoint groups:
- Group membership is expanded
- Individual users listed in "Users" column
- Group name shown in "GrantedThrough" column
- System Account users are filtered out
- Empty groups are skipped

## Permission Types Detected
- **Site Collection Administrators**: Always listed with "Site Owner" permission
- **Direct Permissions**: Permissions assigned directly to users/groups
- **SharePoint Group Permissions**: Permissions via group membership
- **Inherited Permissions**: Can be included via `-IncludeInheritedPermissions` switch

## Scanning Options

### Standard Scan (Default)
- Scans sites and lists
- Reports only unique permissions
- Skips inherited permissions

### Full Scan Options
Modify the `Generate-PnPSitePermissionRpt` call to include:
- `-Recursive`: Include all sub-sites
- `-ScanFolders`: Scan folder-level permissions
- `-IncludeInheritedPermissions`: Report all permissions, not just unique

Current configuration uses:
```powershell
Generate-PnPSitePermissionRpt -SiteURL $Site.URL -ReportFile $ReportFile -Recursive -ScanFolders
```

## Performance Considerations
- Large tenants with many sites will take significant time
- Each site requires separate connection
- Folder scanning adds substantial processing time
- Consider running during off-hours for production tenants

### Expected Durations
- Small tenant (10 sites): 5-10 minutes
- Medium tenant (50 sites): 30-60 minutes
- Large tenant (200+ sites): 2-4 hours
- Enterprise tenant (1000+ sites): Plan for extended runtime

## Progress Indicators
The script provides real-time progress:
- Console messages for each site being processed
- Progress bars for list and folder enumeration
- Item counters during folder scanning

## Common Use Cases
- Security audit preparation
- Compliance reporting (SOX, HIPAA, etc.)
- Permission cleanup planning
- External sharing analysis
- Data migration preparation
- Access review processes
- Identifying stale permissions

## Troubleshooting

### PowerShell Version Error
Script requires PowerShell 7+:
```powershell
# Check version
$PSVersionTable.PSVersion

# Install PowerShell 7
winget install Microsoft.PowerShell
```

### Module Installation Fails
- Ensure internet connectivity
- Run PowerShell as Administrator
- Check execution policy: `Set-ExecutionPolicy RemoteSigned`

### Authentication Failures
- Verify SharePoint Admin permissions
- Check for Conditional Access policies blocking PowerShell
- Ensure account is not MFA-blocked
- Try alternate admin account

### "Limited Access" Permissions
Filtered out automatically - these are system-managed permissions and don't represent actual access.

### Long Runtime
For large tenants:
- Run in stages using filtered site lists
- Exclude `-ScanFolders` for faster scanning
- Consider targeting specific site collections

## Security Notes
- CSV files contain sensitive access control information
- Store reports securely
- Restrict access to output directory
- Consider encryption for reports
- Follow data retention policies

## Limitations
- Does not show permission inheritance chains
- Cannot detect permissions from external systems
- Group nesting shown as flat membership list
- No change tracking (snapshot only)
- System accounts appear in some lists

## Recommended Post-Processing
After generating reports:
1. Import CSVs into Excel/Power BI for analysis
2. Filter for "HasUniquePermissions = TRUE" to find broken inheritance
3. Identify external users (contains #ext#)
4. Look for deprecated users (deleted accounts still in groups)
5. Find broad "Everyone" or "All Users" permissions
6. Review folder-level unique permissions for data leakage

## Best Practices
- Run regularly (quarterly recommended)
- Compare against previous reports
- Document permission standards
- Create remediation plan for findings
- Schedule during maintenance windows
- Retain reports for compliance periods

## Module Updates
PnP.PowerShell updates frequently. To update:
```powershell
Update-Module PnP.PowerShell -Force
```

## Author
Pacific Office Automation - Problem Solved

## Version History
- Current: PowerShell 7+ required, modern authentication
- Legacy versions used older PnP modules and PowerShell 5.1
