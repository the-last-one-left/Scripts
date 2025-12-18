# SPOSecurityReport

A comprehensive SharePoint Online security and usage reporting tool designed for MSP environments. Generates detailed reports on site permissions, external sharing, and storage usage with professional HTML reports and CSV exports.

## Features

- **No App Registration Required** — Uses delegated authentication with interactive sign-in
- **Complete Site Coverage** — Scans Team Sites, Communication Sites, Classic Sites, Private Channels, and more
- **Permission Auditing** — Identifies Site Admins, Owners, Members, Visitors, and external users across all site types
- **External Sharing Detection** — Tenant-level and per-site sharing configuration analysis
- **Deep Library Analysis** — Optional scanning for sharing links, unique permissions, and folder size distribution
- **Visual Reports** — Branded HTML reports with interactive charts and collapsible sections
- **Export Options** — CSV files for each data category plus consolidated HTML report

## Requirements

### PowerShell Modules

The script will prompt to install missing modules automatically:

| Module | Minimum Version |
|--------|-----------------|
| Microsoft.Graph.Authentication | 2.0.0 |
| Microsoft.Graph.Sites | 2.0.0 |
| Microsoft.Graph.Users | 2.0.0 |
| Microsoft.Graph.Groups | 2.0.0 |
| Microsoft.Online.SharePoint.PowerShell | 16.0.0 |

### Permissions

Sign in with an account that has:

- **Global Administrator** or **SharePoint Administrator** role
- Access to the SharePoint Admin Center

### Microsoft Graph Scopes (Delegated)

- `Sites.Read.All`
- `User.Read.All`
- `Group.Read.All`
- `GroupMember.Read.All`

## Installation

1. Clone or download this repository
2. Open PowerShell as Administrator (for module installation)
3. Run the script — missing modules will be installed automatically

```powershell
.\SPOSecurityReport.ps1 -TenantName "contoso"
```

## Usage

### Basic Scan (Recommended)

Scans all SharePoint sites excluding OneDrive personal sites:

```powershell
.\SPOSecurityReport.ps1 -TenantName "contoso"
```

### Full Deep-Dive Report

Includes library-level sharing links, unique permissions, and folder sizes:

```powershell
.\SPOSecurityReport.ps1 -TenantName "contoso" -IncludeLibraryDeepDive -OutputPath "C:\Reports"
```

### Include OneDrive Sites

By default, OneDrive personal sites are excluded. To include them:

```powershell
.\SPOSecurityReport.ps1 -TenantName "contoso" -IncludeOneDrive
```

### Filter to Specific Sites

Process only sites matching a URL pattern:

```powershell
.\SPOSecurityReport.ps1 -TenantName "contoso" -SiteUrlFilter "*project*"
```

### Test Run with Limited Sites

Process only the first N sites (useful for testing):

```powershell
.\SPOSecurityReport.ps1 -TenantName "contoso" -MaxSites 5 -IncludeLibraryDeepDive
```

### Adjust Scan Depth

Control how deep the script scans folder hierarchies (1-10, default is 3):

```powershell
.\SPOSecurityReport.ps1 -TenantName "contoso" -IncludeLibraryDeepDive -MaxScanDepth 5
```

## Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `TenantName` | String | Yes | — | SharePoint tenant name (e.g., `contoso` for contoso.sharepoint.com) |
| `OutputPath` | String | No | Current directory | Directory for output files |
| `IncludeLibraryDeepDive` | Switch | No | False | Enable detailed library analysis |
| `SiteUrlFilter` | String | No | `*` | Filter sites by URL pattern (supports wildcards) |
| `IncludeOneDrive` | Switch | No | False | Include OneDrive personal sites in scan |
| `MaxSites` | Int | No | 0 (unlimited) | Maximum number of sites to process |
| `SkipTenantSettings` | Switch | No | False | Skip tenant-level settings collection |
| `MaxScanDepth` | Int | No | 3 | Folder depth for deep scanning (1-10) |

## Output Files

All output files are timestamped and saved to the specified output directory:

| File | Description |
|------|-------------|
| `SPO_Sites_[timestamp].csv` | Site inventory with storage and sharing settings |
| `SPO_SiteMembers_[timestamp].csv` | All site users with roles and group memberships |
| `SPO_Libraries_[timestamp].csv` | Document libraries with item counts and sizes |
| `SPO_SharingLinks_[timestamp].csv` | External sharing links (deep-dive only) |
| `SPO_UniquePermissions_[timestamp].csv` | Items with broken inheritance (deep-dive only) |
| `SPO_FolderSizes_[timestamp].csv` | Folder size distribution (deep-dive only) |
| `SPO_SecurityReport_[timestamp].html` | Consolidated HTML report with charts |

## Report Contents

### Executive Summary

- Total sites scanned
- Storage usage overview
- External sharing risk assessment
- Sites with risky sharing configurations

### Site Inventory

- Site URL, title, and template type
- Storage used and quota
- External sharing capability
- Owner and member counts

### Site Permissions

- Complete user listing per site
- Role identification (Site Admin, Owner, Member, Visitor)
- External user flagging
- Group memberships

### External Sharing Analysis

- Tenant-level sharing policies
- Per-site sharing overrides
- Anonymous link detection
- Guest access configuration

### Deep-Dive Analysis (Optional)

- **Sharing Links** — All sharing links with scope, type, and expiration
- **Unique Permissions** — Items with broken permission inheritance
- **Folder Sizes** — Storage distribution across folder hierarchy

## Security Considerations

- The script uses delegated authentication — no credentials are stored
- Read-only operations — no changes are made to SharePoint
- All data remains local — nothing is transmitted externally
- Session tokens are cleared on completion

## Performance Notes

- **Basic scan**: ~2-5 seconds per site
- **Deep-dive scan**: ~30-60 seconds per site (varies with library size)
- Use `MaxSites` parameter to test on a subset first
- Use `MaxScanDepth` to balance thoroughness vs. speed
- OneDrive sites are excluded by default to reduce scan time

## Troubleshooting

### "Access Denied" for Some Sites

This is normal for sites with restricted permissions. The script will continue and note these in the errors section.

### Module Installation Fails

Run PowerShell as Administrator and ensure you have internet access for the PowerShell Gallery.

### Slow Performance on Large Tenants

- Use `-MaxSites` to limit initial scans
- Reduce `-MaxScanDepth` value
- Run without `-IncludeLibraryDeepDive` for faster basic inventory

### Connection Timeouts

The script handles pagination automatically. For very large tenants, consider filtering by site URL pattern.

## License

MIT License — See [LICENSE](LICENSE) for details.

## Author

**Pacific Office Automation** — Escalations Team

*Problem Solved*
