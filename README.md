# Microsoft 365 Security Analysis Tool

**Version:** 10.2  
**Author:** Zachary Child (Pacific Office Automation)  
**Enhanced By:** Claude (Anthropic AI)

## Overview

Comprehensive security analysis tool for Microsoft 365 tenants that detects compromised accounts, identifies security threats, and analyzes suspicious activity patterns using Microsoft Graph PowerShell APIs.

## Key Features

### Data Collection
- **Sign-in Logs**: Geolocation analysis with IPv4/IPv6 support, unusual location detection
- **Admin Audit Logs**: High-risk operation monitoring and risk assessment
- **Inbox Rules**: Forwarding, deletion, and suspicious pattern detection
- **Mailbox Delegations**: External delegate and high-privilege access identification
- **App Registrations**: High-privilege permission and configuration analysis
- **Conditional Access**: Policy configuration review and risk assessment
- **Message Traces**: Exchange Online message trace with spam pattern analysis
- **MFA Status**: Comprehensive multi-factor authentication audit
- **Failed Login Patterns**: Password spray, brute force, and breach detection
- **Password Changes**: Suspicious password reset pattern analysis

### Analysis & Detection
- Risk-based user scoring (Critical/High/Medium/Low)
- Unusual location detection with high-risk ISP identification
- Spam pattern analysis with configurable thresholds
- HTML report generation with dark mode support
- Attack pattern correlation across data sources

### User Interface
- Modern GUI with Pacific Office branding
- Dark/Light theme support
- Real-time progress tracking
- Connection status monitoring
- Batch operations support

## Requirements

### Software Requirements
- **PowerShell:** 5.1 or later
- **Operating System:** Windows 10/11 or Windows Server 2016+

### PowerShell Modules (Auto-installed)
- `Microsoft.Graph.Authentication`
- `Microsoft.Graph.Users`
- `Microsoft.Graph.Reports`
- `Microsoft.Graph.Beta.Reports`
- `Microsoft.Graph.Identity.DirectoryManagement`
- `Microsoft.Graph.Applications`
- `ExchangeOnlineManagement`

### Permissions Required
**Minimum (Recommended):**
- Security Reader
- Exchange Administrator

**Alternative (Full Access):**
- Global Administrator
- Security Administrator

### Microsoft Graph API Scopes
- `User.Read.All`
- `AuditLog.Read.All`
- `Directory.Read.All`
- `Mail.Read`
- `MailboxSettings.Read`
- `Mail.ReadWrite`
- `MailboxSettings.ReadWrite`
- `SecurityEvents.Read.All`
- `IdentityRiskEvent.Read.All`
- `IdentityRiskyUser.Read.All`
- `Application.Read.All`
- `RoleManagement.Read.All`
- `Policy.Read.All`
- `UserAuthenticationMethod.Read.All`

## Installation

1. **Download the script:**
   ```powershell
   # Clone from GitHub
   git clone https://github.com/the-last-one-left/Scripts.git
   cd Scripts
   ```

2. **Ensure execution policy allows script execution:**
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

3. **Run the script:**
   ```powershell
   .\CompromisedDiscovery-Graph.ps1
   ```

4. **Module installation:** The script will automatically prompt to install missing modules on first run.

## Usage

### Quick Start

1. **Launch the tool:**
   ```powershell
   .\CompromisedDiscovery-Graph.ps1
   ```

2. **Connect to Microsoft 365:**
   - Click "🔌 Connect to Microsoft Graph"
   - Sign in with admin credentials
   - Select appropriate tenant if multiple are available

3. **Run data collection:**
   - **Individual collections:** Click specific data collection buttons
   - **Comprehensive analysis:** Click "🚀 Run All Data Collection"

4. **Generate report:**
   - Click "🔎 Analyze Data"
   - View generated HTML report

### Configuration Options

**Working Directory:**
- Default: `C:\Temp\`
- Automatically creates tenant-specific subdirectories
- Format: `C:\Temp\<TenantName>\<Timestamp>\`

**Date Range:**
- Default: 14 days
- Range: 1-365 days
- Exchange message trace limited to 10 days

**Risk Scoring Weights:**
Configured in `$ConfigData.ETRAnalysis.RiskWeights`:
- RiskyIPMatch: 25 points
- ExcessiveVolume: 20 points
- SpamKeywords: 15 points
- MassDistribution: 15 points
- FailedDelivery: 10 points

### Data Collection Functions

| Function | Description | Output File |
|----------|-------------|-------------|
| **Sign-In Data** | Sign-in logs with geolocation | `UserLocationData.csv` |
| **Admin Audits** | Admin audit logs with risk scoring | `AdminAuditLogs_HighRisk.csv` |
| **Inbox Rules** | Mailbox forwarding and deletion rules | `InboxRules.csv` |
| **MFA Status** | Multi-factor authentication status | `MFAStatus.csv` |
| **Failed Logins** | Attack pattern detection | `FailedLoginAnalysis.csv` |
| **Password Changes** | Suspicious reset patterns | `PasswordChangeAnalysis.csv` |
| **Delegations** | Mailbox delegation permissions | `MailboxDelegation.csv` |
| **App Registrations** | Application registration analysis | `AppRegistrations.csv` |
| **Conditional Access** | CA policy review | `ConditionalAccess.csv` |
| **Message Trace** | Exchange message trace | `MessageTraceResult.csv` |
| **ETR Analysis** | Spam pattern analysis | `ETRSpamAnalysis.csv` |

## Output Files

### Primary Outputs
- **SecurityReport.html**: Comprehensive HTML report with dark mode
- **SecurityReport.csv**: User risk summary in CSV format

### Specialized Reports
- `*_Unusual.csv`: Unusual location sign-ins
- `*_Failed.csv`: Failed operations
- `*_Suspicious.csv`: Suspicious patterns
- `*_HighRisk.csv`: High-risk findings
- `*_Critical.csv`: Critical security issues

### Report Features
- Risk-based color coding
- Collapsible user details
- MFA status indicators
- High-risk ISP highlighting
- Attack pattern visualization
- Recommendation sections

## Risk Scoring

### Score Ranges
- **Critical (50+)**: Immediate action required
- **High (30-49)**: Urgent review needed
- **Medium (15-29)**: Investigation recommended
- **Low (0-14)**: Routine monitoring

### Risk Factors
| Factor | Points | Description |
|--------|--------|-------------|
| No MFA | 40 | Account without multi-factor authentication |
| Confirmed Breach | 50 | 5+ failed logins then success from same IP |
| High-Risk ISP | 25 | VPN/Hosting/Datacenter provider |
| Suspicious Rules | 15 | Email forwarding or deletion rules |
| Password Spray | 30 | Same IP, multiple users attacked |
| Admin Without MFA | 10 | Additional risk for privileged accounts |

## Key Security Detections

### Attack Patterns
1. **Password Spray**: Same IP attempting multiple user accounts
2. **Brute Force**: Multiple failed attempts on same user
3. **Successful Breach**: Failed attempts followed by success from same IP
4. **High-Risk ISP**: Connections from VPN/hosting providers
5. **Suspicious Rules**: Email forwarding to external domains
6. **Rapid Password Changes**: Multiple resets in short timeframe

### Unusual Activity
- Sign-ins from unexpected countries
- Off-hours administrative changes
- Multiple authentication initiators
- High-privilege permission grants
- Spam keyword detection in subjects

## Troubleshooting

### Common Issues

**"Premium license required" Error:**
- Script automatically falls back to Exchange Online (10-day limit)
- Consider upgrading to Azure AD Premium P1/P2 for full features

**Connection Failures:**
- Verify internet connectivity
- Check firewall/proxy settings
- Ensure correct admin permissions
- Complete MFA challenges

**Slow Performance:**
- Reduce date range (default: 14 days)
- Increase batch size in configuration
- Filter inactive users (enabled by default)

**Exchange Online Issues:**
- Verify Exchange Administrator role
- Check for active Exchange Online sessions
- Script automatically retries connection

### Log Files
- Located in working directory
- Format: `ScriptLog_YYYYMMDD_HHmmss.log`
- Contains detailed execution trace

## Best Practices

### Security
1. **Always enable MFA** for admin accounts before analysis
2. **Review Critical risks immediately** (within 24 hours)
3. **Investigate High-Risk ISP connections** with users
4. **Disable suspicious inbox rules** during investigation
5. **Reset passwords** for confirmed breach accounts

### Operational
1. **Run weekly** for proactive monitoring
2. **Archive reports** for compliance
3. **Customize expected countries** for your organization
4. **Adjust date range** based on tenant size
5. **Use tenant-specific directories** for organization

### Performance Optimization
```powershell
# Configuration adjustments in script
$ConfigData.DateRange = 7              # Reduce for faster processing
$ConfigData.BatchSize = 1000           # Increase for larger tenants
$ConfigData.CacheTimeout = 3600        # Geolocation cache duration
```

## Limitations

### Data Retention
- **Sign-in logs**: 30 days (Azure AD Free), longer with Premium
- **Admin audits**: 90 days (most organizations)
- **Message trace**: 10 days (Exchange Online limit)

### API Throttling
- Microsoft Graph: Automatic retry with backoff
- Exchange Online: Rate limiting applied
- Geolocation: Cached results to reduce API calls

### Tenant Requirements
- **Azure AD Free**: Limited sign-in data, Exchange fallback supported
- **Azure AD Premium**: Full feature access, longer retention

## Version History

### Version 10.2 (Current)
- Enhanced IPv6 support with private range detection
- High-risk ISP identification (VPN/Hosting providers)
- MFA status audit with beta API integration
- Failed login pattern analysis (spray/brute force/breach)
- Password change anomaly detection
- Dark/Light theme GUI with Pacific Office branding
- Improved geolocation with caching
- Exchange Online fallback for non-premium tenants

### Earlier Versions
- See [CHANGELOG.md](CHANGELOG.md) for detailed version history

## Copyright & Licensing

**© Pacific Office Automation - Proprietary Tool**

⚠️ **AUTHORIZED USE ONLY** ⚠️

This tool is proprietary to Pacific Office Automation. Unauthorized use, distribution, or modification is strictly prohibited. For licensing inquiries, contact [zachary.child@pacificoffice.com](mailto:zachary.child@pacificoffice.com).

## Credits

**Original Development:**  
Zachary Child - Pacific Office Automation

**AI Enhancement:**  
Claude (Anthropic AI) - Code organization, documentation, error handling, performance optimization

## Support

For issues, questions, or feature requests:
- **GitHub Issues**: [https://github.com/the-last-one-left/Scripts/issues](https://github.com/the-last-one-left/Scripts/issues)
- **Email**: zachary.child@pacificoffice.com
- **Internal Support**: Pacific Office Automation escalations team

## Additional Resources

### Microsoft Documentation
- [Microsoft Graph API](https://docs.microsoft.com/en-us/graph/)
- [Azure AD Sign-in Logs](https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/)
- [Exchange Online PowerShell](https://docs.microsoft.com/en-us/powershell/exchange/exchange-online-powershell)

### Security Best Practices
- [Microsoft 365 Security Best Practices](https://docs.microsoft.com/en-us/microsoft-365/security/)
- [Azure AD Security Operations Guide](https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/security-operations-introduction)

---

**Last Updated:** 2025-01-25  
**Script Version:** 10.2  
**Documentation Version:** 1.0
