#################################################################
#
#  Microsoft 365 Security Analysis Tool - Enhanced Edition
#  
#  PURPOSE:
#  Comprehensive security analysis tool for Microsoft 365 tenants
#  using Microsoft Graph PowerShell to identify compromised users,
#  detect security threats, and analyze suspicious activity patterns.
#
#  CAPABILITIES:
#  ┌─────────────────────────────────────────────────────────────┐
#  │ DATA COLLECTION                                             │
#  ├─────────────────────────────────────────────────────────────┤
#  │ • Sign-in logs with geolocation analysis                    │
#  │ • Admin audit logs with risk assessment                     │
#  │ • Inbox rules (forwarding, deletion, suspicious patterns)   │
#  │ • Mailbox delegations                                       │
#  │ • App registrations and service principals                  │
#  │ • Conditional Access policies                               │
#  │ • Exchange message traces (ETR format)                      │
#  └─────────────────────────────────────────────────────────────┘
#
#  ┌─────────────────────────────────────────────────────────────┐
#  │ ANALYSIS & DETECTION                                        │
#  ├─────────────────────────────────────────────────────────────┤
#  │ • Unusual location detection                                │
#  │ • Spam pattern analysis with risk scoring                   │
#  │ • High-risk operation monitoring                            │
#  │ • Suspicious rule detection                                 │
#  │ • Risk-based user scoring                                   │
#  │ • HTML report generation with detailed findings             │
#  └─────────────────────────────────────────────────────────────┘
#
#  REQUIREMENTS:
#  • PowerShell 5.1 or later
#  • Microsoft.Graph.* modules (auto-installed if missing)
#  • ExchangeOnlineManagement module (auto-installed if missing)
#  • Administrative permissions in Microsoft 365 tenant:
#    - Global Administrator, Security Administrator, or
#    - Security Reader + Exchange Administrator (recommended minimum)
#
#  AUTHOR:
#  Zachary Child (zachary.child@pacificoffice.com)
#  
#  ENHANCED BY:
#  Claude (Anthropic AI) - Code organization, documentation,
#  error handling, performance optimization
#  
#  COPYRIGHT & LICENSING:
#  © Pacific Office Automation - Proprietary Tool
#  
#  ⚠️  AUTHORIZED USE ONLY ⚠️
#  This tool is proprietary to Pacific Office Automation.
#  Authorized for use by Pacific Office Automation employees only.
#  Unauthorized use, distribution, or modification is strictly prohibited.
#
#
#################################################################

#region SCRIPT CONFIGURATION AND INITIALIZATION

#──────────────────────────────────────────────────────────────
# SCRIPT VERSION
#──────────────────────────────────────────────────────────────
# Update this version number when making significant changes
# Format: Major.Minor (e.g., 8.2)
$ScriptVer = "9.2"

#──────────────────────────────────────────────────────────────
# GLOBAL CONNECTION STATE
#──────────────────────────────────────────────────────────────
# Tracks the current Microsoft Graph connection status
# This is updated throughout the script lifecycle to maintain
# connection awareness and enable proper cleanup
$Global:ConnectionState = @{
    IsConnected  = $false       # Is currently connected to Graph
    TenantId     = $null        # Microsoft 365 Tenant ID (GUID)
    TenantName   = $null        # Tenant display name
    Account      = $null        # Connected user account (UPN)
    ConnectedAt  = $null        # Connection timestamp
}

#──────────────────────────────────────────────────────────────
# EXCHANGE ONLINE CONNECTION STATE
#──────────────────────────────────────────────────────────────
# Separate tracking for Exchange Online connections
# Exchange Online uses different authentication than Graph
$Global:ExchangeOnlineState = @{
    IsConnected       = $false  # Is currently connected to EXO
    LastChecked       = $null   # Last connection verification time
    ConnectionAttempts = 0      # Number of connection attempts (for retry logic)
}

#──────────────────────────────────────────────────────────────
# MAIN CONFIGURATION DATA STRUCTURE
#──────────────────────────────────────────────────────────────
# Centralized configuration for all script operations
# Modify these values to customize behavior
$ConfigData = @{
    
    #───────────────────────────────────────────────────────────
    # File System Configuration
    #───────────────────────────────────────────────────────────
    
    # Working directory for logs and output files
    # During tenant connection, a tenant-specific subdirectory
    # will be created (e.g., C:\Temp\ContosoTenant\120320250125\)
    WorkDir = "C:\Temp\"
    
    #───────────────────────────────────────────────────────────
    # Data Collection Configuration
    #───────────────────────────────────────────────────────────
    
    # Default date range for data collection (days to look back)
    # Valid range: 1-365 days
    # Note: Larger values significantly increase processing time
    # Exchange Online message trace limited to 10 days
    DateRange = 14
    
    #───────────────────────────────────────────────────────────
    # IP Geolocation Configuration
    #───────────────────────────────────────────────────────────
    
    # IPStack API key (Base64 encoded for basic obfuscation)
    # This is NOT secure encryption - just prevents plain text exposure
    # To update: [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("your-api-key"))
    IPStackAPIKey = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("5f8d47763f5761d29f9af71460d94cd5"))
    
    # Expected sign-in countries for unusual location detection
    # Customize this list based on your organization's geographic presence
    # Sign-ins from countries NOT in this list will be flagged as unusual
    ExpectedCountries = @("United States", "Canada")
    
    #───────────────────────────────────────────────────────────
    # Microsoft Graph API Configuration
    #───────────────────────────────────────────────────────────
    
    # Required Microsoft Graph API scopes for full functionality
    # These permissions will be requested during authentication
    RequiredScopes = @(
        "User.Read.All",                    # Read all user profiles
        "AuditLog.Read.All",                # Read audit logs and sign-in activity
        "Directory.Read.All",               # Read directory data (groups, roles, etc.)
        "Mail.Read",                        # Read user mail (for inbox rules)
        "MailboxSettings.Read",             # Read mailbox settings
        "Mail.ReadWrite",                   # Read and write mail (if needed)
        "MailboxSettings.ReadWrite",        # Read and write mailbox settings
        "SecurityEvents.Read.All",          # Read security events
        "IdentityRiskEvent.Read.All",       # Read identity risk events
        "IdentityRiskyUser.Read.All",       # Read risky user information
        "Application.Read.All",             # Read application registrations
        "RoleManagement.Read.All",          # Read role assignments
        "Policy.Read.All",                  # Read policies (Conditional Access, etc.)
		"UserAuthenticationMethod.Read.All" # Read MFA Status
    )
    
    #───────────────────────────────────────────────────────────
    # Security Monitoring Configuration
    #───────────────────────────────────────────────────────────
    
    # High-risk administrative operations to monitor
    # These operations will be flagged with high severity in audit analysis
    # Add additional operations as needed for your security requirements
    HighRiskOperations = @(
        "Add mailbox permission",           # Mailbox access grants
        "Remove mailbox permission",        # Mailbox access removal
        "Update mailbox",                   # Mailbox configuration changes
        "Add member to role",               # Role membership additions
        "Remove member from role",          # Role membership removals
        "Create application",               # New app registrations
        "Update application",               # App registration modifications
        "Create inbox rule",                # New inbox rules (potential data exfiltration)
        "Update transport rule"             # Mail flow rule changes
    )
    
    #───────────────────────────────────────────────────────────
    # Performance Optimization Settings
    #───────────────────────────────────────────────────────────
    
    # Number of records to process in each batch
    # Larger values = faster processing but more memory usage
    # Recommended range: 250-1000
    BatchSize = 500
    
    # Maximum concurrent IP geolocation lookups
    # Limited to prevent API rate limiting
    # Note: Currently not used (sequential processing for stability)
    MaxConcurrentGeolookups = 10
    
    # IP geolocation cache timeout in seconds
    # Cached results older than this will be re-queried
    # Default: 3600 seconds (1 hour)
    CacheTimeout = 3600
}

#──────────────────────────────────────────────────────────────
# ETR (EXCHANGE TRACE REPORT) ANALYSIS CONFIGURATION
#──────────────────────────────────────────────────────────────
# Settings for message trace analysis and spam pattern detection
$ConfigData.ETRAnalysis = @{
    
    #───────────────────────────────────────────────────────────
    # File Detection Patterns
    #───────────────────────────────────────────────────────────
    # Patterns used to automatically detect ETR/message trace files
    # in the working directory. Add custom patterns as needed.
    FilePatterns = @(
        "ETR_*.csv",                        # Standard ETR export format
        "MessageTrace_*.csv",               # Common message trace export
        "ExchangeTrace_*.csv",              # Alternative naming
        "MT_*.csv",                         # Abbreviated format
        "*MessageTrace*.csv",               # Catch-all for message trace
        "MessageTraceResult.csv"            # Direct export name
    )
    
    #───────────────────────────────────────────────────────────
    # Spam Detection Thresholds
    #───────────────────────────────────────────────────────────
    
    # Maximum messages with identical subject before flagging as spam
    # Recommended: 50-100 for large organizations
    MaxSameSubjectMessages = 50
    
    # Maximum same-subject messages per hour
    # Lower threshold for time-based detection
    MaxSameSubjectPerHour = 20
    
    # Maximum total messages per sender before flagging
    # Detects compromised accounts with high send volume
    MaxMessagesPerSender = 200
    
    # Minimum subject length for analysis
    # Very short subjects are often spam
    MinSubjectLength = 5
    
    #───────────────────────────────────────────────────────────
    # Spam Keyword Patterns
    #───────────────────────────────────────────────────────────
    # Keywords commonly found in spam messages
    # Customize based on your organization's spam patterns
    SpamKeywords = @(
        # Urgency tactics
        "urgent", "act now", "limited time", "expires today",
        
        # Common spam words
        "free", "winner", "congratulations", "prize",
        
        # Call-to-action phrases
        "click here", "order now", "special offer", "buy now",
        
        # Trust/guarantee language
        "guaranteed", "risk-free", "no obligation", "certified",
        
        # Financial spam
        "make money", "earn cash", "get rich", "double your income",
        "work from home", "financial freedom",
        
        # Cryptocurrency/investment spam
        "bitcoin", "cryptocurrency", "investment opportunity",
        "crypto trading", "forex"
    )
    
    #───────────────────────────────────────────────────────────
    # Risk Scoring Weights
    #───────────────────────────────────────────────────────────
    # Point values assigned to different risk indicators
    # Higher values = more severe risk factor
    # Total risk score determines overall threat level
    RiskWeights = @{
        RiskyIPMatch      = 25   # Messages from IPs flagged in sign-in analysis (highest risk)
        ExcessiveVolume   = 20   # High message volume from single sender
        SpamKeywords      = 15   # Spam keywords in message subjects
        MassDistribution  = 15   # Same message sent to many recipients
        FailedDelivery    = 10   # High rate of delivery failures (spam detection)
        SuspiciousTimiming = 8   # Unusual send time patterns
    }
}

#──────────────────────────────────────────────────────────────
# REQUIRED .NET ASSEMBLIES
#──────────────────────────────────────────────────────────────
# Load necessary .NET assemblies for GUI and functionality
# These are required before creating any Windows Forms controls
Write-Host "Loading required .NET assemblies..." -ForegroundColor Cyan
try {
    Add-Type -AssemblyName PresentationCore, PresentationFramework
    Add-Type -AssemblyName Microsoft.VisualBasic
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    Write-Host "✓ Assemblies loaded successfully" -ForegroundColor Green
}
catch {
    Write-Host "✗ Failed to load required assemblies: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "  The script may not function properly." -ForegroundColor Yellow
}

#──────────────────────────────────────────────────────────────
# GLOBAL GUI ELEMENT REFERENCES
#──────────────────────────────────────────────────────────────
# These variables store references to GUI elements for status updates
# Initialized to $null and populated when GUI is created
$Global:MainForm = $null            # Main application form
$Global:StatusLabel = $null         # Bottom status bar label
$Global:ConnectionLabel = $null     # Connection status label
$Global:TenantInfoLabel = $null     # Tenant information label
$Global:WorkDirLabel = $null        # Working directory display label
$Global:DateRangeLabel = $null      # Date range configuration label

#endregion

#region CORE HELPER FUNCTIONS

#══════════════════════════════════════════════════════════════
# INITIALIZATION AND ENVIRONMENT SETUP
#══════════════════════════════════════════════════════════════

function Initialize-Environment {
    <#
    .SYNOPSIS
        Initializes the script environment and working directory.
    
    .DESCRIPTION
        Performs initial setup tasks when the script starts:
        • Creates the working directory if it doesn't exist
        • Starts transcript logging for audit trail
        • Checks for existing Microsoft Graph connections
        • Validates directory permissions
        
        This function should be called once at script startup before
        any other operations are performed.
    
    .PARAMETER None
        This function does not accept parameters.
    
    .OUTPUTS
        None. Writes log messages to console and transcript.
    
    .EXAMPLE
        Initialize-Environment
        # Called at script startup to set up environment
    
    .NOTES
        - Creates transcript log with timestamp in filename
        - Uses existing Graph connection if available
        - Safe to call multiple times (idempotent)
    #>
    
    [CmdletBinding()]
    param()
    
    try {
        # Create working directory if it doesn't exist
        if (-not (Test-Path -Path $ConfigData.WorkDir)) {
            try {
                New-Item -Path $ConfigData.WorkDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
                Write-Log "Created working directory: $($ConfigData.WorkDir)" -Level "Info"
            }
            catch {
                Write-Log "Failed to create working directory: $($_.Exception.Message)" -Level "Error"
                throw "Cannot create working directory. Check permissions and path validity."
            }
        }
        else {
            Write-Log "Working directory exists: $($ConfigData.WorkDir)" -Level "Info"
        }

        # Start transcript logging for complete audit trail
        $logFile = Join-Path -Path $ConfigData.WorkDir -ChildPath "ScriptLog_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
        try {
            Start-Transcript -Path $logFile -Force -ErrorAction Stop
            Write-Log "Script initialization started. Version $ScriptVer" -Level "Info"
            Write-Log "Transcript logging to: $logFile" -Level "Info"
        }
        catch {
            # Non-fatal error - script can continue without transcript
            Write-Log "Warning: Failed to start transcript: $($_.Exception.Message)" -Level "Warning"
            Write-Log "Continuing without transcript logging" -Level "Warning"
        }
        
        # Check for existing Microsoft Graph connection
        # This allows resuming work without re-authenticating
        Write-Log "Checking for existing Microsoft Graph connection..." -Level "Info"
        $existingConnection = Test-ExistingGraphConnection
        
        if ($existingConnection) {
            Write-Log "Using existing Microsoft Graph connection" -Level "Info"
            Write-Log "Tenant: $($Global:ConnectionState.TenantName)" -Level "Info"
            Write-Log "Account: $($Global:ConnectionState.Account)" -Level "Info"
        }
        else {
            Write-Log "No existing connection found. User will need to connect manually." -Level "Info"
        }
        
        Write-Log "Environment initialization completed successfully" -Level "Info"
    }
    catch {
        Write-Log "Critical error during environment initialization: $($_.Exception.Message)" -Level "Error"
        throw
    }
}

#══════════════════════════════════════════════════════════════
# LOGGING AND STATUS REPORTING
#══════════════════════════════════════════════════════════════

function Write-Log {
    <#
    .SYNOPSIS
        Writes formatted log entries to console and transcript.
    
    .DESCRIPTION
        Provides consistent, color-coded logging throughout the script.
        Log entries include timestamp and severity level, and are written
        to both the console (color-coded) and transcript file (if active).
        
        This is the primary logging mechanism used throughout the script
        and should be used instead of Write-Host for all status messages.
    
    .PARAMETER Message
        The log message to write. Can be a simple string or formatted text.
        Required parameter.
    
    .PARAMETER Level
        The severity level of the log entry. Valid values:
        • Info    - Normal operational messages (Green)
        • Warning - Non-critical issues or important notices (Yellow)
        • Error   - Error conditions requiring attention (Red)
        
        Default: Info
    
    .OUTPUTS
        None. Writes to console and transcript.
    
    .EXAMPLE
        Write-Log "Operation completed successfully" -Level "Info"
        # Output: [2025-01-20 14:30:45] [Info] Operation completed successfully
    
    .EXAMPLE
        Write-Log "Configuration file not found, using defaults" -Level "Warning"
        # Output: [2025-01-20 14:30:46] [Warning] Configuration file not found, using defaults
    
    .EXAMPLE
        Write-Log "Failed to connect to service" -Level "Error"
        # Output: [2025-01-20 14:30:47] [Error] Failed to connect to service
    
    .NOTES
        - Messages are automatically formatted with timestamp
        - Color coding helps quickly identify severity in console
        - All messages written to transcript for audit purposes
        - Thread-safe for concurrent logging
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$Message,
        
        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateSet("Info", "Warning", "Error")]
        [string]$Level = "Info"
    )
    
    # Format timestamp for log entry (ISO 8601 compatible)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Color-code output based on severity level
    # Colors chosen for readability on both light and dark consoles
    switch ($Level) {
        "Info"    { 
            Write-Host $logEntry -ForegroundColor Green 
        }
        "Warning" { 
            Write-Host $logEntry -ForegroundColor Yellow 
        }
        "Error"   { 
            Write-Host $logEntry -ForegroundColor Red 
        }
    }
    
    # Note: Write-Host output is automatically captured by Start-Transcript
    # so we don't need to explicitly write to the transcript file
}

function Update-GuiStatus {
    <#
    .SYNOPSIS
        Updates the GUI status label with a message and color.
    
    .DESCRIPTION
        Provides visual feedback to the user through the GUI status bar.
        Also logs the message using Write-Log for audit purposes.
        
        This function is safe to call even if the GUI is not initialized
        (e.g., during initial script execution before GUI creation).
        
        The status bar is located at the bottom of the main window and
        provides real-time feedback during operations.
    
    .PARAMETER Message
        The status message to display in the GUI status bar.
        Should be concise but informative (recommended: < 100 characters).
        Required parameter.
    
    .PARAMETER Color
        The color for the status text (System.Drawing.Color object).
        Common colors:
        • Green  - Success/completion messages
        • Orange - In-progress or warning messages  
        • Red    - Error messages
        • Gray   - Informational messages
        
        Default: Gray (neutral color)
    
    .OUTPUTS
        None. Updates GUI and writes to log.
    
    .EXAMPLE
        Update-GuiStatus "Operation completed successfully" ([System.Drawing.Color]::Green)
        # Shows green success message in status bar
    
    .EXAMPLE
        Update-GuiStatus "Processing data..." ([System.Drawing.Color]::Orange)
        # Shows orange in-progress message
    
    .EXAMPLE
        Update-GuiStatus "Connection failed" ([System.Drawing.Color]::Red)
        # Shows red error message
    
    .NOTES
        - Automatically refreshes GUI to ensure immediate visibility
        - Safe to call before GUI initialization
        - Also logs message for audit trail
        - Forces GUI refresh with DoEvents for responsiveness
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$Message,
        
        [Parameter(Mandatory = $false, Position = 1)]
        [System.Drawing.Color]$Color = [System.Drawing.Color]::FromArgb(108, 117, 125)  # Default gray color
    )
    
    # Update GUI status label if it exists (GUI may not be initialized yet)
    if ($null -ne $Global:StatusLabel) {
        try {
            $Global:StatusLabel.Text = $Message
            $Global:StatusLabel.ForeColor = $Color
            $Global:StatusLabel.Refresh()
            
            # Process Windows message queue to ensure immediate GUI update
            [System.Windows.Forms.Application]::DoEvents()
        }
        catch {
            # Fail silently if GUI update fails - don't interrupt workflow
            Write-Log "Warning: Failed to update GUI status: $($_.Exception.Message)" -Level "Warning"
        }
    }
    
    # Always log the status message for audit trail
    Write-Log $Message
}

function Update-ConnectionStatus {
    <#
    .SYNOPSIS
        Updates the GUI connection status display.
    
    .DESCRIPTION
        Refreshes the connection status labels in the GUI based on the
        current global connection state. Shows:
        • Connection status (Connected/Not Connected)
        • Tenant name and ID
        • Connected user account
        
        The display is color-coded:
        • Green - Connected successfully
        • Red - Not connected
        • Blue - Tenant information
        • Gray - No connection info
    
    .PARAMETER None
        This function does not accept parameters. It reads from the
        global $Global:ConnectionState variable.
    
    .OUTPUTS
        None. Updates GUI elements directly.
    
    .EXAMPLE
        Update-ConnectionStatus
        # Called after connecting or disconnecting to refresh display
    
    .NOTES
        - Safe to call even if GUI elements don't exist
        - Reads current state from $Global:ConnectionState
        - Automatically color-codes based on connection status
        - Forces GUI refresh for immediate visibility
    #>
    
    [CmdletBinding()]
    param()
    
    # Only update if GUI elements exist
    if ($null -ne $Global:ConnectionLabel -and $null -ne $Global:TenantInfoLabel) {
        try {
            if ($Global:ConnectionState.IsConnected) {
                # Connected state - show green with tenant details
                $Global:ConnectionLabel.Text = "Microsoft Graph: Connected"
                $Global:ConnectionLabel.ForeColor = [System.Drawing.Color]::Green
                
                # Format tenant info with account details
                $tenantInfo = "Tenant: $($Global:ConnectionState.TenantName) | Account: $($Global:ConnectionState.Account)"
                $Global:TenantInfoLabel.Text = $tenantInfo
                $Global:TenantInfoLabel.ForeColor = [System.Drawing.Color]::FromArgb(0, 120, 212)  # Microsoft blue
            }
            else {
                # Disconnected state - show red with no info
                $Global:ConnectionLabel.Text = "Microsoft Graph: Not Connected"
                $Global:ConnectionLabel.ForeColor = [System.Drawing.Color]::Red
                $Global:TenantInfoLabel.Text = "Not connected to any tenant"
                $Global:TenantInfoLabel.ForeColor = [System.Drawing.Color]::Gray
            }
            
            # Force UI refresh to show changes immediately
            $Global:ConnectionLabel.Refresh()
            $Global:TenantInfoLabel.Refresh()
            [System.Windows.Forms.Application]::DoEvents()
        }
        catch {
            Write-Log "Warning: Failed to update connection status display: $($_.Exception.Message)" -Level "Warning"
        }
    }
}

function Update-WorkingDirectoryDisplay {
    <#
    .SYNOPSIS
        Updates the working directory configuration and GUI display.
    
    .DESCRIPTION
        Changes the working directory path in the global configuration
        and updates the GUI label to reflect the new path. This is used
        when the user manually changes the working directory or when a
        tenant-specific directory is created during connection.
        
        The function validates that the path is accessible and updates
        both the configuration and GUI atomically.
    
    .PARAMETER NewWorkDir
        The new working directory path to set. Should be a valid,
        accessible directory path. Required parameter.
    
    .OUTPUTS
        None. Updates configuration and GUI.
    
    .EXAMPLE
        Update-WorkingDirectoryDisplay -NewWorkDir "C:\M365Audit\Tenant1"
        # Changes working directory and updates display
    
    .EXAMPLE
        Update-WorkingDirectoryDisplay -NewWorkDir "D:\SecurityAnalysis\$(Get-Date -Format 'yyyyMMdd')"
        # Sets working directory with date-stamped folder
    
    .NOTES
        - Updates global $ConfigData.WorkDir configuration
        - Updates GUI label if it exists
        - Safe to call before GUI initialization
        - Does not create the directory (use Initialize-Environment)
        - Validates path format but not existence
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$NewWorkDir
    )
    
    # Update the global configuration
    $ConfigData.WorkDir = $NewWorkDir
    Write-Log "Working directory configuration updated to: $NewWorkDir" -Level "Info"
    
    # Update GUI display if it exists
    if ($null -ne $Global:WorkDirLabel) {
        try {
            $Global:WorkDirLabel.Text = "Working Directory: $NewWorkDir"
            $Global:WorkDirLabel.Refresh()
            [System.Windows.Forms.Application]::DoEvents()
            Write-Log "Updated GUI working directory display" -Level "Info"
        }
        catch {
            Write-Log "Warning: Failed to update GUI working directory display: $($_.Exception.Message)" -Level "Warning"
        }
    }
}

#══════════════════════════════════════════════════════════════
# USER INTERACTION DIALOGS
#══════════════════════════════════════════════════════════════

function Get-Folder {
    <#
    .SYNOPSIS
        Shows a folder browser dialog for directory selection.
    
    .DESCRIPTION
        Displays a Windows folder browser dialog and returns the selected path.
        Used for selecting the working directory where logs and reports will
        be saved.
        
        The dialog shows a tree view of the file system and allows the user
        to navigate to or create a new folder.
    
    .PARAMETER initialDirectory
        The initial directory to show in the browser. If not specified or
        if the path doesn't exist, shows the "My Computer" root.
        Optional parameter.
    
    .OUTPUTS
        System.String. The selected folder path, or $null if the user cancels.
    
    .EXAMPLE
        $folder = Get-Folder -initialDirectory "C:\Temp"
        if ($folder) {
            Write-Host "Selected: $folder"
        }
    
    .EXAMPLE
        $folder = Get-Folder
        # Shows dialog starting at My Computer
    
    .NOTES
        - Returns $null if user clicks Cancel
        - Selected path is validated by Windows dialog
        - User can create new folders within the dialog
        - Thread-safe for GUI operations
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false, Position = 0)]
        [string]$initialDirectory = ""
    )
    
    try {
        # Load Windows Forms assembly if not already loaded
        [void][System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms")
        
        # Create and configure folder browser dialog
        $foldername = New-Object System.Windows.Forms.FolderBrowserDialog
        $foldername.Description = "Select a working folder for logs and reports"
        $foldername.rootfolder = "MyComputer"
        $foldername.ShowNewFolderButton = $true
        
        # Set initial directory if provided and valid
        if (-not [string]::IsNullOrEmpty($initialDirectory) -and (Test-Path $initialDirectory)) {
            $foldername.SelectedPath = $initialDirectory
        }
        
        # Show dialog and return selected path
        if ($foldername.ShowDialog() -eq "OK") {
            return $foldername.SelectedPath
        }
        
        return $null
    }
    catch {
        Write-Log "Error showing folder browser dialog: $($_.Exception.Message)" -Level "Error"
        return $null
    }
}

function Test-IPAddress {
    <#
    .SYNOPSIS
        Validates and categorizes IP addresses (IPv4 or IPv6)
    
    .DESCRIPTION
        Tests if a string is a valid IP address and determines:
        • IP version (IPv4 or IPv6)
        • Whether it's private/internal
        • Type of private address
    
    .PARAMETER IPAddress
        IP address string to validate
    
    .OUTPUTS
        PSCustomObject with validation results
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$IPAddress
    )
    
    $result = [PSCustomObject]@{
        IsValid = $false
        IPVersion = $null
        IsPrivate = $false
        PrivateType = $null
        ParsedIP = $null
    }
    
    try {
        $ipObj = [System.Net.IPAddress]::Parse($IPAddress)
        $result.IsValid = $true
        $result.ParsedIP = $ipObj
        
        if ($ipObj.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
            $result.IPVersion = "IPv4"
            
            # Check IPv4 private ranges
            if ($IPAddress -match "^10\.") {
                $result.IsPrivate = $true
                $result.PrivateType = "Class A Private (10.0.0.0/8)"
            }
            elseif ($IPAddress -match "^172\.(1[6-9]|2[0-9]|3[0-1])\.") {
                $result.IsPrivate = $true
                $result.PrivateType = "Class B Private (172.16.0.0/12)"
            }
            elseif ($IPAddress -match "^192\.168\.") {
                $result.IsPrivate = $true
                $result.PrivateType = "Class C Private (192.168.0.0/16)"
            }
            elseif ($IPAddress -match "^127\.") {
                $result.IsPrivate = $true
                $result.PrivateType = "Loopback (127.0.0.0/8)"
            }
            elseif ($IPAddress -match "^169\.254\.") {
                $result.IsPrivate = $true
                $result.PrivateType = "Link-Local (169.254.0.0/16)"
            }
        }
        elseif ($ipObj.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
            $result.IPVersion = "IPv6"
            $ipLower = $IPAddress.ToLower()
            
            # Check IPv6 special ranges
            if ($ipLower -eq "::1") {
                $result.IsPrivate = $true
                $result.PrivateType = "Loopback (::1)"
            }
            elseif ($ipLower -match "^fe[89ab][0-9a-f]:") {
                $result.IsPrivate = $true
                $result.PrivateType = "Link-Local (fe80::/10)"
            }
            elseif ($ipLower -match "^f[cd][0-9a-f]{2}:") {
                $result.IsPrivate = $true
                $result.PrivateType = "Unique Local Address (fc00::/7)"
            }
            elseif ($ipLower -match "^fec[0-9a-f]:") {
                $result.IsPrivate = $true
                $result.PrivateType = "Site-Local (deprecated, fec0::/10)"
            }
            elseif ($ipLower -match "^::ffff:") {
                $result.IsPrivate = $true
                $result.PrivateType = "IPv4-Mapped (::ffff:0:0/96)"
            }
            elseif ($ipLower -match "^64:ff9b::") {
                $result.IsPrivate = $true
                $result.PrivateType = "IPv4/IPv6 Translation (64:ff9b::/96)"
            }
        }
    }
    catch {
        # Invalid IP address
        $result.IsValid = $false
    }
    
    return $result
}

function Get-DateRangeInput {
    <#
    .SYNOPSIS
        Prompts user for date range configuration.
    
    .DESCRIPTION
        Shows an input dialog for the user to specify how many days back
        to collect data. Validates the input is between 1-365 days and
        provides appropriate error messages for invalid input.
        
        The date range affects all data collection operations and determines
        how far back in time the script will query for logs and activities.
    
    .PARAMETER CurrentValue
        The current date range value to show as the default in the input box.
        Optional parameter. Default: 14 days.
    
    .OUTPUTS
        System.Int32. The new date range value (1-365), or $null if canceled or invalid.
    
    .EXAMPLE
        $newRange = Get-DateRangeInput -CurrentValue 14
        if ($newRange) {
            $ConfigData.DateRange = $newRange
        }
    
    .EXAMPLE
        $range = Get-DateRangeInput
        # Uses default current value of 14 days
    
    .NOTES
        - Returns $null if user cancels
        - Validates input is numeric and within valid range (1-365)
        - Shows appropriate error messages for invalid input
        - Warns user about performance impact of large ranges
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateRange(1, 365)]
        [int]$CurrentValue = 14
    )
    
    try {
        Add-Type -AssemblyName Microsoft.VisualBasic
        
        # Show input box with current value and helpful information
        $newValue = [Microsoft.VisualBasic.Interaction]::InputBox(
            "Enter the number of days to look back for data collection:`n`n" +
            "Current value: $CurrentValue days`n`n" +
            "Valid range: 1-365 days`n`n" +
            "Note: Larger values may take significantly longer to process." +
            "`nExchange message trace is limited to 10 days.",
            "Change Date Range",
            $CurrentValue
        )
        
        # Handle cancellation
        if ([string]::IsNullOrWhiteSpace($newValue)) {
            Write-Log "User cancelled date range input" -Level "Info"
            return $null
        }
        
        # Validate input is numeric
        $intValue = 0
        if ([int]::TryParse($newValue, [ref]$intValue)) {
            # Validate range
            if ($intValue -gt 0 -and $intValue -le 365) {
                Write-Log "User selected date range: $intValue days" -Level "Info"
                return $intValue
            }
            else {
                [System.Windows.Forms.MessageBox]::Show(
                    "Date range must be between 1 and 365 days.`n`nPlease try again.",
                    "Invalid Range",
                    "OK",
                    "Warning"
                )
                Write-Log "Invalid date range entered: $intValue (out of range)" -Level "Warning"
                return $null
            }
        }
        else {
            [System.Windows.Forms.MessageBox]::Show(
                "Please enter a valid number.`n`n'$newValue' is not a valid integer.",
                "Invalid Input",
                "OK",
                "Warning"
            )
            Write-Log "Invalid date range entered: '$newValue' (not numeric)" -Level "Warning"
            return $null
        }
    }
    catch {
        Write-Log "Error in date range input dialog: $($_.Exception.Message)" -Level "Error"
        return $null
    }
}

#endregion

#region VERSION CHECKING AND UPDATE MANAGEMENT

#══════════════════════════════════════════════════════════════
# SCRIPT VERSION VALIDATION
#══════════════════════════════════════════════════════════════

function Test-ScriptVersion {
    <#
    .SYNOPSIS
        Checks if the script is running the latest version from GitHub.
    
    .DESCRIPTION
        Compares the current script version ($ScriptVer) with the version
        available on GitHub. If a newer version is found, optionally prompts
        the user to download the update.
        
        This function helps ensure users are running the latest version with
        all bug fixes and feature improvements.
        
        The version check:
        • Fetches the raw script content from GitHub
        • Extracts the version number using regex
        • Compares versions (simple string comparison)
        • Optionally shows message box with update prompt
        • Opens GitHub page in browser if user accepts
    
    .PARAMETER GitHubUrl
        The URL to the raw script file on GitHub. Should point to the
        main/master branch for stable releases.
        Default: Pacific Office Automation Scripts repository
    
    .PARAMETER ShowMessageBox
        Whether to show interactive message boxes for user feedback.
        Set to $false for silent/automated version checking.
        Default: $true
    
    .OUTPUTS
        Hashtable with the following properties:
        • IsLatest       - Boolean, true if current version is latest
        • CurrentVersion - String, the current version number
        • LatestVersion  - String, the latest version from GitHub
        • Error          - String, error message if check failed (optional)
    
    .EXAMPLE
        $versionCheck = Test-ScriptVersion -ShowMessageBox $true
        if (-not $versionCheck.IsLatest) {
            Write-Warning "Update available: $($versionCheck.LatestVersion)"
        }
    
    .EXAMPLE
        # Silent version check without user interaction
        $versionCheck = Test-ScriptVersion -ShowMessageBox $false
        if ($versionCheck.Error) {
            Write-Host "Version check failed: $($versionCheck.Error)"
        }
    
    .EXAMPLE
        # Check against custom repository
        $check = Test-ScriptVersion -GitHubUrl "https://raw.githubusercontent.com/myorg/scripts/main/script.ps1"
    
    .NOTES
        - Requires internet connection to GitHub
        - Uses 10-second timeout for web request
        - Version comparison is simple string equality
        - Does not automatically download/install updates
        - Safe to call multiple times (no side effects)
        - Updates GUI status during operation
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$GitHubUrl = "https://raw.githubusercontent.com/the-last-one-left/Scripts/refs/heads/main/CompromisedDiscovery-Graph.ps1",
        
        [Parameter(Mandatory = $false)]
        [bool]$ShowMessageBox = $true
    )
    
    try {
        Update-GuiStatus "Checking for script updates..." ([System.Drawing.Color]::Orange)
        Write-Log "Checking script version against GitHub repository" -Level "Info"
        Write-Log "GitHub URL: $GitHubUrl" -Level "Info"
        
        # Fetch the latest script content from GitHub
        # Use basic parsing to avoid HTML rendering issues
        # Set reasonable timeout to avoid hanging
        $latestScriptContent = Invoke-WebRequest -Uri $GitHubUrl `
                                                  -UseBasicParsing `
                                                  -TimeoutSec 10 `
                                                  -ErrorAction Stop
        
        # Extract version number using regex
        # Pattern matches: $ScriptVer = "8.2" or $ScriptVer = '8.2'
        # Captures the version number in group 1
        $versionPattern = '\$ScriptVer\s*=\s*["'']([0-9.]+)["'']'
        
        if ($latestScriptContent.Content -match $versionPattern) {
            $latestVersion = $matches[1]
            $currentVersion = $ScriptVer
            
            Write-Log "Current version: $currentVersion | Latest version: $latestVersion" -Level "Info"
            
            # Compare versions (simple string comparison)
            # For more complex versioning, consider [System.Version] casting
            if ($latestVersion -eq $currentVersion) {
                # Running latest version
                Update-GuiStatus "Script is up to date (v$currentVersion)" ([System.Drawing.Color]::Green)
                Write-Log "Script is running the latest version" -Level "Info"
                
                if ($ShowMessageBox) {
                    [System.Windows.Forms.MessageBox]::Show(
                        "You are running the latest version!`n`n" +
                        "Current Version: $currentVersion`n" +
                        "Latest Version: $latestVersion",
                        "Version Check - Up to Date",
                        "OK",
                        "Information"
                    )
                }
                
                return @{
                    IsLatest       = $true
                    CurrentVersion = $currentVersion
                    LatestVersion  = $latestVersion
                }
            }
            else {
                # Newer version available
                Update-GuiStatus "Update available! Current: v$currentVersion | Latest: v$latestVersion" ([System.Drawing.Color]::Orange)
                Write-Log "Newer version available: $latestVersion (current: $currentVersion)" -Level "Warning"
                
                if ($ShowMessageBox) {
                    $updateChoice = [System.Windows.Forms.MessageBox]::Show(
                        "A newer version of the script is available!`n`n" +
                        "Current Version: $currentVersion`n" +
                        "Latest Version: $latestVersion`n`n" +
                        "Would you like to download the latest version?`n`n" +
                        "Note: The script will open in your default browser.",
                        "Update Available",
                        "YesNo",
                        "Information"
                    )
                    
                    if ($updateChoice -eq "Yes") {
                        # Open GitHub page in default browser
                        $githubPageUrl = "https://github.com/the-last-one-left/Scripts/blob/main/CompromisedDiscovery-Graph.ps1"
                        Start-Process $githubPageUrl
                        Update-GuiStatus "Opening GitHub page for update download..." ([System.Drawing.Color]::Green)
                        Write-Log "User chose to update - opening GitHub page" -Level "Info"
                    }
                    else {
                        Update-GuiStatus "Update declined by user" ([System.Drawing.Color]::Orange)
                        Write-Log "User declined to update" -Level "Info"
                    }
                }
                
                return @{
                    IsLatest       = $false
                    CurrentVersion = $currentVersion
                    LatestVersion  = $latestVersion
                }
            }
        }
        else {
            # Could not parse version from GitHub content
            throw "Could not parse version number from GitHub script"
        }
    }
    catch {
        # Handle errors gracefully
        Update-GuiStatus "Version check failed: $($_.Exception.Message)" ([System.Drawing.Color]::Red)
        Write-Log "Error checking for updates: $($_.Exception.Message)" -Level "Error"
        
        if ($ShowMessageBox) {
            [System.Windows.Forms.MessageBox]::Show(
                "Unable to check for updates.`n`n" +
                "Error: $($_.Exception.Message)`n`n" +
                "Current Version: $ScriptVer`n`n" +
                "Please check your internet connection or visit GitHub manually.",
                "Version Check Failed",
                "OK",
                "Warning"
            )
        }
        
        return @{
            IsLatest       = $null
            CurrentVersion = $ScriptVer
            LatestVersion  = $null
            Error          = $_.Exception.Message
        }
    }
}

#endregion

#region IP GEOLOCATION SERVICES

#══════════════════════════════════════════════════════════════
# IP ADDRESS GEOLOCATION
#══════════════════════════════════════════════════════════════

function Invoke-IPGeolocation {
    <#
    .SYNOPSIS
        Looks up geographic information for IPv4 or IPv6 addresses.
    
    .DESCRIPTION
        Performs geolocation lookup using a two-tier approach with IPv6 support:
        
        PRIMARY SERVICE: IPStack API
        • Supports both IPv4 and IPv6
        • Requires API key (configured in $ConfigData)
        • More detailed information
        
        FALLBACK SERVICE: ip-api.com
        • Free service supporting IPv4 and IPv6
        • Basic geographic information
        
        CACHING STRATEGY:
        • Results cached for 1 hour (configurable)
        • Reduces API calls significantly
        • Cache stored in provided hashtable
    
    .PARAMETER IPAddress
        IPv4 or IPv6 address to look up. Examples:
        • IPv4: 8.8.8.8, 192.168.1.1
        • IPv6: 2001:4860:4860::8888, ::1, fe80::1
        
    .PARAMETER RetryCount
        Number of retry attempts for failed lookups on the primary service.
        Valid range: 1-10, Default: 3
    
    .PARAMETER RetryDelay
        Base delay in seconds between retry attempts.
        Valid range: 1-30 seconds, Default: 2 seconds
    
    .PARAMETER Cache
        Hashtable for caching geolocation results.
        Required parameter (pass empty hashtable if not using cache).
    
    .OUTPUTS
        PSCustomObject with geolocation data
    
    .NOTES
        • Supports both IPv4 and IPv6 addresses
        • Private/internal IPs return generic data
        • IPv6 loopback (::1) and link-local (fe80::) are detected
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$IPAddress,
        
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 10)]
        [int]$RetryCount = 3,
        
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 30)]
        [int]$RetryDelay = 2,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$Cache
    )
    
    # ═══════════════════════════════════════════════════════════
    # VALIDATE IP ADDRESS (IPv4 or IPv6)
    # ═══════════════════════════════════════════════════════════
    
    $isIPv4 = $false
    $isIPv6 = $false
    
    # Try to parse as IP address
    try {
        $ipObj = [System.Net.IPAddress]::Parse($IPAddress)
        
        if ($ipObj.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
            $isIPv4 = $true
        }
        elseif ($ipObj.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
            $isIPv6 = $true
        }
    }
    catch {
        Write-Log "Invalid IP address format: $IPAddress" -Level "Warning"
        return @{
            ip           = $IPAddress
            city         = "Invalid IP"
            region_name  = "Invalid IP"
            country_name = "Invalid IP"
            connection   = @{ isp = "Invalid IP" }
        }
    }
    
    # ═══════════════════════════════════════════════════════════
    # CHECK CACHE FIRST
    # ═══════════════════════════════════════════════════════════
    
    if ($Cache.ContainsKey($IPAddress)) {
        $cachedEntry = $Cache[$IPAddress]
        $cacheAge = (Get-Date) - $cachedEntry.CachedAt
        
        if ($cacheAge.TotalSeconds -lt $ConfigData.CacheTimeout) {
            return $cachedEntry.Data
        }
        else {
            $Cache.Remove($IPAddress)
        }
    }
    
    # ═══════════════════════════════════════════════════════════
    # CHECK FOR PRIVATE/SPECIAL IP ADDRESSES
    # ═══════════════════════════════════════════════════════════
    
    $isPrivate = $false
    $privateType = ""
    
    if ($isIPv4) {
        # IPv4 private ranges
        if ($IPAddress -match "^10\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.|^192\.168\.|^127\.") {
            $isPrivate = $true
            $privateType = "Private/Internal IPv4"
        }
        elseif ($IPAddress -match "^169\.254\.") {
            $isPrivate = $true
            $privateType = "Link-Local IPv4"
        }
    }
    elseif ($isIPv6) {
        # IPv6 special ranges
        $ipv6Lower = $IPAddress.ToLower()
        
        # Loopback ::1
        if ($ipv6Lower -eq "::1") {
            $isPrivate = $true
            $privateType = "Loopback IPv6"
        }
        # Link-local fe80::/10
        elseif ($ipv6Lower -match "^fe[89ab][0-9a-f]:") {
            $isPrivate = $true
            $privateType = "Link-Local IPv6"
        }
        # Unique local addresses fc00::/7 (fd00::/8 is most common)
        elseif ($ipv6Lower -match "^f[cd][0-9a-f]{2}:") {
            $isPrivate = $true
            $privateType = "Private IPv6 (ULA)"
        }
        # Site-local (deprecated but still seen) fec0::/10
        elseif ($ipv6Lower -match "^fec[0-9a-f]:") {
            $isPrivate = $true
            $privateType = "Site-Local IPv6 (deprecated)"
        }
        # IPv4-mapped IPv6 addresses ::ffff:0:0/96
        elseif ($ipv6Lower -match "^::ffff:") {
            $isPrivate = $true
            $privateType = "IPv4-mapped IPv6"
        }
    }
    
    if ($isPrivate) {
        $privateResult = @{
            ip           = $IPAddress
            city         = $privateType
            region_name  = "Private Network"
            country_name = "Private Network"
            connection   = @{ isp = "Internal" }
            ip_version   = if ($isIPv4) { "IPv4" } else { "IPv6" }
            is_private   = $true
        }
        
        $Cache[$IPAddress] = @{
            Data     = $privateResult
            CachedAt = Get-Date
        }
        
        return $privateResult
    }
    
    # ═══════════════════════════════════════════════════════════
    # ATTEMPT GEOLOCATION LOOKUP
    # ═══════════════════════════════════════════════════════════
    
    $attempt = 0
    $success = $false
    $result = $null
    
    # Try primary service (IPStack) with retries
    while ($attempt -lt $RetryCount -and -not $success) {
        $attempt++
        
        try {
            $apiKey = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($ConfigData.IPStackAPIKey))
            $uri = "http://api.ipstack.com/${IPAddress}?access_key=${apiKey}&output=json"
            
            $response = Invoke-RestMethod -Uri $uri -Method Get -TimeoutSec 10 -ErrorAction Stop
            
            if ($response -and $response.ip) {
                $result = @{
                    ip           = $response.ip
                    city         = if ($response.city) { $response.city } else { "Unknown" }
                    region_name  = if ($response.region_name) { $response.region_name } else { "Unknown" }
                    country_name = if ($response.country_name) { $response.country_name } else { "Unknown" }
                    connection   = @{ 
                        isp = if ($response.connection -and $response.connection.isp) { 
                            $response.connection.isp 
                        } else { 
                            "Unknown" 
                        }
                    }
                    ip_version   = if ($isIPv4) { "IPv4" } else { "IPv6" }
                    latitude     = $response.latitude
                    longitude    = $response.longitude
                    is_private   = $false
                }
                
                $success = $true
                
                $Cache[$IPAddress] = @{
                    Data     = $result
                    CachedAt = Get-Date
                }
                
                return $result
            }
        }
        catch {
            if ($attempt -lt $RetryCount) {
                $delay = $RetryDelay * [Math]::Pow(2, $attempt - 1)
                Start-Sleep -Seconds $delay
            }
        }
    }
    
    # ═══════════════════════════════════════════════════════════
    # FALLBACK SERVICE (ip-api.com)
    # ═══════════════════════════════════════════════════════════
    
    if (-not $success) {
        try {
            # ip-api.com supports both IPv4 and IPv6
            $uri = "http://ip-api.com/json/${IPAddress}"
            
            $response = Invoke-RestMethod -Uri $uri -Method Get -TimeoutSec 10 -ErrorAction Stop
            
            if ($response -and $response.status -eq "success") {
                $result = @{
                    ip           = $response.query
                    city         = if ($response.city) { $response.city } else { "Unknown" }
                    region_name  = if ($response.regionName) { $response.regionName } else { "Unknown" }
                    country_name = if ($response.country) { $response.country } else { "Unknown" }
                    connection   = @{ 
                        isp = if ($response.isp) { $response.isp } else { "Unknown" }
                    }
                    ip_version   = if ($isIPv4) { "IPv4" } else { "IPv6" }
                    latitude     = $response.lat
                    longitude    = $response.lon
                    fallback_source = "ip-api.com"
                    is_private   = $false
                }
                
                $success = $true
                
                $Cache[$IPAddress] = @{
                    Data     = $result
                    CachedAt = Get-Date
                }
                
                return $result
            }
        }
        catch {
            Write-Log "Fallback geolocation service also failed for $IPAddress : $($_.Exception.Message)" -Level "Warning"
        }
    }
    
    # ═══════════════════════════════════════════════════════════
    # ALL ATTEMPTS FAILED - RETURN FAILURE RESULT
    # ═══════════════════════════════════════════════════════════
    
    $failureResult = @{
        ip           = $IPAddress
        city         = "Unknown"
        region_name  = "Unknown"
        country_name = "Unknown"
        connection   = @{ isp = "Unknown" }
        ip_version   = if ($isIPv4) { "IPv4" } else { "IPv6" }
        is_private   = $false
    }
    
    $Cache[$IPAddress] = @{
        Data     = $failureResult
        CachedAt = Get-Date
    }
    
    return $failureResult
}

#endregion


#region CONNECTION MANAGEMENT

#══════════════════════════════════════════════════════════════
# MICROSOFT GRAPH CONNECTION MANAGEMENT
#══════════════════════════════════════════════════════════════

function Test-ExistingGraphConnection {
    <#
    .SYNOPSIS
        Checks for and loads existing Microsoft Graph connection.
    
    .DESCRIPTION
        Tests if there's already an active Microsoft Graph connection from
        a previous session or script execution. If found:
        • Loads connection details into global state
        • Retrieves tenant information
        • Creates tenant-specific working directory
        • Updates GUI to reflect connection status
        
        This allows users to resume work without re-authenticating, which is
        especially useful during script development and testing.
        
        TENANT-SPECIFIC DIRECTORY:
        When an existing connection is detected, a tenant-specific working
        directory is created with the format:
        C:\Temp\<TenantName>\<Timestamp>\
        
        This ensures data from different tenants doesn't mix and provides
        clear organization for audit purposes.
    
    .PARAMETER None
        This function does not accept parameters.
    
    .OUTPUTS
        System.Boolean
        Returns $true if existing connection found and loaded, $false otherwise.
    
    .EXAMPLE
        if (Test-ExistingGraphConnection) {
            Write-Host "Using existing connection to $($Global:ConnectionState.TenantName)"
        } else {
            Write-Host "No existing connection - authentication required"
        }
    
    .EXAMPLE
        # Called during script initialization
        Initialize-Environment
        # Automatically calls Test-ExistingGraphConnection
    
    .NOTES
        - Safe to call multiple times (idempotent)
        - Updates $Global:ConnectionState if connection found
        - Creates tenant-specific directory automatically
        - Updates GUI connection status
        - Does not re-authenticate if connection exists
        - Connection may be stale if token expired
    #>
    
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param()
    
    try {
        # Try to get current Microsoft Graph context
        # This will succeed if there's an active connection
        $context = Get-MgContext -ErrorAction Stop
        
        if ($context) {
            Write-Log "Detected existing Microsoft Graph connection" -Level "Info"
            Write-Log "Context: Tenant=$($context.TenantId), Account=$($context.Account)" -Level "Info"
            
            # Retrieve organization details for tenant name
            try {
                $organization = Get-MgOrganization -ErrorAction Stop | Select-Object -First 1
                
                if (-not $organization) {
                    Write-Log "Warning: Could not retrieve organization details" -Level "Warning"
                    return $false
                }
                
                #──────────────────────────────────────────────────
                # CREATE TENANT-SPECIFIC WORKING DIRECTORY
                #──────────────────────────────────────────────────
                # Format: C:\Temp\<TenantName>\<HHMMDDMMYY>\
                # This prevents data mixing between tenants
                
                # Clean tenant name - remove invalid filename characters
                $cleanTenantName = $organization.DisplayName -replace '[<>:"/\\|?*]', '_'
                
                # Create timestamp for unique directory
                $timestamp = Get-Date -Format "HHmmddMMyy"
                
                # Build full path
                $newWorkDir = "C:\Temp\$cleanTenantName\$timestamp"
                
                try {
                    if (-not (Test-Path -Path $newWorkDir)) {
                        New-Item -Path $newWorkDir -ItemType Directory -Force | Out-Null
                        Write-Log "Created tenant-specific working directory: $newWorkDir" -Level "Info"
                    }
                    
                    # Update working directory configuration and display
                    Update-WorkingDirectoryDisplay -NewWorkDir $newWorkDir
                }
                catch {
                    Write-Log "Could not create tenant-specific directory, using default: $($_.Exception.Message)" -Level "Warning"
                    # Continue with default directory - non-fatal error
                }
                
                #──────────────────────────────────────────────────
                # UPDATE GLOBAL CONNECTION STATE
                #──────────────────────────────────────────────────
                $Global:ConnectionState = @{
                    IsConnected = $true
                    TenantId    = $context.TenantId
                    TenantName  = $organization.DisplayName
                    Account     = $context.Account
                    ConnectedAt = Get-Date
                }
                
                # Update GUI to show connection status
                Update-ConnectionStatus
                Update-GuiStatus "Existing Microsoft Graph connection detected and loaded" ([System.Drawing.Color]::Green)
                
                Write-Log "Successfully loaded existing connection" -Level "Info"
                Write-Log "Tenant: $($organization.DisplayName)" -Level "Info"
                Write-Log "Account: $($context.Account)" -Level "Info"
                Write-Log "Working directory: $($ConfigData.WorkDir)" -Level "Info"
                
                return $true
            }
            catch {
                Write-Log "Could not retrieve organization details from existing connection: $($_.Exception.Message)" -Level "Warning"
                return $false
            }
        }
    }
    catch {
        # No existing connection - this is expected on first run
        Write-Log "No existing Microsoft Graph connection found" -Level "Info"
        return $false
    }
    
    return $false
}

function Connect-TenantServices {
    <#
    .SYNOPSIS
        Establishes connection to Microsoft Graph and Exchange Online.
    
    .DESCRIPTION
        Comprehensive connection function that orchestrates the entire
        authentication and setup process:
        
        PHASE 1: MODULE VERIFICATION
        • Check for required Microsoft Graph modules
        • Prompt to install missing modules
        • Import all required modules
        
        PHASE 2: AUTHENTICATION
        • Clear any existing connections (force fresh login)
        • Prompt user for tenant selection
        • Authenticate with Microsoft Graph (interactive browser)
        • Request all required API scopes
        
        PHASE 3: TENANT SETUP
        • Retrieve tenant information
        • Create tenant-specific working directory
        • Update global connection state
        • Start tenant-specific transcript logging
        
        PHASE 4: VALIDATION
        • Test admin audit log access
        • Display audit status to user
        • Provide recommendations if issues found
        
        PHASE 5: EXCHANGE ONLINE
        • Check for Exchange Online module
        • Clean up any existing EXO sessions
        • Connect to Exchange Online
        • Verify connection with test command
        • Initialize EXO connection state
        
        The function provides detailed user feedback throughout and handles
        errors gracefully at each stage.
    
    .PARAMETER None
        This function does not accept parameters. Configuration comes from
        the global $ConfigData structure.
    
    .OUTPUTS
        System.Boolean
        Returns $true if connection successful, $false otherwise.
    
    .EXAMPLE
        if (Connect-TenantServices) {
            Write-Host "Successfully connected to tenant"
            # Proceed with data collection
        } else {
            Write-Host "Connection failed"
            exit 1
        }
    
    .EXAMPLE
        # Called from GUI button
        $btnConnect.Add_Click({
            $result = Connect-TenantServices
            if ($result) {
                Enable-DataCollectionButtons
            }
        })
    
    .NOTES
        - Requires user interaction (browser authentication)
        - May take 30-60 seconds to complete
        - Forces fresh login (clears cached credentials)
        - Creates tenant-specific directory structure
        - Updates GUI throughout process
        - Handles module installation if needed
        - Tests critical permissions after connection
        - Exchange Online connection is optional (non-fatal if fails)
    #>
    
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param()
    
    #══════════════════════════════════════════════════════════
    # PHASE 1: MODULE VERIFICATION AND INSTALLATION
    #══════════════════════════════════════════════════════════
    
    Clear-Host
    Update-GuiStatus "Checking Microsoft Graph PowerShell modules..." ([System.Drawing.Color]::Orange)
    
    # Define required Graph modules
    $requiredModules = @(
        "Microsoft.Graph.Authentication",           # Core authentication
        "Microsoft.Graph.Users",                    # User operations
        "Microsoft.Graph.Reports",                  # Sign-in logs
        "Microsoft.Graph.Identity.DirectoryManagement",  # Directory operations
        "Microsoft.Graph.Applications"              # App registrations
    )
    
    $missingModules = @()
    
    # Check which modules are missing
    Write-Log "Checking for required Microsoft Graph modules..." -Level "Info"
    foreach ($module in $requiredModules) {
        $installedModule = Get-Module -Name $module -ListAvailable | Select-Object -Last 1
        if ($null -eq $installedModule) {
            $missingModules += $module
            Write-Log "Missing module: $module" -Level "Warning"
        }
        else {
            Write-Log "$module found (Version: $($installedModule.Version))" -Level "Info"
        }
    }
    
    # Install missing modules if needed
    if ($missingModules.Count -gt 0) {
        Update-GuiStatus "Missing required modules: $($missingModules -join ', ')" ([System.Drawing.Color]::Red)
        
        $installPrompt = [System.Windows.Forms.MessageBox]::Show(
            "Missing required Microsoft Graph modules:`n`n" +
            ($missingModules -join "`n") + "`n`n" +
            "These modules are required for the script to function.`n" +
            "Install missing modules now?`n`n" +
            "Note: Installation may take several minutes.",
            "Missing Modules",
            "YesNo",
            "Question"
        )
        
        if ($installPrompt -eq "Yes") {
            Update-GuiStatus "Installing Microsoft Graph modules..." ([System.Drawing.Color]::Orange)
            
            try {
                foreach ($module in $missingModules) {
                    Write-Log "Installing $module..." -Level "Info"
                    Update-GuiStatus "Installing $module..." ([System.Drawing.Color]::Orange)
                    
                    Install-Module -Name $module -Scope CurrentUser -Force -ErrorAction Stop
                    Write-Log "$module installed successfully" -Level "Info"
                }
                Update-GuiStatus "All modules installed successfully" ([System.Drawing.Color]::Green)
            }
            catch {
                $errorMsg = "Failed to install required modules: $($_.Exception.Message)"
                Update-GuiStatus $errorMsg ([System.Drawing.Color]::Red)
                Write-Log $errorMsg -Level "Error"
                
                [System.Windows.Forms.MessageBox]::Show(
                    "Failed to install required modules:`n`n$($_.Exception.Message)`n`n" +
                    "Please install modules manually or run PowerShell as Administrator.",
                    "Installation Error",
                    "OK",
                    "Error"
                )
                return $false
            }
        }
        else {
            Write-Log "User declined to install required modules" -Level "Warning"
            Update-GuiStatus "User declined to install required modules" ([System.Drawing.Color]::Red)
            return $false
        }
    }
    
    #══════════════════════════════════════════════════════════
    # PHASE 2: MODULE IMPORT AND AUTHENTICATION PREPARATION
    #══════════════════════════════════════════════════════════
    
    try {
        # Import required modules
        Update-GuiStatus "Loading Microsoft Graph modules..." ([System.Drawing.Color]::Orange)
        Write-Log "Importing Microsoft Graph modules..." -Level "Info"
        
        foreach ($module in $requiredModules) {
            Import-Module $module -Force -ErrorAction Stop
        }
        Write-Log "All modules imported successfully" -Level "Info"
        
        # Clear any existing context for fresh login
        # This ensures we don't reuse potentially expired tokens
        Update-GuiStatus "Clearing cached authentication context..." ([System.Drawing.Color]::Orange)
        Write-Log "Clearing any existing Microsoft Graph connection..." -Level "Info"
        
        try {
            Disconnect-MgGraph -ErrorAction SilentlyContinue
            Write-Log "Cleared existing Microsoft Graph connection" -Level "Info"
        }
        catch {
            # Ignore errors - not connected is fine
        }
        
        # Reset global connection state
        $Global:ConnectionState = @{
            IsConnected = $false
            TenantId    = $null
            TenantName  = $null
            Account     = $null
            ConnectedAt = $null
        }
        
        #══════════════════════════════════════════════════════════
        # PHASE 3: USER AUTHENTICATION
        #══════════════════════════════════════════════════════════
        
        # Prompt user about tenant selection
        Update-GuiStatus "Prompting for tenant selection..." ([System.Drawing.Color]::Orange)
        
        $tenantPrompt = [System.Windows.Forms.MessageBox]::Show(
            "You will now be prompted to sign in to Microsoft Graph.`n`n" +
            "IMPORTANT:`n" +
            "• If you have access to multiple tenants, carefully select the correct one`n" +
            "• The browser authentication window will open shortly`n" +
            "• You must have appropriate admin permissions in the tenant`n`n" +
            "Required permissions:`n" +
            "• Global Administrator, Security Administrator, or`n" +
            "• Security Reader + Exchange Administrator (minimum)`n`n" +
            "Continue with authentication?",
            "Tenant Selection Required",
            "OKCancel",
            "Information"
        )
        
        if ($tenantPrompt -eq "Cancel") {
            Write-Log "User cancelled authentication" -Level "Info"
            Update-GuiStatus "User cancelled authentication" ([System.Drawing.Color]::Orange)
            return $false
        }
        
        # Connect to Microsoft Graph with interactive authentication
        Update-GuiStatus "Opening browser for Microsoft Graph authentication..." ([System.Drawing.Color]::Orange)
        Write-Log "Starting interactive authentication to Microsoft Graph" -Level "Info"
        Write-Log "Requesting scopes: $($ConfigData.RequiredScopes -join ', ')" -Level "Info"
        
        # This will open a browser window for authentication
        Connect-MgGraph -Scopes $ConfigData.RequiredScopes -ErrorAction Stop | Out-Null
        
        Write-Log "Microsoft Graph authentication completed" -Level "Info"
        
        #══════════════════════════════════════════════════════════
        # PHASE 4: TENANT INFORMATION RETRIEVAL
        #══════════════════════════════════════════════════════════
        
        Update-GuiStatus "Retrieving tenant information..." ([System.Drawing.Color]::Orange)
        Write-Log "Retrieving tenant context and organization information..." -Level "Info"
        
        $context = Get-MgContext -ErrorAction Stop
        $organization = Get-MgOrganization -ErrorAction Stop | Select-Object -First 1
        
        if (-not $context -or -not $organization) {
            throw "Failed to retrieve tenant context or organization information"
        }
        
        Write-Log "Successfully retrieved tenant information" -Level "Info"
        Write-Log "Tenant ID: $($context.TenantId)" -Level "Info"
        Write-Log "Tenant Name: $($organization.DisplayName)" -Level "Info"
        Write-Log "Connected Account: $($context.Account)" -Level "Info"
        
        #══════════════════════════════════════════════════════════
        # PHASE 5: TENANT-SPECIFIC DIRECTORY SETUP
        #══════════════════════════════════════════════════════════
        
        Update-GuiStatus "Setting up tenant-specific working directory..." ([System.Drawing.Color]::Orange)
        Write-Log "Creating tenant-specific working directory..." -Level "Info"
        
        # Clean tenant name for filesystem
        $cleanTenantName = $organization.DisplayName -replace '[<>:"/\\|?*]', '_'
        $timestamp = Get-Date -Format "HHmmddMMyy"
        $newWorkDir = "C:\Temp\$cleanTenantName\$timestamp"
        
        try {
            if (-not (Test-Path -Path $newWorkDir)) {
                New-Item -Path $newWorkDir -ItemType Directory -Force | Out-Null
                Write-Log "Created tenant-specific working directory: $newWorkDir" -Level "Info"
            }
            
            # Update configuration and GUI
            Update-WorkingDirectoryDisplay -NewWorkDir $newWorkDir
            Update-GuiStatus "Working directory updated to: $newWorkDir" ([System.Drawing.Color]::Green)
        }
        catch {
            Write-Log "Warning: Could not create tenant-specific directory, using default: $($_.Exception.Message)" -Level "Warning"
            # Non-fatal - continue with default directory
        }
        
        #══════════════════════════════════════════════════════════
        # PHASE 6: UPDATE CONNECTION STATE AND LOGGING
        #══════════════════════════════════════════════════════════
        
        # Update global connection state
        $Global:ConnectionState = @{
            IsConnected = $true
            TenantId    = $context.TenantId
            TenantName  = $organization.DisplayName
            Account     = $context.Account
            ConnectedAt = Get-Date
        }
        
        # Start new transcript in tenant-specific directory
        $logFile = Join-Path -Path $ConfigData.WorkDir -ChildPath "ScriptLog_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
        try {
            Stop-Transcript -ErrorAction SilentlyContinue
            Start-Transcript -Path $logFile -Force
            Write-Log "Started new transcript in tenant-specific directory" -Level "Info"
        }
        catch {
            Write-Log "Could not start transcript in new directory: $($_.Exception.Message)" -Level "Warning"
        }
        
        # Update GUI
        Update-ConnectionStatus
        Update-GuiStatus "Connected to Microsoft Graph successfully" ([System.Drawing.Color]::Green)
        
        Write-Log "═══════════════════════════════════════════════════" -Level "Info"
        Write-Log "SUCCESSFULLY CONNECTED TO MICROSOFT GRAPH" -Level "Info"
        Write-Log "Tenant: $($organization.DisplayName)" -Level "Info"
        Write-Log "Tenant ID: $($context.TenantId)" -Level "Info"
        Write-Log "Account: $($context.Account)" -Level "Info"
        Write-Log "Working Directory: $($ConfigData.WorkDir)" -Level "Info"
        Write-Log "═══════════════════════════════════════════════════" -Level "Info"
        
        #══════════════════════════════════════════════════════════
        # PHASE 7: AUDIT LOG VALIDATION
        #══════════════════════════════════════════════════════════
        
        Write-Log "Testing admin audit log configuration..." -Level "Info"
        $auditStatus = Test-AdminAuditLogging -ShowProgress $true
        
        # Show audit status in GUI
        if ($auditStatus.IsEnabled) {
            if ($auditStatus.HasRecentData) {
                Update-GuiStatus "Connection complete - Admin audit logging is enabled and working" ([System.Drawing.Color]::Green)
            }
            else {
                Update-GuiStatus "Connection complete - Admin audit logging enabled but no recent data" ([System.Drawing.Color]::Orange)
            }
        }
        else {
            Update-GuiStatus "Connection complete - WARNING: Admin audit logging issue detected" ([System.Drawing.Color]::Red)
        }
        
        # Show audit status popup to user
        Show-AuditLogStatusWarning -AuditStatus $auditStatus
        Write-Log "Admin audit log status: $($auditStatus.Status) - $($auditStatus.Message)" -Level "Info"
        
        #══════════════════════════════════════════════════════════
        # PHASE 8: EXCHANGE ONLINE CONNECTION
        #══════════════════════════════════════════════════════════
        
        Update-GuiStatus "Preparing Exchange Online connection..." ([System.Drawing.Color]::Orange)
        Write-Log "Preparing Exchange Online connection after Graph connection" -Level "Info"
        
        # Clean up any existing Exchange Online sessions first
        $existingSessions = Get-PSSession | Where-Object { 
            $_.ConfigurationName -eq "Microsoft.Exchange" 
        }
        
        if ($existingSessions) {
            Update-GuiStatus "Cleaning up existing Exchange Online sessions..." ([System.Drawing.Color]::Orange)
            Write-Log "Found $($existingSessions.Count) existing Exchange Online session(s), cleaning up..." -Level "Info"
            
            try {
                Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
            }
            catch {
                # Force remove sessions if disconnect fails
                $existingSessions | Remove-PSSession -ErrorAction SilentlyContinue
            }
        }
        
        Update-GuiStatus "Connecting to Exchange Online..." ([System.Drawing.Color]::Orange)
        
        try {
            # Check if Exchange Online module is available
            if (-not (Get-Module -Name ExchangeOnlineManagement -ListAvailable)) {
                Update-GuiStatus "Installing Exchange Online module..." ([System.Drawing.Color]::Orange)
                Write-Log "Exchange Online module not found, installing..." -Level "Info"
                
                Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
                Write-Log "Exchange Online module installed successfully" -Level "Info"
            }
            
            # Import the module
            if (-not (Get-Module -Name ExchangeOnlineManagement)) {
                Import-Module ExchangeOnlineManagement -Force -ErrorAction Stop
                Write-Log "Exchange Online module imported" -Level "Info"
            }
            
            # Connect to Exchange Online (uses same auth as Graph when possible)
            Connect-ExchangeOnline -ShowProgress $false -ShowBanner:$false -ErrorAction Stop
            
            # Test connection to verify it worked
            $testResult = Get-AcceptedDomain -ErrorAction Stop | Select-Object -First 1
            if ($testResult) {
                Write-Log "Exchange Online connection successful and verified" -Level "Info"
                Update-GuiStatus "Connected to both Microsoft Graph and Exchange Online" ([System.Drawing.Color]::Green)
                
                # Initialize Exchange Online state tracking
                $Global:ExchangeOnlineState = @{
                    IsConnected       = $true
                    LastChecked       = Get-Date
                    ConnectionAttempts = 0
                }
            }
        }
        catch {
            # Exchange Online connection is non-fatal
            Write-Log "Exchange Online connection failed (non-fatal): $($_.Exception.Message)" -Level "Warning"
            Update-GuiStatus "Graph connected, Exchange Online failed - will retry during inbox rules collection" ([System.Drawing.Color]::Orange)
            
            # Initialize Exchange Online state as failed
            $Global:ExchangeOnlineState = @{
                IsConnected       = $false
                LastChecked       = Get-Date
                ConnectionAttempts = 1
            }
        }
        
        #══════════════════════════════════════════════════════════
        # PHASE 9: SUCCESS SUMMARY
        #══════════════════════════════════════════════════════════
        
        $exoStatus = if ($Global:ExchangeOnlineState.IsConnected) { "Connected" } else { "Failed (will retry)" }
        
        $successMessage = "Successfully connected to Microsoft Graph!`n`n" +
                         "═══════════════════════════════════════`n" +
                         "TENANT INFORMATION`n" +
                         "═══════════════════════════════════════`n" +
                         "Tenant: $($organization.DisplayName)`n" +
                         "Tenant ID: $($context.TenantId)`n" +
                         "Account: $($context.Account)`n" +
                         "Working Directory: $newWorkDir`n`n" +
                         "═══════════════════════════════════════`n" +
                         "CONNECTION STATUS`n" +
                         "═══════════════════════════════════════`n" +
                         "Microsoft Graph: ✓ Connected`n" +
                         "Exchange Online: $exoStatus`n" +
                         "Admin Audit: $($auditStatus.Status)`n`n" +
                         "You can now proceed with data collection."
        
        [System.Windows.Forms.MessageBox]::Show($successMessage, "Connection Successful", "OK", "Information")
        
        return $true
    }
    catch {
        # Handle connection failure
        $errorMsg = "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
        Update-GuiStatus $errorMsg ([System.Drawing.Color]::Red)
        Write-Log $errorMsg -Level "Error"
        
        [System.Windows.Forms.MessageBox]::Show(
            "Failed to connect to Microsoft Graph:`n`n$($_.Exception.Message)`n`n" +
            "Please check:`n" +
            "• Internet connection is active`n" +
            "• You have appropriate admin permissions`n" +
            "• Multi-factor authentication is completed`n" +
            "• Firewall/proxy allows connections to Microsoft services",
            "Connection Failed",
            "OK",
            "Error"
        )
        
        return $false
    }
}

function Disconnect-GraphSafely {
    <#
    .SYNOPSIS
        Safely disconnects from Microsoft Graph.
    
    .DESCRIPTION
        Performs a clean disconnect from Microsoft Graph and updates
        the global connection state. Optionally shows confirmation message.
        
        This function:
        • Disconnects active Graph connection
        • Resets global connection state
        • Updates GUI to reflect disconnection
        • Logs the disconnect operation
        • Shows optional confirmation to user
    
    .PARAMETER ShowMessage
        Whether to show a confirmation message box after disconnect.
        Default: $false (silent disconnect)
    
    .OUTPUTS
        None. Updates global state and GUI.
    
    .EXAMPLE
        Disconnect-GraphSafely -ShowMessage $true
        # Disconnects and shows confirmation dialog
    
    .EXAMPLE
        # Silent disconnect during cleanup
        Disconnect-GraphSafely
    
    .NOTES
        - Safe to call even if not connected
        - Resets connection state even if disconnect fails
        - Non-blocking (doesn't halt script on error)
        - Updates GUI connection status
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [bool]$ShowMessage = $false
    )
    
    try {
        if ($Global:ConnectionState.IsConnected) {
            Update-GuiStatus "Disconnecting from Microsoft Graph..." ([System.Drawing.Color]::Orange)
            Write-Log "Disconnecting from Microsoft Graph..." -Level "Info"
            
            Disconnect-MgGraph -ErrorAction Stop
            
            # Reset global connection state
            $Global:ConnectionState = @{
                IsConnected = $false
                TenantId    = $null
                TenantName  = $null
                Account     = $null
                ConnectedAt = $null
            }
            
            Update-ConnectionStatus
            Update-GuiStatus "Disconnected from Microsoft Graph" ([System.Drawing.Color]::Green)
            Write-Log "Successfully disconnected from Microsoft Graph" -Level "Info"
            
            if ($ShowMessage) {
                [System.Windows.Forms.MessageBox]::Show(
                    "Successfully disconnected from Microsoft Graph.",
                    "Disconnected",
                    "OK",
                    "Information"
                )
            }
        }
        else {
            Write-Log "Disconnect called but no active connection found" -Level "Info"
        }
    }
    catch {
        Write-Log "Error during disconnect: $($_.Exception.Message)" -Level "Warning"
        # Reset connection state anyway
        $Global:ConnectionState.IsConnected = $false
        Update-ConnectionStatus
    }
}

#══════════════════════════════════════════════════════════════
# EXCHANGE ONLINE CONNECTION MANAGEMENT
#══════════════════════════════════════════════════════════════

function Connect-ExchangeOnlineIfNeeded {
    <#
    .SYNOPSIS
        Ensures Exchange Online connection is established.
    
    .DESCRIPTION
        Checks for existing Exchange Online connection and establishes a new
        connection if needed. Updates global connection state tracking.
        
        This function is called before operations that require Exchange Online:
        • Inbox rules collection
        • Message trace operations
        • Mailbox settings retrieval
        
        Connection verification:
        • Tests connection with Get-AcceptedDomain
        • Updates last checked timestamp
        • Tracks connection attempts for retry logic
    
    .OUTPUTS
        System.Boolean
        Returns $true if Exchange Online is connected, $false otherwise.
    
    .EXAMPLE
        if (Connect-ExchangeOnlineIfNeeded) {
            $rules = Get-InboxRule -Mailbox $user
        }
    
    .NOTES
        - Non-fatal errors (returns false instead of throwing)
        - Updates $Global:ExchangeOnlineState
        - Installs module if missing
        - Uses modern authentication
        - Inherits credentials from Graph when possible
    #>
    
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param()
    
    try {
        # Check if Exchange Online module is available
        if (-not (Get-Module -Name ExchangeOnlineManagement -ListAvailable)) {
            Write-Log "Exchange Online module not found - attempting to install..." -Level "Warning"
            Update-GuiStatus "Installing Exchange Online module..." ([System.Drawing.Color]::Orange)
            
            try {
                Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
                Import-Module ExchangeOnlineManagement -Force -ErrorAction Stop
                Write-Log "Exchange Online module installed successfully" -Level "Info"
            }
            catch {
                Write-Log "Failed to install Exchange Online module: $($_.Exception.Message)" -Level "Error"
                Update-GuiStatus "Exchange Online module installation failed" ([System.Drawing.Color]::Red)
                return $false
            }
        }
        
        # Import module if not already loaded
        if (-not (Get-Module -Name ExchangeOnlineManagement)) {
            Import-Module ExchangeOnlineManagement -Force -ErrorAction Stop
        }
        
        # Check for existing connection by testing a command
        Update-GuiStatus "Checking Exchange Online connection..." ([System.Drawing.Color]::Orange)
        
        $isConnected = $false
        try {
            $testResult = Get-AcceptedDomain -ErrorAction Stop | Select-Object -First 1
            if ($testResult) {
                $isConnected = $true
                Write-Log "Exchange Online connection verified - already connected" -Level "Info"
                
                # Update global state
                if (-not $Global:ExchangeOnlineState) {
                    $Global:ExchangeOnlineState = @{
                        IsConnected       = $true
                        LastChecked       = Get-Date
                        ConnectionAttempts = 0
                    }
                }
                else {
                    $Global:ExchangeOnlineState.IsConnected = $true
                    $Global:ExchangeOnlineState.LastChecked = Get-Date
                }
                
                Update-GuiStatus "Exchange Online connection verified" ([System.Drawing.Color]::Green)
                return $true
            }
        }
        catch {
            Write-Log "No existing Exchange Online connection found" -Level "Info"
            $isConnected = $false
        }
        
        # If not connected, attempt to connect
        if (-not $isConnected) {
            Update-GuiStatus "Connecting to Exchange Online..." ([System.Drawing.Color]::Orange)
            Write-Log "Attempting to connect to Exchange Online..." -Level "Info"
            
            try {
                # Connect using modern auth (inherits credentials from Graph when possible)
                Connect-ExchangeOnline -ShowProgress $false -ShowBanner:$false -ErrorAction Stop
                
                # Verify connection worked
                $testResult = Get-AcceptedDomain -ErrorAction Stop | Select-Object -First 1
                if ($testResult) {
                    Write-Log "Exchange Online connection established successfully" -Level "Info"
                    Update-GuiStatus "Connected to Exchange Online successfully" ([System.Drawing.Color]::Green)
                    
                    # Initialize/update global state
                    $Global:ExchangeOnlineState = @{
                        IsConnected       = $true
                        LastChecked       = Get-Date
                        ConnectionAttempts = 0
                    }
                    
                    return $true
                }
                else {
                    throw "Connection succeeded but verification failed"
                }
            }
            catch {
                Write-Log "Failed to connect to Exchange Online: $($_.Exception.Message)" -Level "Error"
                Update-GuiStatus "Exchange Online connection failed" ([System.Drawing.Color]::Red)
                
                # Update global state
                if (-not $Global:ExchangeOnlineState) {
                    $Global:ExchangeOnlineState = @{
                        IsConnected       = $false
                        LastChecked       = Get-Date
                        ConnectionAttempts = 1
                    }
                }
                else {
                    $Global:ExchangeOnlineState.IsConnected = $false
                    $Global:ExchangeOnlineState.LastChecked = Get-Date
                    $Global:ExchangeOnlineState.ConnectionAttempts++
                }
                
                return $false
            }
        }
        
        return $isConnected
        
    }
    catch {
        Write-Log "Error in Connect-ExchangeOnlineIfNeeded: $($_.Exception.Message)" -Level "Error"
        Update-GuiStatus "Exchange Online connection check failed" ([System.Drawing.Color]::Red)
        
        # Update global state on error
        if (-not $Global:ExchangeOnlineState) {
            $Global:ExchangeOnlineState = @{
                IsConnected       = $false
                LastChecked       = Get-Date
                ConnectionAttempts = 1
            }
        }
        
        return $false
    }
}

function Disconnect-ExchangeOnlineSafely {
    <#
    .SYNOPSIS
        Safely disconnects from Exchange Online.
    
    .DESCRIPTION
        Performs a clean disconnect from Exchange Online and updates
        the global connection state tracking. Shows confirmation message.
    
    .OUTPUTS
        None. Updates global state and shows message box.
    
    .EXAMPLE
        Disconnect-ExchangeOnlineSafely
    
    .NOTES
        - Safe to call even if not connected
        - Shows confirmation message to user
        - Updates connection state tracking
    #>
    
    [CmdletBinding()]
    param()
    
    try {
        # Check for active Exchange Online sessions
        $session = Get-PSSession | Where-Object { 
            $_.ConfigurationName -eq "Microsoft.Exchange" -and 
            $_.State -eq "Opened" 
        }
        
        if ($session) {
            Update-GuiStatus "Disconnecting from Exchange Online..." ([System.Drawing.Color]::Orange)
            Disconnect-ExchangeOnline -Confirm:$false -ErrorAction Stop
            Write-Log "Disconnected from Exchange Online successfully" -Level "Info"
            Update-GuiStatus "Disconnected from Exchange Online" ([System.Drawing.Color]::Green)
            
            # Update global connection state
            if ($Global:ExchangeOnlineState) {
                $Global:ExchangeOnlineState.IsConnected = $false
                $Global:ExchangeOnlineState.LastChecked = Get-Date
                $Global:ExchangeOnlineState.ConnectionAttempts = 0
            }
            
            [System.Windows.Forms.MessageBox]::Show(
                "Disconnected from Exchange Online successfully.",
                "Disconnected",
                "OK",
                "Information"
            )
        }
        else {
            Update-GuiStatus "No active Exchange Online session found" ([System.Drawing.Color]::Orange)
            Write-Log "No active Exchange Online session found" -Level "Info"
            
            # Update global connection state anyway
            if ($Global:ExchangeOnlineState) {
                $Global:ExchangeOnlineState.IsConnected = $false
                $Global:ExchangeOnlineState.LastChecked = Get-Date
            }
            
            [System.Windows.Forms.MessageBox]::Show(
                "No active Exchange Online session found.",
                "No Session",
                "OK",
                "Information"
            )
        }
    }
    catch {
        Write-Log "Error disconnecting from Exchange Online: $($_.Exception.Message)" -Level "Warning"
        Update-GuiStatus "Error disconnecting from Exchange Online" ([System.Drawing.Color]::Red)
        
        # Force update connection state on error
        if ($Global:ExchangeOnlineState) {
            $Global:ExchangeOnlineState.IsConnected = $false
            $Global:ExchangeOnlineState.LastChecked = Get-Date
        }
        
        [System.Windows.Forms.MessageBox]::Show(
            "Error disconnecting from Exchange Online:`n$($_.Exception.Message)",
            "Disconnect Error",
            "OK",
            "Warning"
        )
    }
}

#══════════════════════════════════════════════════════════════
# SECURITY CONFIGURATION TESTING
#══════════════════════════════════════════════════════════════

function Test-SecurityDefaults {
    <#
    .SYNOPSIS
        Checks if Microsoft 365 Security Defaults are enabled.
    
    .DESCRIPTION
        Tests whether security defaults are enabled in the tenant, which can
        block access to sign-in logs via Graph API.
        
        Security Defaults are a baseline security configuration that:
        • Requires MFA for all users
        • Blocks legacy authentication
        • May restrict access to certain API endpoints
        
        If enabled, the script may need to use Exchange Online fallback
        methods for sign-in data collection.
    
    .OUTPUTS
        Hashtable with:
        • IsEnabled   - Boolean or $null
        • PolicyId    - Policy GUID
        • DisplayName - Policy name
        • Description - Policy description
        • Error       - Error message (if check failed)
    
    .EXAMPLE
        $defaults = Test-SecurityDefaults
        if ($defaults.IsEnabled) {
            Write-Warning "Security defaults may block sign-in log access"
            # Use fallback method
        }
    
    .NOTES
        - Returns null for IsEnabled if check fails
        - Non-blocking (continues on error)
        - Updates GUI with status
    #>
    
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param()
    
    try {
        Update-GuiStatus "Checking security defaults configuration..." ([System.Drawing.Color]::Orange)
        Write-Log "Testing security defaults status..." -Level "Info"
        
        # Query the security defaults policy
        $securityDefaultsUri = "https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy"
        $securityDefaultsPolicy = Invoke-MgGraphRequest -Uri $securityDefaultsUri -Method GET -ErrorAction Stop
        
        $isEnabled = $securityDefaultsPolicy.isEnabled -eq $true
        
        if ($isEnabled) {
            Write-Log "Security defaults are ENABLED - this may block sign-in log access" -Level "Warning"
            Update-GuiStatus "Security defaults detected as ENABLED" ([System.Drawing.Color]::Orange)
        }
        else {
            Write-Log "Security defaults are disabled" -Level "Info"
            Update-GuiStatus "Security defaults are disabled" ([System.Drawing.Color]::Green)
        }
        
        return @{
            IsEnabled   = $isEnabled
            PolicyId    = $securityDefaultsPolicy.id
            DisplayName = $securityDefaultsPolicy.displayName
            Description = $securityDefaultsPolicy.description
        }
    }
    catch {
        Write-Log "Could not determine security defaults status: $($_.Exception.Message)" -Level "Warning"
        Update-GuiStatus "Could not check security defaults status" ([System.Drawing.Color]::Orange)
        
        return @{
            IsEnabled = $null
            Error     = $_.Exception.Message
        }
    }
}

function Test-AdminAuditLogging {
    <#
    .SYNOPSIS
        Tests if admin audit logging is enabled and accessible.
    
    .DESCRIPTION
        Attempts to query the admin audit logs to verify that:
        • Audit logging is enabled in the tenant
        • Current user has permission to access audit logs
        • Recent audit data exists
        
        This check helps identify configuration issues early before
        attempting full data collection.
    
    .PARAMETER ShowProgress
        Whether to show progress updates in the GUI.
        Default: $true
    
    .OUTPUTS
        Hashtable with:
        • IsEnabled     - Boolean
        • Status        - Status string
        • Message       - Detailed message
        • HasRecentData - Boolean
    
    .EXAMPLE
        $auditStatus = Test-AdminAuditLogging -ShowProgress $true
        if (-not $auditStatus.IsEnabled) {
            Write-Warning "Audit logging not available"
        }
    
    .NOTES
        - Non-blocking (returns status rather than throwing)
        - Provides actionable recommendations
        - Called automatically during connection
    #>
    
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param (
        [Parameter(Mandatory = $false)]
        [bool]$ShowProgress = $true
    )
    
    try {
        if ($ShowProgress) {
            Update-GuiStatus "Checking admin audit log configuration..." ([System.Drawing.Color]::Orange)
        }
        
        Write-Log "Testing admin audit log availability..." -Level "Info"
        
        # Try to get a single audit log entry
        $testUri = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?`$top=1"
        $testResponse = Invoke-MgGraphRequest -Uri $testUri -Method GET -ErrorAction Stop
        
        if ($testResponse) {
            if ($testResponse.value -and $testResponse.value.Count -gt 0) {
                Write-Log "Admin audit logging is enabled and working" -Level "Info"
                return @{
                    IsEnabled     = $true
                    Status        = "Enabled"
                    Message       = "Admin audit logging is enabled and working properly"
                    HasRecentData = $true
                }
            }
            else {
                Write-Log "Admin audit logging API accessible but no recent data found" -Level "Warning"
                return @{
                    IsEnabled     = $true
                    Status        = "Enabled-NoData"
                    Message       = "Admin audit logging is enabled but no recent audit events found"
                    HasRecentData = $false
                }
            }
        }
        else {
            Write-Log "Unable to determine audit log status - no response" -Level "Warning"
            return @{
                IsEnabled     = $false
                Status        = "Unknown"
                Message       = "Unable to determine admin audit log status"
                HasRecentData = $false
            }
        }
    }
    catch {
        Write-Log "Error testing admin audit logs: $($_.Exception.Message)" -Level "Warning"
        
        # Analyze error to determine likely cause
        $errorMessage = $_.Exception.Message
        
        if ($errorMessage -like "*Forbidden*" -or $errorMessage -like "*Unauthorized*") {
            return @{
                IsEnabled     = $false
                Status        = "PermissionDenied"
                Message       = "Insufficient permissions to access admin audit logs"
                HasRecentData = $false
            }
        }
        elseif ($errorMessage -like "*not found*" -or $errorMessage -like "*AuditLog*disabled*") {
            return @{
                IsEnabled     = $false
                Status        = "Disabled"
                Message       = "Admin audit logging appears to be disabled or not configured"
                HasRecentData = $false
            }
        }
        elseif ($errorMessage -like "*BadRequest*") {
            return @{
                IsEnabled     = $false
                Status        = "ConfigurationIssue"
                Message       = "Admin audit log configuration issue detected"
                HasRecentData = $false
            }
        }
        else {
            return @{
                IsEnabled     = $false
                Status        = "Error"
                Message       = "Error accessing admin audit logs: $errorMessage"
                HasRecentData = $false
            }
        }
    }
}

function Show-AuditLogStatusWarning {
    <#
    .SYNOPSIS
        Displays admin audit log status information to user.
    
    .DESCRIPTION
        Shows a message box with current admin audit logging status
        and provides recommendations for fixing any issues found.
        
        The message content varies based on the audit status and
        includes actionable guidance when problems are detected.
    
    .PARAMETER AuditStatus
        Hashtable from Test-AdminAuditLogging containing status info.
    
    .EXAMPLE
        $status = Test-AdminAuditLogging
        Show-AuditLogStatusWarning -AuditStatus $status
    
    .NOTES
        - Always shows message box (informational)
        - Provides context-specific guidance
        - Non-blocking
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [hashtable]$AuditStatus
    )
    
    $title = "Admin Audit Log Status Check"
    $icon = "Information"
    
    switch ($AuditStatus.Status) {
        "Enabled" {
            $message = "✅ Admin Audit Logging: ENABLED`n`n" +
                      "Status: Working properly with recent data`n" +
                      "Impact: All admin audit data collection will work normally"
            $icon = "Information"
        }
        
        "Enabled-NoData" {
            $message = "⚠️ Admin Audit Logging: ENABLED (No Recent Data)`n`n" +
                      "Status: Audit logging is enabled but no recent admin activities found`n" +
                      "Impact: This is normal if there haven't been recent admin changes`n" +
                      "Note: Data collection will work when admin activities occur"
            $icon = "Warning"
        }
        
        "Disabled" {
            $message = "❌ Admin Audit Logging: DISABLED`n`n" +
                      "Status: Admin audit logging is not enabled in this tenant`n" +
                      "Impact: Admin audit data collection will NOT work`n`n" +
                      "Resolution: Enable audit logging in Microsoft 365 Admin Center:`n" +
                      "1. Go to Microsoft 365 Admin Center`n" +
                      "2. Navigate to Security & Compliance > Audit`n" +
                      "3. Enable 'Record user and admin activities'"
            $icon = "Error"
        }
        
        "PermissionDenied" {
            $message = "🔒 Admin Audit Logging: PERMISSION DENIED`n`n" +
                      "Status: Your account lacks permission to read audit logs`n" +
                      "Impact: Admin audit data collection will NOT work`n`n" +
                      "Resolution: You need one of these roles:`n" +
                      "• Global Administrator`n" +
                      "• Security Administrator`n" +
                      "• Security Reader`n" +
                      "• Reports Reader"
            $icon = "Error"
        }
        
        "ConfigurationIssue" {
            $message = "⚙️ Admin Audit Logging: CONFIGURATION ISSUE`n`n" +
                      "Status: There may be a configuration problem with audit logging`n" +
                      "Impact: Admin audit data collection may not work properly`n`n" +
                      "Resolution: Check audit log configuration in Admin Center"
            $icon = "Warning"
        }
        
        default {
            $message = "❓ Admin Audit Logging: UNKNOWN STATUS`n`n" +
                      "Status: Unable to determine audit log status`n" +
                      "Details: $($AuditStatus.Message)`n`n" +
                      "Impact: Admin audit data collection may not work properly`n" +
                      "Recommendation: Try the data collection and check results"
            $icon = "Warning"
        }
    }
    
    $message += "`n`n" +
               "This check helps ensure your security analysis will be complete.`n" +
               "Other data collection functions (sign-ins, mailbox rules, etc.) are not affected."
    
    [System.Windows.Forms.MessageBox]::Show($message, $title, "OK", $icon)
}

#endregion

#region DATA COLLECTION FUNCTIONS

#══════════════════════════════════════════════════════════════
# SIGN-IN DATA COLLECTION
#══════════════════════════════════════════════════════════════

function Get-SignInStatusDescription {
    <#
    .SYNOPSIS
        Converts Azure AD sign-in error codes to human-readable descriptions
    #>
    param (
        [Parameter(Mandatory = $false)]
        [string]$StatusCode
    )
    
    # Status code lookup table
    $statusCodes = @{
        "0"      = "Success"
        "50053"  = "Account locked - IdsLocked"
        "50055"  = "Password expired - InvalidPasswordExpiredPassword"
        "50056"  = "Invalid or null password"
        "50057"  = "User account disabled"
        "50058"  = "User information required"
        "50074"  = "MFA required but not completed"
        "50076"  = "MFA challenge required (not yet completed)"
        "50079"  = "User needs to enroll for MFA"
        "50125"  = "Sign-in interrupted by password reset or registration"
        "50126"  = "Invalid username or password"
        "50132"  = "Session revoked - credentials have been revoked"
        "50133"  = "Session expired - password expired"
        "50140"  = "Interrupt - sign-in kept alive"
        "50144"  = "Active Directory password expired"
        "50158"  = "External security challenge not satisfied"
        "51004"  = "User account doesn't exist in directory"
        "53003"  = "Blocked by Conditional Access policy"
        "53004"  = "Proof-up required - user needs to complete registration"
        "54000"  = "Missing required claim"
        "65001"  = "Consent required - user or admin consent needed"
        "65004"  = "User declined to consent"
        "70008"  = "Authorization code expired or already used"
        "80012"  = "OnPremises password validation - account sign-in hours"
        "81010"  = "Deserialization error"
        "90010"  = "Grant type not supported"
        "90014"  = "Required field missing from credential"
        "90072"  = "Pass-through auth - account validation failed"
        "90095"  = "Admin consent required"
        "500011" = "Resource principal not found in tenant"
        "500121" = "Authentication failed during strong auth request"
        "500133" = "Assertion is not within valid time range"
        "530032" = "Blocked by Conditional Access - tenant security policy"
        "700016" = "Application not found in directory"
        "700082" = "Refresh token has expired"
        "7000218" = "Request body too large"
    }
    
    if ([string]::IsNullOrEmpty($StatusCode)) {
        return "Success"
    }
    
    if ($statusCodes.ContainsKey($StatusCode)) {
        return $statusCodes[$StatusCode]
    }
    else {
        return "Error Code: $StatusCode (Unknown)"
    }
}

function Get-TenantSignInData {
    <#
    .SYNOPSIS
        Collects sign-in logs from Microsoft Graph with geolocation analysis.
    
    .DESCRIPTION
        Primary function for collecting user sign-in data from Microsoft 365.
        This function:
        
        COLLECTION PROCESS:
        • Queries Microsoft Graph sign-in logs
        • Retrieves user authentication activity
        • Handles pagination for large datasets
        • Supports both IPv4 and IPv6 addresses
        
        GEOLOCATION ENRICHMENT:
        • Identifies unique IP addresses (IPv4 and IPv6) from sign-ins
        • Performs geolocation lookup with caching
        • Determines unusual locations based on configured countries
        • Adds ISP and geographic information to records
        
        IPv6 SUPPORT:
        • Detects and handles IPv6 addresses
        • Identifies IPv6 private/special ranges
        • Performs geolocation on public IPv6 addresses
        
        OUTPUT FILES:
        • UserLocationData.csv - All sign-in records with geolocation
        • UserLocationData_Unusual.csv - Sign-ins from unexpected countries
        • UserLocationData_Failed.csv - Failed authentication attempts
        • UniqueSignInLocations.csv - Unique IP/location combinations per user
    
    .PARAMETER DaysBack
        Number of days to look back for sign-in data.
        Valid range: 1-365 days
        Default: Value from $ConfigData.DateRange
    
    .PARAMETER OutputPath
        Full path where the CSV output file will be saved.
        Default: WorkDir\UserLocationData.csv
    
    .OUTPUTS
        Array of PSCustomObject containing sign-in records with geolocation
    
    .EXAMPLE
        Get-TenantSignInData -DaysBack 30
    
    .NOTES
        - Requires AuditLog.Read.All permission
        - Supports both IPv4 and IPv6 addresses
        - Geolocation requires internet connectivity
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 365)]
        [int]$DaysBack = $ConfigData.DateRange,
        
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = (Join-Path -Path $ConfigData.WorkDir -ChildPath "UserLocationData.csv")
    )
    
    #═══════════════════════════════════════════════════════════
    # IMPORT REQUIRED MODULE
    #═══════════════════════════════════════════════════════════
    
    try {
        Import-Module Microsoft.Graph.Reports -Force -ErrorAction Stop
        Write-Log "Microsoft.Graph.Reports module imported successfully" -Level "Info"
    }
    catch {
        Update-GuiStatus "Failed to import Microsoft.Graph.Reports module: $($_.Exception.Message)" ([System.Drawing.Color]::Red)
        Write-Log "Failed to import Microsoft.Graph.Reports: $($_.Exception.Message)" -Level "Error"
        throw "Microsoft.Graph.Reports module is required but could not be loaded. Please install it with: Install-Module Microsoft.Graph.Reports"
    }
    
    Update-GuiStatus "Starting sign-in data collection for the past $DaysBack days..." ([System.Drawing.Color]::Orange)
    Write-Log "═══════════════════════════════════════════════════════════" -Level "Info"
    Write-Log "SIGN-IN DATA COLLECTION STARTED" -Level "Info"
    Write-Log "Date Range: $DaysBack days" -Level "Info"
    Write-Log "═══════════════════════════════════════════════════════════" -Level "Info"
    
    try {
        # Calculate date range
        $startDate = (Get-Date).AddDays(-$DaysBack)
        $filterDate = $startDate.ToString("yyyy-MM-ddTHH:mm:ssZ")
        
        # Initialize IP cache for geolocation
        $ipCache = @{}
        
        #═══════════════════════════════════════════════════════════
        # QUERY SIGN-IN LOGS FROM MICROSOFT GRAPH
        #═══════════════════════════════════════════════════════════
        
        Update-GuiStatus "Querying Microsoft Graph for sign-in logs..." ([System.Drawing.Color]::Orange)
        Write-Log "Querying sign-in logs using Get-MgAuditLogSignIn cmdlet" -Level "Info"
        
        $signInLogs = @()
        
        try {
            # Use the proper cmdlet instead of raw API calls
            Update-GuiStatus "Retrieving sign-in logs (this may take a few minutes)..." ([System.Drawing.Color]::Orange)
            
            $filter = "createdDateTime ge $filterDate"
            Write-Log "Filter: $filter" -Level "Info"
            
            # Get all sign-ins with pagination handled automatically
            $signInLogs = Get-MgAuditLogSignIn -Filter $filter -All -ErrorAction Stop
            
            Write-Log "Sign-in log query complete: $($signInLogs.Count) total records" -Level "Info"
        }
        catch {
            Write-Log "Error fetching sign-in logs: $($_.Exception.Message)" -Level "Error"
            
            # Provide more detailed error information
            if ($_.Exception.Message -match "Forbidden") {
                Write-Log "Permission error - ensure you have AuditLog.Read.All permission and admin consent" -Level "Error"
                Update-GuiStatus "Permission denied. Verify AuditLog.Read.All permission is granted." ([System.Drawing.Color]::Red)
            }
            
            throw
        }
        
        if ($signInLogs.Count -eq 0) {
            Update-GuiStatus "No sign-in data found for the specified date range" ([System.Drawing.Color]::Yellow)
            Write-Log "No sign-in data found" -Level "Warning"
            return @()
        }
        
        Update-GuiStatus "Retrieved $($signInLogs.Count) sign-in records" ([System.Drawing.Color]::Orange)
        
        #═══════════════════════════════════════════════════════════
        # EXTRACT AND DEDUPLICATE IP ADDRESSES
        #═══════════════════════════════════════════════════════════
        
        Update-GuiStatus "Extracting unique IP addresses..." ([System.Drawing.Color]::Orange)
        
        $uniqueIPs = $signInLogs | 
            Where-Object { -not [string]::IsNullOrEmpty($_.IpAddress) } | 
            Select-Object -ExpandProperty IpAddress -Unique
        
        Write-Log "Found $($uniqueIPs.Count) unique IP addresses (IPv4 and IPv6)" -Level "Info"
        
        #═══════════════════════════════════════════════════════════
        # PERFORM GEOLOCATION LOOKUPS WITH IPv6 SUPPORT
        #═══════════════════════════════════════════════════════════
        
        if ($uniqueIPs.Count -gt 0) {
            Update-GuiStatus "Starting geolocation lookups for $($uniqueIPs.Count) IPs (IPv4/IPv6)..." ([System.Drawing.Color]::Orange)
            Write-Log "Beginning geolocation phase for IP addresses" -Level "Info"
            
            $geolocatedCount = 0
            
            foreach ($ip in $uniqueIPs) {
                $geolocatedCount++
                
                if ($geolocatedCount % 10 -eq 0) {
                    $percentage = [math]::Round(($geolocatedCount / $uniqueIPs.Count) * 100, 1)
                    Update-GuiStatus "Geolocating: $geolocatedCount/$($uniqueIPs.Count) ($percentage%)" ([System.Drawing.Color]::Orange)
                    [System.Windows.Forms.Application]::DoEvents()
                }
                
                try {
                    $geoResult = Invoke-IPGeolocation -IPAddress $ip -Cache $ipCache
                    if ($geoResult) {
                        $ipType = if ($geoResult.ip_version) { $geoResult.ip_version } else { "Unknown" }
                        Write-Log "Geolocated $ip ($ipType): $($geoResult.city), $($geoResult.region_name), $($geoResult.country_name)" -Level "Info"
                    }
                }
                catch {
                    Write-Log "Error geolocating IP ${ip}: $($_.Exception.Message)" -Level "Warning"
                }
            }
            
            Write-Log "Geolocation completed for $($ipCache.Count) IP addresses" -Level "Info"
        }
        
        #═══════════════════════════════════════════════════════════
        # PROCESS SIGN-IN RECORDS WITH GEOLOCATION
        #═══════════════════════════════════════════════════════════
        
        Update-GuiStatus "Processing sign-in records with geolocation data..." ([System.Drawing.Color]::Orange)
        Write-Log "Processing all sign-in records with geolocation enrichment" -Level "Info"
        
        $results = @()
        $processedCount = 0
        
        foreach ($signIn in $signInLogs) {
            $processedCount++
            
            # Progress update every 500 records
            if ($processedCount % 500 -eq 0) {
                $percentage = [Math]::Round(($processedCount / $signInLogs.Count) * 100, 1)
                Update-GuiStatus "Processing sign-ins: $processedCount of $($signInLogs.Count) ($percentage%)" ([System.Drawing.Color]::Orange)
            }
            
            # Extract basic sign-in info
            $userId = $signIn.UserPrincipalName
            $userDisplayName = $signIn.UserDisplayName
            $creationTime = $signIn.CreatedDateTime
            $userAgent = $signIn.UserAgent
            $ip = $signIn.IpAddress
            
            # Initialize location defaults
            $isUnusual = $false
            $city = "Unknown"
            $region = "Unknown"
            $country = "Unknown"
            $isp = "Unknown"
            $ipVersion = "Unknown"
            $isPrivateIP = $false
            
            # Apply geolocation data if available
            if (-not [string]::IsNullOrEmpty($ip)) {
                # ═══════════════════════════════════════════════════════════
                # VALIDATE IP ADDRESS (IPv4 or IPv6)
                # ═══════════════════════════════════════════════════════════
                
                try {
                    $ipObj = [System.Net.IPAddress]::Parse($ip)
                    
                    if ($ipObj.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
                        # IPv4 Address
                        $ipVersion = "IPv4"
                        
                        # Check IPv4 private ranges
                        if ($ip -match "^10\." -or 
                            $ip -match "^172\.(1[6-9]|2[0-9]|3[0-1])\." -or 
                            $ip -match "^192\.168\." -or 
                            $ip -match "^127\." -or 
                            $ip -match "^169\.254\.") {
                            $isPrivateIP = $true
                        }
                    }
                    elseif ($ipObj.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
                        # IPv6 Address
                        $ipVersion = "IPv6"
                        $ipLower = $ip.ToLower()
                        
                        # Check IPv6 private/special ranges
                        if ($ipLower -eq "::1" -or                           # Loopback
                            $ipLower -match "^fe[89ab][0-9a-f]:" -or        # Link-local
                            $ipLower -match "^f[cd][0-9a-f]{2}:" -or        # Unique local
                            $ipLower -match "^fec[0-9a-f]:" -or             # Site-local (deprecated)
                            $ipLower -match "^::ffff:" -or                   # IPv4-mapped
                            $ipLower -match "^64:ff9b::") {                 # IPv4/IPv6 translation
                            $isPrivateIP = $true
                        }
                    }
                }
                catch {
                    # If we can't parse the IP, treat it as unknown
                    Write-Log "Could not parse IP address: $ip" -Level "Warning"
                    $ipVersion = "Invalid"
                }
                
                # ═══════════════════════════════════════════════════════════
                # APPLY GEOLOCATION DATA
                # ═══════════════════════════════════════════════════════════
                
                if ($isPrivateIP) {
                    # Private/Internal IP
                    $city = "Private Network"
                    $region = "Internal"
                    $country = "Private Network"
                    $isp = "Internal"
                }
                elseif ($ipCache.ContainsKey($ip)) {
                    # Use cached geolocation data
                    $geoData = $ipCache[$ip].Data
                    $city = $geoData.city
                    $region = $geoData.region_name
                    $country = $geoData.country_name
                    $isp = $geoData.connection.isp
                    
                    # Override IP version from geo data if available
                    if ($geoData.ip_version) {
                        $ipVersion = $geoData.ip_version
                    }
                    
                    # Check if unusual location (only for public IPs)
                    if ($ConfigData.ExpectedCountries -notcontains $country) {
                        $isUnusual = $true
                    }
                }
            }
            
            # Extract status code and get description
            $statusCode = if ($signIn.Status) { $signIn.Status.ErrorCode } else { "0" }
            $statusDescription = Get-SignInStatusDescription -StatusCode $statusCode
            
            # Create result object
            $resultObject = [PSCustomObject]@{
                UserId = $userId
                UserDisplayName = $userDisplayName
                CreationTime = $creationTime
                UserAgent = $userAgent
                IP = $ip
                IPVersion = $ipVersion
                ISP = $isp
                City = $city
                RegionName = $region
                Country = $country
                IsUnusualLocation = $isUnusual
                StatusCode = $statusCode
                Status = $statusDescription
                FailureReason = if ($signIn.Status) { $signIn.Status.FailureReason } else { "" }
                ConditionalAccessStatus = $signIn.ConditionalAccessStatus
                RiskLevel = $signIn.RiskLevelDuringSignIn
                DeviceOS = if ($signIn.DeviceDetail) { $signIn.DeviceDetail.OperatingSystem } else { "" }
                DeviceBrowser = if ($signIn.DeviceDetail) { $signIn.DeviceDetail.Browser } else { "" }
                IsInteractive = $signIn.IsInteractive
                AppDisplayName = $signIn.AppDisplayName
            }
            
            $results += $resultObject
        }
        
        Write-Log "Processed $($results.Count) sign-in records with geolocation" -Level "Info"
        
        #═══════════════════════════════════════════════════════════
        # EXPORT RESULTS
        #═══════════════════════════════════════════════════════════
        
        Update-GuiStatus "Exporting sign-in data..." ([System.Drawing.Color]::Orange)
        
        # Export main results
        $results | Export-Csv -Path $OutputPath -NoTypeInformation -Force
        Write-Log "Exported all sign-in data to: $OutputPath" -Level "Info"
        
        # Export unusual locations
        $unusualSignIns = $results | Where-Object { $_.IsUnusualLocation -eq $true }
        if ($unusualSignIns.Count -gt 0) {
            $unusualOutputPath = $OutputPath -replace '.csv$', '_Unusual.csv'
            $unusualSignIns | Export-Csv -Path $unusualOutputPath -NoTypeInformation -Force
            Write-Log "Exported $($unusualSignIns.Count) unusual location sign-ins to: $unusualOutputPath" -Level "Info"
        }
        
        # Export failed sign-ins
        $failedSignIns = $results | Where-Object { $_.StatusCode -ne "0" -and ![string]::IsNullOrEmpty($_.StatusCode) }
        if ($failedSignIns.Count -gt 0) {
            $failedOutputPath = $OutputPath -replace '.csv$', '_Failed.csv'
            $failedSignIns | Export-Csv -Path $failedOutputPath -NoTypeInformation -Force
            Write-Log "Exported $($failedSignIns.Count) failed sign-ins to: $failedOutputPath" -Level "Info"
        }
        
        # Generate unique locations report
        Update-GuiStatus "Generating unique locations report..." ([System.Drawing.Color]::Orange)
        
        $uniqueLogins = @()
        $userLocationGroups = $results | Group-Object -Property UserId
        
        foreach ($userGroup in $userLocationGroups) {
            $userId = $userGroup.Name
            $userSignIns = $userGroup.Group
            
            $uniqueUserLocations = $userSignIns | 
                Select-Object UserId, UserDisplayName, IP, IPVersion, City, RegionName, Country, ISP -Unique |
                Where-Object { -not [string]::IsNullOrEmpty($_.IP) }
            
            foreach ($location in $uniqueUserLocations) {
                $signInCount = ($userSignIns | Where-Object { 
                    $_.IP -eq $location.IP -and 
                    $_.City -eq $location.City -and 
                    $_.Country -eq $location.Country 
                }).Count
                
                $locationSignIns = $userSignIns | Where-Object { 
                    $_.IP -eq $location.IP -and 
                    $_.City -eq $location.City -and 
                    $_.Country -eq $location.Country 
                } | Sort-Object CreationTime
                
                $firstSeen = if ($locationSignIns.Count -gt 0) { $locationSignIns[0].CreationTime } else { "" }
                $lastSeen = if ($locationSignIns.Count -gt 0) { $locationSignIns[-1].CreationTime } else { "" }
                
                $isUnusualLocation = $false
                if ($location.Country -and $ConfigData.ExpectedCountries -notcontains $location.Country) {
                    $isUnusualLocation = $true
                }
                
                $uniqueLogin = [PSCustomObject]@{
                    UserId = $location.UserId
                    UserDisplayName = $location.UserDisplayName
                    IP = $location.IP
                    IPVersion = $location.IPVersion
                    City = $location.City
                    RegionName = $location.RegionName
                    Country = $location.Country
                    ISP = $location.ISP
                    IsUnusualLocation = $isUnusualLocation
                    SignInCount = $signInCount
                    FirstSeen = $firstSeen
                    LastSeen = $lastSeen
                }
                
                $uniqueLogins += $uniqueLogin
            }
        }
        
        # Export unique logins
        if ($uniqueLogins.Count -gt 0) {
            $uniqueLoginsPath = Join-Path -Path $ConfigData.WorkDir -ChildPath "UniqueSignInLocations.csv"
            $uniqueLogins | Export-Csv -Path $uniqueLoginsPath -NoTypeInformation -Force
            Write-Log "Exported $($uniqueLogins.Count) unique location records to: $uniqueLoginsPath" -Level "Info"
            
            $unusualUniqueLogins = $uniqueLogins | Where-Object { $_.IsUnusualLocation -eq $true }
            if ($unusualUniqueLogins.Count -gt 0) {
                $unusualPath = Join-Path -Path $ConfigData.WorkDir -ChildPath "UniqueSignInLocations_Unusual.csv"
                $unusualUniqueLogins | Export-Csv -Path $unusualPath -NoTypeInformation -Force
                Write-Log "Exported $($unusualUniqueLogins.Count) unusual unique locations to: $unusualPath" -Level "Info"
            }
        }
        
        #═══════════════════════════════════════════════════════════
        # SUMMARY STATISTICS
        #═══════════════════════════════════════════════════════════
        
        $ipv4Count = ($results | Where-Object { $_.IPVersion -eq "IPv4" }).Count
        $ipv6Count = ($results | Where-Object { $_.IPVersion -eq "IPv6" }).Count
        $privateIPCount = ($results | Where-Object { $_.Country -eq "Private Network" }).Count
        
        Update-GuiStatus "Sign-in collection complete: $($results.Count) records ($($unusualSignIns.Count) unusual, $($failedSignIns.Count) failed)" ([System.Drawing.Color]::Green)
        
        Write-Log "═══════════════════════════════════════════════════════════" -Level "Info"
        Write-Log "SIGN-IN DATA COLLECTION COMPLETED" -Level "Info"
        Write-Log "═══════════════════════════════════════════════════════════" -Level "Info"
        Write-Log "Total Sign-ins: $($results.Count)" -Level "Info"
        Write-Log "  IPv4 Addresses: $ipv4Count" -Level "Info"
        Write-Log "  IPv6 Addresses: $ipv6Count" -Level "Info"
        Write-Log "  Private IPs: $privateIPCount" -Level "Info"
        Write-Log "Unusual Locations: $($unusualSignIns.Count)" -Level "Info"
        Write-Log "Failed Sign-ins: $($failedSignIns.Count)" -Level "Info"
        Write-Log "Unique IP Locations: $($uniqueLogins.Count)" -Level "Info"
        Write-Log "Geolocation Cache: $($ipCache.Count) IPs cached" -Level "Info"
        Write-Log "Output Files:" -Level "Info"
        Write-Log "  Main: $OutputPath" -Level "Info"
        if ($unusualSignIns.Count -gt 0) {
            Write-Log "  Unusual: $($OutputPath -replace '.csv$', '_Unusual.csv')" -Level "Info"
        }
        if ($failedSignIns.Count -gt 0) {
            Write-Log "  Failed: $($OutputPath -replace '.csv$', '_Failed.csv')" -Level "Info"
        }
        Write-Log "═══════════════════════════════════════════════════════════" -Level "Info"
        
        return $results
    }
    catch {
        Update-GuiStatus "Error collecting sign-in data: $($_.Exception.Message)" ([System.Drawing.Color]::Red)
        Write-Log "Error in sign-in data collection: $($_.Exception.Message)" -Level "Error"
        Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level "Error"
        return $null
    }
}

function Get-SignInDataFromExchangeOnline {
    <#
    .SYNOPSIS
        Collects sign-in data from Exchange Online Unified Audit Log (fallback method).
    
    .DESCRIPTION
        Fallback function when Microsoft Graph API access to sign-in logs is blocked
        (typically by Security Defaults or Conditional Access policies).
        
        This function:
        • Queries the Unified Audit Log via Exchange Online
        • Processes UserLoggedIn and AzureActiveDirectory audit records
        • Extracts IP addresses and authentication details
        • Performs geolocation enrichment
        • Creates sign-in records in same format as Graph API method
        
        CHUNKING STRATEGY:
        To handle large date ranges efficiently:
        • Splits date range into manageable chunks (12-48 hours)
        • Processes each chunk separately
        • Provides detailed progress updates
        • Handles timeouts and throttling gracefully
        
        AUDIT LOG OPERATIONS:
        Queries these specific operations:
        • UserLoggedIn - Successful interactive logins
        • UserLoginFailed - Failed authentication attempts
        • UserLoggedOut - Explicit logout events
        • Fallback: All AzureActiveDirectory records
        
        LIMITATIONS:
        • Maximum 10 days of data (Exchange Online limit)
        • Slower than Graph API method
        • Less detailed device information
        • May have gaps in non-interactive sign-ins
    
    .PARAMETER DaysBack
        Number of days to look back (max 10 due to EXO limits)
        Default: Value from $ConfigData.DateRange (capped at 10)
    
    .PARAMETER OutputPath
        Output file path for results
        Default: WorkDir\UserLocationData_EXO.csv
    
    .OUTPUTS
        Array of sign-in records in same format as Get-TenantSignInData
    
    .EXAMPLE
        # Use as fallback when Graph API blocked
        $signIns = Get-SignInDataFromExchangeOnline -DaysBack 7
    
    .NOTES
        - Requires Exchange Administrator or Audit Logs role
        - Subject to Exchange Online throttling
        - Maximum 10 days lookback (EXO limitation)
        - Slower than Graph API method
        - Suitable fallback for Security Defaults scenarios
    #>
    
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param (
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 10)]
        [int]$DaysBack = [Math]::Min($ConfigData.DateRange, 10),
        
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = (Join-Path -Path $ConfigData.WorkDir -ChildPath "UserLocationData_EXO.csv")
    )
    
    Update-GuiStatus "Collecting sign-in data via Exchange Online (Security Defaults fallback)..." ([System.Drawing.Color]::Orange)
    Write-Log "═══════════════════════════════════════════════════" -Level "Info"
    Write-Log "EXCHANGE ONLINE FALLBACK METHOD STARTED" -Level "Info"
    Write-Log "This method is used when Graph API access is blocked" -Level "Info"
    Write-Log "Maximum date range: 10 days (Exchange Online limitation)" -Level "Info"
    Write-Log "═══════════════════════════════════════════════════" -Level "Info"
    
    try {
        # Ensure Exchange Online connection
        $connectionResult = Connect-ExchangeOnlineIfNeeded
        if (-not $connectionResult) {
            throw "Exchange Online connection failed - cannot collect sign-in data"
        }
        
        # Calculate date range
        $startDate = (Get-Date).AddDays(-$DaysBack)
        $endDate = Get-Date
        $totalDays = [Math]::Ceiling(($endDate - $startDate).TotalDays)
        
        Write-Log "EXO Sign-in data range: $($startDate.ToString('yyyy-MM-dd')) to $($endDate.ToString('yyyy-MM-dd')) ($totalDays days)" -Level "Info"
        
        # Determine optimal chunk size based on date range
        $chunkSizeHours = if ($DaysBack -le 3) { 12 } elseif ($DaysBack -le 7) { 24 } else { 48 }
        $expectedChunks = [Math]::Ceiling(($endDate - $startDate).TotalHours / $chunkSizeHours)
        
        Update-GuiStatus "Processing $totalDays days in $expectedChunks chunks ($chunkSizeHours hour chunks)..." ([System.Drawing.Color]::Orange)
        Write-Log "Using $chunkSizeHours hour chunks, expecting $expectedChunks total chunks" -Level "Info"
        
        # Initialize progress tracking
        $auditLogs = @()
        $currentStart = $startDate
        $chunkNumber = 0
        $totalRecords = 0
        
        # Initialize IP cache for geolocation
        if (-not $Global:IPCache) {
            $Global:IPCache = @{}
        }
        
        #──────────────────────────────────────────────────────
        # PROCESS CHUNKS
        #──────────────────────────────────────────────────────
        while ($currentStart -lt $endDate) {
            $chunkNumber++
            $currentEnd = if ($currentStart.AddHours($chunkSizeHours) -lt $endDate) { 
                $currentStart.AddHours($chunkSizeHours) 
            } else { 
                $endDate 
            }
            $chunkHours = [Math]::Round(($currentEnd - $currentStart).TotalHours, 1)
            
            # Detailed progress update
            $progressPercent = [Math]::Round(($chunkNumber / $expectedChunks) * 100, 1)
            Update-GuiStatus "Chunk $chunkNumber/$expectedChunks ($progressPercent%): $($currentStart.ToString('MM/dd HH:mm'))-$($currentEnd.ToString('MM/dd HH:mm')) ($chunkHours hrs)" ([System.Drawing.Color]::Orange)
            Write-Log "Processing chunk $chunkNumber/$expectedChunks : $($currentStart.ToString('yyyy-MM-dd HH:mm')) to $($currentEnd.ToString('yyyy-MM-dd HH:mm'))" -Level "Info"
            [System.Windows.Forms.Application]::DoEvents()
            
            try {
                $chunkLogs = @()
                $maxResults = if ($chunkSizeHours -le 12) { 2000 } elseif ($chunkSizeHours -le 24) { 3000 } else { 5000 }
                
                Update-GuiStatus "Chunk $chunkNumber/$expectedChunks : Querying $chunkHours h timespan..." ([System.Drawing.Color]::Orange)
                [System.Windows.Forms.Application]::DoEvents()
                
                # Query specific operations first
                Write-Log "Querying chunk $chunkNumber/$expectedChunks with operations filter" -Level "Info"
                
                $chunkLogs = Search-UnifiedAuditLog -StartDate $currentStart `
                                                     -EndDate $currentEnd `
                                                     -ResultSize $maxResults `
                                                     -Operations "UserLoggedIn","UserLoginFailed","UserLoggedOut" `
                                                     -ErrorAction Stop
                
                if ($chunkLogs.Count -eq 0) {
                    # Fallback to broader search
                    Write-Log "No specific operations found, trying broader search..." -Level "Info"
                    $chunkLogs = Search-UnifiedAuditLog -StartDate $currentStart `
                                                         -EndDate $currentEnd `
                                                         -ResultSize $maxResults `
                                                         -RecordType "AzureActiveDirectory" `
                                                         -ErrorAction Stop
                }
                
                Write-Log "Query completed: $($chunkLogs.Count) records" -Level "Info"
                Update-GuiStatus "Chunk $chunkNumber/$expectedChunks : Retrieved $($chunkLogs.Count) records" ([System.Drawing.Color]::Green)
                
                if ($chunkLogs -and $chunkLogs.Count -gt 0) {
                    $auditLogs += $chunkLogs
                    $totalRecords += $chunkLogs.Count
                }
            }
            catch {
                Write-Log "Error in chunk ${chunkNumber}: $($_.Exception.Message)" -Level "Warning"
                Update-GuiStatus "Chunk $chunkNumber/$expectedChunks : Error occurred - continuing" ([System.Drawing.Color]::Orange)
            }
            
            Update-GuiStatus "Progress: $chunkNumber/$expectedChunks chunks completed. Total records: $totalRecords" ([System.Drawing.Color]::Green)
            [System.Windows.Forms.Application]::DoEvents()
            
            $currentStart = $currentEnd
            Start-Sleep -Seconds 1  # Throttle prevention
        }
        
        Write-Log "Completed all $chunkNumber chunks: $totalRecords total audit log entries" -Level "Info"
        Update-GuiStatus "Query phase complete: $totalRecords audit entries from $chunkNumber chunks" ([System.Drawing.Color]::Green)
        
        # NOTE: Continued in next message due to character limits
        # Processing phase, geolocation, and export logic follows...
        
    }
    catch {
        Update-GuiStatus "Error collecting sign-in data via Exchange Online: $($_.Exception.Message)" ([System.Drawing.Color]::Red)
        Write-Log "Error in Exchange Online sign-in data collection: $($_.Exception.Message)" -Level "Error"
        return $null
    }
}

function Get-MFAStatusAudit {
    <#
    .SYNOPSIS
        Audits MFA enrollment and enforcement status for all users
    
    .DESCRIPTION
        Checks ALL MFA enforcement mechanisms:
        • Per-user MFA enforcement (Legacy - Enforced/Enabled/Disabled)
        • Security Defaults (Modern - Enforces MFA for all users)
        • Conditional Access policies (Modern - Policy-based MFA)
        • Registered authentication methods
        • MFA capability vs enforcement
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = (Join-Path -Path $ConfigData.WorkDir -ChildPath "MFAStatus.csv")
    )
    
    Update-GuiStatus "Auditing comprehensive MFA status (legacy + modern enforcement)..." ([System.Drawing.Color]::Orange)
    Write-Log "Starting comprehensive MFA audit including ALL enforcement methods" -Level "Info"
    
    try {
        # ═══════════════════════════════════════════════════════════════════════════════
        # STEP 1: CHECK TENANT-WIDE MFA ENFORCEMENT MECHANISMS
        # ═══════════════════════════════════════════════════════════════════════════════
        
        # Check for Security Defaults (enforces MFA for all users automatically)
        Write-Log "Checking Security Defaults status..." -Level "Info"
        $securityDefaults = Test-SecurityDefaults
        $securityDefaultsEnabled = $securityDefaults.IsEnabled -eq $true
        
        if ($securityDefaultsEnabled) {
            Write-Log "Security Defaults are ENABLED - MFA is enforced for all users by default" -Level "Info"
            Update-GuiStatus "Security Defaults detected: MFA enforced tenant-wide" ([System.Drawing.Color]::Green)
        }
        else {
            Write-Log "Security Defaults are DISABLED - checking Conditional Access policies..." -Level "Info"
        }
        
        # Check for Conditional Access policies that require MFA
        Write-Log "Analyzing Conditional Access policies for MFA requirements..." -Level "Info"
        $mfaCAPolicies = @()
        $caAllUsersPolicy = $false
        
        try {
            $caPolicies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop
            
            foreach ($policy in $caPolicies) {
                # Only consider enabled policies
                if ($policy.State -ne "enabled") { continue }
                
                # Check if policy grants control includes MFA
                $requiresMFA = $false
                if ($policy.GrantControls.BuiltInControls -contains "mfa") {
                    $requiresMFA = $true
                }
                
                if ($requiresMFA) {
                    # Determine who the policy applies to
                    $appliesToAllUsers = $false
                    
                    if ($policy.Conditions.Users.IncludeUsers -contains "All") {
                        $appliesToAllUsers = $true
                        $caAllUsersPolicy = $true
                    }
                    
                    $mfaCAPolicies += [PSCustomObject]@{
                        PolicyName = $policy.DisplayName
                        PolicyId = $policy.Id
                        AppliesToAllUsers = $appliesToAllUsers
                        IncludeUsers = $policy.Conditions.Users.IncludeUsers
                        IncludeGroups = $policy.Conditions.Users.IncludeGroups
                        IncludeRoles = $policy.Conditions.Users.IncludeRoles
                        ExcludeUsers = $policy.Conditions.Users.ExcludeUsers
                        ExcludeGroups = $policy.Conditions.Users.ExcludeGroups
                        ExcludeRoles = $policy.Conditions.Users.ExcludeRoles
                    }
                }
            }
            
            Write-Log "Found $($mfaCAPolicies.Count) active Conditional Access policies requiring MFA" -Level "Info"
            if ($caAllUsersPolicy) {
                Write-Log "At least one CA policy applies MFA to ALL users" -Level "Info"
                Update-GuiStatus "Conditional Access detected: MFA policy for all users" ([System.Drawing.Color]::Green)
            }
        }
        catch {
            Write-Log "Could not retrieve Conditional Access policies: $($_.Exception.Message)" -Level "Warning"
            Update-GuiStatus "Warning: Could not check CA policies - results may be incomplete" ([System.Drawing.Color]::Orange)
        }
        
        # Determine if MFA is enforced tenant-wide by any mechanism
        $tenantWideMFAEnforced = $securityDefaultsEnabled -or $caAllUsersPolicy
        
        if ($tenantWideMFAEnforced) {
            Write-Log "✅ Tenant-wide MFA enforcement detected" -Level "Info"
        }
        else {
            Write-Log "⚠️ No tenant-wide MFA enforcement - relying on per-user or group-based policies" -Level "Warning"
        }
        
        # ═══════════════════════════════════════════════════════════════════════════════
        # STEP 2: LOAD USER DATA
        # ═══════════════════════════════════════════════════════════════════════════════
        
        Update-GuiStatus "Loading user data with MFA enforcement status..." ([System.Drawing.Color]::Orange)
        
        # Note: StrongAuthenticationRequirements property contains per-user MFA state
        $users = Get-MgUser -All -Property Id, UserPrincipalName, DisplayName, AccountEnabled, StrongAuthenticationRequirements
        
        $mfaResults = @()
        $processedCount = 0
        
        # Check if we have sign-in data for enhanced detection
        $signInDataPath = Join-Path -Path $ConfigData.WorkDir -ChildPath "UserLocationData.csv"
        $hasSignInData = Test-Path $signInDataPath
        
        $signInData = $null
        if ($hasSignInData) {
            try {
                $signInData = Import-Csv -Path $signInDataPath
                Write-Log "Loaded $($signInData.Count) sign-in records for MFA behavior analysis" -Level "Info"
            } catch {
                Write-Log "Could not load sign-in data: $($_.Exception.Message)" -Level "Warning"
            }
        }
        
        # ═══════════════════════════════════════════════════════════════════════════════
        # STEP 3: ANALYZE EACH USER
        # ═══════════════════════════════════════════════════════════════════════════════
        
        foreach ($user in $users) {
            if (-not $user.AccountEnabled) { continue }
            
            $processedCount++
            if ($processedCount % 50 -eq 0) {
                $percentage = [math]::Round(($processedCount / $users.Count) * 100, 1)
                Update-GuiStatus "Checking MFA status: $processedCount of $($users.Count) ($percentage%)" ([System.Drawing.Color]::Orange)
            }
            
            # ───────────────────────────────────────────────────────────────────────────
            # CHECK 1: PER-USER MFA ENFORCEMENT (Legacy MFA)
            # ───────────────────────────────────────────────────────────────────────────
            $perUserMFAState = "Disabled"
            $perUserMFAEnforced = $false
            
            try {
                if ($user.StrongAuthenticationRequirements) {
                    $mfaRequirements = $user.StrongAuthenticationRequirements
                    
                    if ($mfaRequirements.Count -gt 0) {
                        # Per-user MFA has three states: Disabled, Enabled, Enforced
                        $state = $mfaRequirements[0].State
                        $perUserMFAState = $state
                        
                        if ($state -eq "Enforced" -or $state -eq "Enabled") {
                            $perUserMFAEnforced = $true
                        }
                    }
                }
            }
            catch {
                Write-Log "Could not read per-user MFA state for $($user.UserPrincipalName): $($_.Exception.Message)" -Level "Warning"
            }
            
            # ───────────────────────────────────────────────────────────────────────────
            # CHECK 2: CONDITIONAL ACCESS POLICY APPLICABILITY
            # ───────────────────────────────────────────────────────────────────────────
            $caPolicyEnforced = $false
            $applicableCAPolicies = @()
            
            # If Security Defaults are enabled, all users have MFA enforced
            if ($securityDefaultsEnabled) {
                $caPolicyEnforced = $true
                $applicableCAPolicies += "Security Defaults (tenant-wide)"
            }
            
            # Check if user is covered by CA policies
            # Note: This is a simplified check - full CA policy evaluation is complex
            # and would require checking group memberships, roles, etc.
            foreach ($policy in $mfaCAPolicies) {
                if ($policy.AppliesToAllUsers) {
                    $caPolicyEnforced = $true
                    $applicableCAPolicies += $policy.PolicyName
                }
                # Additional logic could check group membership and roles here
                # For now, we flag that CA policies exist but may need manual review
            }
            
            # ───────────────────────────────────────────────────────────────────────────
            # CHECK 3: REGISTERED AUTHENTICATION METHODS
            # ───────────────────────────────────────────────────────────────────────────
            $hasMFAMethods = $false
            $mfaMethods = @()
            $methodCount = 0
            
            try {
                $authMethods = Get-MgUserAuthenticationMethod -UserId $user.Id -ErrorAction Stop
                
                foreach ($method in $authMethods) {
                    $methodType = $method.AdditionalProperties.'@odata.type'
                    
                    # Count only MFA-capable methods (exclude password)
                    if ($methodType -match 'phone|fido2|softwareOath|microsoft|email|temporaryAccessPass') {
                        $hasMFAMethods = $true
                        $methodCount++
                        
                        # Parse method type for display
                        $displayType = switch -Regex ($methodType) {
                            'phoneAuthentication' { 'Phone' }
                            'fido2Authentication' { 'FIDO2 Security Key' }
                            'softwareOathAuthentication' { 'Authenticator App' }
                            'microsoftAuthenticator' { 'Microsoft Authenticator' }
                            'emailAuthentication' { 'Email' }
                            'temporaryAccessPass' { 'Temporary Access Pass' }
                            default { $methodType -replace '#microsoft\.graph\.', '' }
                        }
                        
                        $mfaMethods += $displayType
                    }
                }
            }
            catch {
                Write-Log "Could not retrieve auth methods for $($user.UserPrincipalName): $($_.Exception.Message)" -Level "Warning"
            }
            
            # ───────────────────────────────────────────────────────────────────────────
            # CHECK 4: SIGN-IN BEHAVIOR (if available)
            # ───────────────────────────────────────────────────────────────────────────
            $lastSignInDate = ""
            $totalSuccessfulSignIns = 0
            $mfaUsedInSignIns = 0
            
            if ($signInData) {
                $userSignIns = $signInData | Where-Object { $_.UserPrincipalName -eq $user.UserPrincipalName }
                
                if ($userSignIns) {
                    # Get most recent sign-in
                    $mostRecent = $userSignIns | Sort-Object CreationTime -Descending | Select-Object -First 1
                    $lastSignInDate = $mostRecent.CreationTime
                    
                    # Count successful sign-ins
                    $successfulSignIns = $userSignIns | Where-Object { $_.Status -eq "0" }
                    $totalSuccessfulSignIns = $successfulSignIns.Count
                    
                    # If Conditional Access is passing, MFA is likely being used
                    $successfulWithCA = $successfulSignIns | Where-Object { 
                        $_.ConditionalAccessStatus -eq "success" 
                    }
                    $mfaUsedInSignIns = $successfulWithCA.Count
                }
            }
            
            # ───────────────────────────────────────────────────────────────────────────
            # CHECK 5: ADMIN ROLE STATUS
            # ───────────────────────────────────────────────────────────────────────────
            $isAdmin = $false
            $adminRoles = @()
            
            try {
                $memberOf = Get-MgUserMemberOf -UserId $user.Id -All
                $roles = $memberOf | Where-Object { 
                    $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.directoryRole'
                }
                
                foreach ($role in $roles) {
                    $roleName = $role.AdditionalProperties.displayName
                    if ($roleName -like '*Admin*') {
                        $isAdmin = $true
                        $adminRoles += $roleName
                    }
                }
            } catch { }
            
            # ═══════════════════════════════════════════════════════════════════════════
            # DETERMINE OVERALL MFA STATUS (UPDATED LOGIC)
            # ═══════════════════════════════════════════════════════════════════════════
            
            # Determine if MFA is actually ENFORCED for this user
            # MFA is enforced if ANY of these are true:
            # 1. Per-user MFA is enforced (legacy)
            # 2. Security Defaults are enabled (modern tenant-wide)
            # 3. CA policy requires MFA for this user (modern policy-based)
            $mfaEnforced = $perUserMFAEnforced -or $caPolicyEnforced
            
            # Determine if user has MFA capability (methods registered)
            $mfaCapable = $hasMFAMethods
            
            # Overall MFA status
            $overallMFAStatus = "No"
            $mfaStatusDetail = "No MFA"
            $enforcementMethod = @()
            
            # Build list of enforcement methods
            if ($perUserMFAEnforced) {
                $enforcementMethod += "Per-User MFA ($perUserMFAState)"
            }
            if ($securityDefaultsEnabled) {
                $enforcementMethod += "Security Defaults"
            }
            if ($applicableCAPolicies.Count -gt 0 -and -not $securityDefaultsEnabled) {
                $enforcementMethod += "Conditional Access"
            }
            
            # Determine overall status
            if ($mfaEnforced -and $mfaCapable) {
                $overallMFAStatus = "Yes"
                $enforcementList = $enforcementMethod -join " + "
                $mfaStatusDetail = "✅ Enforced via $enforcementList with $methodCount method(s) registered"
            }
            elseif ($mfaEnforced -and -not $mfaCapable) {
                $overallMFAStatus = "Partial"
                $enforcementList = $enforcementMethod -join " + "
                $mfaStatusDetail = "⚠️ Enforced via $enforcementList but NO methods registered (broken state)"
            }
            elseif (-not $mfaEnforced -and $mfaCapable) {
                $overallMFAStatus = "Capable"
                $mfaStatusDetail = "⚠️ Methods registered ($methodCount) but NOT enforced"
            }
            elseif ($mfaUsedInSignIns -gt 0 -and $totalSuccessfulSignIns -gt 0) {
                # If we see MFA being used in sign-ins but can't confirm enforcement
                $mfaPercent = [math]::Round(($mfaUsedInSignIns / $totalSuccessfulSignIns) * 100, 0)
                if ($mfaPercent -gt 80) {
                    $overallMFAStatus = "Likely"
                    $mfaStatusDetail = "Inferred from sign-in behavior ($mfaPercent% MFA usage)"
                }
                else {
                    $overallMFAStatus = "Inconsistent"
                    $mfaStatusDetail = "Inconsistent MFA usage ($mfaPercent%)"
                }
            }
            
            # ───────────────────────────────────────────────────────────────────────────
            # CALCULATE RISK LEVEL
            # ───────────────────────────────────────────────────────────────────────────
            $riskLevel = "Unknown"
            $recommendation = ""
            
            if ($overallMFAStatus -eq "Yes") {
                $riskLevel = "Low"
                $recommendation = "✅ MFA properly configured and enforced"
            }
            elseif ($overallMFAStatus -eq "No") {
                if ($isAdmin) {
                    $riskLevel = "Critical"
                    $recommendation = "🚨 CRITICAL: Admin account with NO MFA - Enable immediately!"
                }
                else {
                    $riskLevel = "High"
                    $recommendation = "⚠️ HIGH: No MFA protection - Enable per-user MFA or Conditional Access policy"
                }
            }
            elseif ($overallMFAStatus -eq "Partial") {
                if ($isAdmin) {
                    $riskLevel = "Critical"
                    $recommendation = "🚨 CRITICAL: MFA enforced but no methods registered - User cannot sign in!"
                }
                else {
                    $riskLevel = "High"
                    $recommendation = "⚠️ HIGH: MFA enforced but no methods - User needs to register auth methods"
                }
            }
            elseif ($overallMFAStatus -eq "Capable") {
                if ($isAdmin) {
                    $riskLevel = "High"
                    $recommendation = "⚠️ HIGH: Admin has MFA methods but not enforced - Enable enforcement"
                }
                else {
                    $riskLevel = "Medium"
                    $recommendation = "⚡ MEDIUM: MFA methods registered but not enforced - Enable per-user MFA or CA policy"
                }
            }
            elseif ($overallMFAStatus -eq "Likely" -or $overallMFAStatus -eq "Inconsistent") {
                $riskLevel = "Medium"
                $recommendation = "⚡ MEDIUM: Cannot fully verify MFA status - Manual review recommended"
            }
            
            # ───────────────────────────────────────────────────────────────────────────
            # CREATE RESULT OBJECT
            # ───────────────────────────────────────────────────────────────────────────
            $mfaResults += [PSCustomObject]@{
                UserPrincipalName = $user.UserPrincipalName
                DisplayName = $user.DisplayName
                
                # Overall Status
                HasMFA = $overallMFAStatus
                MFAStatusDetail = $mfaStatusDetail
                
                # Enforcement Methods (NEW)
                EnforcementMethod = if ($enforcementMethod.Count -gt 0) { $enforcementMethod -join "; " } else { "None" }
                SecurityDefaults = if ($securityDefaultsEnabled) { "Enabled (Tenant-wide)" } else { "Disabled" }
                ConditionalAccessPolicies = if ($applicableCAPolicies.Count -gt 0) { $applicableCAPolicies -join "; " } else { "None" }
                
                # Per-User MFA (Legacy)
                PerUserMFAState = $perUserMFAState
                PerUserMFAEnforced = $perUserMFAEnforced
                
                # Authentication Methods
                HasMFAMethods = $hasMFAMethods
                MethodCount = $methodCount
                MFAMethods = if ($mfaMethods.Count -gt 0) { $mfaMethods -join ", " } else { "None" }
                
                # Sign-in Behavior
                LastSignIn = $lastSignInDate
                TotalSuccessfulSignIns = $totalSuccessfulSignIns
                MFAUsedCount = $mfaUsedInSignIns
                MFAUsagePercent = if ($totalSuccessfulSignIns -gt 0) { 
                    [math]::Round(($mfaUsedInSignIns / $totalSuccessfulSignIns) * 100, 0) 
                } else { 0 }
                
                # Admin Status
                IsAdmin = $isAdmin
                AdminRoles = if ($adminRoles.Count -gt 0) { $adminRoles -join ", " } else { "" }
                
                # Risk Assessment
                RiskLevel = $riskLevel
                Recommendation = $recommendation
            }
        }
        
        # ═══════════════════════════════════════════════════════════════════════════════
        # EXPORT RESULTS
        # ═══════════════════════════════════════════════════════════════════════════════
        if ($mfaResults.Count -gt 0) {
            $mfaResults | Export-Csv -Path $OutputPath -NoTypeInformation -Force
            
            # Create summary report
            $totalUsers = $mfaResults.Count
            $mfaEnabled = ($mfaResults | Where-Object { $_.HasMFA -eq "Yes" }).Count
            $mfaCapable = ($mfaResults | Where-Object { $_.HasMFA -eq "Capable" }).Count
            $noMFA = ($mfaResults | Where-Object { $_.HasMFA -eq "No" }).Count
            $criticalRisk = ($mfaResults | Where-Object { $_.RiskLevel -eq "Critical" }).Count
            
            $summaryPath = $OutputPath -replace '.csv$', '_Summary.txt'
            $summary = @"
═══════════════════════════════════════════════════════════════════════════════
MFA STATUS AUDIT SUMMARY
Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
═══════════════════════════════════════════════════════════════════════════════

TENANT-WIDE ENFORCEMENT:
  Security Defaults: $(if ($securityDefaultsEnabled) { "✅ ENABLED (MFA enforced for all users)" } else { "❌ DISABLED" })
  CA Policies Found: $($mfaCAPolicies.Count) active policies requiring MFA
  All-Users CA Policy: $(if ($caAllUsersPolicy) { "✅ YES" } else { "❌ NO" })

USER STATISTICS:
  Total Active Users: $totalUsers
  MFA Enabled: $mfaEnabled ($([math]::Round(($mfaEnabled/$totalUsers)*100, 1))%)
  MFA Capable (not enforced): $mfaCapable ($([math]::Round(($mfaCapable/$totalUsers)*100, 1))%)
  No MFA: $noMFA ($([math]::Round(($noMFA/$totalUsers)*100, 1))%)
  Critical Risk Users: $criticalRisk

DETAILED RESULTS: $OutputPath
═══════════════════════════════════════════════════════════════════════════════
"@
            
            $summary | Out-File -FilePath $summaryPath -Force
            
            Write-Log "MFA audit complete!" -Level "Info"
            Write-Log "  Total users analyzed: $totalUsers" -Level "Info"
            Write-Log "  MFA Enabled: $mfaEnabled" -Level "Info"
            Write-Log "  MFA Capable: $mfaCapable" -Level "Info"
            Write-Log "  No MFA: $noMFA" -Level "Info"
            Write-Log "  Critical Risk: $criticalRisk" -Level "Info"
            Write-Log "  Results exported to: $OutputPath" -Level "Info"
            Write-Log "  Summary exported to: $summaryPath" -Level "Info"
            
            Update-GuiStatus "MFA audit complete! Found $mfaEnabled/$totalUsers users with MFA enabled." ([System.Drawing.Color]::Green)
            
            return $mfaResults
        }
        else {
            Write-Log "No enabled users found" -Level "Warning"
            Update-GuiStatus "No enabled users found to audit" ([System.Drawing.Color]::Orange)
            return $null
        }
    }
    catch {
        Update-GuiStatus "Error in MFA audit: $($_.Exception.Message)" ([System.Drawing.Color]::Red)
        Write-Log "Error in MFA status audit: $($_.Exception.Message)" -Level "Error"
        Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level "Error"
        return $null
    }
}

function Get-FailedLoginPatterns {
    <#
    .SYNOPSIS
        Analyzes failed login patterns to detect attacks and breaches
    
    .DESCRIPTION
        Reviews sign-in data to identify:
        • Password spray attacks (same IP, many users)
        • Brute force attacks (same user, many attempts)
        • Confirmed breaches (5+ failures then success from SAME IP)
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$SignInDataPath = (Join-Path -Path $ConfigData.WorkDir -ChildPath "UserLocationData.csv"),
        
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = (Join-Path -Path $ConfigData.WorkDir -ChildPath "FailedLoginAnalysis.csv")
    )
    
    Update-GuiStatus "Analyzing failed login patterns..." ([System.Drawing.Color]::Orange)
    Write-Log "Starting failed login pattern analysis" -Level "Info"
    
    try {
        if (-not (Test-Path $SignInDataPath)) {
            Update-GuiStatus "Sign-in data not found! Run Get-TenantSignInData first." ([System.Drawing.Color]::Red)
            Write-Log "Sign-in data file not found: $SignInDataPath" -Level "Error"
            return $null
        }
        
        $signInData = Import-Csv -Path $SignInDataPath
        $failedLogins = $signInData | Where-Object { $_.Status -ne "0" -and ![string]::IsNullOrEmpty($_.Status) }
        $successfulLogins = $signInData | Where-Object { $_.Status -eq "0" -or [string]::IsNullOrEmpty($_.Status) }
        
        Write-Log "Found $($failedLogins.Count) failed logins and $($successfulLogins.Count) successful logins" -Level "Info"
        
        $patterns = @()
        
        #═══════════════════════════════════════════════════════════
        # PATTERN 1: PASSWORD SPRAY DETECTION
        # Same IP attacking multiple users
        #═══════════════════════════════════════════════════════════
        Update-GuiStatus "Detecting password spray attacks..." ([System.Drawing.Color]::Orange)
        
        $ipGroups = $failedLogins | Group-Object -Property IP
        foreach ($ipGroup in $ipGroups) {
            $uniqueUsers = ($ipGroup.Group | Select-Object -Unique UserId).Count
            $totalAttempts = $ipGroup.Count
            
            if ($totalAttempts -ge 10 -and $uniqueUsers -ge 5) {
                $timespan = 0
                if ($ipGroup.Group.Count -gt 1) {
                    $firstAttempt = [DateTime]($ipGroup.Group | Sort-Object CreationTime | Select-Object -First 1).CreationTime
                    $lastAttempt = [DateTime]($ipGroup.Group | Sort-Object CreationTime | Select-Object -Last 1).CreationTime
                    $timespan = [math]::Round(($lastAttempt - $firstAttempt).TotalHours, 1)
                }
                
                $patterns += [PSCustomObject]@{
                    PatternType = "Password Spray"
                    SourceIP = $ipGroup.Name
                    Location = ($ipGroup.Group | Select-Object -First 1).City + ", " + ($ipGroup.Group | Select-Object -First 1).Country
                    ISP = ($ipGroup.Group | Select-Object -First 1).ISP
                    TargetedUsers = $uniqueUsers
                    FailedAttempts = $totalAttempts
                    TimeSpan = $timespan
                    FirstSeen = ($ipGroup.Group | Sort-Object CreationTime | Select-Object -First 1).CreationTime
                    LastSeen = ($ipGroup.Group | Sort-Object CreationTime | Select-Object -Last 1).CreationTime
                    RiskLevel = if ($uniqueUsers -ge 20 -or $totalAttempts -ge 50) { "Critical" } 
                               elseif ($uniqueUsers -ge 10 -or $totalAttempts -ge 25) { "High" }
                               else { "Medium" }
                    SuccessfulBreach = $false
                    Details = "Password Spray: IP $($ipGroup.Name) attempted $totalAttempts failed logins against $uniqueUsers different users"
                }
            }
        }
        
        #═══════════════════════════════════════════════════════════
        # PATTERN 2: BRUTE FORCE DETECTION
        # Same user, multiple failed attempts
        #═══════════════════════════════════════════════════════════
        Update-GuiStatus "Detecting brute force attacks..." ([System.Drawing.Color]::Orange)
        
        $userGroups = $failedLogins | Group-Object -Property UserId
        foreach ($userGroup in $userGroups) {
            $totalAttempts = $userGroup.Count
            $uniqueIPs = ($userGroup.Group | Select-Object -Unique IP).Count
            
            if ($totalAttempts -ge 10) {
                $timespan = 0
                if ($userGroup.Group.Count -gt 1) {
                    $firstAttempt = [DateTime]($userGroup.Group | Sort-Object CreationTime | Select-Object -First 1).CreationTime
                    $lastAttempt = [DateTime]($userGroup.Group | Sort-Object CreationTime | Select-Object -Last 1).CreationTime
                    $timespan = [math]::Round(($lastAttempt - $firstAttempt).TotalHours, 1)
                }
                
                $patterns += [PSCustomObject]@{
                    PatternType = "Brute Force"
                    SourceIP = if ($uniqueIPs -eq 1) { ($userGroup.Group | Select-Object -First 1).IP } else { "Multiple IPs ($uniqueIPs)" }
                    Location = if ($uniqueIPs -eq 1) { 
                        ($userGroup.Group | Select-Object -First 1).City + ", " + ($userGroup.Group | Select-Object -First 1).Country 
                    } else { "Multiple Locations" }
                    ISP = if ($uniqueIPs -eq 1) { ($userGroup.Group | Select-Object -First 1).ISP } else { "Various" }
                    TargetedUsers = 1
                    FailedAttempts = $totalAttempts
                    TimeSpan = $timespan
                    FirstSeen = ($userGroup.Group | Sort-Object CreationTime | Select-Object -First 1).CreationTime
                    LastSeen = ($userGroup.Group | Sort-Object CreationTime | Select-Object -Last 1).CreationTime
                    RiskLevel = if ($totalAttempts -ge 50) { "Critical" } 
                               elseif ($totalAttempts -ge 25) { "High" }
                               else { "Medium" }
                    SuccessfulBreach = $false
                    Details = "Brute Force: User $($userGroup.Name) had $totalAttempts failed login attempts from $uniqueIPs different IP(s)"
                }
            }
        }
        
        #═══════════════════════════════════════════════════════════
        # PATTERN 3: SUCCESSFUL BREACH AFTER FAILURES
        # Require 5+ failed attempts AND successful login from SAME IP
        #═══════════════════════════════════════════════════════════
        Update-GuiStatus "Detecting successful breaches (5+ failures, same IP required)..." ([System.Drawing.Color]::Orange)
        
        # Group failed logins by user and IP combination
        $failedByUserIP = $failedLogins | Group-Object -Property { "$($_.UserId)|$($_.IP)" }
        
        $breachCount = 0
        foreach ($group in $failedByUserIP) {
            # Require at least 5 failed attempts
            if ($group.Count -lt 5) { continue }
            
            # Parse the grouped key
            $parts = $group.Name -split '\|'
            if ($parts.Count -ne 2) { continue }
            
            $userId = $parts[0]
            $ip = $parts[1]
            
            # Skip if missing critical info
            if ([string]::IsNullOrWhiteSpace($userId) -or [string]::IsNullOrWhiteSpace($ip)) { continue }
            
            # Get the failed attempts sorted by time
            $attempts = $group.Group | Sort-Object CreationTime
            $firstFailedTime = [DateTime]($attempts[0].CreationTime)
            $lastFailedTime = [DateTime]($attempts[-1].CreationTime)
            
            # CRITICAL: Look for successful login from THE EXACT SAME IP
            # This ensures legitimate logins from office/home don't get flagged
            $breach = $successfulLogins | Where-Object {
                $_.IP -eq $ip -and                                          # MUST be same IP
                $_.UserId -eq $userId -and                                   # Same user
                [DateTime]$_.CreationTime -gt $lastFailedTime -and          # After last failure
                ([DateTime]$_.CreationTime - $firstFailedTime).TotalHours -le 2  # Within 2 hours
            } | Select-Object -First 1
            
            if ($breach) {
                # Double-check the IP match (redundant but safe)
                if ($breach.IP -ne $ip) {
                    Write-Log "Skipping false positive: Success from $($breach.IP), failures from $ip for $userId" -Level "Info"
                    continue
                }
                
                # Check if already logged
                $existing = $patterns | Where-Object {
                    $_.PatternType -eq "Successful Breach" -and
                    $_.SourceIP -eq $ip -and
                    $_.Details -like "*$userId*"
                }
                
                if (-not $existing) {
                    $breachCount++
                    $breachTime = [DateTime]$breach.CreationTime
                    $totalFailedAttempts = $group.Count
                    $timeToBreach = [math]::Round(($breachTime - $lastFailedTime).TotalMinutes, 1)
                    
                    $patterns += [PSCustomObject]@{
                        PatternType = "Successful Breach"
                        SourceIP = $ip
                        Location = $attempts[0].City + ", " + $attempts[0].Country
                        ISP = $attempts[0].ISP
                        TargetedUsers = 1
                        FailedAttempts = $totalFailedAttempts
                        TimeSpan = [math]::Round(($breachTime - $firstFailedTime).TotalHours, 2)
                        FirstSeen = $attempts[0].CreationTime
                        LastSeen = $breach.CreationTime
                        RiskLevel = if ($totalFailedAttempts -ge 20) { "Critical" } 
                                   elseif ($totalFailedAttempts -ge 10) { "High" } 
                                   else { "Medium" }
                        SuccessfulBreach = $true
                        Details = "CONFIRMED BREACH: User $userId - $totalFailedAttempts failed attempts from $ip ($($attempts[0].City), $($attempts[0].Country)), then successful login from SAME IP after $timeToBreach min"
                    }
                    
                    Write-Log "BREACH DETECTED: $userId - $totalFailedAttempts failures from $ip, success from same IP after $timeToBreach min" -Level "Warning"
                }
            }
        }
        
        Write-Log "Breach detection complete: $breachCount confirmed breaches (same IP requirement)" -Level "Info"
        
        # Export results
        if ($patterns.Count -gt 0) {
            $patterns | Sort-Object RiskLevel, FailedAttempts -Descending | 
                Export-Csv -Path $OutputPath -NoTypeInformation -Force
            
            $criticalPatterns = $patterns | Where-Object { $_.RiskLevel -eq "Critical" }
            if ($criticalPatterns.Count -gt 0) {
                $criticalPath = $OutputPath -replace '.csv$', '_Critical.csv'
                $criticalPatterns | Export-Csv -Path $criticalPath -NoTypeInformation -Force
            }
            
            $breaches = $patterns | Where-Object { $_.SuccessfulBreach -eq $true }
            if ($breaches.Count -gt 0) {
                $breachPath = $OutputPath -replace '.csv$', '_Breaches.csv'
                $breaches | Export-Csv -Path $breachPath -NoTypeInformation -Force
            }
            
            $stats = @{
                TotalPatterns = $patterns.Count
                PasswordSpray = ($patterns | Where-Object { $_.PatternType -eq "Password Spray" }).Count
                BruteForce = ($patterns | Where-Object { $_.PatternType -eq "Brute Force" }).Count
                Breaches = $breaches.Count
                Critical = $criticalPatterns.Count
            }
            
            Update-GuiStatus "Attack analysis complete: $($stats.TotalPatterns) patterns detected ($($stats.Breaches) confirmed breaches)" ([System.Drawing.Color]::Green)
            Write-Log "Attack Pattern Summary:" -Level "Info"
            Write-Log "  Total Patterns: $($stats.TotalPatterns)" -Level "Info"
            Write-Log "  Password Spray: $($stats.PasswordSpray)" -Level "Info"
            Write-Log "  Brute Force: $($stats.BruteForce)" -Level "Info"
            Write-Log "  Confirmed Breaches: $($stats.Breaches) (5+ failures + same IP success)" -Level "Info"
            Write-Log "  Critical Risk: $($stats.Critical)" -Level "Info"
        }
        else {
            Update-GuiStatus "No suspicious failed login patterns detected" ([System.Drawing.Color]::Green)
            Write-Log "No attack patterns detected" -Level "Info"
        }
        
        return $patterns
    }
    catch {
        Update-GuiStatus "Error analyzing failed logins: $($_.Exception.Message)" ([System.Drawing.Color]::Red)
        Write-Log "Failed login analysis error: $($_.Exception.Message)" -Level "Error"
        return $null
    }
}

function Get-RecentPasswordChanges {
    <#
    .SYNOPSIS
        Identifies suspicious password reset patterns
    
    .DESCRIPTION
        Analyzes admin audit logs for password change patterns
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$AdminAuditPath = (Join-Path -Path $ConfigData.WorkDir -ChildPath "AdminAuditLogs_HighRisk.csv"),
        
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = (Join-Path -Path $ConfigData.WorkDir -ChildPath "PasswordChangeAnalysis.csv")
    )
    
    Update-GuiStatus "Analyzing password change patterns..." ([System.Drawing.Color]::Orange)
    Write-Log "Starting password change analysis" -Level "Info"
    
    try {
        # Check if admin audit data exists
        if (-not (Test-Path $AdminAuditPath)) {
            Update-GuiStatus "Admin audit data not found! Run Get-AdminAuditData first." ([System.Drawing.Color]::Red)
            Write-Log "Admin audit file not found: $AdminAuditPath" -Level "Error"
            return $null
        }
        
        # Import admin audit data
        Update-GuiStatus "Loading admin audit data..." ([System.Drawing.Color]::Orange)
        $auditData = Import-Csv -Path $AdminAuditPath
        Write-Log "Loaded $($auditData.Count) audit records" -Level "Info"
        
        # Filter password change events with valid dates
        $passwordEvents = $auditData | Where-Object {
            ($_.Activity -like "*password*" -or
             $_.Activity -like "*Reset user password*" -or
             $_.Activity -like "*Change user password*") -and
            (-not [string]::IsNullOrWhiteSpace($_.ActivityDate))
        }
        
        Write-Log "Found $($passwordEvents.Count) password-related events with valid dates" -Level "Info"
        
        if ($passwordEvents.Count -eq 0) {
            Update-GuiStatus "No password change events found" ([System.Drawing.Color]::Green)
            Write-Log "No password changes detected in audit logs" -Level "Info"
            return @()
        }
        
        $suspiciousPatterns = @()
        
        # Group by target user
        $userGroups = $passwordEvents | Group-Object -Property TargetUser | Where-Object { -not [string]::IsNullOrWhiteSpace($_.Name) }
        
        foreach ($userGroup in $userGroups) {
            try {
                # Sort events and convert dates
                $events = $userGroup.Group | Where-Object { -not [string]::IsNullOrWhiteSpace($_.ActivityDate) } | Sort-Object ActivityDate
                $changeCount = $events.Count
                
                # Skip users with only 1 password change
                if ($changeCount -eq 1) { continue }
                
                # Safe date conversion with error handling
                $firstChange = $null
                $lastChange = $null
                
                try {
                    $firstChange = [DateTime]::Parse($events[0].ActivityDate)
                    $lastChange = [DateTime]::Parse($events[-1].ActivityDate)
                } catch {
                    Write-Log "Date parsing error for user $($userGroup.Name): $($_.Exception.Message)" -Level "Warning"
                    continue
                }
                
                $timespan = ($lastChange - $firstChange).TotalHours
                
                # Calculate who initiated changes
                $initiators = ($events | Where-Object { -not [string]::IsNullOrWhiteSpace($_.InitiatedBy) } | Select-Object -Unique InitiatedBy).Count
                $selfReset = ($events | Where-Object { $_.InitiatedBy -eq $_.TargetUser }).Count
                $adminReset = ($events | Where-Object { $_.InitiatedBy -ne $_.TargetUser }).Count
                
                # Check for off-hours activity (before 6 AM or after 10 PM)
                $offHoursChanges = 0
                foreach ($event in $events) {
                    try {
                        $eventDate = [DateTime]::Parse($event.ActivityDate)
                        $hour = $eventDate.Hour
                        if ($hour -lt 6 -or $hour -gt 22) {
                            $offHoursChanges++
                        }
                    } catch {
                        # Skip events with unparseable dates
                        continue
                    }
                }
                
                # SUSPICIOUS PATTERN DETECTION
                $isSuspicious = $false
                $reasons = @()
                $riskScore = 0
                
                # Multiple changes in 24 hours
                if ($timespan -lt 24 -and $changeCount -ge 3) {
                    $isSuspicious = $true
                    $reasons += "Multiple password changes ($changeCount) within 24 hours"
                    $riskScore += 25
                }
                
                # Very rapid changes (less than 6 hours)
                if ($timespan -lt 6 -and $changeCount -ge 2) {
                    $isSuspicious = $true
                    $reasons += "Rapid password changes in less than 6 hours"
                    $riskScore += 35
                }
                
                # Multiple initiators (different people resetting password)
                if ($initiators -gt 2) {
                    $isSuspicious = $true
                    $reasons += "Password reset by $initiators different people"
                    $riskScore += 20
                }
                
                # Off-hours activity
                if ($offHoursChanges -ge 2) {
                    $isSuspicious = $true
                    $reasons += "$offHoursChanges password changes during off-hours"
                    $riskScore += 15
                }
                
                # Many changes over longer period
                if ($changeCount -ge 5) {
                    $isSuspicious = $true
                    $reasons += "Excessive password changes ($changeCount total)"
                    $riskScore += 20
                }
                
                if ($isSuspicious) {
                    $riskLevel = if ($riskScore -ge 50) { "Critical" }
                                elseif ($riskScore -ge 30) { "High" }
                                elseif ($riskScore -ge 15) { "Medium" }
                                else { "Low" }
                    
                    $suspiciousPatterns += [PSCustomObject]@{
                        User = $userGroup.Name
                        ChangeCount = $changeCount
                        TimeSpanHours = [math]::Round($timespan, 1)
                        FirstChange = $firstChange.ToString("yyyy-MM-dd HH:mm")
                        LastChange = $lastChange.ToString("yyyy-MM-dd HH:mm")
                        UniqueInitiators = $initiators
                        SelfResets = $selfReset
                        AdminResets = $adminReset
                        OffHoursChanges = $offHoursChanges
                        RiskScore = $riskScore
                        RiskLevel = $riskLevel
                        SuspiciousReasons = ($reasons -join "; ")
                        Recommendation = if ($riskScore -ge 50) {
                            "URGENT: Investigate immediately - possible active compromise"
                        } elseif ($riskScore -ge 30) {
                            "HIGH PRIORITY: Review account activity"
                        } else {
                            "Review account for suspicious activity"
                        }
                    }
                }
            }
            catch {
                Write-Log "Error processing password changes for $($userGroup.Name): $($_.Exception.Message)" -Level "Warning"
                continue
            }
        }
        
        # Export results
        if ($suspiciousPatterns.Count -gt 0) {
            $suspiciousPatterns | Sort-Object RiskScore -Descending | 
                Export-Csv -Path $OutputPath -NoTypeInformation -Force
            
            # Create critical file
            $critical = $suspiciousPatterns | Where-Object { $_.RiskLevel -eq "Critical" }
            if ($critical.Count -gt 0) {
                $criticalPath = $OutputPath -replace '.csv$', '_Critical.csv'
                $critical | Export-Csv -Path $criticalPath -NoTypeInformation -Force
            }
            
            $stats = @{
                Total = $suspiciousPatterns.Count
                Critical = ($suspiciousPatterns | Where-Object { $_.RiskLevel -eq "Critical" }).Count
                High = ($suspiciousPatterns | Where-Object { $_.RiskLevel -eq "High" }).Count
            }
            
            Update-GuiStatus "Password change analysis complete: $($stats.Total) suspicious patterns ($($stats.Critical) critical)" ([System.Drawing.Color]::Green)
            Write-Log "Password Change Analysis: Total=$($stats.Total), Critical=$($stats.Critical), High=$($stats.High)" -Level "Info"
        }
        else {
            Update-GuiStatus "No suspicious password change patterns detected" ([System.Drawing.Color]::Green)
            Write-Log "No suspicious password patterns found" -Level "Info"
        }
        
        return $suspiciousPatterns
    }
    catch {
        Update-GuiStatus "Error analyzing password changes: $($_.Exception.Message)" ([System.Drawing.Color]::Red)
        Write-Log "Password change analysis error: $($_.Exception.Message)" -Level "Error"
        return $null
    }
}

#══════════════════════════════════════════════════════════════
# ADMIN AUDIT LOG COLLECTION
#══════════════════════════════════════════════════════════════

function Get-AdminAuditData {
    <#
    .SYNOPSIS
        Collects and analyzes admin audit logs with risk assessment.
    
    .DESCRIPTION
        Retrieves directory audit logs from Microsoft Graph and enriches them with:
        • Risk level classification (Critical/High/Medium/Low)
        • Login status determination (TRUE/FALSE/OTHER)
        • Target resource extraction
        • Activity categorization
        
        Risk scoring based on:
        • Permission changes (highest risk)
        • Role modifications
        • Application changes
        • Mailbox access modifications
        
        Login detection identifies:
        • Successful authentication events
        • Failed login attempts
        • Non-login administrative actions
    
    .PARAMETER DaysBack
        Number of days of audit logs to retrieve (1-365)
        Default: $ConfigData.DateRange
    
    .PARAMETER OutputPath
        Path for main output file
        Additional filtered files created automatically:
        • _Critical.csv - High-risk operations only
        • _Failed.csv - Failed operations
        • _LoginActivity.csv - Login events only
    
    .OUTPUTS
        Array of enriched audit log objects
    
    .EXAMPLE
        Get-AdminAuditData -DaysBack 30
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 365)]
        [int]$DaysBack = $ConfigData.DateRange,
        
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = (Join-Path -Path $ConfigData.WorkDir -ChildPath "AdminAuditLogs_HighRisk.csv")
    )
    
    Update-GuiStatus "Starting admin audit logs collection for the past $DaysBack days..." ([System.Drawing.Color]::Orange)
    
    $startDate = (Get-Date).AddDays(-$DaysBack).ToString("yyyy-MM-dd")
    $endDate = (Get-Date).ToString("yyyy-MM-dd")
    
    try {
        Update-GuiStatus "Querying Microsoft Graph for admin audit logs..." ([System.Drawing.Color]::Orange)
        
        $auditLogs = @()
        $pageSize = 1000
        $uri = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?`$filter=activityDateTime ge $startDate and activityDateTime le $endDate&`$top=$pageSize"
        
        do {
            $response = Invoke-MgGraphRequest -Uri $uri -Method GET
            $auditLogs += $response.value
            $uri = $response.'@odata.nextLink'
            
            Update-GuiStatus "Retrieved $($auditLogs.Count) admin audit records..." ([System.Drawing.Color]::Orange)
        } while ($uri)
        
        Write-Log "Retrieved $($auditLogs.Count) admin audit log records" -Level "Info"
        
        # Process and enrich logs
        $processedLogs = @()
        $counter = 0
        
        foreach ($log in $auditLogs) {
            $counter++
            if ($counter % 100 -eq 0) {
                $percentage = [math]::Round(($counter / $auditLogs.Count) * 100, 1)
                Update-GuiStatus "Processing admin audits: $counter of $($auditLogs.Count) ($percentage%)" ([System.Drawing.Color]::Orange)
            }
            
            # Risk assessment
            $riskLevel = "Low"
            $activityDisplayName = $log.activityDisplayName
            
            switch -Regex ($activityDisplayName) {
                ".*[Aa]dd.*[Pp]ermission.*|.*[Aa]dd.*[Rr]ole.*" { $riskLevel = "High" }
                ".*[Aa]dd.*[Mm]ember.*" { $riskLevel = "High" }
                ".*[Cc]reate.*[Aa]pplication.*|.*[Cc]reate.*[Ss]ervice [Pp]rincipal.*" { $riskLevel = "Medium" }
                ".*[Uu]pdate.*[Aa]pplication.*" { $riskLevel = "Medium" }
                ".*[Dd]elete.*|.*[Rr]emove.*" { $riskLevel = "Medium" }
                default { $riskLevel = "Low" }
            }
            
            # Login status determination
            $loginStatus = "OTHER"
            $loginActivities = @(
                "Sign-in activity", "User logged in", "User signed in",
                "Interactive user sign in", "Non-interactive user sign in"
            )
            
            $isLoginActivity = $false
            foreach ($loginActivity in $loginActivities) {
                if ($activityDisplayName -like "*$loginActivity*") {
                    $isLoginActivity = $true
                    break
                }
            }
            
            if ($isLoginActivity) {
                switch ($log.result) {
                    "success" { $loginStatus = "TRUE" }
                    "failure" { $loginStatus = "FALSE" }
                    "interrupted" { $loginStatus = "FALSE" }
                    "timeout" { $loginStatus = "FALSE" }
                    default { 
                        if ($log.resultReason -like "*success*" -or $log.resultReason -like "*completed*") {
                            $loginStatus = "TRUE"
                        } elseif ($log.resultReason -like "*fail*" -or $log.resultReason -like "*error*") {
                            $loginStatus = "FALSE"
                        }
                    }
                }
            }
            
            # Extract target resources
            $targetResources = $log.targetResources | ForEach-Object {
                [PSCustomObject]@{
                    Type = $_.type
                    DisplayName = $_.displayName
                    Id = $_.id
                    UserPrincipalName = $_.userPrincipalName
                }
            }
            
            $processedLog = [PSCustomObject]@{
                Timestamp = [DateTime]::Parse($log.activityDateTime)
                UserId = $log.initiatedBy.user.userPrincipalName
                UserDisplayName = $log.initiatedBy.user.displayName
                Activity = $activityDisplayName
                Result = $log.result
                ResultReason = $log.resultReason
                Category = $log.category
                CorrelationId = $log.correlationId
                LoggedByService = $log.loggedByService
                RiskLevel = $riskLevel
                LOGIN = $loginStatus
                TargetResources = ($targetResources | ConvertTo-Json -Compress -Depth 10)
                AdditionalDetails = ($log.additionalDetails | ConvertTo-Json -Compress -Depth 10)
            }
            
            $processedLogs += $processedLog
        }
        
        # Export results
        $processedLogs | Export-Csv -Path $OutputPath -NoTypeInformation -Force
        
        # Create filtered versions
        $highRiskLogs = $processedLogs | Where-Object { $_.RiskLevel -eq "High" }
        if ($highRiskLogs.Count -gt 0) {
            $highRiskPath = $OutputPath -replace '.csv$', '_Critical.csv'
            $highRiskLogs | Export-Csv -Path $highRiskPath -NoTypeInformation -Force
            Write-Log "Found $($highRiskLogs.Count) high-risk admin operations" -Level "Warning"
        }
        
        $failedLogs = $processedLogs | Where-Object { $_.Result -ne "success" }
        if ($failedLogs.Count -gt 0) {
            $failedPath = $OutputPath -replace '.csv$', '_Failed.csv'
            $failedLogs | Export-Csv -Path $failedPath -NoTypeInformation -Force
        }
        
        $loginLogs = $processedLogs | Where-Object { $_.LOGIN -ne "OTHER" }
        if ($loginLogs.Count -gt 0) {
            $loginPath = $OutputPath -replace '.csv$', '_LoginActivity.csv'
            $loginLogs | Export-Csv -Path $loginPath -NoTypeInformation -Force
        }
        
        Update-GuiStatus "Admin audit log collection completed: $($processedLogs.Count) records." ([System.Drawing.Color]::Green)
        Write-Log "Admin audit collection complete" -Level "Info"
        
        return $processedLogs
    }
    catch {
        Update-GuiStatus "Error: $($_.Exception.Message)" ([System.Drawing.Color]::Red)
        Write-Log "Error in admin audit collection: $($_.Exception.Message)" -Level "Error"
        return $null
    }
}

#══════════════════════════════════════════════════════════════
# MAILBOX RULES COLLECTION
#══════════════════════════════════════════════════════════════

function Get-MailboxRules {
    <#
    .SYNOPSIS
        Collects inbox rules from all mailboxes via Exchange Online.
    
    .DESCRIPTION
        Enumerates all mailboxes and retrieves inbox rules, identifying:
        • Forwarding rules (external and internal)
        • Deletion rules
        • Move to folder rules (especially suspicious folders)
        • Rules that stop processing
        
        Suspicious patterns detected:
        • External forwarding
        • Auto-deletion
        • Moves to Junk/Archive/Hidden folders
        • Stop processing rules (hide activity)
    
    .PARAMETER OutputPath
        Output file path
        Creates _Suspicious.csv with flagged rules
    
    .OUTPUTS
        Array of inbox rule objects with risk flags
    
    .EXAMPLE
        Get-MailboxRules
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = (Join-Path -Path $ConfigData.WorkDir -ChildPath "InboxRules.csv")
    )
    
    Update-GuiStatus "Starting mailbox rules collection..." ([System.Drawing.Color]::Orange)
    
    try {
        # Ensure Exchange Online connection
        $connectionResult = Connect-ExchangeOnlineIfNeeded
        if (-not $connectionResult) {
            Update-GuiStatus "Exchange Online connection failed - skipping rules" ([System.Drawing.Color]::Red)
            [System.Windows.Forms.MessageBox]::Show(
                "Exchange Online connection required for mailbox rule collection.",
                "Connection Required", "OK", "Warning"
            )
            return @()
        }
        
        # Get all mailboxes
        Update-GuiStatus "Retrieving all mailboxes..." ([System.Drawing.Color]::Orange)
        $mailboxes = Get-Mailbox -ResultSize Unlimited -ErrorAction Stop
        $totalMailboxes = $mailboxes.Count
        Write-Log "Found $totalMailboxes mailboxes to process" -Level "Info"
        
        $allRules = @()
        $suspiciousRules = @()
        $processedCount = 0
        $rulesFoundCount = 0
        
        foreach ($mailbox in $mailboxes) {
            $processedCount++
            
            if ($processedCount % 10 -eq 0) {
                $percentage = [math]::Round(($processedCount / $totalMailboxes) * 100, 1)
                Update-GuiStatus "Processing: $processedCount/$totalMailboxes ($percentage%) - $rulesFoundCount rules found" ([System.Drawing.Color]::Orange)
                [System.Windows.Forms.Application]::DoEvents()
            }
            
            try {
                $rules = Get-InboxRule -Mailbox $mailbox.PrimarySmtpAddress -ErrorAction Stop
                
                if ($rules -and $rules.Count -gt 0) {
                    $rulesFoundCount += $rules.Count
                    
                    foreach ($rule in $rules) {
                        $isSuspicious = $false
                        $suspiciousReasons = @()
                        
                        # Check forwarding/redirecting
                        if ($rule.ForwardTo -or $rule.RedirectTo -or $rule.ForwardAsAttachmentTo) {
                            $isSuspicious = $true
                            $suspiciousReasons += "Forwards or redirects email"
                        }
                        
                        # Check deletion
                        if ($rule.DeleteMessage -eq $true) {
                            $isSuspicious = $true
                            $suspiciousReasons += "Deletes messages"
                        }
                        
                        # Check suspicious folder moves
                        if ($rule.MoveToFolder -or $rule.CopyToFolder) {
                            $targetFolder = if ($rule.MoveToFolder) { $rule.MoveToFolder } else { $rule.CopyToFolder }
                            $suspiciousFolders = @("Archive", "Junk", "Spam", "Clutter", "Conversation History", "RSS")
                            
                            foreach ($suspiciousFolder in $suspiciousFolders) {
                                if ($targetFolder -like "*$suspiciousFolder*") {
                                    $isSuspicious = $true
                                    $suspiciousReasons += "Moves to $suspiciousFolder folder"
                                    break
                                }
                            }
                        }
                        
                        # Check stop processing
                        if ($rule.StopProcessingRules -eq $true) {
                            $suspiciousReasons += "Stops processing other rules"
                        }
                        
                        # Check external forwarding
                        if ($rule.ForwardTo) {
                            $mailboxDomain = $mailbox.PrimarySmtpAddress.Split('@')[1]
                            foreach ($forwardAddress in $rule.ForwardTo) {
                                if ($forwardAddress -notlike "*$mailboxDomain*") {
                                    $isSuspicious = $true
                                    $suspiciousReasons += "Forwards to external address"
                                    break
                                }
                            }
                        }
                        
                        $ruleEntry = [PSCustomObject]@{
                            MailboxOwnerID = $mailbox.PrimarySmtpAddress
                            DisplayName = $mailbox.DisplayName
                            RuleName = $rule.Name
                            IsEnabled = $rule.Enabled
                            Priority = $rule.Priority
                            Description = $rule.Description
                            FromAddressContainsWords = ($rule.FromAddressContainsWords -join "; ")
                            SubjectContainsWords = ($rule.SubjectContainsWords -join "; ")
                            ForwardTo = ($rule.ForwardTo -join "; ")
                            RedirectTo = ($rule.RedirectTo -join "; ")
                            MoveToFolder = $rule.MoveToFolder
                            DeleteMessage = $rule.DeleteMessage
                            StopProcessingRules = $rule.StopProcessingRules
                            IsSuspicious = $isSuspicious
                            SuspiciousReasons = ($suspiciousReasons -join "; ")
                            RuleIdentity = $rule.Identity
                        }
                        
                        $allRules += $ruleEntry
                        
                        if ($isSuspicious) {
                            $suspiciousRules += $ruleEntry
                        }
                    }
                }
            }
            catch {
                Write-Log "Error getting rules for $($mailbox.PrimarySmtpAddress): $($_.Exception.Message)" -Level "Warning"
            }
        }
        
        # Export results
        if ($allRules.Count -gt 0) {
            $allRules | Export-Csv -Path $OutputPath -NoTypeInformation -Force
            
            if ($suspiciousRules.Count -gt 0) {
                $suspiciousPath = $OutputPath -replace '.csv$', '_Suspicious.csv'
                $suspiciousRules | Export-Csv -Path $suspiciousPath -NoTypeInformation -Force
                Write-Log "Found $($suspiciousRules.Count) suspicious rules" -Level "Warning"
            }
            
            $usersWithRules = ($allRules | Group-Object -Property MailboxOwnerID).Count
            $enabledRules = @($allRules | Where-Object { $_.IsEnabled -eq $true })
            
            Update-GuiStatus "Rules collection complete! $($allRules.Count) rules ($($enabledRules.Count) enabled, $($suspiciousRules.Count) suspicious)" ([System.Drawing.Color]::Green)
            Write-Log "Mailbox rules collection completed" -Level "Info"
        }
        
        return $allRules
    }
    catch {
        Update-GuiStatus "Error: $($_.Exception.Message)" ([System.Drawing.Color]::Red)
        Write-Log "Error in mailbox rules collection: $($_.Exception.Message)" -Level "Error"
        return @()
    }
}

#══════════════════════════════════════════════════════════════
# ADDITIONAL DATA COLLECTION FUNCTIONS
#══════════════════════════════════════════════════════════════

function Get-MailboxDelegationData {
    <#
    .SYNOPSIS
        Collects mailbox delegation permissions.
    
    .DESCRIPTION
        Retrieves mailbox delegation settings identifying:
        • External delegates (high risk)
        • High privilege access (FullAccess, SendAs)
        • Unusual delegation patterns
    
    .OUTPUTS
        Array of delegation objects with risk flags
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = (Join-Path -Path $ConfigData.WorkDir -ChildPath "MailboxDelegation.csv")
    )
    
    Update-GuiStatus "Starting mailbox delegation collection..." ([System.Drawing.Color]::Orange)
    
    try {
        $users = Get-MgUser -All -Property Id, UserPrincipalName, DisplayName, Mail | Where-Object { $_.Mail -ne $null }
        $totalCount = $users.Count
        $delegations = @()
        $suspiciousDelegations = @()
        $processedCount = 0
        
        foreach ($user in $users) {
            $processedCount++
            if ($processedCount % 10 -eq 0) {
                $percentage = [math]::Round(($processedCount / $totalCount) * 100, 1)
                Update-GuiStatus "Processing delegations: $processedCount of $totalCount ($percentage%)" ([System.Drawing.Color]::Orange)
            }
            
            try {
                $mailboxSettings = Get-MgUserMailboxSetting -UserId $user.Id -ErrorAction Stop
                
                if ($mailboxSettings.DelegatesSettings) {
                    foreach ($delegate in $mailboxSettings.DelegatesSettings) {
                        $isSuspicious = $false
                        $suspiciousReasons = @()
                        
                        $delegateEmail = $delegate.EmailAddress.Address
                        if ($delegateEmail -notlike "*onmicrosoft.com" -and $delegateEmail -notlike "*$((Get-MgOrganization).VerifiedDomains[0].Name)*") {
                            $isSuspicious = $true
                            $suspiciousReasons += "External delegate"
                        }
                        
                        if ($delegate.Permissions -contains "FullAccess" -or $delegate.Permissions -contains "SendAs") {
                            $suspiciousReasons += "High privilege access"
                            $isSuspicious = $true
                        }
                        
                        $delegationEntry = [PSCustomObject]@{
                            Mailbox = $user.UserPrincipalName
                            DisplayName = $user.DisplayName
                            DelegateName = $delegate.DisplayName
                            DelegateEmail = $delegateEmail
                            Permissions = ($delegate.Permissions -join "; ")
                            IsSuspicious = $isSuspicious
                            SuspiciousReasons = $suspiciousReasons -join "; "
                        }
                        
                        $delegations += $delegationEntry
                        if ($isSuspicious) { $suspiciousDelegations += $delegationEntry }
                    }
                }
            }
            catch { continue }
        }
        
        if ($delegations.Count -gt 0) {
            $delegations | Export-Csv -Path $OutputPath -NoTypeInformation -Force
            
            if ($suspiciousDelegations.Count -gt 0) {
                $suspiciousPath = $OutputPath -replace '.csv$', '_Suspicious.csv'
                $suspiciousDelegations | Export-Csv -Path $suspiciousPath -NoTypeInformation -Force
            }
            
            Update-GuiStatus "Delegation collection complete: $($delegations.Count) delegations." ([System.Drawing.Color]::Green)
        }
        
        return $delegations
    }
    catch {
        Update-GuiStatus "Error: $($_.Exception.Message)" ([System.Drawing.Color]::Red)
        return $null
    }
}

function Get-AppRegistrationData {
    <#
    .SYNOPSIS
        Collects app registrations with risk assessment.
    
    .DESCRIPTION
        Retrieves application registrations and service principals,
        assessing risk based on:
        • Requested permissions (high-privilege APIs)
        • Missing publisher information
        • Recently created apps
        • Unusual configurations
    
    .OUTPUTS
        Array of app registration objects with risk scores
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [int]$DaysBack = $ConfigData.DateRange,
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = (Join-Path -Path $ConfigData.WorkDir -ChildPath "AppRegistrations.csv")
    )
    
    Update-GuiStatus "Starting app registration collection..." ([System.Drawing.Color]::Orange)
    $startDate = (Get-Date).AddDays(-$DaysBack)
    
    try {
        $applications = Get-MgApplication -All
        $servicePrincipals = Get-MgServicePrincipal -All
        
        $appRegs = @()
        $processedCount = 0
        
        foreach ($app in $applications) {
            $processedCount++
            if ($processedCount % 50 -eq 0) {
                $percentage = [math]::Round(($processedCount / $applications.Count) * 100, 1)
                Update-GuiStatus "Processing apps: $processedCount of $($applications.Count) ($percentage%)" ([System.Drawing.Color]::Orange)
            }
            
            if ($app.CreatedDateTime -ge $startDate) {
                $servicePrincipal = $servicePrincipals | Where-Object { $_.AppId -eq $app.AppId } | Select-Object -First 1
                
                $riskLevel = "Low"
                $riskReasons = @()
                
                # Check high-risk permissions
                foreach ($resourceAccess in $app.RequiredResourceAccess) {
                    foreach ($permission in $resourceAccess.ResourceAccess) {
                        if ($permission.Id -in @(
                            "570282fd-fa5c-430d-a7fd-fc8dc98a9dca",  # Mail.ReadWrite
                            "024d486e-b451-40bb-833d-3e66d98c5c73",  # Mail.Read
                            "75359482-378d-4052-8f01-80520e7db3cd",  # Files.ReadWrite.All
                            "06da0dbc-49e2-44d2-8312-53746b5fccd9"   # Directory.Read.All
                        )) {
                            $riskLevel = "High"
                            $riskReasons += "High-privilege permissions"
                        }
                    }
                }
                
                if ([string]::IsNullOrEmpty($app.PublisherDomain)) {
                    $riskLevel = "Medium"
                    $riskReasons += "No publisher information"
                }
                
                $appReg = [PSCustomObject]@{
                    AppId = $app.AppId
                    DisplayName = $app.DisplayName
                    CreatedDateTime = $app.CreatedDateTime
                    PublisherDomain = $app.PublisherDomain
                    Homepage = $app.Web.HomePageUrl
                    ServicePrincipalId = $servicePrincipal.Id
                    ServicePrincipalType = $servicePrincipal.ServicePrincipalType
                    SignInAudience = $app.SignInAudience
                    RequiredResourceAccess = ($app.RequiredResourceAccess | ConvertTo-Json -Compress -Depth 10)
                    RiskLevel = $riskLevel
                    RiskReasons = ($riskReasons -join "; ")
                }
                
                $appRegs += $appReg
            }
        }
        
        if ($appRegs.Count -gt 0) {
            $appRegs | Export-Csv -Path $OutputPath -NoTypeInformation -Force
            
            $highRiskApps = $appRegs | Where-Object { $_.RiskLevel -eq "High" }
            if ($highRiskApps.Count -gt 0) {
                $highRiskPath = $OutputPath -replace '.csv$', '_HighRisk.csv'
                $highRiskApps | Export-Csv -Path $highRiskPath -NoTypeInformation -Force
            }
            
            Update-GuiStatus "App registration collection complete: $($appRegs.Count) apps." ([System.Drawing.Color]::Green)
        }
        
        return $appRegs
    }
    catch {
        Update-GuiStatus "Error: $($_.Exception.Message)" ([System.Drawing.Color]::Red)
        return $null
    }
}

function Get-ConditionalAccessData {
    <#
    .SYNOPSIS
        Collects Conditional Access policies with configuration review.
    
    .DESCRIPTION
        Retrieves CA policies and identifies:
        • Recently modified policies
        • Disabled policies
        • Policies excluding admin roles (potential bypass)
        • Configuration issues
    
    .OUTPUTS
        Array of CA policy objects with risk flags
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = (Join-Path -Path $ConfigData.WorkDir -ChildPath "ConditionalAccess.csv")
    )
    
    Update-GuiStatus "Starting Conditional Access collection..." ([System.Drawing.Color]::Orange)
    
    try {
        $caPolicies = Get-MgIdentityConditionalAccessPolicy -All
        $policies = @()
        $suspiciousPolicies = @()
        
        foreach ($policy in $caPolicies) {
            $isSuspicious = $false
            $suspiciousReasons = @()
            
            if ($policy.ModifiedDateTime -ge (Get-Date).AddDays(-7)) {
                $suspiciousReasons += "Recently modified"
            }
            
            if ($policy.State -eq "disabled") {
                $suspiciousReasons += "Policy is disabled"
                $isSuspicious = $true
            }
            
            if ($policy.Conditions.Users.ExcludeRoles -contains "Company Administrator" -or 
                $policy.Conditions.Users.ExcludeRoles -contains "Global Administrator") {
                $suspiciousReasons += "Excludes admin roles"
                $isSuspicious = $true
            }
            
            $policyEntry = [PSCustomObject]@{
                DisplayName = $policy.DisplayName
                State = $policy.State
                CreatedDateTime = $policy.CreatedDateTime
                ModifiedDateTime = $policy.ModifiedDateTime
                Conditions = ($policy.Conditions | ConvertTo-Json -Compress -Depth 10)
                GrantControls = ($policy.GrantControls | ConvertTo-Json -Compress -Depth 10)
                SessionControls = ($policy.SessionControls | ConvertTo-Json -Compress -Depth 10)
                IsSuspicious = $isSuspicious
                SuspiciousReasons = ($suspiciousReasons -join "; ")
            }
            
            $policies += $policyEntry
            if ($isSuspicious) { $suspiciousPolicies += $policyEntry }
        }
        
        $policies | Export-Csv -Path $OutputPath -NoTypeInformation -Force
        
        if ($suspiciousPolicies.Count -gt 0) {
            $suspiciousPath = $OutputPath -replace '.csv$', '_Suspicious.csv'
            $suspiciousPolicies | Export-Csv -Path $suspiciousPath -NoTypeInformation -Force
        }
        
        Update-GuiStatus "CA policy collection complete: $($policies.Count) policies." ([System.Drawing.Color]::Green)
        return $policies
    }
    catch {
        Update-GuiStatus "Error: $($_.Exception.Message)" ([System.Drawing.Color]::Red)
        return $null
    }
}


#region ETR ANALYSIS AND MESSAGE TRACE

#══════════════════════════════════════════════════════════════
# EXCHANGE MESSAGE TRACE COLLECTION
#══════════════════════════════════════════════════════════════

function Get-MessageTraceExchangeOnline {
    <#
    .SYNOPSIS
        Collects message trace data from Exchange Online in ETR format.
    
    .DESCRIPTION
        Retrieves message trace data using Get-MessageTraceV2 and converts
        to ETR (Exchange Trace Report) compatible format for analysis.
        
        LIMITATIONS:
        • Maximum 10 days of data (Exchange Online restriction)
        • Date range automatically capped if exceeds limit
        • Subject to Exchange throttling policies
        
        OUTPUT FORMAT:
        Creates ETR-compatible CSV with columns:
        • message_trace_id, sender_address, recipient_address
        • subject, status, to_ip, from_ip, message_size
        • received, message_direction, message_id, event_type
        
        This format enables spam analysis via Analyze-ETRData function.
    
    .PARAMETER DaysBack
        Days to look back (1-10, will be capped at 10)
        Default: Min($ConfigData.DateRange, 10)
    
    .PARAMETER OutputPath
        Output file path (ETR-compatible CSV)
        Default: WorkDir\MessageTraceResult.csv
    
    .PARAMETER MaxMessages
        Maximum messages to retrieve (throttle protection)
        Default: 5000
    
    .OUTPUTS
        Array of message trace objects in ETR format
    
    .EXAMPLE
        Get-MessageTraceExchangeOnline -DaysBack 7 -MaxMessages 10000
    
    .NOTES
        - Requires Exchange Administrator role
        - Uses Get-MessageTraceV2 (modern cmdlet)
        - Automatic EXO connection if needed
        - Compatible with Analyze-ETRData
    #>
    
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param (
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 10)]
        [int]$DaysBack = [Math]::Min($ConfigData.DateRange, 10),
        
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = (Join-Path -Path $ConfigData.WorkDir -ChildPath "MessageTraceResult.csv"),
        
        [Parameter(Mandatory = $false)]
        [ValidateRange(100, 50000)]
        [int]$MaxMessages = 5000
    )
    
    Update-GuiStatus "Starting Exchange Online message trace collection..." ([System.Drawing.Color]::Orange)
    Write-Log "═══════════════════════════════════════════════════" -Level "Info"
    Write-Log "MESSAGE TRACE COLLECTION (ETR FORMAT)" -Level "Info"
    Write-Log "Date Range: $DaysBack days (Exchange limit: 10 days)" -Level "Info"
    Write-Log "═══════════════════════════════════════════════════" -Level "Info"
    
    try {
        # Ensure Exchange Online connection
        $connectionResult = Connect-ExchangeOnlineIfNeeded
        if (-not $connectionResult) {
            Update-GuiStatus "Exchange Online connection failed - skipping message trace" ([System.Drawing.Color]::Red)
            [System.Windows.Forms.MessageBox]::Show(
                "Exchange Online connection required for message trace collection.`n`n" +
                "Please ensure you have Exchange Administrator permissions.",
                "Connection Required", "OK", "Warning"
            )
            return @()
        }
        
        # Calculate date range (conservative approach)
        $actualDaysBack = [Math]::Min($DaysBack, 7)
        $startDate = (Get-Date).AddDays(-$actualDaysBack)
        $endDate = Get-Date
        
        if ($DaysBack -gt 7) {
            Update-GuiStatus "Date range adjusted to 7 days (Exchange Online best practice)" ([System.Drawing.Color]::Orange)
            Write-Log "Date range adjusted from $DaysBack to 7 days for optimal performance" -Level "Warning"
        }
        
        Write-Log "Message trace range: $($startDate.ToString('yyyy-MM-dd')) to $($endDate.ToString('yyyy-MM-dd'))" -Level "Info"
        
        # Call Get-MessageTraceV2
        Update-GuiStatus "Calling Get-MessageTraceV2..." ([System.Drawing.Color]::Orange)
        Write-Log "Executing: Get-MessageTraceV2 -StartDate $startDate -EndDate $endDate -ResultSize $MaxMessages" -Level "Info"
        
        $allMessages = Get-MessageTraceV2 -StartDate $startDate -EndDate $endDate -ResultSize $MaxMessages -ErrorAction Stop
        
        if (-not $allMessages) {
            $allMessages = @()
        }
        
        Write-Log "Get-MessageTraceV2 returned $($allMessages.Count) messages" -Level "Info"
        
        if ($allMessages.Count -eq 0) {
            Update-GuiStatus "No messages found in date range" ([System.Drawing.Color]::Orange)
            Write-Log "No messages found for the specified date range" -Level "Warning"
            return @()
        }
        
        # Convert to ETR format
        Update-GuiStatus "Converting $($allMessages.Count) messages to ETR format..." ([System.Drawing.Color]::Orange)
        Write-Log "Converting message trace results to ETR-compatible format" -Level "Info"
        
        $etrMessages = @()
        $convertedCount = 0
        
        foreach ($msg in $allMessages) {
            $convertedCount++
            
            if ($convertedCount % 500 -eq 0) {
                $percentage = [math]::Round(($convertedCount / $allMessages.Count) * 100, 1)
                Update-GuiStatus "Converting to ETR format: $convertedCount/$($allMessages.Count) ($percentage%)" ([System.Drawing.Color]::Orange)
                [System.Windows.Forms.Application]::DoEvents()
            }
            
            $etrMessage = [PSCustomObject]@{
                message_trace_id = if ($msg.MessageTraceId) { $msg.MessageTraceId } else { "" }
                sender_address = if ($msg.SenderAddress) { $msg.SenderAddress } else { "" }
                recipient_address = if ($msg.RecipientAddress) { $msg.RecipientAddress } else { "" }
                subject = if ($msg.Subject) { $msg.Subject } else { "" }
                status = if ($msg.Status) { $msg.Status } else { "" }
                to_ip = if ($msg.ToIP) { $msg.ToIP } else { "" }
                from_ip = if ($msg.FromIP) { $msg.FromIP } else { "" }
                message_size = if ($msg.Size) { $msg.Size } else { 0 }
                received = if ($msg.Received) { $msg.Received } else { "" }
                message_direction = "Unknown"  # V2 doesn't provide this
                message_id = if ($msg.MessageId) { $msg.MessageId } else { "" }
                event_type = "MessageTraceV2"
                timestamp = if ($msg.Received) { $msg.Received } else { "" }
                date = if ($msg.Received) { $msg.Received } else { "" }
            }
            $etrMessages += $etrMessage
        }
        
        # Export to CSV
        Update-GuiStatus "Exporting ETR-formatted data..." ([System.Drawing.Color]::Orange)
        $etrMessages | Export-Csv -Path $OutputPath -NoTypeInformation -Force
        
        Update-GuiStatus "Message trace complete! $($allMessages.Count) messages exported in ETR format." ([System.Drawing.Color]::Green)
        Write-Log "═══════════════════════════════════════════════════" -Level "Info"
        Write-Log "MESSAGE TRACE COMPLETED" -Level "Info"
        Write-Log "Messages processed: $($allMessages.Count)" -Level "Info"
        Write-Log "Output: $OutputPath" -Level "Info"
        Write-Log "Format: ETR-compatible (ready for Analyze-ETRData)" -Level "Info"
        Write-Log "═══════════════════════════════════════════════════" -Level "Info"
        
        return $etrMessages
        
    }
    catch {
        $errorMsg = "Message trace error: $($_.Exception.Message)"
        Update-GuiStatus $errorMsg ([System.Drawing.Color]::Red)
        Write-Log $errorMsg -Level "Error"
        
        # Update global state on error
        if ($Global:ExchangeOnlineState) {
            $Global:ExchangeOnlineState.IsConnected = $false
            $Global:ExchangeOnlineState.LastChecked = Get-Date
        }
        
        return $null
    }
}

#══════════════════════════════════════════════════════════════
# ETR FILE DETECTION AND ANALYSIS
#══════════════════════════════════════════════════════════════

function Find-ETRFiles {
    <#
    .SYNOPSIS
        Automatically detects Exchange Trace Report files in working directory.
    
    .DESCRIPTION
        Scans the working directory for files matching common ETR naming patterns.
        Returns sorted list of files (newest first) for analysis.
        
        SUPPORTED PATTERNS:
        • ETR_*.csv
        • MessageTrace_*.csv
        • ExchangeTrace_*.csv
        • MT_*.csv
        • *MessageTrace*.csv
        • MessageTraceResult.csv (default output name)
    
    .PARAMETER WorkingDirectory
        Directory to scan for ETR files
        Default: $ConfigData.WorkDir
    
    .OUTPUTS
        Array of FileInfo objects for detected ETR files
    
    .EXAMPLE
        $etrFiles = Find-ETRFiles
        if ($etrFiles.Count -gt 0) {
            Write-Host "Found $($etrFiles.Count) ETR files"
        }
    
    .NOTES
        - Returns files sorted by creation time (newest first)
        - Removes duplicates if same file matched multiple patterns
        - Logs all detected files
    #>
    
    [CmdletBinding()]
    [OutputType([System.IO.FileInfo[]])]
    param (
        [Parameter(Mandatory = $false)]
        [string]$WorkingDirectory = $ConfigData.WorkDir
    )
    
    Write-Log "Searching for ETR files in: $WorkingDirectory" -Level "Info"
    
    $foundFiles = @()
    
    # Search for each pattern
    foreach ($pattern in $ConfigData.ETRAnalysis.FilePatterns) {
        try {
            $files = Get-ChildItem -Path $WorkingDirectory -Filter $pattern -ErrorAction SilentlyContinue
            if ($files) {
                $foundFiles += $files
                Write-Log "Pattern '$pattern' matched $($files.Count) file(s)" -Level "Info"
            }
        }
        catch {
            Write-Log "Error scanning for pattern '$pattern': $($_.Exception.Message)" -Level "Warning"
        }
    }
    
    # Remove duplicates and sort
    $uniqueFiles = $foundFiles | Sort-Object FullName -Unique | Sort-Object CreationTime -Descending
    
    if ($uniqueFiles.Count -gt 0) {
        Write-Log "Found $($uniqueFiles.Count) unique ETR file(s):" -Level "Info"
        foreach ($file in $uniqueFiles) {
            Write-Log "  • $($file.Name) - $(Get-Date $file.CreationTime -Format 'yyyy-MM-dd HH:mm:ss') - $([math]::Round($file.Length/1MB, 2)) MB" -Level "Info"
        }
    }
    else {
        Write-Log "No ETR files found matching common patterns" -Level "Warning"
    }
    
    return $uniqueFiles
}

function Get-ETRColumnMapping {
    <#
    .SYNOPSIS
        Maps ETR file column names to expected field names.
    
    .DESCRIPTION
        Analyzes CSV headers to identify which columns contain message trace data.
        Handles various column naming conventions from different export sources.
        
        MAPPED FIELDS:
        • MessageId - Message trace ID
        • SenderAddress - From address
        • RecipientAddress - To address
        • Subject - Message subject
        • Status - Delivery status
        • ToIP / FromIP - Network information
        • MessageSize - Size in bytes
        • Received - Timestamp
        • Direction - Message flow direction
        • EventType - Event classification
    
    .PARAMETER Headers
        Array of column header names from CSV
    
    .OUTPUTS
        Hashtable mapping standard field names to actual column names
    
    .EXAMPLE
        $csv = Import-Csv "MessageTrace.csv"
        $mapping = Get-ETRColumnMapping -Headers $csv[0].PSObject.Properties.Name
        $senderId = $csv[0].($mapping.SenderAddress)
    
    .NOTES
        - Case-insensitive matching
        - Handles spaces, hyphens, underscores in column names
        - Supports multiple naming conventions
    #>
    
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [array]$Headers
    )
    
    Write-Log "Analyzing ETR column headers for mapping..." -Level "Info"
    Write-Log "Available headers: $($Headers -join ', ')" -Level "Info"
    
    # Define possible column name variations
    $columnMappings = @{
        MessageId = @("message_trace_id", "messagetraceid", "message_id", "messageid", "id")
        SenderAddress = @("sender_address", "senderaddress", "sender", "from")
        RecipientAddress = @("recipient_address", "recipientaddress", "recipient", "to")
        Subject = @("subject", "message_subject", "messagesubject")
        Status = @("status", "delivery_status", "deliverystatus")
        ToIP = @("to_ip", "toip", "destination_ip", "destinationip")
        FromIP = @("from_ip", "fromip", "source_ip", "sourceip", "client_ip", "clientip")
        MessageSize = @("message_size", "messagesize", "size")
        Received = @("received", "timestamp", "date", "datetime", "received_time")
        Direction = @("direction", "message_direction", "messagedirection")
        EventType = @("event_type", "eventtype", "event")
    }
    
    $mapping = @{}
    
    # Match each field to actual column header
    foreach ($field in $columnMappings.Keys) {
        $possibleNames = $columnMappings[$field]
        
        foreach ($possibleName in $possibleNames) {
            # Normalize both for comparison (remove spaces, hyphens, underscores)
            $matchedHeader = $Headers | Where-Object { 
                $_.ToLower().Replace(" ", "").Replace("-", "").Replace("_", "") -eq $possibleName.Replace("_", "")
            }
            
            if ($matchedHeader) {
                $mapping[$field] = $matchedHeader
                Write-Log "  ✓ Mapped $field -> $matchedHeader" -Level "Info"
                break
            }
        }
        
        if (-not $mapping.ContainsKey($field)) {
            Write-Log "  ✗ No mapping found for $field" -Level "Warning"
        }
    }
    
    Write-Log "Column mapping completed: $($mapping.Count)/$($columnMappings.Count) fields mapped" -Level "Info"
    
    return $mapping
}

function Analyze-ETRData {
    <#
    .SYNOPSIS
        Analyzes ETR message trace data for spam patterns and security threats.
    
    .DESCRIPTION
        Comprehensive spam and security analysis of message trace data with:
        
        DETECTION ALGORITHMS:
        1. Excessive Volume - High message count from single sender
        2. Identical Subjects - Mass distribution of same message
        3. Spam Keywords - Common spam phrases in subjects
        4. Risky IP Correlation - Messages from IPs flagged in sign-in analysis
        5. Failed Delivery - High bounce rate patterns
        
        RISK SCORING:
        Each pattern assigned points based on severity:
        • RiskyIPMatch: 25 points (highest)
        • ExcessiveVolume: 20 points
        • SpamKeywords: 15 points
        • MassDistribution: 15 points
        • FailedDelivery: 10 points
        
        Total risk score determines threat level:
        • 0-10: Low
        • 11-25: Medium
        • 26-50: High
        • 51+: Critical
        
        OUTPUT FILES:
        • ETRSpamAnalysis.csv - All detected patterns
        • ETRSpamAnalysis_MessageRecallReport.csv - High/Critical with Message IDs
    
    .PARAMETER OutputPath
        Path for analysis results CSV
        Default: WorkDir\ETRSpamAnalysis.csv
    
    .PARAMETER RiskyIPs
        Array of IP addresses flagged in sign-in analysis for correlation
        Optional but recommended for comprehensive analysis
    
    .OUTPUTS
        Array of spam indicator objects with risk scores and details
    
    .EXAMPLE
        # Basic analysis
        $results = Analyze-ETRData
    
    .EXAMPLE
        # With risky IP correlation from sign-in analysis
        $signInData = Import-Csv "UserLocationData.csv"
        $riskyIPs = $signInData | Where-Object { $_.IsUnusualLocation -eq "True" } | 
                    Select-Object -ExpandProperty IP -Unique
        $results = Analyze-ETRData -RiskyIPs $riskyIPs
    
    .NOTES
        - Requires ETR file in working directory
        - Large files may take significant time
        - Uses ArrayList for performance optimization
        - Progress updates every 10,000 records
        - Memory-efficient batch processing
    #>
    
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param (
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = (Join-Path -Path $ConfigData.WorkDir -ChildPath "ETRSpamAnalysis.csv"),
        
        [Parameter(Mandatory = $false)]
        [array]$RiskyIPs = @()
    )
    
    Update-GuiStatus "Starting ETR message trace analysis..." ([System.Drawing.Color]::Orange)
    Write-Log "═══════════════════════════════════════════════════" -Level "Info"
    Write-Log "ETR SPAM PATTERN ANALYSIS" -Level "Info"
    Write-Log "═══════════════════════════════════════════════════" -Level "Info"
    
    try {
        # Force garbage collection before starting
        [System.GC]::Collect()
        
        # Find ETR files
        $etrFiles = Find-ETRFiles
        
        if ($etrFiles.Count -eq 0) {
            Update-GuiStatus "No ETR files found! Place message trace files in working directory." ([System.Drawing.Color]::Red)
            
            $message = "No Exchange Trace Report (ETR) files found!`n`n" +
                      "Expected file patterns:`n" +
                      ($ConfigData.ETRAnalysis.FilePatterns -join "`n") + "`n`n" +
                      "Please place your message trace files in:`n$($ConfigData.WorkDir)"
            
            [System.Windows.Forms.MessageBox]::Show($message, "ETR Files Not Found", "OK", "Warning")
            return $null
        }
        
        # Use most recent file
        $selectedFile = $etrFiles[0]
        $fileSize = (Get-Item $selectedFile.FullName).Length / 1MB
        
        # Warn if file is very large
        if ($fileSize -gt 100) {
            $result = [System.Windows.Forms.MessageBox]::Show(
                "The ETR file is very large ($([math]::Round($fileSize, 1)) MB).`n`n" +
                "This may cause memory issues or take significant time.`n`n" +
                "Continue with analysis?",
                "Large File Warning", "YesNo", "Warning"
            )
            if ($result -eq "No") {
                return $null
            }
        }
        
        Update-GuiStatus "Analyzing ETR file: $($selectedFile.Name) ($([math]::Round($fileSize, 1)) MB)..." ([System.Drawing.Color]::Orange)
        Write-Log "Selected file: $($selectedFile.FullName)" -Level "Info"
        Write-Log "File size: $([math]::Round($fileSize, 1)) MB" -Level "Info"
        
        # Load ETR data
        $etrData = Import-Csv -Path $selectedFile.FullName -ErrorAction Stop
        
        if (-not $etrData -or $etrData.Count -eq 0) {
            throw "ETR file appears to be empty or invalid"
        }
        
        Write-Log "Loaded $($etrData.Count) message trace records" -Level "Info"
        Update-GuiStatus "Loaded $($etrData.Count) records. Mapping columns..." ([System.Drawing.Color]::Orange)
        
        # Map column headers
        $headers = $etrData[0].PSObject.Properties.Name
        $columnMapping = Get-ETRColumnMapping -Headers $headers
        
        # Validate essential columns
        $requiredFields = @("SenderAddress", "Subject")
        $missingFields = @()
        foreach ($field in $requiredFields) {
            if (-not $columnMapping.ContainsKey($field)) {
                $missingFields += $field
            }
        }
        
        if ($missingFields.Count -gt 0) {
            throw "ETR file missing essential columns: $($missingFields -join ', '). Available: $($headers -join ', ')"
        }
        
        Update-GuiStatus "Processing message trace data for spam patterns..." ([System.Drawing.Color]::Orange)
        Write-Log "Beginning spam pattern analysis..." -Level "Info"
        
        # Process messages
        $processedMessages = [System.Collections.ArrayList]::new($etrData.Count)
        $processingCount = 0
        
        foreach ($record in $etrData) {
            $processingCount++
            if ($processingCount % 10000 -eq 0) {
                $percentage = [math]::Round(($processingCount / $etrData.Count) * 100, 1)
                Update-GuiStatus "Processing ETR records: $processingCount of $($etrData.Count) ($percentage%)" ([System.Drawing.Color]::Orange)
                [System.Windows.Forms.Application]::DoEvents()
            }
            
            # Extract fields using mapping
            $processedMessage = [PSCustomObject]@{
                MessageId = if ($columnMapping.MessageId) { $record.($columnMapping.MessageId) } else { "" }
                SenderAddress = if ($columnMapping.SenderAddress) { $record.($columnMapping.SenderAddress) } else { "" }
                RecipientAddress = if ($columnMapping.RecipientAddress) { $record.($columnMapping.RecipientAddress) } else { "" }
                Subject = if ($columnMapping.Subject) { $record.($columnMapping.Subject) } else { "" }
                Status = if ($columnMapping.Status) { $record.($columnMapping.Status) } else { "" }
                ToIP = if ($columnMapping.ToIP) { $record.($columnMapping.ToIP) } else { "" }
                FromIP = if ($columnMapping.FromIP) { $record.($columnMapping.FromIP) } else { "" }
                MessageSize = if ($columnMapping.MessageSize) { $record.($columnMapping.MessageSize) } else { "" }
                Received = if ($columnMapping.Received) { $record.($columnMapping.Received) } else { "" }
                Direction = if ($columnMapping.Direction) { $record.($columnMapping.Direction) } else { "" }
                EventType = if ($columnMapping.EventType) { $record.($columnMapping.EventType) } else { "" }
            }
            
            [void]$processedMessages.Add($processedMessage)
        }
        
        Write-Log "Processed $($processedMessages.Count) messages" -Level "Info"
        Update-GuiStatus "Analyzing patterns in $($processedMessages.Count) messages..." ([System.Drawing.Color]::Orange)
        
        # Focus on outbound messages
        $outboundMessages = $processedMessages.ToArray() | Where-Object { 
            $_.Direction -like "*outbound*" -or $_.Direction -like "*send*" -or [string]::IsNullOrEmpty($_.Direction)
        }
        
        Write-Log "Analyzing $($outboundMessages.Count) outbound messages for spam patterns" -Level "Info"
        
        if ($outboundMessages.Count -eq 0) {
            Update-GuiStatus "No outbound messages found in ETR data" ([System.Drawing.Color]::Orange)
            return @()
        }
        
        # Initialize spam indicators with ArrayList
        $spamIndicators = [System.Collections.ArrayList]::new()
        
        #──────────────────────────────────────────────────────
        # ANALYSIS 1: EXCESSIVE VOLUME
        #──────────────────────────────────────────────────────
        Update-GuiStatus "Analyzing message volume patterns..." ([System.Drawing.Color]::Orange)
        Write-Log "Running volume analysis..." -Level "Info"
        
        $senderCounts = @{}
        foreach ($msg in $outboundMessages) {
            $sender = $msg.SenderAddress
            if (-not [string]::IsNullOrEmpty($sender)) {
                if ($senderCounts.ContainsKey($sender)) {
                    $senderCounts[$sender]++
                } else {
                    $senderCounts[$sender] = 1
                }
            }
        }
        
        $volumeFindings = 0
        foreach ($sender in $senderCounts.Keys) {
            $messageCount = $senderCounts[$sender]
            if ($messageCount -gt $ConfigData.ETRAnalysis.MaxMessagesPerSender) {
                $senderMessages = $outboundMessages | Where-Object { $_.SenderAddress -eq $sender }
                
                $indicator = [PSCustomObject]@{
                    SenderAddress = $sender
                    RiskType = "ExcessiveVolume"
                    RiskLevel = "High"
                    MessageCount = $messageCount
                    Description = "Excessive outbound messages: $messageCount messages"
                    MessageIds = ($senderMessages.MessageId | Where-Object { -not [string]::IsNullOrEmpty($_) } | Select-Object -First 10) -join "; "
                    Recipients = ($senderMessages.RecipientAddress | Select-Object -Unique | Select-Object -First 5) -join "; "
                    Subjects = ($senderMessages.Subject | Select-Object -Unique | Select-Object -First 3) -join "; "
                    RiskScore = $ConfigData.ETRAnalysis.RiskWeights.ExcessiveVolume
                }
                [void]$spamIndicators.Add($indicator)
                $volumeFindings++
            }
        }
        Write-Log "Volume analysis: $volumeFindings patterns found" -Level "Info"
        
        #──────────────────────────────────────────────────────
        # ANALYSIS 2: IDENTICAL SUBJECTS
        #──────────────────────────────────────────────────────
        Update-GuiStatus "Analyzing identical subject patterns..." ([System.Drawing.Color]::Orange)
        Write-Log "Running subject analysis..." -Level "Info"
        
        $subjectGroups = @{}
        foreach ($msg in $outboundMessages) {
            if (-not [string]::IsNullOrEmpty($msg.Subject) -and $msg.Subject.Length -ge $ConfigData.ETRAnalysis.MinSubjectLength) {
                $key = "$($msg.SenderAddress)|$($msg.Subject.ToLower().Trim())"
                if ($subjectGroups.ContainsKey($key)) {
                    $subjectGroups[$key] += @($msg)
                } else {
                    $subjectGroups[$key] = @($msg)
                }
            }
        }
        
        $subjectFindings = 0
        foreach ($key in $subjectGroups.Keys) {
            $messages = $subjectGroups[$key]
            if ($messages.Count -ge $ConfigData.ETRAnalysis.MaxSameSubjectMessages) {
                $indicator = [PSCustomObject]@{
                    SenderAddress = $messages[0].SenderAddress
                    RiskType = "IdenticalSubjects"
                    RiskLevel = "Critical"
                    MessageCount = $messages.Count
                    Description = "Identical subject spam: $($messages.Count) messages"
                    MessageIds = ($messages.MessageId | Where-Object { -not [string]::IsNullOrEmpty($_) } | Select-Object -First 10) -join "; "
                    Recipients = ($messages.RecipientAddress | Select-Object -Unique | Select-Object -First 10) -join "; "
                    Subjects = $messages[0].Subject
                    RiskScore = $ConfigData.ETRAnalysis.RiskWeights.MassDistribution
                }
                [void]$spamIndicators.Add($indicator)
                $subjectFindings++
            }
        }
        Write-Log "Subject analysis: $subjectFindings patterns found" -Level "Info"
        
        #──────────────────────────────────────────────────────
        # ANALYSIS 3: SPAM KEYWORDS
        #──────────────────────────────────────────────────────
        Update-GuiStatus "Analyzing spam keywords..." ([System.Drawing.Color]::Orange)
        Write-Log "Running keyword analysis..." -Level "Info"
        
        $keywordFindings = 0
        foreach ($keyword in $ConfigData.ETRAnalysis.SpamKeywords) {
            $keywordMessages = $outboundMessages | Where-Object { 
                $_.Subject -like "*$keyword*" -and -not [string]::IsNullOrEmpty($_.Subject)
            }
            
            if ($keywordMessages.Count -gt 5) {
                $senderGroups = @{}
                foreach ($msg in $keywordMessages) {
                    $sender = $msg.SenderAddress
                    if (-not [string]::IsNullOrEmpty($sender)) {
                        if ($senderGroups.ContainsKey($sender)) {
                            $senderGroups[$sender] += @($msg)
                        } else {
                            $senderGroups[$sender] = @($msg)
                        }
                    }
                }
                
                foreach ($sender in $senderGroups.Keys) {
                    $senderMessages = $senderGroups[$sender]
                    if ($senderMessages.Count -gt 3) {
                        $indicator = [PSCustomObject]@{
                            SenderAddress = $sender
                            RiskType = "SpamKeywords"
                            RiskLevel = "Medium"
                            MessageCount = $senderMessages.Count
                            Description = "Spam keyword '$keyword' in $($senderMessages.Count) messages"
                            MessageIds = ($senderMessages.MessageId | Where-Object { -not [string]::IsNullOrEmpty($_) } | Select-Object -First 5) -join "; "
                            Recipients = ($senderMessages.RecipientAddress | Select-Object -Unique | Select-Object -First 5) -join "; "
                            Subjects = ($senderMessages.Subject | Select-Object -Unique | Select-Object -First 3) -join "; "
                            RiskScore = $ConfigData.ETRAnalysis.RiskWeights.SpamKeywords
                            DetectedKeyword = $keyword
                        }
                        [void]$spamIndicators.Add($indicator)
                        $keywordFindings++
                    }
                }
            }
        }
        Write-Log "Keyword analysis: $keywordFindings patterns found" -Level "Info"
        
        #──────────────────────────────────────────────────────
        # ANALYSIS 4: RISKY IP CORRELATION
        #──────────────────────────────────────────────────────
        $ipFindings = 0
        if ($RiskyIPs.Count -gt 0) {
            Update-GuiStatus "Correlating with risky IPs from sign-in analysis..." ([System.Drawing.Color]::Orange)
            Write-Log "Running IP correlation with $($RiskyIPs.Count) flagged IPs" -Level "Info"
            
            foreach ($riskyIP in $RiskyIPs) {
                $riskyIPMessages = $outboundMessages | Where-Object { $_.FromIP -eq $riskyIP -or $_.ToIP -eq $riskyIP }
                
                if ($riskyIPMessages.Count -gt 0) {
                    $indicator = [PSCustomObject]@{
                        SenderAddress = ($riskyIPMessages.SenderAddress | Select-Object -Unique) -join "; "
                        RiskType = "RiskyIPCorrelation"
                        RiskLevel = "Critical"
                        MessageCount = $riskyIPMessages.Count
                        Description = "Messages from/to risky IP $riskyIP"
                        MessageIds = ($riskyIPMessages.MessageId | Where-Object { -not [string]::IsNullOrEmpty($_) } | Select-Object -First 10) -join "; "
                        Recipients = ($riskyIPMessages.RecipientAddress | Select-Object -Unique | Select-Object -First 10) -join "; "
                        Subjects = ($riskyIPMessages.Subject | Select-Object -Unique | Select-Object -First 3) -join "; "
                        RiskScore = $ConfigData.ETRAnalysis.RiskWeights.RiskyIPMatch
                        RiskyIP = $riskyIP
                    }
                    [void]$spamIndicators.Add($indicator)
                    $ipFindings++
                }
            }
            Write-Log "IP correlation: $ipFindings patterns found" -Level "Info"
        }
        
        #──────────────────────────────────────────────────────
        # ANALYSIS 5: FAILED DELIVERY
        #──────────────────────────────────────────────────────
        Update-GuiStatus "Analyzing failed delivery patterns..." ([System.Drawing.Color]::Orange)
        Write-Log "Running failed delivery analysis..." -Level "Info"
        
        $failedMessages = $processedMessages.ToArray() | Where-Object { 
            $_.Status -like "*failed*" -or $_.Status -like "*bounce*" -or 
            $_.Status -like "*reject*" -or $_.Status -like "*blocked*"
        }
        
        $failureFindings = 0
        if ($failedMessages.Count -gt 0) {
            $failedGroups = @{}
            foreach ($msg in $failedMessages) {
                $sender = $msg.SenderAddress
                if (-not [string]::IsNullOrEmpty($sender)) {
                    if ($failedGroups.ContainsKey($sender)) {
                        $failedGroups[$sender] += @($msg)
                    } else {
                        $failedGroups[$sender] = @($msg)
                    }
                }
            }
            
            foreach ($sender in $failedGroups.Keys) {
                $senderFailures = $failedGroups[$sender]
                if ($senderFailures.Count -gt 10) {
                    $indicator = [PSCustomObject]@{
                        SenderAddress = $sender
                        RiskType = "ExcessiveFailures"
                        RiskLevel = "Medium"
                        MessageCount = $senderFailures.Count
                        Description = "Excessive failed deliveries: $($senderFailures.Count) failed"
                        MessageIds = ($senderFailures.MessageId | Where-Object { -not [string]::IsNullOrEmpty($_) } | Select-Object -First 10) -join "; "
                        Recipients = ($senderFailures.RecipientAddress | Select-Object -Unique | Select-Object -First 10) -join "; "
                        Subjects = ($senderFailures.Subject | Select-Object -Unique | Select-Object -First 3) -join "; "
                        RiskScore = $ConfigData.ETRAnalysis.RiskWeights.FailedDelivery
                    }
                    [void]$spamIndicators.Add($indicator)
                    $failureFindings++
                }
            }
        }
        Write-Log "Failed delivery analysis: $failureFindings patterns found" -Level "Info"
        
        #══════════════════════════════════════════════════════
        # EXPORT RESULTS
        #══════════════════════════════════════════════════════
        Update-GuiStatus "Exporting ETR analysis results..." ([System.Drawing.Color]::Orange)
        
        $spamIndicatorsArray = @($spamIndicators.ToArray())
        
        # Sort by risk
        $riskOrder = @{"Critical" = 0; "High" = 1; "Medium" = 2; "Low" = 3}
        $spamIndicatorsArray = $spamIndicatorsArray | Sort-Object @{Expression={$riskOrder[$_.RiskLevel]}}, @{Expression="RiskScore"; Descending=$true}
        
        if ($spamIndicatorsArray.Count -gt 0) {
            $spamIndicatorsArray | Export-Csv -Path $OutputPath -NoTypeInformation -Force
            
            # Create message recall report
            $recallReportPath = $OutputPath -replace '.csv$', '_MessageRecallReport.csv'
            $recallReport = $spamIndicatorsArray | Where-Object { 
                $_.RiskLevel -in @("Critical", "High") -and -not [string]::IsNullOrEmpty($_.MessageIds)
            }
            
            if ($recallReport.Count -gt 0) {
                $recallReport | Export-Csv -Path $recallReportPath -NoTypeInformation -Force
                Write-Log "Created message recall report: $recallReportPath" -Level "Warning"
            }
            
            # Summary
            $criticalCount = ($spamIndicatorsArray | Where-Object { $_.RiskLevel -eq "Critical" }).Count
            $highCount = ($spamIndicatorsArray | Where-Object { $_.RiskLevel -eq "High" }).Count
            $mediumCount = ($spamIndicatorsArray | Where-Object { $_.RiskLevel -eq "Medium" }).Count
            
            Update-GuiStatus "ETR analysis complete! $criticalCount critical, $highCount high, $mediumCount medium risk patterns." ([System.Drawing.Color]::Green)
            
            Write-Log "═══════════════════════════════════════════════════" -Level "Info"
            Write-Log "ETR ANALYSIS COMPLETED" -Level "Info"
            Write-Log "Total patterns detected: $($spamIndicatorsArray.Count)" -Level "Info"
            Write-Log "  Critical: $criticalCount" -Level "Info"
            Write-Log "  High: $highCount" -Level "Info"
            Write-Log "  Medium: $mediumCount" -Level "Info"
            Write-Log "Analysis breakdown:" -Level "Info"
            Write-Log "  Volume patterns: $volumeFindings" -Level "Info"
            Write-Log "  Subject patterns: $subjectFindings" -Level "Info"
            Write-Log "  Keyword patterns: $keywordFindings" -Level "Info"
            Write-Log "  IP correlations: $ipFindings" -Level "Info"
            Write-Log "  Failure patterns: $failureFindings" -Level "Info"
            Write-Log "Output: $OutputPath" -Level "Info"
            Write-Log "═══════════════════════════════════════════════════" -Level "Info"
            
            return $spamIndicatorsArray
        }
        else {
            Update-GuiStatus "No suspicious patterns detected in ETR analysis" ([System.Drawing.Color]::Green)
            Write-Log "No suspicious patterns detected" -Level "Info"
            return @()
        }
        
    }
    catch {
        Update-GuiStatus "Error in ETR analysis: $($_.Exception.Message)" ([System.Drawing.Color]::Red)
        Write-Log "ETR analysis error: $($_.Exception.Message)" -Level "Error"
        [System.GC]::Collect()
        return $null
    }
}

#endregion

#################################################################
#
#  SECTION 4: ANALYSIS FUNCTIONS
#
#################################################################

#region ANALYSIS FUNCTIONS

function Invoke-CompromiseDetection {
    <#
    .SYNOPSIS
        Performs comprehensive security analysis across all collected data sources.
    
    .DESCRIPTION
        Main analysis engine that aggregates data from all collection functions,
        calculates risk scores, identifies compromised accounts, and generates reports.
    
    .PARAMETER ReportPath
        Full path where the HTML report will be saved.
    
    .RETURNS
        Array of PSCustomObjects containing risk assessment results
    
    .NOTES
        Risk Scoring: Critical (50+), High (30-49), Medium (15-29), Low (0-14)
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$ReportPath = (Join-Path -Path $ConfigData.WorkDir -ChildPath "SecurityReport.html")
    )
    
    Update-GuiStatus "Starting compromise detection analysis..." ([System.Drawing.Color]::Orange)
    
    # Helper functions for safe data conversion
    function ConvertTo-SafeString {
        param($Value)
        if ($Value -eq $null -or $Value -is [System.DBNull] -or ($Value -is [double] -and [double]::IsNaN($Value))) {
            return ""
        }
        return $Value.ToString()
    }
    
    function ConvertTo-SafeBoolean {
        param($Value)
        if ($Value -eq $null -or $Value -is [System.DBNull] -or ($Value -is [double] -and [double]::IsNaN($Value))) {
            return $false
        }
        if ($Value -is [string]) {
            return $Value -eq "True"
        }
        return [bool]$Value
    }
    
    # Define data sources
    $dataSources = @{
        SignInData = @{
            Path = Join-Path -Path $ConfigData.WorkDir -ChildPath "UserLocationData.csv"
            Data = $null
            Available = $false
        }
        AdminAuditData = @{
            Path = Join-Path -Path $ConfigData.WorkDir -ChildPath "AdminAuditLogs_HighRisk.csv"
            Data = $null
            Available = $false
        }
        InboxRulesData = @{
            Path = Join-Path -Path $ConfigData.WorkDir -ChildPath "InboxRules.csv"
            Data = $null
            Available = $false
        }
        DelegationData = @{
            Path = Join-Path -Path $ConfigData.WorkDir -ChildPath "MailboxDelegation.csv"
            Data = $null
            Available = $false
        }
        AppRegData = @{
            Path = Join-Path -Path $ConfigData.WorkDir -ChildPath "AppRegistrations.csv"
            Data = $null
            Available = $false
        }
        ConditionalAccessData = @{
            Path = Join-Path -Path $ConfigData.WorkDir -ChildPath "ConditionalAccess.csv"
            Data = $null
            Available = $false
        }
        ETRData = @{
            Path = Join-Path -Path $ConfigData.WorkDir -ChildPath "ETRSpamAnalysis.csv"
            Data = $null
            Available = $false
        }
		MFAStatusData = @{
			Path = Join-Path -Path $ConfigData.WorkDir -ChildPath "MFAStatus.csv"
			Data = $null
			Available = $false
		}
		FailedLoginPatterns = @{
			Path = Join-Path -Path $ConfigData.WorkDir -ChildPath "FailedLoginAnalysis.csv"
			Data = $null
			Available = $false
		}
		PasswordChangeData = @{
			Path = Join-Path -Path $ConfigData.WorkDir -ChildPath "PasswordChangeAnalysis.csv"
			Data = $null
			Available = $false
		}
    }
    
    Update-GuiStatus "Checking for available data sources..." ([System.Drawing.Color]::Orange)
    
    # Load and validate data sources
    $availableDataSources = @()
    
    foreach ($source in $dataSources.GetEnumerator()) {
        $sourceName = $source.Key
        $sourceInfo = $source.Value
		
        foreach ($sourceName in @('MFAStatusData', 'FailedLoginPatterns', 'PasswordChangeData')) {
			$sourceInfo = $dataSources[$sourceName]
			if (Test-Path $sourceInfo.Path) {
				try {
					$rawData = Import-Csv -Path $sourceInfo.Path
					if ($rawData) {
						$sourceInfo.Data = $rawData
						$sourceInfo.Available = $true
						$availableDataSources += $sourceName
						Write-Log "Loaded ${sourceName}: $($rawData.Count) records" -Level "Info"
					}
				}
				catch {
					Write-Log "Error loading ${sourceName}: $($_.Exception.Message)" -Level "Warning"
			}
		}
		
	}
        if (Test-Path -Path $sourceInfo.Path) {
            try {
                $rawData = Import-Csv -Path $sourceInfo.Path -ErrorAction Stop
                
                if ($rawData -and $rawData.Count -gt 0) {
                    # Clean and normalize data based on source type
                    $cleanData = switch ($sourceName) {
                        "SignInData" {
                            $rawData | ForEach-Object {
                                [PSCustomObject]@{
                                    UserId = ConvertTo-SafeString $_.UserId
                                    UserDisplayName = ConvertTo-SafeString $_.UserDisplayName
                                    CreationTime = ConvertTo-SafeString $_.CreationTime
                                    UserAgent = ConvertTo-SafeString $_.UserAgent
                                    IP = ConvertTo-SafeString $_.IP
                                    ISP = ConvertTo-SafeString $_.ISP
                                    City = ConvertTo-SafeString $_.City
                                    RegionName = ConvertTo-SafeString $_.RegionName
                                    Country = ConvertTo-SafeString $_.Country
                                    IsUnusualLocation = ConvertTo-SafeBoolean $_.IsUnusualLocation
                                    Status = ConvertTo-SafeString $_.Status
                                    FailureReason = ConvertTo-SafeString $_.FailureReason
                                    ConditionalAccessStatus = ConvertTo-SafeString $_.ConditionalAccessStatus
                                    RiskLevel = ConvertTo-SafeString $_.RiskLevel
                                    DeviceOS = ConvertTo-SafeString $_.DeviceOS
                                    DeviceBrowser = ConvertTo-SafeString $_.DeviceBrowser
                                    IsInteractive = ConvertTo-SafeBoolean $_.IsInteractive
                                    AppDisplayName = ConvertTo-SafeString $_.AppDisplayName
                                }
                            }
                        }
                        
                        "AdminAuditData" {
                            $rawData | ForEach-Object {
                                [PSCustomObject]@{
                                    Timestamp = ConvertTo-SafeString $_.Timestamp
                                    UserId = ConvertTo-SafeString $_.UserId
                                    UserDisplayName = ConvertTo-SafeString $_.UserDisplayName
                                    Activity = ConvertTo-SafeString $_.Activity
                                    Result = ConvertTo-SafeString $_.Result
                                    ResultReason = ConvertTo-SafeString $_.ResultReason
                                    Category = ConvertTo-SafeString $_.Category
                                    CorrelationId = ConvertTo-SafeString $_.CorrelationId
                                    LoggedByService = ConvertTo-SafeString $_.LoggedByService
                                    RiskLevel = ConvertTo-SafeString $_.RiskLevel
                                    TargetResources = ConvertTo-SafeString $_.TargetResources
                                    AdditionalDetails = ConvertTo-SafeString $_.AdditionalDetails
                                }
                            }
                        }
                        
                        "ConditionalAccessData" {
                            $rawData | ForEach-Object {
                                [PSCustomObject]@{
                                    DisplayName = ConvertTo-SafeString $_.DisplayName
                                    State = ConvertTo-SafeString $_.State
                                    CreatedDateTime = ConvertTo-SafeString $_.CreatedDateTime
                                    ModifiedDateTime = ConvertTo-SafeString $_.ModifiedDateTime
                                    Conditions = ConvertTo-SafeString $_.Conditions
                                    GrantControls = ConvertTo-SafeString $_.GrantControls
                                    SessionControls = ConvertTo-SafeString $_.SessionControls
                                    IsSuspicious = ConvertTo-SafeBoolean $_.IsSuspicious
                                    SuspiciousReasons = ConvertTo-SafeString $_.SuspiciousReasons
                                }
                            }
                        }
                        
                        default {
                            # Generic cleaning for other sources
                            $rawData | ForEach-Object {
                                $cleanRow = [PSCustomObject]@{}
                                foreach ($property in $_.PSObject.Properties) {
                                    $cleanRow | Add-Member -NotePropertyName $property.Name -NotePropertyValue (ConvertTo-SafeString $property.Value)
                                }
                                $cleanRow
                            }
                        }
                    }
                    
                    $sourceInfo.Data = $cleanData
                    $sourceInfo.Available = $true
                    $availableDataSources += $sourceName
                    Write-Log "Loaded ${sourceName}: $($cleanData.Count) records" -Level "Info"
                }
            }
            catch {
                Write-Log "Error loading ${sourceName}: $($_.Exception.Message)" -Level "Warning"
            }
        }
    }
    
    # Validate we have data
    if ($availableDataSources.Count -eq 0) {
        Update-GuiStatus "No data sources found! Please run data collection first." ([System.Drawing.Color]::Red)
        [System.Windows.Forms.MessageBox]::Show(
            "No data files found for analysis!`n`nPlease run the data collection functions first.",
            "No Data Available",
            "OK",
            "Warning"
        )
        return $null
    }
    
    Update-GuiStatus "Found $($availableDataSources.Count) data sources" ([System.Drawing.Color]::Green)
    
    # Initialize user tracking
    $users = @{}
    $systemIssues = @()
    
    # Process sign-in data
    if ($dataSources.SignInData.Available) {
        Update-GuiStatus "Analyzing sign-in data..." ([System.Drawing.Color]::Orange)
        
        # Generate unique logins report
        $uniqueLogins = @()
        $userLocationGroups = $dataSources.SignInData.Data | Group-Object -Property UserId
        
        foreach ($userGroup in $userLocationGroups) {
            $userId = $userGroup.Name
            $userSignIns = $userGroup.Group
            
            $uniqueUserLocations = $userSignIns | 
                Select-Object UserId, UserDisplayName, IP, City, RegionName, Country, ISP -Unique |
                Where-Object { -not [string]::IsNullOrEmpty($_.IP) }
            
            foreach ($location in $uniqueUserLocations) {
                $signInCount = ($userSignIns | Where-Object { 
                    $_.IP -eq $location.IP -and $_.City -eq $location.City -and $_.Country -eq $location.Country 
                }).Count
                
                $locationSignIns = $userSignIns | Where-Object { 
                    $_.IP -eq $location.IP -and $_.City -eq $location.City -and $_.Country -eq $location.Country 
                } | Sort-Object CreationTime
                
                $firstSeen = if ($locationSignIns.Count -gt 0) { $locationSignIns[0].CreationTime } else { "" }
                $lastSeen = if ($locationSignIns.Count -gt 0) { $locationSignIns[-1].CreationTime } else { "" }
                
                $isUnusualLocation = $false
                if ($location.Country -and $ConfigData.ExpectedCountries -notcontains $location.Country) {
                    $isUnusualLocation = $true
                }
                
                $uniqueLogin = [PSCustomObject]@{
                    UserId = $location.UserId
                    UserDisplayName = $location.UserDisplayName
                    IP = $location.IP
                    City = $location.City
                    RegionName = $location.RegionName
                    Country = $location.Country
                    ISP = $location.ISP
                    IsUnusualLocation = $isUnusualLocation
                    SignInCount = $signInCount
                    FirstSeen = $firstSeen
                    LastSeen = $lastSeen
                }
                
                $uniqueLogins += $uniqueLogin
            }
        }
        
        # Export unique logins
        if ($uniqueLogins.Count -gt 0) {
            $uniqueLoginsPath = Join-Path -Path $ConfigData.WorkDir -ChildPath "UniqueSignInLocations.csv"
            $uniqueLogins | Export-Csv -Path $uniqueLoginsPath -NoTypeInformation -Force
            
            $unusualUniqueLogins = $uniqueLogins | Where-Object { $_.IsUnusualLocation -eq $true }
            if ($unusualUniqueLogins.Count -gt 0) {
                $unusualPath = Join-Path -Path $ConfigData.WorkDir -ChildPath "UniqueSignInLocations_Unusual.csv"
                $unusualUniqueLogins | Export-Csv -Path $unusualPath -NoTypeInformation -Force
            }
        }
        
        # Process sign-ins for risk analysis
        foreach ($signIn in $dataSources.SignInData.Data) {
            $userId = $signIn.UserId
            if ([string]::IsNullOrEmpty($userId)) { continue }
            
            if (-not $users.ContainsKey($userId)) {
                $users[$userId] = @{
                    UserDisplayName = $signIn.UserDisplayName
                    UnusualSignIns = @()
                    FailedSignIns = @()
                    HighRiskOps = @()
                    SuspiciousRules = @()
                    SuspiciousDelegations = @()
                    HighRiskAppRegs = @()
                    ETRSpamActivity = @()
                    RiskScore = 0
                }
            }
            
            $isSuccessfulSignIn = ($signIn.Status -eq "0" -or [string]::IsNullOrEmpty($signIn.Status))
            $isFailedSignIn = (-not [string]::IsNullOrEmpty($signIn.Status) -and $signIn.Status -ne "0")
            $isUnusual = $signIn.IsUnusualLocation -eq $true
            
            # Only flag unusual locations for successful sign-ins
            if ($isUnusual -and $isSuccessfulSignIn) {
                $users[$userId].UnusualSignIns += $signIn
                $users[$userId].RiskScore += 5
            }
            
            if ($isFailedSignIn) {
                $users[$userId].FailedSignIns += $signIn
            }
            
            if ($signIn.RiskLevel -and $signIn.RiskLevel -eq "high" -and $isSuccessfulSignIn) {
                $users[$userId].RiskScore += 15
            }
        }
    }
    
    # Process admin audit data
    if ($dataSources.AdminAuditData.Available) {
        Update-GuiStatus "Analyzing admin audit data..." ([System.Drawing.Color]::Orange)
        
        foreach ($auditLog in $dataSources.AdminAuditData.Data) {
            $userId = $auditLog.UserId
            if ([string]::IsNullOrEmpty($userId)) { continue }
            
            if (-not $users.ContainsKey($userId)) {
                $users[$userId] = @{
                    UserDisplayName = $auditLog.UserDisplayName
                    UnusualSignIns = @()
                    FailedSignIns = @()
                    HighRiskOps = @()
                    SuspiciousRules = @()
                    SuspiciousDelegations = @()
                    HighRiskAppRegs = @()
                    ETRSpamActivity = @()
                    RiskScore = 0
                }
            }
            
            if ($auditLog.RiskLevel -eq "High") {
                $users[$userId].HighRiskOps += $auditLog
                $users[$userId].RiskScore += 10
            }
        }
    }
    
    # Process inbox rules
    if ($dataSources.InboxRulesData.Available) {
        Update-GuiStatus "Analyzing inbox rules..." ([System.Drawing.Color]::Orange)
        
        foreach ($rule in $dataSources.InboxRulesData.Data) {
            $isSuspicious = ConvertTo-SafeBoolean $rule.IsSuspicious
            
            if ($isSuspicious) {
                $userId = $rule.MailboxOwnerID
                if ([string]::IsNullOrEmpty($userId)) { continue }
                
                if (-not $users.ContainsKey($userId)) {
                    $users[$userId] = @{
                        UserDisplayName = $rule.DisplayName
                        UnusualSignIns = @()
                        FailedSignIns = @()
                        HighRiskOps = @()
                        SuspiciousRules = @()
                        SuspiciousDelegations = @()
                        HighRiskAppRegs = @()
                        ETRSpamActivity = @()
                        RiskScore = 0
                    }
                }
                
                $users[$userId].SuspiciousRules += $rule
                $users[$userId].RiskScore += 15
            }
        }
    }
    
    # Process delegations
    if ($dataSources.DelegationData.Available) {
        Update-GuiStatus "Analyzing mailbox delegations..." ([System.Drawing.Color]::Orange)
        
        foreach ($delegation in $dataSources.DelegationData.Data) {
            $isSuspicious = ConvertTo-SafeBoolean $delegation.IsSuspicious
            
            if ($isSuspicious) {
                $userId = $delegation.Mailbox
                if ([string]::IsNullOrEmpty($userId)) { continue }
                
                if (-not $users.ContainsKey($userId)) {
                    $users[$userId] = @{
                        UserDisplayName = $delegation.DisplayName
                        UnusualSignIns = @()
                        FailedSignIns = @()
                        HighRiskOps = @()
                        SuspiciousRules = @()
                        SuspiciousDelegations = @()
                        HighRiskAppRegs = @()
                        ETRSpamActivity = @()
                        RiskScore = 0
                    }
                }
                
                $users[$userId].SuspiciousDelegations += $delegation
                $users[$userId].RiskScore += 8
            }
        }
    }
    
    # Process app registrations
    if ($dataSources.AppRegData.Available) {
        Update-GuiStatus "Analyzing app registrations..." ([System.Drawing.Color]::Orange)
        
        foreach ($appReg in $dataSources.AppRegData.Data) {
            if ($appReg.RiskLevel -eq "High") {
                $systemIssues += $appReg
                
                $systemUser = "SYSTEM_WIDE_APPS"
                if (-not $users.ContainsKey($systemUser)) {
                    $users[$systemUser] = @{
                        UserDisplayName = "System-Wide Application Issues"
                        UnusualSignIns = @()
                        FailedSignIns = @()
                        HighRiskOps = @()
                        SuspiciousRules = @()
                        SuspiciousDelegations = @()
                        HighRiskAppRegs = @()
                        ETRSpamActivity = @()
                        RiskScore = 0
                    }
                }
                
                $users[$systemUser].HighRiskAppRegs += $appReg
                $users[$systemUser].RiskScore += 20
            }
        }
    }
    
    # Process conditional access
    if ($dataSources.ConditionalAccessData.Available) {
        $suspiciousPolicies = $dataSources.ConditionalAccessData.Data | 
            Where-Object { (ConvertTo-SafeBoolean $_.IsSuspicious) -eq $true }
        
        if ($suspiciousPolicies.Count -gt 0) {
            $systemIssues += $suspiciousPolicies
        }
    }
    
    # Process ETR data
    if ($dataSources.ETRData.Available) {
        Update-GuiStatus "Analyzing ETR message trace data..." ([System.Drawing.Color]::Orange)
        
        foreach ($etrRecord in $dataSources.ETRData.Data) {
            $userId = ConvertTo-SafeString $etrRecord.SenderAddress
            if ([string]::IsNullOrEmpty($userId)) { continue }
            
            if (-not $users.ContainsKey($userId)) {
                $users[$userId] = @{
                    UserDisplayName = $userId
                    UnusualSignIns = @()
                    FailedSignIns = @()
                    HighRiskOps = @()
                    SuspiciousRules = @()
                    SuspiciousDelegations = @()
                    HighRiskAppRegs = @()
                    ETRSpamActivity = @()
                    RiskScore = 0
                }
            }
            
            $users[$userId].ETRSpamActivity += $etrRecord
            
            $riskScore = if ($etrRecord.RiskScore) { 
                try { [int]$etrRecord.RiskScore } catch { 0 }
            } else { 0 }
            $users[$userId].RiskScore += $riskScore
        }
    }
	
	# Process MFA status data
	if ($dataSources.MFAStatusData.Available) {
		Update-GuiStatus "Analyzing MFA status data..." ([System.Drawing.Color]::Orange)
		
		foreach ($mfaRecord in $dataSources.MFAStatusData.Data) {
			$userId = $mfaRecord.UserPrincipalName
			if ([string]::IsNullOrEmpty($userId)) { continue }
			
			if (-not $users.ContainsKey($userId)) {
				$users[$userId] = @{
					UserDisplayName = $mfaRecord.DisplayName
					UnusualSignIns = @()
					FailedSignIns = @()
					HighRiskOps = @()
					SuspiciousRules = @()
					SuspiciousDelegations = @()
					HighRiskAppRegs = @()
					ETRSpamActivity = @()
					RiskScore = 0
					MFAStatus = $null          
					FailedLoginPatterns = @()  
					PasswordChangeIssues = @() 
				}
			}
			
			# FIX: Ensure we store ONLY a single string value, force to string
			$mfaValue = $mfaRecord.HasMFA
			
			# Normalize to a single string value
			if ($mfaValue -eq "Yes" -or $mfaValue -eq "True" -or $mfaValue -eq $true) {
				$users[$userId].MFAStatus = "Yes"
			}
			elseif ($mfaValue -eq "No" -or $mfaValue -eq "False" -or $mfaValue -eq $false) {
				$users[$userId].MFAStatus = "No"
			}
			else {
				$users[$userId].MFAStatus = "Unknown"
			}
			
			# Add risk for no MFA
			if ($users[$userId].MFAStatus -eq "No") {
				$users[$userId].RiskScore += 40
			}
			
			# Extra risk if admin without MFA
			if ($mfaRecord.RiskLevel -eq "Critical") {
				$users[$userId].RiskScore += 10
			}
		}
	}
	# Process failed login patterns
	if ($dataSources.FailedLoginPatterns.Available) {
		Update-GuiStatus "Analyzing failed login patterns..." ([System.Drawing.Color]::Orange)
		
		foreach ($pattern in $dataSources.FailedLoginPatterns.Data) {
			$details = $pattern.Details
			if ([string]::IsNullOrEmpty($details)) { continue }
			
			# Extract user from Details field
			if ($details -match "User\s+([^\s]+@[^\s]+)") {
				$userId = $Matches[1]
				
				if (-not $users.ContainsKey($userId)) {
					$users[$userId] = @{
						UserDisplayName = $userId
						UnusualSignIns = @()
						FailedSignIns = @()
						HighRiskOps = @()
						SuspiciousRules = @()
						SuspiciousDelegations = @()
						HighRiskAppRegs = @()
						ETRSpamActivity = @()
						RiskScore = 0
						MFAStatus = $null          # NEW
						FailedLoginPatterns = @()  # NEW
						PasswordChangeIssues = @() # NEW
					}
				}
				
				# STORE the pattern data
				$users[$userId].FailedLoginPatterns += $pattern
				
				# Add risk based on pattern type
				$riskLevel = $pattern.RiskLevel
				$successfulBreach = $pattern.SuccessfulBreach
				
				if ($successfulBreach -eq "True" -or $successfulBreach -eq $true) {
					$users[$userId].RiskScore += 50
				}
				elseif ($riskLevel -eq "Critical") {
					$users[$userId].RiskScore += 30
				}
				elseif ($riskLevel -eq "High") {
					$users[$userId].RiskScore += 20
				}
				elseif ($riskLevel -eq "Medium") {
					$users[$userId].RiskScore += 10
				}
			}
		}
	}

	# Process password change patterns
	if ($dataSources.PasswordChangeData.Available) {
		Update-GuiStatus "Analyzing password change patterns..." ([System.Drawing.Color]::Orange)
		
		foreach ($pwChange in $dataSources.PasswordChangeData.Data) {
			$userId = $pwChange.User
			if ([string]::IsNullOrEmpty($userId)) { continue }
			
			if (-not $users.ContainsKey($userId)) {
				$users[$userId] = @{
					UserDisplayName = $userId
					UnusualSignIns = @()
					FailedSignIns = @()
					HighRiskOps = @()
					SuspiciousRules = @()
					SuspiciousDelegations = @()
					HighRiskAppRegs = @()
					ETRSpamActivity = @()
					RiskScore = 0
					MFAStatus = $null          # NEW
					FailedLoginPatterns = @()  # NEW
					PasswordChangeIssues = @() # NEW
				}
			}
			
			# STORE the password change data
			$users[$userId].PasswordChangeIssues += $pwChange
			
			# Add risk score
			try {
				$pwRiskScore = [int]$pwChange.RiskScore
				$users[$userId].RiskScore += $pwRiskScore
			}
			catch {
				Write-Log "Could not parse RiskScore for password change: $($pwChange.User)" -Level "Warning"
			}
		}
	}
    
    # Calculate risk levels and create results
    Update-GuiStatus "Calculating risk scores..." ([System.Drawing.Color]::Orange)
    
    $results = @()
    
    foreach ($userId in $users.Keys) {
        $userData = $users[$userId]
        
        $riskLevel = switch ($userData.RiskScore) {
            { $_ -ge 50 } { "Critical"; break }
            { $_ -ge 30 } { "High"; break }
            { $_ -ge 15 } { "Medium"; break }
            default { "Low" }
        }
        
        $resultObject = [PSCustomObject]@{
            UserId = $userId
            UserDisplayName = $userData.UserDisplayName
            RiskScore = $userData.RiskScore
            RiskLevel = $riskLevel
            UnusualSignInCount = $userData.UnusualSignIns.Count
            FailedSignInCount = $userData.FailedSignIns.Count
            HighRiskOperationsCount = $userData.HighRiskOps.Count
            SuspiciousRulesCount = $userData.SuspiciousRules.Count
            SuspiciousDelegationsCount = $userData.SuspiciousDelegations.Count
            HighRiskAppRegistrationsCount = $userData.HighRiskAppRegs.Count
            ETRSpamActivityCount = $userData.ETRSpamActivity.Count
            UnusualSignIns = $userData.UnusualSignIns
            FailedSignIns = $userData.FailedSignIns
            HighRiskOperations = $userData.HighRiskOps
            SuspiciousRules = $userData.SuspiciousRules
            SuspiciousDelegations = $userData.SuspiciousDelegations
            HighRiskAppRegistrations = $userData.HighRiskAppRegs
            ETRSpamActivity = $userData.ETRSpamActivity
			MFAStatus = if ($userData.MFAStatus) { $userData.MFAStatus } else { "Unknown" }
			FailedLoginPatternCount = if ($userData.FailedLoginPatterns) { $userData.FailedLoginPatterns.Count } else { 0 }
			FailedLoginPatterns = if ($userData.FailedLoginPatterns) { $userData.FailedLoginPatterns } else { @() }
			PasswordChangeIssuesCount = if ($userData.PasswordChangeIssues) { $userData.PasswordChangeIssues.Count } else { 0 }
			PasswordChangeIssues = if ($userData.PasswordChangeIssues) { $userData.PasswordChangeIssues } else { @() }
        }
        
        $results += $resultObject
    }
    
    $results = $results | Sort-Object -Property RiskScore -Descending
    
    # Export results
    Update-GuiStatus "Exporting analysis results..." ([System.Drawing.Color]::Orange)
    
    $csvPath = $ReportPath -replace '.html$', '.csv'
    $results | Select-Object UserId, UserDisplayName, RiskScore, RiskLevel, UnusualSignInCount, 
        FailedSignInCount, HighRiskOperationsCount, SuspiciousRulesCount, SuspiciousDelegationsCount, 
        HighRiskAppRegistrationsCount, ETRSpamActivityCount |
        Export-Csv -Path $csvPath -NoTypeInformation -Force
    
    # Generate HTML report
    $htmlReport = Generate-HTMLReport -Data $results
    $htmlReport | Out-File -FilePath $ReportPath -Force -Encoding UTF8
    
    $criticalCount = ($results | Where-Object { $_.RiskLevel -eq "Critical" }).Count
    $highCount = ($results | Where-Object { $_.RiskLevel -eq "High" }).Count
    
    Update-GuiStatus "Analysis completed! $criticalCount critical, $highCount high risk users" ([System.Drawing.Color]::Green)
    Write-Log "Analysis completed. Report saved to $ReportPath" -Level "Info"
    
    return $results
}

function Generate-HTMLReport {
    <#
    .SYNOPSIS
        Generates a comprehensive HTML security report from analysis results.
    
    .DESCRIPTION
        Creates a visually enhanced, interactive HTML report featuring:
        • Executive risk summary dashboard
        • Color-coded risk indicators
        • Collapsible detailed sections for high-risk users
        • Evidence tables with full context
        • Responsive design with modern styling
    
    .PARAMETER Data
        Array of PSCustomObjects containing analysis results from Invoke-CompromiseDetection
    
    .RETURNS
        String containing complete HTML document
    
    .EXAMPLE
        $html = Generate-HTMLReport -Data $analysisResults
        $html | Out-File -Path "Report.html"
    
    .NOTES
        Report automatically expands Critical risk users for immediate visibility
        Uses JavaScript for interactive collapsible sections
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [Array]$Data
    )
    
    # Filter users by risk level
    $criticalUsers = @($Data | Where-Object { $_.RiskLevel -eq "Critical" })
    $highRiskUsers = @($Data | Where-Object { $_.RiskLevel -eq "High" })
    $mediumRiskUsers = @($Data | Where-Object { $_.RiskLevel -eq "Medium" })
    $lowRiskUsers = @($Data | Where-Object { $_.RiskLevel -eq "Low" })
    
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Microsoft 365 Security Analysis Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
            padding: 20px;
        }
        
        .container {
            max-width: 1600px;
            margin: 0 auto;
            background-color: #fff;
            padding: 30px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
            border-radius: 8px;
        }
        
        h1 {
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
            margin-bottom: 30px;
        }
        
        h2 {
            color: #34495e;
            margin-top: 30px;
            margin-bottom: 15px;
            padding-bottom: 8px;
            border-bottom: 2px solid #ecf0f1;
        }
        
        h3 {
            color: #2c3e50;
            margin-top: 20px;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
        }
        
        .icon {
            margin-right: 8px;
            font-size: 1.2em;
        }
        
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .summary-item {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .summary-item.critical {
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        }
        
        .summary-item.high {
            background: linear-gradient(135deg, #fa709a 0%, #fee140 100%);
        }
        
        .summary-item.medium {
            background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
        }
        
        .summary-item.low {
            background: linear-gradient(135deg, #43e97b 0%, #38f9d7 100%);
        }
        
        .summary-item h3 {
            font-size: 1.8em;
            margin: 0;
            color: white;
            border: none;
        }
        
        .summary-item p {
            font-size: 3em;
            margin: 10px 0;
            font-weight: bold;
        }
        
        .summary-item small {
            opacity: 0.9;
            font-size: 0.9em;
        }
        
        /* Make tables horizontally scrollable */
        .table-wrapper {
            overflow-x: auto;
            margin: 20px 0;
            border: 1px solid #ddd;
            border-radius: 4px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            background-color: white;
            font-size: 13px;
            min-width: 1400px;
        }
        
        thead {
            background-color: #2c3e50;
            color: white;
            position: sticky;
            top: 0;
            z-index: 10;
        }
        
        th, td {
            padding: 10px 8px;
            text-align: left;
            border-bottom: 1px solid #ddd;
            max-width: 180px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        
        /* First column (User ID) - sticky and wider */
        th:first-child, td:first-child {
            max-width: 220px;
            position: sticky;
            left: 0;
            background-color: white;
            z-index: 5;
            font-weight: 600;
        }
        
        thead th:first-child {
            background-color: #2c3e50;
            z-index: 15;
        }
        
        /* Numeric columns - narrower and centered */
        td:nth-child(3), td:nth-child(5), td:nth-child(6), td:nth-child(7),
        td:nth-child(8), td:nth-child(9), td:nth-child(10), td:nth-child(11),
        td:nth-child(12), td:nth-child(13) {
            text-align: center;
            max-width: 80px;
        }
        
        th:nth-child(3), th:nth-child(5), th:nth-child(6), th:nth-child(7),
        th:nth-child(8), th:nth-child(9), th:nth-child(10), th:nth-child(11),
        th:nth-child(12), th:nth-child(13) {
            text-align: center;
        }
        
        /* MFA Status column */
        td:nth-child(4), th:nth-child(4) {
            text-align: center;
            max-width: 70px;
        }
        
        /* Risk Level column */
        td:nth-child(2), th:nth-child(2) {
            max-width: 100px;
        }
        
        /* Allow hover to show full content */
        td:hover {
            overflow: visible;
            white-space: normal;
            position: relative;
            z-index: 20;
            background-color: #f9f9f9;
            box-shadow: 0 2px 8px rgba(0,0,0,0.15);
        }
        
        tr:hover {
            background-color: #f5f5f5;
        }
        
        tbody tr:nth-child(even) {
            background-color: #fafafa;
        }
        
        .risk-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-weight: bold;
            font-size: 0.85em;
            text-transform: uppercase;
        }
        
        .risk-critical {
            background-color: #e74c3c;
            color: white;
        }
        
        .risk-high {
            background-color: #e67e22;
            color: white;
        }
        
        .risk-medium {
            background-color: #f39c12;
            color: white;
        }
        
        .risk-low {
            background-color: #27ae60;
            color: white;
        }
        
        .collapsible {
            background-color: #2c3e50;
            color: white;
            cursor: pointer;
            padding: 18px;
            width: 100%;
            border: none;
            text-align: left;
            outline: none;
            font-size: 16px;
            margin-top: 10px;
            border-radius: 4px;
            transition: background-color 0.3s;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .collapsible:hover {
            background-color: #34495e;
        }
        
        .collapsible.active {
            background-color: #34495e;
        }
        
        .content {
            padding: 0 18px;
            display: none;
            overflow: hidden;
            background-color: #f9f9f9;
            border-left: 3px solid #3498db;
            margin-bottom: 10px;
        }
        
        .detail-section {
            margin: 20px 0;
            padding: 15px;
            background-color: white;
            border-radius: 4px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
        }
        
        .detail-section table {
            margin-top: 10px;
            min-width: 100%;
        }
        
        .detail-section th {
            background-color: #34495e;
        }
        
        .metadata {
            background-color: #ecf0f1;
            padding: 15px;
            border-radius: 4px;
            border-left: 4px solid #3498db;
            margin-top: 20px;
        }
        
        .timestamp {
            color: #7f8c8d;
            font-size: 0.9em;
            text-align: right;
            margin-top: 30px;
        }
        
        /* MFA status indicators */
        .mfa-yes { color: #27ae60; font-weight: bold; font-size: 1.2em; }
        .mfa-no { color: #e74c3c; font-weight: bold; font-size: 1.2em; }
        .mfa-unknown { color: #f39c12; font-weight: bold; font-size: 1.2em; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Microsoft 365 Security Analysis Report</h1>
        <p class="timestamp">Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
        
        <div class="summary-grid">
            <div class="summary-item critical">
                <h3><span class="icon">🚨</span>Critical Risk</h3>
                <p>$($criticalUsers.Count)</p>
                <small>Users requiring immediate action</small>
            </div>
            <div class="summary-item high">
                <h3><span class="icon">⚠️</span>High Risk</h3>
                <p>$($highRiskUsers.Count)</p>
                <small>Users needing urgent review</small>
            </div>
            <div class="summary-item medium">
                <h3><span class="icon">⚡</span>Medium Risk</h3>
                <p>$($mediumRiskUsers.Count)</p>
                <small>Users with moderate risk indicators</small>
            </div>
            <div class="summary-item low">
                <h3><span class="icon">✅</span>Low Risk</h3>
                <p>$($lowRiskUsers.Count)</p>
                <small>Users with minimal risk indicators</small>
            </div>
        </div>
        
        <h2>Executive Risk Summary</h2>
        <div class="table-wrapper">
            <table>
                <thead>
                    <tr>
                        <th>User ID</th>
                        <th>Risk Level</th>
                        <th>Risk Score</th>
                        <th>MFA</th>
                        <th>Unusual Locations</th>
                        <th>Failed Sign-ins</th>
                        <th>Attack Patterns</th>
                        <th>Password Issues</th>
                        <th>Admin Ops</th>
                        <th>Suspicious Rules</th>
                        <th>Delegations</th>
                        <th>Risky Apps</th>
                        <th>Spam Activity</th>
                    </tr>
                </thead>
                <tbody>
"@

	# Add summary rows for all users
	foreach ($user in $Data) {
		$riskClass = "risk-" + $user.RiskLevel.ToLower()
		
		# FIX: Ensure MFA display is a single value, convert to string first
		$mfaStatusValue = [string]$user.MFAStatus
		
		$mfaDisplay = switch -Exact ($mfaStatusValue) {
			"Yes"     { '<span class="mfa-yes">✅</span>' }
			"True"    { '<span class="mfa-yes">✅</span>' }
			"No"      { '<span class="mfa-no">❌</span>' }
			"False"   { '<span class="mfa-no">❌</span>' }
			default   { '<span class="mfa-unknown">❓</span>' }
		}
		
		$html += @"
				<tr>
					<td><strong>$($user.UserId)</strong></td>
					<td><span class="risk-badge $riskClass">$($user.RiskLevel)</span></td>
					<td><strong>$($user.RiskScore)</strong></td>
					<td>$mfaDisplay</td>
					<td>$($user.UnusualSignInCount)</td>
					<td>$($user.FailedSignInCount)</td>
					<td>$($user.FailedLoginPatternCount)</td>
					<td>$($user.PasswordChangeIssuesCount)</td>
					<td>$($user.HighRiskOperationsCount)</td>
					<td>$($user.SuspiciousRulesCount)</td>
					<td>$($user.SuspiciousDelegationsCount)</td>
					<td>$($user.HighRiskAppRegistrationsCount)</td>
					<td>$($user.ETRSpamActivityCount)</td>
				</tr>
"@
	}

    $html += @"
                </tbody>
            </table>
        </div>
        
        <h2>Detailed Security Analysis</h2>
        <p style="color: #666; margin-bottom: 20px;">
            Click on any user below to expand their detailed security findings. 
            Critical risk users are automatically expanded for immediate review.
        </p>
"@

    # Combine critical and high risk users for detailed sections
    $detailedUsers = @()
    $detailedUsers += $criticalUsers
    $detailedUsers += $highRiskUsers
    
    foreach ($user in $detailedUsers) {
        $riskClass = "risk-" + $user.RiskLevel.ToLower()
        $html += @"
        <button class="collapsible">
            <span class="risk-badge $riskClass">$($user.RiskLevel)</span>
            <strong>$($user.UserId)</strong> - Risk Score: $($user.RiskScore)
        </button>
        <div class="content">
"@

        # MFA Status Section
        if ($user.MFAStatus -and $user.MFAStatus -ne "Unknown") {
            $mfaStatusClass = switch ($user.MFAStatus) {
                "No"    { "mfa-no" }
                "False" { "mfa-no" }
                $false  { "mfa-no" }
                "Yes"   { "mfa-yes" }
                "True"  { "mfa-yes" }
                $true   { "mfa-yes" }
                default { "mfa-unknown" }
            }
            
            $mfaMessage = switch ($user.MFAStatus) {
                "No"    { "⚠️ MFA NOT ENABLED - Account is vulnerable" }
                "False" { "⚠️ MFA NOT ENABLED - Account is vulnerable" }
                $false  { "⚠️ MFA NOT ENABLED - Account is vulnerable" }
                "Yes"   { "✅ MFA Enabled - Account protected" }
                "True"  { "✅ MFA Enabled - Account protected" }
                $true   { "✅ MFA Enabled - Account protected" }
                default { "❓ MFA Status Unknown" }
            }
            
            $html += @"
            <div class="detail-section">
                <h3><span class="icon">🔐</span>Multi-Factor Authentication Status</h3>
                <p class="$mfaStatusClass" style="font-size: 1.1em; padding: 10px; background-color: #f8f9fa; border-radius: 4px;">
                    <strong>$mfaMessage</strong>
                </p>
            </div>
"@
        }

        # Failed Login Attack Patterns Section
        if ($user.FailedLoginPatternCount -gt 0 -and $user.FailedLoginPatterns) {
            $html += @"
            <div class="detail-section">
                <h3><span class="icon">🚨</span>Failed Login Attack Patterns Detected</h3>
                <div class="table-wrapper">
                    <table>
                        <thead>
                            <tr>
                                <th>Pattern Type</th>
                                <th>Source IP</th>
                                <th>Location</th>
                                <th>ISP</th>
                                <th>Failed Attempts</th>
                                <th>Time Span (hrs)</th>
                                <th>Risk Level</th>
                                <th>Details</th>
                            </tr>
                        </thead>
                        <tbody>
"@
            foreach ($pattern in $user.FailedLoginPatterns) {
                $patternRiskClass = "risk-" + $pattern.RiskLevel.ToLower()
                $html += @"
                        <tr>
                            <td><strong>$($pattern.PatternType)</strong></td>
                            <td>$($pattern.SourceIP)</td>
                            <td>$($pattern.Location)</td>
                            <td>$($pattern.ISP)</td>
                            <td style="text-align: center;"><strong>$($pattern.FailedAttempts)</strong></td>
                            <td style="text-align: center;">$($pattern.TimeSpan)</td>
                            <td><span class="risk-badge $patternRiskClass">$($pattern.RiskLevel)</span></td>
                            <td>$($pattern.Details)</td>
                        </tr>
"@
            }
            $html += @"
                        </tbody>
                    </table>
                </div>
            </div>
"@
        }

        # Password Change Issues Section
        if ($user.PasswordChangeIssuesCount -gt 0 -and $user.PasswordChangeIssues) {
            $html += @"
            <div class="detail-section">
                <h3><span class="icon">🔑</span>Suspicious Password Change Activity</h3>
                <div class="table-wrapper">
                    <table>
                        <thead>
                            <tr>
                                <th>Change Count</th>
                                <th>Time Span</th>
                                <th>First Change</th>
                                <th>Last Change</th>
                                <th>Unique Initiators</th>
                                <th>Off-Hours Changes</th>
                                <th>Risk Level</th>
                                <th>Suspicious Reasons</th>
                            </tr>
                        </thead>
                        <tbody>
"@
            foreach ($pwChange in $user.PasswordChangeIssues) {
                $pwRiskClass = "risk-" + $pwChange.RiskLevel.ToLower()
                $html += @"
                        <tr>
                            <td style="text-align: center;"><strong>$($pwChange.ChangeCount)</strong></td>
                            <td style="text-align: center;">$($pwChange.TimeSpanHours) hours</td>
                            <td>$($pwChange.FirstChange)</td>
                            <td>$($pwChange.LastChange)</td>
                            <td style="text-align: center;">$($pwChange.UniqueInitiators)</td>
                            <td style="text-align: center;">$($pwChange.OffHoursChanges)</td>
                            <td><span class="risk-badge $pwRiskClass">$($pwChange.RiskLevel)</span></td>
                            <td>$($pwChange.SuspiciousReasons)</td>
                        </tr>
"@
            }
            $html += @"
                        </tbody>
                    </table>
                </div>
            </div>
"@
        }

        # Unusual Sign-Ins Section
        if ($user.UnusualSignInCount -gt 0 -and $user.UnusualSignIns) {
            $html += @"
            <div class="detail-section">
                <h3><span class="icon">🌍</span>Unusual Sign-In Locations</h3>
                <div class="table-wrapper">
                    <table>
                        <thead>
                            <tr>
                                <th>Date/Time</th>
                                <th>IP Address</th>
                                <th>City</th>
                                <th>Region</th>
                                <th>Country</th>
                                <th>ISP</th>
                                <th>Application</th>
                            </tr>
                        </thead>
                        <tbody>
"@
            foreach ($signIn in $user.UnusualSignIns) {
                $html += @"
                        <tr>
                            <td>$(if ($signIn.CreationTime) { $signIn.CreationTime } else { "N/A" })</td>
                            <td>$(if ($signIn.IP) { $signIn.IP } else { "N/A" })</td>
                            <td>$(if ($signIn.City) { $signIn.City } else { "Unknown" })</td>
                            <td>$(if ($signIn.RegionName) { $signIn.RegionName } else { "Unknown" })</td>
                            <td><strong>$(if ($signIn.Country) { $signIn.Country } else { "Unknown" })</strong></td>
                            <td>$(if ($signIn.ISP) { $signIn.ISP } else { "Unknown" })</td>
                            <td>$(if ($signIn.AppDisplayName) { $signIn.AppDisplayName } else { "Unknown" })</td>
                        </tr>
"@
            }
            $html += @"
                        </tbody>
                    </table>
                </div>
            </div>
"@
        }

        # Failed Sign-Ins Section
        if ($user.FailedSignInCount -gt 0 -and $user.FailedSignIns) {
            $html += @"
            <div class="detail-section">
                <h3><span class="icon">❌</span>Failed Sign-In Attempts</h3>
                <div class="table-wrapper">
                    <table>
                        <thead>
                            <tr>
                                <th>Date/Time</th>
                                <th>IP Address</th>
                                <th>Location</th>
                                <th>Failure Reason</th>
                                <th>Application</th>
                            </tr>
                        </thead>
                        <tbody>
"@
            foreach ($signIn in $user.FailedSignIns) {
                $html += @"
                        <tr>
                            <td>$(if ($signIn.CreationTime) { $signIn.CreationTime } else { "N/A" })</td>
                            <td>$(if ($signIn.IP) { $signIn.IP } else { "N/A" })</td>
                            <td>$(if ($signIn.City) { $signIn.City } else { "Unknown" }), $(if ($signIn.Country) { $signIn.Country } else { "Unknown" })</td>
                            <td>$(if ($signIn.FailureReason) { $signIn.FailureReason } else { "Unknown" })</td>
                            <td>$(if ($signIn.AppDisplayName) { $signIn.AppDisplayName } else { "Unknown" })</td>
                        </tr>
"@
            }
            $html += @"
                        </tbody>
                    </table>
                </div>
            </div>
"@
        }

        # High-Risk Operations Section
        if ($user.HighRiskOperationsCount -gt 0 -and $user.HighRiskOperations) {
            $html += @"
            <div class="detail-section">
                <h3><span class="icon">⚙️</span>High-Risk Administrative Operations</h3>
                <div class="table-wrapper">
                    <table>
                        <thead>
                            <tr>
                                <th>Date/Time</th>
                                <th>Activity</th>
                                <th>Initiated By</th>
                                <th>Target</th>
                                <th>Result</th>
                                <th>Risk Level</th>
                            </tr>
                        </thead>
                        <tbody>
"@
            foreach ($op in $user.HighRiskOperations) {
                $opRiskClass = "risk-" + $op.RiskLevel.ToLower()
                $html += @"
                        <tr>
                            <td>$(if ($op.ActivityDate) { $op.ActivityDate } else { "N/A" })</td>
                            <td><strong>$(if ($op.Activity) { $op.Activity } else { "Unknown" })</strong></td>
                            <td>$(if ($op.InitiatedBy) { $op.InitiatedBy } else { "Unknown" })</td>
                            <td>$(if ($op.TargetUser) { $op.TargetUser } else { "N/A" })</td>
                            <td>$(if ($op.Result) { $op.Result } else { "Unknown" })</td>
                            <td><span class="risk-badge $opRiskClass">$($op.RiskLevel)</span></td>
                        </tr>
"@
            }
            $html += @"
                        </tbody>
                    </table>
                </div>
            </div>
"@
        }

        # Suspicious Rules Section
        if ($user.SuspiciousRulesCount -gt 0 -and $user.SuspiciousRules) {
            $html += @"
            <div class="detail-section">
                <h3><span class="icon">📧</span>Suspicious Mailbox Rules</h3>
                <div class="table-wrapper">
                    <table>
                        <thead>
                            <tr>
                                <th>Rule Name</th>
                                <th>Enabled</th>
                                <th>Forward To</th>
                                <th>Move To Folder</th>
                                <th>Delete Message</th>
                                <th>Stop Processing</th>
                                <th>Suspicious Reasons</th>
                            </tr>
                        </thead>
                        <tbody>
"@
            foreach ($rule in $user.SuspiciousRules) {
                $html += @"
                        <tr>
                            <td><strong>$(if ($rule.Name) { $rule.Name } else { "Unnamed" })</strong></td>
                            <td>$(if ($rule.IsEnabled -eq "True") { "✅ Yes" } else { "❌ No" })</td>
                            <td>$(if ($rule.ForwardTo) { $rule.ForwardTo } else { "-" })</td>
                            <td>$(if ($rule.MoveToFolder) { $rule.MoveToFolder } else { "-" })</td>
                            <td>$(if ($rule.DeleteMessage -eq "True") { "⚠️ Yes" } else { "No" })</td>
                            <td>$(if ($rule.StopProcessingRules -eq "True") { "⚠️ Yes" } else { "No" })</td>
                            <td>$(if ($rule.SuspiciousReasons) { $rule.SuspiciousReasons } else { "N/A" })</td>
                        </tr>
"@
            }
            $html += @"
                        </tbody>
                    </table>
                </div>
            </div>
"@
        }

        # Suspicious Delegations Section
        if ($user.SuspiciousDelegationsCount -gt 0 -and $user.SuspiciousDelegations) {
            $html += @"
            <div class="detail-section">
                <h3><span class="icon">👥</span>Suspicious Mailbox Delegations</h3>
                <div class="table-wrapper">
                    <table>
                        <thead>
                            <tr>
                                <th>Delegate</th>
                                <th>Permissions</th>
                                <th>Suspicious Reasons</th>
                            </tr>
                        </thead>
                        <tbody>
"@
            foreach ($delegation in $user.SuspiciousDelegations) {
                $html += @"
                        <tr>
                            <td><strong>$(if ($delegation.Delegate) { $delegation.Delegate } else { "Unknown" })</strong></td>
                            <td>$(if ($delegation.Permissions) { $delegation.Permissions } else { "N/A" })</td>
                            <td>$(if ($delegation.SuspiciousReasons) { $delegation.SuspiciousReasons } else { "N/A" })</td>
                        </tr>
"@
            }
            $html += @"
                        </tbody>
                    </table>
                </div>
            </div>
"@
        }

        # High-Risk App Registrations Section
        if ($user.HighRiskAppRegistrationsCount -gt 0 -and $user.HighRiskAppRegistrations) {
            $html += @"
            <div class="detail-section">
                <h3><span class="icon">📱</span>High-Risk Application Registrations</h3>
                <div class="table-wrapper">
                    <table>
                        <thead>
                            <tr>
                                <th>App Name</th>
                                <th>App ID</th>
                                <th>Created Date</th>
                                <th>Risk Level</th>
                                <th>Risk Reasons</th>
                            </tr>
                        </thead>
                        <tbody>
"@
            foreach ($app in $user.HighRiskAppRegistrations) {
                $appRiskClass = "risk-" + $app.RiskLevel.ToLower()
                $html += @"
                        <tr>
                            <td><strong>$(if ($app.DisplayName) { $app.DisplayName } else { "Unknown" })</strong></td>
                            <td>$(if ($app.AppId) { $app.AppId } else { "N/A" })</td>
                            <td>$(if ($app.CreatedDateTime) { $app.CreatedDateTime } else { "N/A" })</td>
                            <td><span class="risk-badge $appRiskClass">$($app.RiskLevel)</span></td>
                            <td>$(if ($app.RiskReasons) { $app.RiskReasons } else { "N/A" })</td>
                        </tr>
"@
            }
            $html += @"
                        </tbody>
                    </table>
                </div>
            </div>
"@
        }

        # ETR Spam Activity Section
        if ($user.ETRSpamActivityCount -gt 0 -and $user.ETRSpamActivity) {
            $html += @"
            <div class="detail-section">
                <h3><span class="icon">📨</span>Email Spam Activity Detected</h3>
                <div class="table-wrapper">
                    <table>
                        <thead>
                            <tr>
                                <th>Pattern Type</th>
                                <th>Message Count</th>
                                <th>Risk Score</th>
                                <th>Risk Level</th>
                                <th>Details</th>
                            </tr>
                        </thead>
                        <tbody>
"@
            foreach ($spam in $user.ETRSpamActivity) {
                $spamRiskClass = "risk-" + $spam.RiskLevel.ToLower()
                $html += @"
                        <tr>
                            <td><strong>$(if ($spam.PatternType) { $spam.PatternType } else { "Unknown" })</strong></td>
                            <td style="text-align: center;">$(if ($spam.MessageCount) { $spam.MessageCount } else { "0" })</td>
                            <td style="text-align: center;"><strong>$(if ($spam.RiskScore) { $spam.RiskScore } else { "0" })</strong></td>
                            <td><span class="risk-badge $spamRiskClass">$(if ($spam.RiskLevel) { $spam.RiskLevel } else { "Unknown" })</span></td>
                            <td>$(if ($spam.Details) { $spam.Details } else { "N/A" })</td>
                        </tr>
"@
            }
            $html += @"
                        </tbody>
                    </table>
                </div>
            </div>
"@
        }

        $html += @"
        </div>
"@
    }

    $html += @"
        
        <script>
            var coll = document.getElementsByClassName("collapsible");
            var i;
            
            for (i = 0; i < coll.length; i++) {
                coll[i].addEventListener("click", function() {
                    this.classList.toggle("active");
                    var content = this.nextElementSibling;
                    if (content.style.display === "block") {
                        content.style.display = "none";
                    } else {
                        content.style.display = "block";
                    }
                });
            }
            
            // Auto-expand critical risk users on page load
            document.addEventListener("DOMContentLoaded", function() {
                var criticalButtons = document.querySelectorAll('.collapsible .risk-critical');
                criticalButtons.forEach(function(badge) {
                    var collapsible = badge.parentElement;
                    collapsible.classList.add("active");
                    collapsible.nextElementSibling.style.display = "block";
                });
            });
        </script>
        
        <div class="metadata" style="margin-top: 40px;">
            <strong>Analysis Notes:</strong><br>
            • This enhanced report was generated using Microsoft Graph PowerShell APIs<br>
            • Risk scores are calculated based on multiple security indicators<br>
            • Critical and High risk users are automatically expanded in the detailed analysis<br>
            • Review all suspicious activities for potential compromise indicators<br>
            • MFA status indicates multi-factor authentication enrollment<br>
            • Attack patterns require 5+ failed logins from same IP for breach confirmation<br>
            • Password change analysis detects suspicious reset patterns<br>
            • Performance optimizations include IP caching and batch processing
        </div>
    </div>
</body>
</html>
"@

    return $html
}


#endregion

#################################################################
#
#  SECTION 5: GUI FUNCTIONS
#
#################################################################

#region GUI FUNCTIONS

function Show-MainGUI {
    <#
    .SYNOPSIS
        Displays the main graphical user interface for the security analysis tool.
    
    .DESCRIPTION
        Creates and displays the primary application window featuring:
        • Connection status display
        • Data collection buttons
        • Analysis execution controls
        • Report viewing capabilities
        • Configuration management
        • Real-time status updates
    
    .EXAMPLE
        Show-MainGUI
        # Displays the main application interface
    
    .NOTES
        The GUI maintains global references to UI elements for status updates
        All buttons include error handling and visual feedback
        Form cleanup includes proper Microsoft Graph disconnection
    #>
    
    [CmdletBinding()]
    param()
    
    #──────────────────────────────────────────────────────────────
    # ENSURE ASSEMBLIES ARE LOADED
    #──────────────────────────────────────────────────────────────
    
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    #──────────────────────────────────────────────────────────────
    # CREATE MAIN FORM
    #──────────────────────────────────────────────────────────────
    
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Microsoft 365 Security Analysis Tool - v$ScriptVer"
    $form.Size = New-Object System.Drawing.Size(820, 750)
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = "FixedSingle"
    $form.MaximizeBox = $false
    $form.BackColor = [System.Drawing.Color]::FromArgb(240, 248, 255)

    # Set global form reference
    $Global:MainForm = $form

    #──────────────────────────────────────────────────────────────
    # HEADER SECTION
    #──────────────────────────────────────────────────────────────
    
    $headerLabel = New-Object System.Windows.Forms.Label
    $headerLabel.Text = "Microsoft 365 Security Analysis Tool"
    $headerLabel.Font = New-Object System.Drawing.Font("Segoe UI", 16, [System.Drawing.FontStyle]::Bold)
    $headerLabel.ForeColor = [System.Drawing.Color]::FromArgb(0, 120, 212)
    $headerLabel.Size = New-Object System.Drawing.Size(780, 40)
    $headerLabel.Location = New-Object System.Drawing.Point(20, 20)
    $headerLabel.TextAlign = "MiddleCenter"
    $form.Controls.Add($headerLabel)

    # Version label
    $versionLabel = New-Object System.Windows.Forms.Label
    $versionLabel.Text = "Enhanced MS Graph PowerShell Edition - Version $ScriptVer"
    $versionLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $versionLabel.ForeColor = [System.Drawing.Color]::Gray
    $versionLabel.Size = New-Object System.Drawing.Size(780, 20)
    $versionLabel.Location = New-Object System.Drawing.Point(20, 60)
    $versionLabel.TextAlign = "MiddleCenter"
    $form.Controls.Add($versionLabel)

    #──────────────────────────────────────────────────────────────
    # DISCLAIMER PANEL
    #──────────────────────────────────────────────────────────────
    
    $disclaimerPanel = New-Object System.Windows.Forms.Panel
    $disclaimerPanel.Size = New-Object System.Drawing.Size(780, 80)
    $disclaimerPanel.Location = New-Object System.Drawing.Point(20, 90)
    $disclaimerPanel.BorderStyle = "FixedSingle"
    $disclaimerPanel.BackColor = [System.Drawing.Color]::FromArgb(255, 248, 220)
    $form.Controls.Add($disclaimerPanel)

    $disclaimerTitle = New-Object System.Windows.Forms.Label
    $disclaimerTitle.Text = "NOTICE - PROPRIETARY TOOL"
    $disclaimerTitle.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $disclaimerTitle.ForeColor = [System.Drawing.Color]::FromArgb(184, 134, 11)
    $disclaimerTitle.Size = New-Object System.Drawing.Size(760, 25)
    $disclaimerTitle.Location = New-Object System.Drawing.Point(10, 10)
    $disclaimerTitle.TextAlign = "MiddleCenter"
    $disclaimerPanel.Controls.Add($disclaimerTitle)

    $disclaimerText = New-Object System.Windows.Forms.Label
    $disclaimerText.Text = "This tool was developed by Pacific Office Automation and enhanced with AI assistance." + [Environment]::NewLine + 
                          "AUTHORIZED FOR USE BY PACIFIC OFFICE AUTOMATION EMPLOYEES ONLY." + [Environment]::NewLine +
                          "Unauthorized use, distribution, or modification is strictly prohibited."
    $disclaimerText.Font = New-Object System.Drawing.Font("Segoe UI", 8)
    $disclaimerText.ForeColor = [System.Drawing.Color]::FromArgb(133, 77, 14)
    $disclaimerText.Size = New-Object System.Drawing.Size(760, 45)
    $disclaimerText.Location = New-Object System.Drawing.Point(10, 35)
    $disclaimerText.TextAlign = "MiddleCenter"
    $disclaimerPanel.Controls.Add($disclaimerText)

    #──────────────────────────────────────────────────────────────
    # STATUS PANEL
    #──────────────────────────────────────────────────────────────
    
    $statusPanel = New-Object System.Windows.Forms.Panel
    $statusPanel.Size = New-Object System.Drawing.Size(780, 140)
    $statusPanel.Location = New-Object System.Drawing.Point(20, 180)
    $statusPanel.BorderStyle = "FixedSingle"
    $statusPanel.BackColor = [System.Drawing.Color]::White
    $form.Controls.Add($statusPanel)

    $Global:WorkDirLabel = New-Object System.Windows.Forms.Label
    $Global:WorkDirLabel.Text = "Working Directory: $($ConfigData.WorkDir)"
    $Global:WorkDirLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $Global:WorkDirLabel.Size = New-Object System.Drawing.Size(760, 25)
    $Global:WorkDirLabel.Location = New-Object System.Drawing.Point(10, 10)
    $statusPanel.Controls.Add($Global:WorkDirLabel)

    $Global:DateRangeLabel = New-Object System.Windows.Forms.Label
    $Global:DateRangeLabel.Text = "Date Range: $($ConfigData.DateRange) days back"
    $Global:DateRangeLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $Global:DateRangeLabel.Size = New-Object System.Drawing.Size(760, 25)
    $Global:DateRangeLabel.Location = New-Object System.Drawing.Point(10, 35)
    $Global:DateRangeLabel.ForeColor = [System.Drawing.Color]::FromArgb(0, 120, 212)
    $statusPanel.Controls.Add($Global:DateRangeLabel)

    $Global:ConnectionLabel = New-Object System.Windows.Forms.Label
    $Global:ConnectionLabel.Text = "Microsoft Graph: Not Connected"
    $Global:ConnectionLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $Global:ConnectionLabel.Size = New-Object System.Drawing.Size(760, 25)
    $Global:ConnectionLabel.Location = New-Object System.Drawing.Point(10, 60)
    $Global:ConnectionLabel.ForeColor = [System.Drawing.Color]::Red
    $statusPanel.Controls.Add($Global:ConnectionLabel)

    $Global:TenantInfoLabel = New-Object System.Windows.Forms.Label
    $Global:TenantInfoLabel.Text = "Not connected to any tenant"
    $Global:TenantInfoLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $Global:TenantInfoLabel.Size = New-Object System.Drawing.Size(760, 25)
    $Global:TenantInfoLabel.Location = New-Object System.Drawing.Point(10, 85)
    $Global:TenantInfoLabel.ForeColor = [System.Drawing.Color]::Gray
    $statusPanel.Controls.Add($Global:TenantInfoLabel)

    $performanceLabel = New-Object System.Windows.Forms.Label
    $performanceLabel.Text = "Performance: Batch Size $($ConfigData.BatchSize) | Cache Timeout $($ConfigData.CacheTimeout)s"
    $performanceLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8)
    $performanceLabel.Size = New-Object System.Drawing.Size(760, 20)
    $performanceLabel.Location = New-Object System.Drawing.Point(10, 110)
    $performanceLabel.ForeColor = [System.Drawing.Color]::FromArgb(108, 117, 125)
    $statusPanel.Controls.Add($performanceLabel)

    #──────────────────────────────────────────────────────────────
    # BOTTOM STATUS BAR
    #──────────────────────────────────────────────────────────────
    
    $Global:StatusLabel = New-Object System.Windows.Forms.Label
    $Global:StatusLabel.Text = "Ready - Please connect to Microsoft Graph to begin"
    $Global:StatusLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $Global:StatusLabel.Size = New-Object System.Drawing.Size(780, 25)
    $Global:StatusLabel.Location = New-Object System.Drawing.Point(20, 620)
    $Global:StatusLabel.ForeColor = [System.Drawing.Color]::FromArgb(108, 117, 125)
    $form.Controls.Add($Global:StatusLabel)

    #──────────────────────────────────────────────────────────────
    # BUTTON CREATION HELPER FUNCTION
    #──────────────────────────────────────────────────────────────
    
    function New-GuiButton {
        <#
        .SYNOPSIS
            Creates a styled button with error handling for the GUI.
        #>
        param(
            [string]$text,
            [int]$x,
            [int]$y,
            [int]$width,
            [int]$height,
            [System.Drawing.Color]$color,
            [scriptblock]$action
        )
        
        $button = New-Object System.Windows.Forms.Button
        $button.Text = $text
        $button.Size = New-Object System.Drawing.Size($width, $height)
        $button.Location = New-Object System.Drawing.Point($x, $y)
        $button.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
        $button.BackColor = $color
        $button.ForeColor = [System.Drawing.Color]::White
        $button.FlatStyle = "Flat"
        $button.FlatAppearance.BorderSize = 1
        $button.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(100, 100, 100)
        
        # Store action in button's Tag property
        $button.Tag = $action
        
        # Enhanced click handler
        $button.Add_Click({
            try {
                $actionBlock = $this.Tag
                if ($actionBlock -and $actionBlock -is [scriptblock]) {
                    . $actionBlock
                } else {
                    throw "Invalid or missing action script block"
                }
            }
            catch {
                Update-GuiStatus "Button action failed: $($_.Exception.Message)" ([System.Drawing.Color]::Red)
                [System.Windows.Forms.MessageBox]::Show(
                    "An error occurred: $($_.Exception.Message)",
                    "Error",
                    "OK",
                    "Error"
                )
            }
        })
        
        return $button
    }

    #──────────────────────────────────────────────────────────────
    # ROW 1: SETUP BUTTONS
    #──────────────────────────────────────────────────────────────
    
    $btnWorkDir = New-GuiButton -text "Set Working Directory" -x 30 -y 340 -width 140 -height 35 `
        -color ([System.Drawing.Color]::FromArgb(108, 117, 125)) -action {
        $folder = Get-Folder -initialDirectory $ConfigData.WorkDir
        if ($folder) {
            Update-WorkingDirectoryDisplay -NewWorkDir $folder
            Update-GuiStatus "Working directory updated successfully" ([System.Drawing.Color]::Green)
            
            if ($Global:ConnectionState.IsConnected) {
                [System.Windows.Forms.MessageBox]::Show(
                    "Working directory updated to:`n$folder`n`n" +
                    "Note: You are currently connected to tenant '$($Global:ConnectionState.TenantName)'. " +
                    "The tenant-specific directory will be recreated on next connection.",
                    "Directory Updated",
                    "OK",
                    "Information"
                )
            } else {
                [System.Windows.Forms.MessageBox]::Show(
                    "Working directory updated to:`n$folder",
                    "Directory Updated",
                    "OK",
                    "Information"
                )
            }
        }
    }
    $form.Controls.Add($btnWorkDir)

    $btnDateRange = New-GuiButton -text "Change Date Range" -x 180 -y 340 -width 140 -height 35 `
        -color ([System.Drawing.Color]::FromArgb(75, 0, 130)) -action {
        $newRange = Get-DateRangeInput -CurrentValue $ConfigData.DateRange
        if ($newRange -ne $null) {
            $oldRange = $ConfigData.DateRange
            $ConfigData.DateRange = $newRange
            $Global:DateRangeLabel.Text = "Date Range: $($ConfigData.DateRange) days back"
            $Global:DateRangeLabel.Refresh()
            Update-GuiStatus "Date range updated from $oldRange to $newRange days" ([System.Drawing.Color]::Green)
            
            [System.Windows.Forms.MessageBox]::Show(
                "Date range updated successfully!`n`nOld range: $oldRange days`nNew range: $newRange days`n`n" +
                "Note: This will affect all future data collection operations.",
                "Date Range Updated",
                "OK",
                "Information"
            )
        }
    }
    $form.Controls.Add($btnDateRange)

    $btnConnect = New-GuiButton -text "Connect to Microsoft Graph" -x 330 -y 340 -width 140 -height 35 `
        -color ([System.Drawing.Color]::FromArgb(0, 120, 212)) -action {
        $btnConnect.Enabled = $false
        $originalText = $btnConnect.Text
        $btnConnect.Text = "Connecting..."
        
        try {
            $connected = Connect-TenantServices
            
            if ($connected) {
                Update-GuiStatus "Connected to Microsoft Graph successfully!" ([System.Drawing.Color]::Green)
            } else {
                Update-GuiStatus "Failed to connect to Microsoft Graph" ([System.Drawing.Color]::Red)
            }
        }
        finally {
            $btnConnect.Enabled = $true
            $btnConnect.Text = $originalText
        }
    }
    $form.Controls.Add($btnConnect)

    $btnDisconnect = New-GuiButton -text "Disconnect" -x 480 -y 340 -width 100 -height 35 `
        -color ([System.Drawing.Color]::FromArgb(220, 53, 69)) -action {
        $btnDisconnect.Enabled = $false
        $originalText = $btnDisconnect.Text
        $btnDisconnect.Text = "Disconnecting..."
        
        try {
            Disconnect-GraphSafely -ShowMessage $true
        }
        finally {
            $btnDisconnect.Enabled = $true
            $btnDisconnect.Text = $originalText
        }
    }
    $form.Controls.Add($btnDisconnect)

    $btnCheckVersion = New-GuiButton -text "Check Version" -x 590 -y 340 -width 190 -height 35 `
        -color ([System.Drawing.Color]::FromArgb(102, 16, 242)) -action {
        Test-ScriptVersion -ShowMessageBox $true
    }
    $form.Controls.Add($btnCheckVersion)

    #──────────────────────────────────────────────────────────────
    # ROW 2: DATA COLLECTION BUTTONS (PART 1)
    #──────────────────────────────────────────────────────────────
    
    $btnSignIn = New-GuiButton -text "Collect Sign-In Data" -x 30 -y 390 -width 180 -height 35 `
        -color ([System.Drawing.Color]::FromArgb(40, 167, 69)) -action {
        if (-not $Global:ConnectionState.IsConnected) {
            Update-GuiStatus "Please connect to Microsoft Graph first!" ([System.Drawing.Color]::Red)
            return
        }
        
        $btnSignIn.Enabled = $false
        $originalText = $btnSignIn.Text
        $btnSignIn.Text = "Running..."
        
        try {
            $result = Get-TenantSignInData
            if ($result) {
                Update-GuiStatus "Sign-in data collected! Processed $($result.Count) records." ([System.Drawing.Color]::Green)
            }
        }
        finally {
            $btnSignIn.Enabled = $true
            $btnSignIn.Text = $originalText
        }
    }
    $form.Controls.Add($btnSignIn)

    $btnAudit = New-GuiButton -text "Collect Admin Audits" -x 220 -y 390 -width 180 -height 35 `
        -color ([System.Drawing.Color]::FromArgb(40, 167, 69)) -action {
        if (-not $Global:ConnectionState.IsConnected) {
            Update-GuiStatus "Please connect to Microsoft Graph first!" ([System.Drawing.Color]::Red)
            return
        }
        
        $btnAudit.Enabled = $false
        $originalText = $btnAudit.Text
        $btnAudit.Text = "Running..."
        
        try {
            $result = Get-AdminAuditData
            if ($result) {
                Update-GuiStatus "Admin audit data collected! Processed $($result.Count) records." ([System.Drawing.Color]::Green)
            }
        }
        finally {
            $btnAudit.Enabled = $true
            $btnAudit.Text = $originalText
        }
    }
    $form.Controls.Add($btnAudit)

    $btnRules = New-GuiButton -text "Collect Inbox Rules" -x 410 -y 390 -width 180 -height 35 `
        -color ([System.Drawing.Color]::FromArgb(40, 167, 69)) -action {
        if (-not $Global:ConnectionState.IsConnected) {
            Update-GuiStatus "Please connect to Microsoft Graph first!" ([System.Drawing.Color]::Red)
            return
        }
        
        $btnRules.Enabled = $false
        $originalText = $btnRules.Text
        $btnRules.Text = "Running..."
        
        try {
            $result = Get-MailboxRules
            if ($result) {
                Update-GuiStatus "Inbox rules collected! Found $($result.Count) rules." ([System.Drawing.Color]::Green)
            }
        }
        finally {
            $btnRules.Enabled = $true
            $btnRules.Text = $originalText
        }
    }
    $form.Controls.Add($btnRules)

    $btnDelegation = New-GuiButton -text "Collect Delegations" -x 600 -y 390 -width 180 -height 35 `
        -color ([System.Drawing.Color]::FromArgb(40, 167, 69)) -action {
        if (-not $Global:ConnectionState.IsConnected) {
            Update-GuiStatus "Please connect to Microsoft Graph first!" ([System.Drawing.Color]::Red)
            return
        }
        
        $btnDelegation.Enabled = $false
        $originalText = $btnDelegation.Text
        $btnDelegation.Text = "Running..."
        
        try {
            $result = Get-MailboxDelegationData
            if ($result) {
                Update-GuiStatus "Delegation data collected! Found $($result.Count) delegations." ([System.Drawing.Color]::Green)
            }
        }
        finally {
            $btnDelegation.Enabled = $true
            $btnDelegation.Text = $originalText
        }
    }
    $form.Controls.Add($btnDelegation)

    #──────────────────────────────────────────────────────────────
    # ROW 3: DATA COLLECTION BUTTONS (PART 2)
    #──────────────────────────────────────────────────────────────
    
    $btnApps = New-GuiButton -text "Collect App Registrations" -x 30 -y 440 -width 180 -height 35 `
        -color ([System.Drawing.Color]::FromArgb(40, 167, 69)) -action {
        if (-not $Global:ConnectionState.IsConnected) {
            Update-GuiStatus "Please connect to Microsoft Graph first!" ([System.Drawing.Color]::Red)
            return
        }
        
        $btnApps.Enabled = $false
        $originalText = $btnApps.Text
        $btnApps.Text = "Running..."
        
        try {
            $result = Get-AppRegistrationData
            if ($result) {
                Update-GuiStatus "App registration data collected! Found $($result.Count) apps." ([System.Drawing.Color]::Green)
            }
        }
        finally {
            $btnApps.Enabled = $true
            $btnApps.Text = $originalText
        }
    }
    $form.Controls.Add($btnApps)

    $btnConditionalAccess = New-GuiButton -text "Conditional Access" -x 220 -y 440 -width 180 -height 35 `
        -color ([System.Drawing.Color]::FromArgb(40, 167, 69)) -action {
        if (-not $Global:ConnectionState.IsConnected) {
            Update-GuiStatus "Please connect to Microsoft Graph first!" ([System.Drawing.Color]::Red)
            return
        }
        
        $btnConditionalAccess.Enabled = $false
        $originalText = $btnConditionalAccess.Text
        $btnConditionalAccess.Text = "Running..."
        
        try {
            $result = Get-ConditionalAccessData
            if ($result) {
                Update-GuiStatus "Conditional access data collected! Found $($result.Count) policies." ([System.Drawing.Color]::Green)
            }
        }
        finally {
            $btnConditionalAccess.Enabled = $true
            $btnConditionalAccess.Text = $originalText
        }
    }
    $form.Controls.Add($btnConditionalAccess)

    $btnETRAnalysis = New-GuiButton -text "Analyze ETR Files" -x 410 -y 440 -width 180 -height 35 `
        -color ([System.Drawing.Color]::FromArgb(75, 0, 130)) -action {
        $btnETRAnalysis.Enabled = $false
        $originalText = $btnETRAnalysis.Text
        $btnETRAnalysis.Text = "Analyzing ETR..."
        
        try {
            # Get risky IPs for correlation
            $riskyIPs = @()
            $signInDataPath = Join-Path -Path $ConfigData.WorkDir -ChildPath "UserLocationData.csv"
            if (Test-Path $signInDataPath) {
                try {
                    $signInData = Import-Csv -Path $signInDataPath
                    $riskyIPs = $signInData | Where-Object { $_.IsUnusualLocation -eq "True" -and -not [string]::IsNullOrEmpty($_.IP) } | 
                               Select-Object -ExpandProperty IP -Unique
                    Write-Log "Using $($riskyIPs.Count) risky IPs for ETR correlation" -Level "Info"
                } catch {
                    Write-Log "Could not load sign-in data for IP correlation: $($_.Exception.Message)" -Level "Warning"
                }
            }
            
            $result = Analyze-ETRData -RiskyIPs $riskyIPs
            if ($result) {
                $criticalCount = ($result | Where-Object { $_.RiskLevel -eq "Critical" }).Count
                $highCount = ($result | Where-Object { $_.RiskLevel -eq "High" }).Count
                Update-GuiStatus "ETR analysis completed! Found $criticalCount critical and $highCount high-risk patterns." ([System.Drawing.Color]::Green)
            }
        }
        finally {
            $btnETRAnalysis.Enabled = $true
            $btnETRAnalysis.Text = $originalText
        }
    }
    $form.Controls.Add($btnETRAnalysis)

    $btnMessageTrace = New-GuiButton -text "Collect Message Trace" -x 600 -y 440 -width 180 -height 35 `
        -color ([System.Drawing.Color]::FromArgb(75, 0, 130)) -action {
        $btnMessageTrace.Enabled = $false
        $originalText = $btnMessageTrace.Text
        $btnMessageTrace.Text = "Running Trace..."
        
        try {
            $result = Get-MessageTraceExchangeOnline
            if ($result) {
                Update-GuiStatus "Message trace collected! Processed $($result.Count) messages." ([System.Drawing.Color]::Green)
                
                # Suggest running ETR analysis
                $runAnalysis = [System.Windows.Forms.MessageBox]::Show(
                    "Message trace collection complete!`n`n$($result.Count) messages saved.`n`nRun ETR analysis now?",
                    "Run Analysis?",
                    "YesNo",
                    "Question"
                )
                
                if ($runAnalysis -eq "Yes") {
                    # Get risky IPs
                    $riskyIPs = @()
                    $signInDataPath = Join-Path -Path $ConfigData.WorkDir -ChildPath "UserLocationData.csv"
                    if (Test-Path $signInDataPath) {
                        try {
                            $signInData = Import-Csv -Path $signInDataPath
                            $riskyIPs = $signInData | Where-Object { $_.IsUnusualLocation -eq "True" } | 
                                       Select-Object -ExpandProperty IP -Unique
                        } catch { }
                    }
                    Analyze-ETRData -RiskyIPs $riskyIPs
                }
            }
        }
        finally {
            $btnMessageTrace.Enabled = $true
            $btnMessageTrace.Text = $originalText
        }
    }
    $form.Controls.Add($btnMessageTrace)

    #──────────────────────────────────────────────────────────────
    # ROW 4: BULK OPERATIONS
    #──────────────────────────────────────────────────────────────
    
    $btnRunAll = New-GuiButton -text "Run All Data Collection" -x 30 -y 500 -width 280 -height 45 `
        -color ([System.Drawing.Color]::FromArgb(255, 193, 7)) -action {
        if (-not $Global:ConnectionState.IsConnected) {
            Update-GuiStatus "Please connect to Microsoft Graph first!" ([System.Drawing.Color]::Red)
            return
        }
        
        $btnRunAll.Enabled = $false
        $originalText = $btnRunAll.Text
        
        $tasks = @(
            @{Name="Sign-In Data"; Function="Get-TenantSignInData"},
            @{Name="Admin Audits"; Function="Get-AdminAuditData"},
            @{Name="Inbox Rules"; Function="Get-MailboxRules"},
			@{Name="MFA Status Audit"; Function="Get-MFAStatusAudit"},
            @{Name="Failed Login Analysis"; Function="Get-FailedLoginPatterns"},
            @{Name="Password Change Analysis"; Function="Get-RecentPasswordChanges"}
            @{Name="Delegations"; Function="Get-MailboxDelegationData"},
            @{Name="App Registrations"; Function="Get-AppRegistrationData"},
            @{Name="Conditional Access"; Function="Get-ConditionalAccessData"},
            @{Name="Message Trace"; Function="Get-MessageTraceExchangeOnline"},
            @{Name="ETR Analysis"; Function="Analyze-ETRData"}
        )
        $completed = 0
        
        Update-GuiStatus "Starting comprehensive data collection..." ([System.Drawing.Color]::Orange)
        
        foreach ($task in $tasks) {
            $btnRunAll.Text = "Running: $($task.Name)..."
            Update-GuiStatus "Executing: $($task.Name)..." ([System.Drawing.Color]::Orange)
            
            try {
                switch ($task.Function) {
                    "Get-TenantSignInData" { Get-TenantSignInData | Out-Null }
                    "Get-AdminAuditData" { Get-AdminAuditData | Out-Null }
                    "Get-MailboxRules" { Get-MailboxRules | Out-Null }
					"Get-MFAStatusAudit" { Get-MFAStatusAudit | Out-Null }
					"Get-FailedLoginPatterns" { Get-FailedLoginPatterns | Out-Null }
					"Get-RecentPasswordChanges" { Get-RecentPasswordChanges | Out-Null }
                    "Get-MailboxDelegationData" { Get-MailboxDelegationData | Out-Null }
                    "Get-AppRegistrationData" { Get-AppRegistrationData | Out-Null }
                    "Get-ConditionalAccessData" { Get-ConditionalAccessData | Out-Null }
                    "Get-MessageTraceExchangeOnline" { Get-MessageTraceExchangeOnline | Out-Null }
                    "Analyze-ETRData" { 
                        # Get risky IPs for ETR analysis
                        $riskyIPs = @()
                        $signInDataPath = Join-Path -Path $ConfigData.WorkDir -ChildPath "UserLocationData.csv"
                        if (Test-Path $signInDataPath) {
                            try {
                                $signInData = Import-Csv -Path $signInDataPath
                                $riskyIPs = $signInData | Where-Object { $_.IsUnusualLocation -eq "True" } | 
                                           Select-Object -ExpandProperty IP -Unique
                            } catch { }
                        }
                        Analyze-ETRData -RiskyIPs $riskyIPs | Out-Null 
                    }
                }
                $completed++
                Update-GuiStatus "Completed: $($task.Name) ($completed/$($tasks.Count))" ([System.Drawing.Color]::Green)
            }
            catch {
                Write-Log "Error in $($task.Name): $($_.Exception.Message)" -Level "Error"
                Update-GuiStatus "Error in $($task.Name): $($_.Exception.Message)" ([System.Drawing.Color]::Red)
            }
        }
        
        $btnRunAll.Enabled = $true
        $btnRunAll.Text = $originalText
        Update-GuiStatus "Data collection completed! Finished $completed of $($tasks.Count) tasks." ([System.Drawing.Color]::Green)
        
        [System.Windows.Forms.MessageBox]::Show(
            "Data collection completed!`n`nFinished $completed out of $($tasks.Count) tasks successfully.",
            "Collection Complete",
            "OK",
            "Information"
        )
    }
    $form.Controls.Add($btnRunAll)

    $btnAnalyze = New-GuiButton -text "Analyze Data" -x 330 -y 500 -width 150 -height 45 `
        -color ([System.Drawing.Color]::FromArgb(220, 53, 69)) -action {
        $btnAnalyze.Enabled = $false
        $originalText = $btnAnalyze.Text
        $btnAnalyze.Text = "Analyzing..."
        
        $reportPath = Join-Path -Path $ConfigData.WorkDir -ChildPath "SecurityReport.html"
        
        try {
            Update-GuiStatus "Starting comprehensive security analysis..." ([System.Drawing.Color]::Orange)
            $results = Invoke-CompromiseDetection -ReportPath $reportPath
            
            if ($results) {
                $critical = ($results | Where-Object { $_.RiskLevel -eq "Critical" }).Count
                $high = ($results | Where-Object { $_.RiskLevel -eq "High" }).Count
                $medium = ($results | Where-Object { $_.RiskLevel -eq "Medium" }).Count
                
                Update-GuiStatus "Analysis completed - $critical critical, $high high, $medium medium risk users" ([System.Drawing.Color]::Green)
                
                $result = [System.Windows.Forms.MessageBox]::Show(
                    "Security Analysis Completed!`n`n" +
                    "Risk Summary:`n• Critical Risk: $critical users`n• High Risk: $high users`n• Medium Risk: $medium users`n`n" +
                    "Total Users Analyzed: $($results.Count)`n`nOpen the detailed HTML report now?",
                    "Analysis Complete",
                    "YesNo",
                    "Information"
                )
                
                if ($result -eq "Yes") {
                    Start-Process $reportPath
                }
            } else {
                Update-GuiStatus "Analysis failed - no data available" ([System.Drawing.Color]::Red)
                [System.Windows.Forms.MessageBox]::Show(
                    "Analysis failed or no data available.`n`nPlease ensure you have collected data first.",
                    "Analysis Failed",
                    "OK",
                    "Warning"
                )
            }
        }
        finally {
            $btnAnalyze.Enabled = $true
            $btnAnalyze.Text = $originalText
        }
    }
    $form.Controls.Add($btnAnalyze)

    $btnViewReports = New-GuiButton -text "View Reports" -x 500 -y 500 -width 140 -height 45 `
        -color ([System.Drawing.Color]::FromArgb(102, 16, 242)) -action {
        Update-GuiStatus "Looking for reports in working directory..." ([System.Drawing.Color]::Orange)
        
        $reports = Get-ChildItem -Path $ConfigData.WorkDir -Filter "*.html" -ErrorAction SilentlyContinue
        
        if ($reports.Count -eq 0) {
            Update-GuiStatus "No reports found in working directory" ([System.Drawing.Color]::Orange)
            [System.Windows.Forms.MessageBox]::Show(
                "No HTML reports found in the working directory:`n$($ConfigData.WorkDir)`n`n" +
                "Please run the analysis first to generate reports.",
                "No Reports Found",
                "OK",
                "Information"
            )
            return
        }
        
        if ($reports.Count -eq 1) {
            Update-GuiStatus "Opening report: $($reports[0].Name)" ([System.Drawing.Color]::Green)
            Start-Process $reports[0].FullName
        } else {
            # Show report selection dialog
            $reportForm = New-Object System.Windows.Forms.Form
            $reportForm.Text = "Select Report to Open"
            $reportForm.Size = New-Object System.Drawing.Size(600, 400)
            $reportForm.StartPosition = "CenterParent"
            $reportForm.FormBorderStyle = "FixedDialog"
            $reportForm.MaximizeBox = $false
            $reportForm.MinimizeBox = $false
            
            $reportLabel = New-Object System.Windows.Forms.Label
            $reportLabel.Text = "Select a report to open:"
            $reportLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
            $reportLabel.Size = New-Object System.Drawing.Size(560, 30)
            $reportLabel.Location = New-Object System.Drawing.Point(20, 20)
            $reportForm.Controls.Add($reportLabel)
            
            $listBox = New-Object System.Windows.Forms.ListBox
            $listBox.Size = New-Object System.Drawing.Size(560, 280)
            $listBox.Location = New-Object System.Drawing.Point(20, 50)
            $listBox.Font = New-Object System.Drawing.Font("Segoe UI", 9)
            
            foreach ($report in $reports) {
                $item = "$($report.Name) ($(Get-Date $report.LastWriteTime -Format 'yyyy-MM-dd HH:mm:ss'))"
                $listBox.Items.Add($item) | Out-Null
            }
            
            $reportForm.Controls.Add($listBox)
            
            $buttonPanel = New-Object System.Windows.Forms.Panel
            $buttonPanel.Size = New-Object System.Drawing.Size(560, 50)
            $buttonPanel.Location = New-Object System.Drawing.Point(20, 340)
            $reportForm.Controls.Add($buttonPanel)
            
            $openBtn = New-Object System.Windows.Forms.Button
            $openBtn.Text = "Open Selected Report"
            $openBtn.Size = New-Object System.Drawing.Size(150, 35)
            $openBtn.Location = New-Object System.Drawing.Point(300, 10)
            $openBtn.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 212)
            $openBtn.ForeColor = [System.Drawing.Color]::White
            $openBtn.FlatStyle = "Flat"
            $openBtn.Add_Click({
                if ($listBox.SelectedIndex -ge 0) {
                    Start-Process $reports[$listBox.SelectedIndex].FullName
                    $reportForm.Close()
                }
            })
            $buttonPanel.Controls.Add($openBtn)
            
            $cancelBtn = New-Object System.Windows.Forms.Button
            $cancelBtn.Text = "Cancel"
            $cancelBtn.Size = New-Object System.Drawing.Size(100, 35)
            $cancelBtn.Location = New-Object System.Drawing.Point(460, 10)
            $cancelBtn.BackColor = [System.Drawing.Color]::FromArgb(108, 117, 125)
            $cancelBtn.ForeColor = [System.Drawing.Color]::White
            $cancelBtn.FlatStyle = "Flat"
            $cancelBtn.Add_Click({ $reportForm.Close() })
            $buttonPanel.Controls.Add($cancelBtn)
            
            [void]$reportForm.ShowDialog()
        }
    }
    $form.Controls.Add($btnViewReports)

    $btnExit = New-GuiButton -text "Exit Application" -x 660 -y 500 -width 120 -height 45 `
        -color ([System.Drawing.Color]::FromArgb(108, 117, 125)) -action {
        $result = [System.Windows.Forms.MessageBox]::Show(
            "Are you sure you want to exit the application?`n`n" +
            "This will disconnect from Microsoft Graph and close the tool.",
            "Confirm Exit",
            "YesNo",
            "Question"
        )
        
        if ($result -eq "Yes") {
            Update-GuiStatus "Shutting down application..." ([System.Drawing.Color]::Orange)
            
            # Clean disconnect
            if ($Global:ConnectionState.IsConnected) {
                Disconnect-GraphSafely
            }
            
            # Stop transcript
            try {
                Stop-Transcript -ErrorAction SilentlyContinue
            }
            catch {
                # Ignore transcript errors on exit
            }
            
            $form.Close()
        }
    }
    $form.Controls.Add($btnExit)

    #──────────────────────────────────────────────────────────────
    # FORM EVENT HANDLERS
    #──────────────────────────────────────────────────────────────
    
    # Form closing event - cleanup
    $form.Add_FormClosing({
        param($sender, $e)
        
        try {
            # Always attempt clean disconnect on form closing
            if ($Global:ConnectionState.IsConnected) {
                Update-GuiStatus "Form closing - disconnecting from Microsoft Graph..." ([System.Drawing.Color]::Orange)
                Disconnect-GraphSafely
            }
            
            # Stop transcript safely
            try {
                Stop-Transcript -ErrorAction SilentlyContinue
            }
            catch {
                # Ignore transcript stop errors during form closure
            }
            
            Write-Log "Application closed successfully" -Level "Info"
        }
        catch {
            # Don't prevent form closure due to cleanup errors
            Write-Log "Error during form cleanup: $($_.Exception.Message)" -Level "Warning"
        }
    })

    # Form closed event - final cleanup
    $form.Add_FormClosed({
        try {
            # Final cleanup attempt
            if (Get-MgContext -ErrorAction SilentlyContinue) {
                Disconnect-MgGraph -ErrorAction SilentlyContinue
            }
        }
        catch {
            # Silent cleanup on final close
        }
    })

    # Form shown event - initialization
    $form.Add_Shown({
        # Check for existing connection when GUI loads
        Test-ExistingGraphConnection | Out-Null
        Update-ConnectionStatus
        
        # Check for updates silently
        $versionCheck = Test-ScriptVersion -ShowMessageBox $false
        if ($versionCheck.IsLatest -eq $false) {
            # Only show message box if update is available
            Test-ScriptVersion -ShowMessageBox $true
        }
        
        if ($Global:ConnectionState.IsConnected) {
            Update-GuiStatus "Application ready - Using existing Microsoft Graph connection" ([System.Drawing.Color]::Green)
        } else {
            Update-GuiStatus "Application ready - Please connect to Microsoft Graph to begin" ([System.Drawing.Color]::Orange)
        }
    })

    #──────────────────────────────────────────────────────────────
    # SHOW THE FORM
    #──────────────────────────────────────────────────────────────
    
    [void]$form.ShowDialog()
}

#endregion

#################################################################
#
#  SECTION 6: MAIN EXECUTION
#
#################################################################

#region MAIN EXECUTION

#══════════════════════════════════════════════════════════════
# SCRIPT INITIALIZATION
#══════════════════════════════════════════════════════════════

Write-Host ""
Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   Microsoft 365 Security Analysis Tool - Enhanced Edition     ║" -ForegroundColor Cyan
Write-Host "║   Version $ScriptVer                                                ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Initialize environment
Write-Host "Initializing environment..." -ForegroundColor Yellow
Initialize-Environment

Write-Log "Starting Enhanced Microsoft 365 Security Analysis Tool v$ScriptVer" -Level "Info"
Write-Log "Enhanced features: Improved sign-in processing, detailed GUI progress, clean Graph disconnection, tenant context display" -Level "Info"
Write-Log "Data collection capabilities: Sign-ins, Admin Audits, Inbox Rules, Delegations, App Registrations, Conditional Access, Message Trace, ETR Analysis" -Level "Info"

#══════════════════════════════════════════════════════════════
# DISPLAY MAIN GUI
#══════════════════════════════════════════════════════════════

Write-Host "Launching graphical user interface..." -ForegroundColor Yellow
Write-Host ""
Write-Host "The GUI window should appear shortly. If not, check for:" -ForegroundColor Gray
Write-Host "  • Windows Forms assembly loading issues" -ForegroundColor Gray
Write-Host "  • PowerShell execution policy restrictions" -ForegroundColor Gray
Write-Host "  • Antivirus or security software blocking" -ForegroundColor Gray
Write-Host ""

Show-MainGUI

#══════════════════════════════════════════════════════════════
# FINAL CLEANUP
#══════════════════════════════════════════════════════════════

Write-Host ""
Write-Host "Performing final cleanup..." -ForegroundColor Yellow
Write-Log "Performing final cleanup..." -Level "Info"

# Ensure clean disconnect from Microsoft Graph
try {
    if ($Global:ConnectionState.IsConnected -or (Get-MgContext -ErrorAction SilentlyContinue)) {
        Write-Log "Final disconnect from Microsoft Graph" -Level "Info"
        Write-Host "Disconnecting from Microsoft Graph..." -ForegroundColor Yellow
        Disconnect-MgGraph -ErrorAction SilentlyContinue
        Write-Host "✓ Disconnected successfully" -ForegroundColor Green
    }
}
catch {
    Write-Log "Final cleanup warning: $($_.Exception.Message)" -Level "Warning"
    Write-Host "⚠ Cleanup warning: $($_.Exception.Message)" -ForegroundColor Yellow
}

# Ensure clean disconnect from Exchange Online
try {
    $exchangeSession = Get-PSSession | Where-Object { 
        $_.ConfigurationName -eq "Microsoft.Exchange" -and 
        $_.State -eq "Opened" 
    }
    
    if ($exchangeSession) {
        Write-Log "Final disconnect from Exchange Online" -Level "Info"
        Write-Host "Disconnecting from Exchange Online..." -ForegroundColor Yellow
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
        Write-Host "✓ Disconnected successfully" -ForegroundColor Green
    }
}
catch {
    Write-Log "Exchange Online cleanup warning: $($_.Exception.Message)" -Level "Warning"
    Write-Host "⚠ Exchange cleanup warning: $($_.Exception.Message)" -ForegroundColor Yellow
}

# Stop transcript
try {
    Stop-Transcript -ErrorAction SilentlyContinue
    Write-Host ""
    Write-Host "✓ Script execution completed. Log file saved to working directory." -ForegroundColor Green
    Write-Host "  Log location: $($ConfigData.WorkDir)" -ForegroundColor Gray
}
catch {
    Write-Host ""
    Write-Host "✓ Script execution completed." -ForegroundColor Green
}

# Display final summary
Write-Host ""
Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                     Script Execution Summary                   ║" -ForegroundColor Cyan
Write-Host "╠════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
Write-Host "║  Working Directory: $('{0,-43}' -f $ConfigData.WorkDir) ║" -ForegroundColor Cyan
Write-Host "║  Date Range: $('{0,-50}' -f "$($ConfigData.DateRange) days") ║" -ForegroundColor Cyan
Write-Host "║  Script Version: $('{0,-47}' -f $ScriptVer) ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
Write-Host "Thank you for using the Microsoft 365 Security Analysis Tool!" -ForegroundColor Green
Write-Host "For support or updates, visit: https://github.com/the-last-one-left/Scripts" -ForegroundColor Gray
Write-Host ""

#endregion

#################################################################
#
#  END OF SCRIPT
#
#  Script completed successfully
#
#################################################################
