#################################################################
#
#  Script to pull data from 365 tenant to identify compromised
#  users using Microsoft Graph PowerShell. Modular design with 
#  improved performance and analysis.
#                       -Original: Zachary.child@pacificoffice.com
#                       -Enhanced: Claude - from Anthropic
#   
#
#################################################################

# Module structure - Main script file
# Load configuration and required modules
$ScriptVer = "7.1"
$Global:ConnectionState = @{
    IsConnected = $false
    TenantId = $null
    TenantName = $null
    Account = $null
    ConnectedAt = $null
}

$ConfigData = @{
    WorkDir = "C:\Temp\"
    DateRange = 14
    # API key is encoded to avoid plain text - not truly secure but better than plaintext
    IPStackAPIKey = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("5f8d47763f5761d29f9af71460d94cd5"))
    ExpectedCountries = @("United States", "Canada") # Customize with expected sign-in countries
    RequiredScopes = @(
        "User.Read.All",
        "AuditLog.Read.All", 
        "Directory.Read.All",
        "Mail.Read",
		"MailboxSettings.Read",
		"Mail.ReadWrite",
		"MailboxSettings.ReadWrite",
		"SecurityEvents.Read.All",
		"IdentityRiskEvent.Read.All",
		"IdentityRiskyUser.Read.All",
        "Application.Read.All",
        "RoleManagement.Read.All",
        "Policy.Read.All"
    )
	
	
    HighRiskOperations = @(
        "Add mailbox permission",
        "Remove mailbox permission", 
        "Update mailbox",
        "Add member to role",
        "Remove member from role",
        "Create application",
        "Update application",
        "Create inbox rule",
        "Update transport rule"
    )
    # Performance settings
    BatchSize = 500
    MaxConcurrentGeolookups = 10
    CacheTimeout = 3600 # 1 hour in seconds
}

$ConfigData.ETRAnalysis = @{
    # ETR file detection patterns
    FilePatterns = @(
        "ETR_*.csv",
        "MessageTrace_*.csv", 
        "ExchangeTrace_*.csv",
        "MT_*.csv",
        "*MessageTrace*.csv",
		"MessageTraceResult.csv"
    )
    
    # Spam detection thresholds for ETR analysis
    MaxSameSubjectMessages = 50
    MaxSameSubjectPerHour = 20
    MaxMessagesPerSender = 200
    MinSubjectLength = 5
    
    # Suspicious patterns
    SpamKeywords = @(
        "urgent", "act now", "limited time", "free", "winner", "congratulations",
        "click here", "order now", "special offer", "guaranteed", "risk-free",
        "make money", "earn cash", "no obligation", "limited offer", "bitcoin",
        "cryptocurrency", "investment opportunity", "get rich", "work from home"
    )
    
    # Risk scoring weights
    RiskWeights = @{
        RiskyIPMatch = 25
        ExcessiveVolume = 20
        SpamKeywords = 15
        MassDistribution = 15
        FailedDelivery = 10
        SuspiciousTimiming = 8
    }
}

# Load required assemblies
Add-Type -AssemblyName PresentationCore, PresentationFramework
Add-Type -AssemblyName Microsoft.VisualBasic
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Global variables for GUI updates
$Global:MainForm = $null
$Global:StatusLabel = $null
$Global:ConnectionLabel = $null
$Global:TenantInfoLabel = $null

#region Helper Functions

function Initialize-Environment {
    # Create working directory if it doesn't exist
    if (-not (Test-Path -Path $ConfigData.WorkDir)) {
        New-Item -Path $ConfigData.WorkDir -ItemType Directory -Force | Out-Null
    }

    # Create log file
    $logFile = Join-Path -Path $ConfigData.WorkDir -ChildPath "ScriptLog_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    Start-Transcript -Path $logFile -Force
    Write-Log "Script initialization started. Version $ScriptVer"
    
    # Check for existing Microsoft Graph connection
    Write-Log "Checking for existing Microsoft Graph connection..." -Level "Info"
    $existingConnection = Test-ExistingGraphConnection
    
    if ($existingConnection) {
        Write-Log "Using existing Microsoft Graph connection" -Level "Info"
    } else {
        Write-Log "No existing connection found. User will need to connect manually." -Level "Info"
    }
}

function Write-Log {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Info", "Warning", "Error")]
        [string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        "Info" { Write-Host $logEntry -ForegroundColor Green }
        "Warning" { Write-Host $logEntry -ForegroundColor Yellow }
        "Error" { Write-Host $logEntry -ForegroundColor Red }
    }
}

function Connect-ExchangeOnlineIfNeeded {
    <#
    .SYNOPSIS
    Connects to Exchange Online only if not already connected with proper state management
    .DESCRIPTION
    Checks for existing Exchange Online session and only prompts for connection if needed
    #>
    
    try {
        # FIXED: Add global tracking for Exchange Online connection state
        if (-not $Global:ExchangeOnlineState) {
            $Global:ExchangeOnlineState = @{
                IsConnected = $false
                LastChecked = $null
                ConnectionAttempts = 0
            }
        }
        
        # FIXED: Don't re-check connection too frequently (cache for 30 seconds)
        if ($Global:ExchangeOnlineState.LastChecked -and 
            ((Get-Date) - $Global:ExchangeOnlineState.LastChecked).TotalSeconds -lt 30 -and
            $Global:ExchangeOnlineState.IsConnected) {
            Write-Log "Using cached Exchange Online connection status (connected)" -Level "Info"
            Update-GuiStatus "Using existing Exchange Online connection" ([System.Drawing.Color]::Green)
            return $true
        }
        
        # FIXED: More robust connection testing with multiple methods
        Write-Log "Testing Exchange Online connection..." -Level "Info"
        $isConnected = $false
        
        # Method 1: Check PowerShell sessions
        try {
            $exchangeSession = Get-PSSession | Where-Object { 
                $_.ConfigurationName -eq "Microsoft.Exchange" -and 
                $_.State -eq "Opened" -and
                $_.ComputerName -like "*outlook.office365.com*"
            } | Select-Object -First 1
            
            if ($exchangeSession) {
                Write-Log "Found active Exchange Online PowerShell session" -Level "Info"
                
                # Method 2: Test with a simple command
                try {
                    $testResult = Get-AcceptedDomain -ErrorAction Stop | Select-Object -First 1
                    if ($testResult) {
                        $isConnected = $true
                        Write-Log "Exchange Online connection verified with Get-AcceptedDomain" -Level "Info"
                    }
                } catch {
                    Write-Log "Get-AcceptedDomain test failed: $($_.Exception.Message)" -Level "Warning"
                    # Session exists but command failed - connection may be stale
                    $isConnected = $false
                }
            }
        } catch {
            Write-Log "PowerShell session check failed: $($_.Exception.Message)" -Level "Info"
        }
        
        # Method 3: Try Get-ConnectionInformation (if available in newer versions)
        if (-not $isConnected) {
            try {
                $connectionInfo = Get-ConnectionInformation -ErrorAction Stop
                if ($connectionInfo -and $connectionInfo.Count -gt 0) {
                    $isConnected = $true
                    Write-Log "Exchange Online connection verified with Get-ConnectionInformation" -Level "Info"
                }
            } catch {
                # Get-ConnectionInformation not available or failed
                Write-Log "Get-ConnectionInformation not available or failed" -Level "Info"
            }
        }
        
        # Update connection state cache
        $Global:ExchangeOnlineState.LastChecked = Get-Date
        $Global:ExchangeOnlineState.IsConnected = $isConnected
        
        if ($isConnected) {
            Write-Log "Exchange Online connection verified - already connected" -Level "Info"
            Update-GuiStatus "Using existing Exchange Online connection" ([System.Drawing.Color]::Green)
            return $true
        }
        
        # FIXED: Not connected - check if we should attempt connection
        Write-Log "No active Exchange Online connection found" -Level "Info"
        
        # FIXED: Prevent infinite connection attempts
        if ($Global:ExchangeOnlineState.ConnectionAttempts -ge 3) {
            Write-Log "Maximum Exchange Online connection attempts reached (3). Skipping automatic connection." -Level "Warning"
            Update-GuiStatus "Exchange Online connection attempts exceeded - manual connection required" ([System.Drawing.Color]::Red)
            
            $manualConnectChoice = [System.Windows.Forms.MessageBox]::Show(
                "Exchange Online Connection Required`n`n" +
                "Multiple automatic connection attempts have failed.`n`n" +
                "Would you like to manually attempt connection now?`n`n" +
                "Click 'No' to skip Exchange Online features for this session.",
                "Manual Connection Required",
                "YesNo",
                "Question"
            )
            
            if ($manualConnectChoice -eq "No") {
                Write-Log "User chose to skip Exchange Online connection" -Level "Info"
                return $false
            } else {
                # Reset attempt counter for manual connection
                $Global:ExchangeOnlineState.ConnectionAttempts = 0
            }
        }
        
        # Check if Exchange Online module is available
        if (-not (Get-Module -Name ExchangeOnlineManagement -ListAvailable)) {
            Update-GuiStatus "Exchange Online module not found - prompting for installation..." ([System.Drawing.Color]::Orange)
            
            $installChoice = [System.Windows.Forms.MessageBox]::Show(
                "Exchange Online PowerShell module is required.`n`nInstall Exchange Online module now?",
                "Module Installation Required",
                "YesNo",
                "Question"
            )
            
            if ($installChoice -eq "Yes") {
                Update-GuiStatus "Installing Exchange Online PowerShell module..." ([System.Drawing.Color]::Orange)
                try {
                    Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
                    Write-Log "Exchange Online module installed successfully" -Level "Info"
                } catch {
                    Write-Log "Failed to install Exchange Online module: $($_.Exception.Message)" -Level "Error"
                    Update-GuiStatus "Exchange Online module installation failed" ([System.Drawing.Color]::Red)
                    return $false
                }
            } else {
                Write-Log "User declined Exchange Online module installation" -Level "Info"
                Update-GuiStatus "Exchange Online module installation declined" ([System.Drawing.Color]::Orange)
                return $false
            }
        }
        
        # Import the module
        if (-not (Get-Module -Name ExchangeOnlineManagement)) {
            try {
                Import-Module ExchangeOnlineManagement -Force -ErrorAction Stop
                Write-Log "Exchange Online module imported" -Level "Info"
            } catch {
                Write-Log "Failed to import Exchange Online module: $($_.Exception.Message)" -Level "Error"
                Update-GuiStatus "Failed to import Exchange Online module" ([System.Drawing.Color]::Red)
                return $false
            }
        }
        
        # FIXED: Increment connection attempt counter
        $Global:ExchangeOnlineState.ConnectionAttempts++
        
        # Connect to Exchange Online
        Write-Log "Attempting to connect to Exchange Online (Attempt #$($Global:ExchangeOnlineState.ConnectionAttempts))" -Level "Info"
        Update-GuiStatus "Connecting to Exchange Online..." ([System.Drawing.Color]::Orange)
        
        [System.Windows.Forms.MessageBox]::Show(
            "Exchange Online Authentication Required`n`n" +
            "A browser window will open for Exchange Online authentication.`n" +
            "Please sign in with an account that has Exchange Administrator permissions.`n`n" +
            "This connection will be reused for all Exchange Online operations.`n`n" +
            "Attempt #$($Global:ExchangeOnlineState.ConnectionAttempts) of 3",
            "Authentication Required",
            "OK",
            "Information"
        )
        
        try {
            # FIXED: Use Connect-ExchangeOnline with better error handling
            Connect-ExchangeOnline -ShowProgress $true -ShowBanner:$false -ErrorAction Stop
            
            # FIXED: Wait longer for connection to stabilize
            Write-Log "Waiting for Exchange Online connection to stabilize..." -Level "Info"
            Start-Sleep -Seconds 5
            
            # FIXED: More thorough connection verification
            $verificationAttempts = 0
            $maxVerificationAttempts = 3
            $connectionVerified = $false
            
            while ($verificationAttempts -lt $maxVerificationAttempts -and -not $connectionVerified) {
                $verificationAttempts++
                Update-GuiStatus "Verifying Exchange Online connection (attempt $verificationAttempts)..." ([System.Drawing.Color]::Orange)
                
                try {
                    # Try multiple verification methods
                    $verifyConnection = Get-AcceptedDomain -ErrorAction Stop | Select-Object -First 1
                    if ($verifyConnection) {
                        $connectionVerified = $true
                        Write-Log "Exchange Online connection verified successfully" -Level "Info"
                    }
                } catch {
                    Write-Log "Connection verification attempt $verificationAttempts failed: $($_.Exception.Message)" -Level "Warning"
                    if ($verificationAttempts -lt $maxVerificationAttempts) {
                        Start-Sleep -Seconds 3
                    }
                }
            }
            
            if ($connectionVerified) {
                # FIXED: Update connection state on successful connection
                $Global:ExchangeOnlineState.IsConnected = $true
                $Global:ExchangeOnlineState.LastChecked = Get-Date
                $Global:ExchangeOnlineState.ConnectionAttempts = 0  # Reset on success
                
                Write-Log "Exchange Online connection successful and verified" -Level "Info"
                Update-GuiStatus "Connected to Exchange Online successfully" ([System.Drawing.Color]::Green)
                return $true
            } else {
                throw "Connection verification failed after $maxVerificationAttempts attempts"
            }
            
        } catch {
            Write-Log "Failed to connect to Exchange Online: $($_.Exception.Message)" -Level "Error"
            Update-GuiStatus "Failed to connect to Exchange Online" ([System.Drawing.Color]::Red)
            
            # FIXED: Update connection state on failure
            $Global:ExchangeOnlineState.IsConnected = $false
            $Global:ExchangeOnlineState.LastChecked = Get-Date
            
            $errorDetails = $_.Exception.Message
            if ($errorDetails -like "*authentication*" -or $errorDetails -like "*login*") {
                $errorType = "Authentication failed"
            } elseif ($errorDetails -like "*permission*" -or $errorDetails -like "*access*") {
                $errorType = "Insufficient permissions"
            } else {
                $errorType = "Connection error"
            }
            
            [System.Windows.Forms.MessageBox]::Show(
                "Failed to connect to Exchange Online:`n`n" +
                "Error Type: $errorType`n" +
                "Details: $errorDetails`n`n" +
                "Please ensure you have Exchange Administrator permissions.`n`n" +
                "Attempt $($Global:ExchangeOnlineState.ConnectionAttempts) of 3",
                "Connection Failed",
                "OK",
                "Error"
            )
            
            return $false
        }
        
    } catch {
        Write-Log "Unexpected error in Exchange Online connection function: $($_.Exception.Message)" -Level "Error"
        Update-GuiStatus "Unexpected error in Exchange Online connection" ([System.Drawing.Color]::Red)
        
        # FIXED: Update connection state on unexpected error
        $Global:ExchangeOnlineState.IsConnected = $false
        $Global:ExchangeOnlineState.LastChecked = Get-Date
        
        return $false
    }
}

function Get-DateRangeInput {
    param (
        [Parameter(Mandatory = $false)]
        [int]$CurrentValue = 14
    )
    
    Add-Type -AssemblyName Microsoft.VisualBasic
    
    $newValue = [Microsoft.VisualBasic.Interaction]::InputBox(
        "Enter the number of days to look back for data collection:`n`nCurrent value: $CurrentValue days`n`nNote: Larger values may take significantly longer to process.",
        "Change Date Range",
        $CurrentValue
    )
    
    # Validate input
    if ([string]::IsNullOrWhiteSpace($newValue)) {
        return $null  # User cancelled
    }
    
    $intValue = 0
    if ([int]::TryParse($newValue, [ref]$intValue)) {
        if ($intValue -gt 0 -and $intValue -le 365) {
            return $intValue
        } else {
            [System.Windows.Forms.MessageBox]::Show("Date range must be between 1 and 365 days.", "Invalid Range", "OK", "Warning")
            return $null
        }
    } else {
        [System.Windows.Forms.MessageBox]::Show("Please enter a valid number.", "Invalid Input", "OK", "Warning")
        return $null
    }
}

function Global:Update-GuiStatus {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [System.Drawing.Color]$Color = [System.Drawing.Color]::FromArgb(108, 117, 125)
    )
    
    if ($Global:StatusLabel) {
        $Global:StatusLabel.Text = $Message
        $Global:StatusLabel.ForeColor = $Color
        $Global:StatusLabel.Refresh()
        [System.Windows.Forms.Application]::DoEvents()
    }
    Write-Log $Message
}

function Update-ConnectionStatus {
    if ($Global:ConnectionLabel -and $Global:TenantInfoLabel) {
        if ($Global:ConnectionState.IsConnected) {
            $Global:ConnectionLabel.Text = "Microsoft Graph: Connected"
            $Global:ConnectionLabel.ForeColor = [System.Drawing.Color]::Green
            $Global:TenantInfoLabel.Text = "Tenant: $($Global:ConnectionState.TenantName) | Account: $($Global:ConnectionState.Account)"
            $Global:TenantInfoLabel.ForeColor = [System.Drawing.Color]::FromArgb(0, 120, 212)
        } else {
            $Global:ConnectionLabel.Text = "Microsoft Graph: Not Connected"
            $Global:ConnectionLabel.ForeColor = [System.Drawing.Color]::Red
            $Global:TenantInfoLabel.Text = "Not connected to any tenant"
            $Global:TenantInfoLabel.ForeColor = [System.Drawing.Color]::Gray
        }
        $Global:ConnectionLabel.Refresh()
        $Global:TenantInfoLabel.Refresh()
        [System.Windows.Forms.Application]::DoEvents()
    }
}


function Disconnect-GraphSafely {
    param (
        [Parameter(Mandatory = $false)]
        [bool]$ShowMessage = $false
    )
    
    try {
        if ($Global:ConnectionState.IsConnected) {
            Update-GuiStatus "Disconnecting from Microsoft Graph..." ([System.Drawing.Color]::Orange)
            Disconnect-MgGraph -ErrorAction Stop
            $Global:ConnectionState = @{
                IsConnected = $false
                TenantId = $null
                TenantName = $null
                Account = $null
                ConnectedAt = $null
            }
            Update-ConnectionStatus
            Update-GuiStatus "Disconnected from Microsoft Graph" ([System.Drawing.Color]::Green)
            Write-Log "Successfully disconnected from Microsoft Graph" -Level "Info"
            
            if ($ShowMessage) {
                [System.Windows.Forms.MessageBox]::Show("Successfully disconnected from Microsoft Graph.", "Disconnected", "OK", "Information")
            }
        }
    }
    catch {
        Write-Log "Error during disconnect: $($_.Exception.Message)" -Level "Warning"
        # Reset connection state anyway
        $Global:ConnectionState.IsConnected = $false
        Update-ConnectionStatus
    }
}

# Add this helper function in the Helper Functions region

# Add this helper function in the Helper Functions region

# Add this helper function in the Helper Functions region

function Update-WorkingDirectoryDisplay {
    param (
        [Parameter(Mandatory = $true)]
        [string]$NewWorkDir
    )
    
    # Update the global configuration
    $ConfigData.WorkDir = $NewWorkDir
    
    # Update GUI using direct global reference (like other GUI elements)
    if ($Global:WorkDirLabel) {
        $Global:WorkDirLabel.Text = "Working Directory: $NewWorkDir"
        $Global:WorkDirLabel.Refresh()
        [System.Windows.Forms.Application]::DoEvents()
        Write-Log "Updated GUI working directory display to: $NewWorkDir" -Level "Info"
    } else {
        Write-Log "Warning: Global working directory label reference not found" -Level "Warning"
    }
    
    Write-Log "Working directory configuration updated to: $NewWorkDir" -Level "Info"
}

function Test-ExistingGraphConnection {
    try {
        $context = Get-MgContext -ErrorAction Stop
        if ($context) {
            # We have an active connection
            Write-Log "Detected existing Microsoft Graph connection" -Level "Info"
            
            # Get organization info
            try {
                $organization = Get-MgOrganization -ErrorAction Stop | Select-Object -First 1
                
                # Create tenant-specific working directory for existing connection
                $cleanTenantName = $organization.DisplayName -replace '[<>:"/\\|?*]', '_'
                $timestamp = Get-Date -Format "HHmmddMMyy"
                $newWorkDir = "C:\Temp\$cleanTenantName\$timestamp"
                
                try {
                    if (-not (Test-Path -Path $newWorkDir)) {
                        New-Item -Path $newWorkDir -ItemType Directory -Force | Out-Null
                        Write-Log "Created tenant-specific working directory for existing connection: $newWorkDir" -Level "Info"
                    }
                    
                    # Update working directory
                    Update-WorkingDirectoryDisplay -NewWorkDir $newWorkDir
                }
                catch {
                    Write-Log "Could not create tenant-specific directory for existing connection, using default: $($_.Exception.Message)" -Level "Warning"
                }
                
                # Update global connection state
                $Global:ConnectionState = @{
                    IsConnected = $true
                    TenantId = $context.TenantId
                    TenantName = $organization.DisplayName
                    Account = $context.Account
                    ConnectedAt = Get-Date
                }
                
                Update-ConnectionStatus
                Update-GuiStatus "Existing Microsoft Graph connection detected and loaded" ([System.Drawing.Color]::Green)
                Write-Log "Loaded existing connection - Tenant: $($organization.DisplayName), Account: $($context.Account)" -Level "Info"
                Write-Log "Working directory set to: $($ConfigData.WorkDir)" -Level "Info"
                return $true
            }
            catch {
                Write-Log "Could not retrieve organization details from existing connection: $($_.Exception.Message)" -Level "Warning"
                return $false
            }
        }
    }
    catch {
        # No existing connection
        Write-Log "No existing Microsoft Graph connection found" -Level "Info"
        return $false
    }
    
    return $false
}

function Get-Folder {
    param (
        [Parameter(Mandatory = $false)]
        [string]$initialDirectory = ""
    )
    
    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
    $foldername = New-Object System.Windows.Forms.FolderBrowserDialog
    $foldername.Description = "Select a working folder for logs"
    $foldername.rootfolder = "MyComputer"
    $foldername.SelectedPath = $initialDirectory
    
    if ($foldername.ShowDialog() -eq "OK") {
        $folder = $foldername.SelectedPath
    }
    
    return $folder
}

function Invoke-IPGeolocation {
    param (
        [Parameter(Mandatory = $true)]
        [string]$IPAddress,
        
        [Parameter(Mandatory = $false)]
        [int]$RetryCount = 3,
        
        [Parameter(Mandatory = $false)]
        [int]$RetryDelay = 2,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Cache = @{}
    )
    
    # Check cache first
    if ($Cache.ContainsKey($IPAddress)) {
        $cachedResult = $Cache[$IPAddress]
        # Check if cache is still valid (1 hour)
        if ((Get-Date) - $cachedResult.CachedAt -lt [TimeSpan]::FromSeconds($ConfigData.CacheTimeout)) {
            return $cachedResult.Data
        } else {
            $Cache.Remove($IPAddress)
        }
    }
    
    # Decode the API key
    $apiKey = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($ConfigData.IPStackAPIKey))
    
    # Implement retry logic with exponential backoff
    for ($i = 0; $i -lt $RetryCount; $i++) {
        try {
            Start-Sleep -Milliseconds (Get-Random -Minimum 100 -Maximum 500) # Add jitter for rate limiting
            $url = "https://api.ipstack.com/{0}?access_key=$apiKey" -f $IPAddress
            $result = Invoke-RestMethod -Method Get -Uri $url -TimeoutSec 30 -ErrorAction Stop
            
            # Cache the result
            $Cache[$IPAddress] = @{
                Data = $result
                CachedAt = Get-Date
            }
            
            return $result
        }
        catch {
            Write-Log "Error querying IP Stack API for $IPAddress. Attempt $($i+1)/$RetryCount. Error: $($_.Exception.Message)" -Level "Warning"
            
            if ($i -lt $RetryCount - 1) {
                $waitTime = [math]::Pow(2, $i) * $RetryDelay
                Start-Sleep -Seconds $waitTime
            }
        }
    }
    
    Write-Log "Failed to get geolocation data for IP $IPAddress after $RetryCount attempts" -Level "Error"
    
    # Return a blank object with the same structure if all retries fail
    $failureResult = [PSCustomObject]@{
        ip = $IPAddress
        city = "Unknown"
        region_name = "Unknown"
        country_name = "Unknown"
        connection = @{ isp = "Unknown" }
    }
    
    # Cache the failure result too to avoid repeated API calls
    $Cache[$IPAddress] = @{
        Data = $failureResult
        CachedAt = Get-Date
    }
    
    return $failureResult
}

# Function to show audit log status warning
function Show-AuditLogStatusWarning {
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$AuditStatus
    )
    
    $title = "Admin Audit Log Status Check"
    $icon = "Information"
    $buttons = "OK"
    
    switch ($AuditStatus.Status) {
        "Enabled" {
            # All good - just a brief confirmation
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
    
    # Add additional context
    $message += "`n`n" +
               "This check helps ensure your security analysis will be complete.`n" +
               "Other data collection functions (sign-ins, mailbox rules, etc.) are not affected."
    
    [System.Windows.Forms.MessageBox]::Show($message, $title, $buttons, $icon)
}

# Function to test if admin audit logging is enabled
function Test-AdminAuditLogging {
    param (
        [Parameter(Mandatory = $false)]
        [bool]$ShowProgress = $true
    )
    
    try {
        if ($ShowProgress) {
            Update-GuiStatus "Checking admin audit log configuration..." ([System.Drawing.Color]::Orange)
        }
        
        Write-Log "Testing admin audit log availability..." -Level "Info"
        
        # Try to get recent audit logs with a minimal query
        $testUri = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?`$top=1"
        $testResponse = Invoke-MgGraphRequest -Uri $testUri -Method GET -ErrorAction Stop
        
        # Check if we got a response and if there are any audit logs available
        if ($testResponse) {
            if ($testResponse.value -and $testResponse.value.Count -gt 0) {
                Write-Log "Admin audit logging is enabled and working" -Level "Info"
                return @{
                    IsEnabled = $true
                    Status = "Enabled"
                    Message = "Admin audit logging is enabled and working properly"
                    HasRecentData = $true
                }
            } else {
                # No audit logs found, but API is accessible - might be no recent activity
                Write-Log "Admin audit logging API accessible but no recent data found" -Level "Warning"
                return @{
                    IsEnabled = $true
                    Status = "Enabled-NoData"
                    Message = "Admin audit logging is enabled but no recent audit events found"
                    HasRecentData = $false
                }
            }
        } else {
            Write-Log "Unable to determine audit log status - no response" -Level "Warning"
            return @{
                IsEnabled = $false
                Status = "Unknown"
                Message = "Unable to determine admin audit log status"
                HasRecentData = $false
            }
        }
    }
    catch {
        Write-Log "Error testing admin audit logs: $($_.Exception.Message)" -Level "Warning"
        
        # Analyze the error to determine the likely cause
        $errorMessage = $_.Exception.Message
        
        if ($errorMessage -like "*Forbidden*" -or $errorMessage -like "*Unauthorized*") {
            return @{
                IsEnabled = $false
                Status = "PermissionDenied"
                Message = "Insufficient permissions to access admin audit logs"
                HasRecentData = $false
            }
        }
        elseif ($errorMessage -like "*not found*" -or $errorMessage -like "*AuditLog*disabled*") {
            return @{
                IsEnabled = $false
                Status = "Disabled"
                Message = "Admin audit logging appears to be disabled or not configured"
                HasRecentData = $false
            }
        }
        elseif ($errorMessage -like "*BadRequest*") {
            return @{
                IsEnabled = $false
                Status = "ConfigurationIssue"
                Message = "Admin audit log configuration issue detected"
                HasRecentData = $false
            }
        }
        else {
            return @{
                IsEnabled = $false
                Status = "Error"
                Message = "Error accessing admin audit logs: $($_.Exception.Message)"
                HasRecentData = $false
            }
        }
    }
}

# Enhanced Connect-TenantServices function with audit log detection
function Connect-TenantServices {
    Clear-Host
    Update-GuiStatus "Checking Microsoft Graph PowerShell modules..." ([System.Drawing.Color]::Orange)
    
    $requiredModules = @("Microsoft.Graph.Authentication", "Microsoft.Graph.Users", "Microsoft.Graph.Reports", "Microsoft.Graph.Identity.DirectoryManagement", "Microsoft.Graph.Applications")
    $missingModules = @()
    
    foreach ($module in $requiredModules) {
        $installedModule = Get-Module -Name $module -ListAvailable | Select-Object -Last 1
        if ($null -eq $installedModule) {
            $missingModules += $module
        } else {
            Write-Log "$module found (Version: $($installedModule.Version))" -Level "Info"
        }
    }
    
    if ($missingModules.Count -gt 0) {
        Update-GuiStatus "Missing required modules: $($missingModules -join ', ')" ([System.Drawing.Color]::Red)
        $Selection = [System.Windows.Forms.MessageBox]::Show("Missing required Microsoft Graph modules:`n$($missingModules -join ', ')`n`nInstall missing modules?", "Missing Modules", "YesNo", "Question")
        
        If ($Selection -eq "Yes") {
            Update-GuiStatus "Installing Microsoft Graph modules..." ([System.Drawing.Color]::Orange)
            
            try {
                foreach ($module in $missingModules) {
                    Update-GuiStatus "Installing $module..." ([System.Drawing.Color]::Orange)
                    Install-Module -Name $module -Scope CurrentUser -Force -ErrorAction Stop
                }
                Update-GuiStatus "All modules installed successfully" ([System.Drawing.Color]::Green)
            }
            catch {
                Update-GuiStatus "Failed to install required modules" ([System.Drawing.Color]::Red)
                [System.Windows.Forms.MessageBox]::Show("Failed to install required modules: $($_.Exception.Message)", "Installation Error", "OK", "Error")
                return $false
            }
        }
        else {
            Update-GuiStatus "User declined to install required modules" ([System.Drawing.Color]::Red)
            return $false
        }
    }
    
    try {
        # Import required modules
        Update-GuiStatus "Loading Microsoft Graph modules..." ([System.Drawing.Color]::Orange)
        foreach ($module in $requiredModules) {
            Import-Module $module -Force -ErrorAction Stop
        }
        
        # FORCE FRESH LOGIN - Clear any existing context
        Update-GuiStatus "Clearing cached authentication context..." ([System.Drawing.Color]::Orange)
        try {
            Disconnect-MgGraph -ErrorAction SilentlyContinue
            Write-Log "Cleared existing Microsoft Graph connection" -Level "Info"
        }
        catch {
            # Ignore errors when disconnecting (might not be connected)
        }
        
        # Reset global connection state
        $Global:ConnectionState = @{
            IsConnected = $false
            TenantId = $null
            TenantName = $null
            Account = $null
            ConnectedAt = $null
        }
        
        # Show tenant selection dialog
        Update-GuiStatus "Prompting for tenant selection..." ([System.Drawing.Color]::Orange)
        $tenantChoice = [System.Windows.Forms.MessageBox]::Show(
            "You will now be prompted to sign in to Microsoft Graph.`n`n" +
            "Please ensure you select the correct tenant if you have access to multiple tenants.`n`n" +
            "The browser authentication window will open shortly.",
            "Tenant Selection Required", 
            "OKCancel", 
            "Information"
        )
        
        if ($tenantChoice -eq "Cancel") {
            Update-GuiStatus "User cancelled authentication" ([System.Drawing.Color]::Orange)
            return $false
        }
        
        # Connect to Microsoft Graph with interactive authentication (forces fresh login)
        Update-GuiStatus "Opening browser for Microsoft Graph authentication..." ([System.Drawing.Color]::Orange)
        Write-Log "Starting fresh interactive authentication to Microsoft Graph" -Level "Info"
        
        # Use interactive authentication to force tenant selection - this will open a browser window
        Connect-MgGraph -Scopes $ConfigData.RequiredScopes -ErrorAction Stop | Out-Null
        
        # Get tenant information
        Update-GuiStatus "Retrieving tenant information..." ([System.Drawing.Color]::Orange)
        $context = Get-MgContext -ErrorAction Stop
        $organization = Get-MgOrganization -ErrorAction Stop | Select-Object -First 1
        
        if (-not $context -or -not $organization) {
            throw "Failed to retrieve tenant context or organization information"
        }
        
        # Create tenant-specific working directory
        Update-GuiStatus "Setting up tenant-specific working directory..." ([System.Drawing.Color]::Orange)
        
        # Clean tenant name for folder creation (remove invalid characters)
        $cleanTenantName = $organization.DisplayName -replace '[<>:"/\\|?*]', '_'
        
        # Create timestamp in HHMMDDMMYY format
        $timestamp = Get-Date -Format "HHmmddMMyy"
        
        # Create new working directory path
        $newWorkDir = "C:\Temp\$cleanTenantName\$timestamp"
        
        try {
            # Create the directory structure
            if (-not (Test-Path -Path $newWorkDir)) {
                New-Item -Path $newWorkDir -ItemType Directory -Force | Out-Null
                Write-Log "Created tenant-specific working directory: $newWorkDir" -Level "Info"
            }
            
            # Update the working directory using the helper function
            Update-WorkingDirectoryDisplay -NewWorkDir $newWorkDir
            
            Update-GuiStatus "Working directory updated to: $newWorkDir" ([System.Drawing.Color]::Green)
        }
        catch {
            Write-Log "Warning: Could not create tenant-specific directory, using default: $($_.Exception.Message)" -Level "Warning"
            # Continue with default working directory if creation fails
        }
        
        # Update global connection state
        $Global:ConnectionState = @{
            IsConnected = $true
            TenantId = $context.TenantId
            TenantName = $organization.DisplayName
            Account = $context.Account
            ConnectedAt = Get-Date
        }
        
        # Create log file in new working directory
        $logFile = Join-Path -Path $ConfigData.WorkDir -ChildPath "ScriptLog_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
        try {
            Stop-Transcript -ErrorAction SilentlyContinue
            Start-Transcript -Path $logFile -Force
            Write-Log "Started new transcript in tenant-specific directory" -Level "Info"
        }
        catch {
            Write-Log "Could not start transcript in new directory: $($_.Exception.Message)" -Level "Warning"
        }
        
        Update-ConnectionStatus
        Update-GuiStatus "Connected to Microsoft Graph successfully" ([System.Drawing.Color]::Green)
        
        Write-Log "Connected to Microsoft Graph successfully" -Level "Info"
        Write-Log "Tenant: $($organization.DisplayName)" -Level "Info"
        Write-Log "Tenant ID: $($context.TenantId)" -Level "Info"
        Write-Log "Connected as: $($context.Account)" -Level "Info"
        Write-Log "Working directory set to: $($ConfigData.WorkDir)" -Level "Info"
        
        # NEW: Test admin audit logging immediately after successful connection
        Write-Log "Testing admin audit log configuration..." -Level "Info"
        $auditStatus = Test-AdminAuditLogging -ShowProgress $true
        
        # Show audit status in GUI
        if ($auditStatus.IsEnabled) {
            if ($auditStatus.HasRecentData) {
                Update-GuiStatus "Connection complete - Admin audit logging is enabled and working" ([System.Drawing.Color]::Green)
            } else {
                Update-GuiStatus "Connection complete - Admin audit logging enabled but no recent data" ([System.Drawing.Color]::Orange)
            }
        } else {
            Update-GuiStatus "Connection complete - WARNING: Admin audit logging issue detected" ([System.Drawing.Color]::Red)
        }
        
        # Always show the audit status popup (but tailor message based on status)
        Show-AuditLogStatusWarning -AuditStatus $auditStatus
        
        # Log the audit status
        Write-Log "Admin audit log status: $($auditStatus.Status) - $($auditStatus.Message)" -Level "Info"
        
        # Show success message with tenant info and audit status
        $successMessage = "Successfully connected to Microsoft Graph!`n`n" +
                         "Tenant: $($organization.DisplayName)`n" +
                         "Account: $($context.Account)`n" +
                         "Working Directory: $newWorkDir`n`n" +
                         "Admin Audit Status: $($auditStatus.Status)"
        
        [System.Windows.Forms.MessageBox]::Show($successMessage, "Connection Successful", "OK", "Information")
        
        return $true
    }
    catch {
        Update-GuiStatus "Failed to connect to Microsoft Graph" ([System.Drawing.Color]::Red)
        Write-Log "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -Level "Error"
        
        # Show detailed error message
        [System.Windows.Forms.MessageBox]::Show(
            "Failed to connect to Microsoft Graph:`n`n$($_.Exception.Message)`n`n" +
            "Please check your internet connection and try again.",
            "Connection Failed", 
            "OK", 
            "Error"
        )
        
        return $false
    }
}

# FIXED: Helper function to reset Exchange Online connection state
function Reset-ExchangeOnlineConnectionState {
    <#
    .SYNOPSIS
    Resets the Exchange Online connection state tracking
    .DESCRIPTION
    This function resets the global Exchange Online connection state variables,
    clearing cached connection status and resetting connection attempt counters.
    Useful for troubleshooting connection issues or when you want to force
    a fresh connection attempt.
    #>
    
    try {
        if ($Global:ExchangeOnlineState) {
            $Global:ExchangeOnlineState.IsConnected = $false
            $Global:ExchangeOnlineState.LastChecked = $null
            $Global:ExchangeOnlineState.ConnectionAttempts = 0
            Write-Log "Exchange Online connection state reset successfully" -Level "Info"
            Update-GuiStatus "Exchange Online connection state reset" ([System.Drawing.Color]::Green)
        } else {
            # Initialize the state if it doesn't exist
            $Global:ExchangeOnlineState = @{
                IsConnected = $false
                LastChecked = $null
                ConnectionAttempts = 0
            }
            Write-Log "Exchange Online connection state initialized" -Level "Info"
            Update-GuiStatus "Exchange Online connection state initialized" ([System.Drawing.Color]::Green)
        }
    } catch {
        Write-Log "Error resetting Exchange Online connection state: $($_.Exception.Message)" -Level "Warning"
        Update-GuiStatus "Error resetting Exchange Online connection state" ([System.Drawing.Color]::Red)
    }
}

# FIXED: Enhanced function to safely disconnect from Exchange Online with state management
function Disconnect-ExchangeOnlineSafely {
    <#
    .SYNOPSIS
    Safely disconnects from Exchange Online and updates connection state
    .DESCRIPTION
    Disconnects from Exchange Online if connected and updates the global
    connection state tracking to reflect the disconnection.
    #>
    
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
        } else {
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
    } catch {
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

# FIXED: Function to check and display current Exchange Online connection status
function Get-ExchangeOnlineConnectionStatus {
    <#
    .SYNOPSIS
    Displays the current Exchange Online connection status
    .DESCRIPTION
    Shows detailed information about the current Exchange Online connection
    including cached state, active sessions, and last check time.
    #>
    
    try {
        $statusInfo = @()
        
        # Check global state
        if ($Global:ExchangeOnlineState) {
            $statusInfo += "Global State: IsConnected = $($Global:ExchangeOnlineState.IsConnected)"
            $statusInfo += "Last Checked: $($Global:ExchangeOnlineState.LastChecked)"
            $statusInfo += "Connection Attempts: $($Global:ExchangeOnlineState.ConnectionAttempts)"
        } else {
            $statusInfo += "Global State: Not initialized"
        }
        
        # Check PowerShell sessions
        $exchangeSessions = Get-PSSession | Where-Object { 
            $_.ConfigurationName -eq "Microsoft.Exchange" 
        }
        
        if ($exchangeSessions) {
            $statusInfo += ""
            $statusInfo += "Active Exchange Online Sessions:"
            foreach ($session in $exchangeSessions) {
                $statusInfo += "  - State: $($session.State), Computer: $($session.ComputerName)"
            }
        } else {
            $statusInfo += ""
            $statusInfo += "No active Exchange Online PowerShell sessions found"
        }
        
        # Test actual connectivity if we think we're connected
        if ($Global:ExchangeOnlineState -and $Global:ExchangeOnlineState.IsConnected) {
            $statusInfo += ""
            try {
                $testResult = Get-AcceptedDomain -ErrorAction Stop | Select-Object -First 1
                if ($testResult) {
                    $statusInfo += "Connectivity Test: PASSED (Get-AcceptedDomain succeeded)"
                } else {
                    $statusInfo += "Connectivity Test: FAILED (No accepted domains returned)"
                }
            } catch {
                $statusInfo += "Connectivity Test: FAILED ($($_.Exception.Message))"
            }
        }
        
        $message = "Exchange Online Connection Status`n`n" + ($statusInfo -join "`n")
        
        [System.Windows.Forms.MessageBox]::Show(
            $message,
            "Exchange Online Status",
            "OK",
            "Information"
        )
        
        Write-Log "Exchange Online connection status displayed to user" -Level "Info"
        
    } catch {
        Write-Log "Error checking Exchange Online connection status: $($_.Exception.Message)" -Level "Error"
        [System.Windows.Forms.MessageBox]::Show(
            "Error checking Exchange Online status:`n$($_.Exception.Message)",
            "Status Check Error",
            "OK",
            "Error"
        )
    }
}

#region Data Collection Functions
function Get-TenantSignInData {
    param (
        [Parameter(Mandatory = $false)]
        [int]$DaysBack = $ConfigData.DateRange,
        
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = (Join-Path -Path $ConfigData.WorkDir -ChildPath "UserLocationData.csv")
    )
    
    Update-GuiStatus "Starting optimized sign-in data collection for the past $DaysBack days..." ([System.Drawing.Color]::Orange)
    
    # FIXED: Proper ISO 8601 date formatting for Microsoft Graph (UTC format)
    $startDate = (Get-Date).AddDays(-$DaysBack).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $endDate = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    
    try {
        # FIXED: Test permissions first before attempting data collection
        Update-GuiStatus "Testing sign-in log permissions..." ([System.Drawing.Color]::Orange)
        
        try {
            # Test with a minimal query first to check permissions
            $testUri = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$top=1"
            $testResponse = Invoke-MgGraphRequest -Uri $testUri -Method GET -Headers @{'ConsistencyLevel' = 'eventual'} -ErrorAction Stop
            Write-Log "Sign-in log permissions verified successfully" -Level "Info"
        }
        catch {
            $errorMessage = $_.Exception.Message
            Write-Log "Sign-in log permission test failed: $errorMessage" -Level "Error"
            
            if ($errorMessage -like "*Forbidden*" -or $errorMessage -like "*Unauthorized*") {
                $permissionError = "PERMISSION DENIED: Sign-in Logs`n`n" +
                                 "Your account lacks the required permissions to read sign-in logs.`n`n" +
                                 "Required Permissions:`n" +
                                 "• AuditLog.Read.All (Application/Delegated)`n" +
                                 "• Directory.Read.All (Application/Delegated)`n`n" +
                                 "Required Admin Roles:`n" +
                                 "• Global Administrator`n" +
                                 "• Security Administrator`n" +
                                 "• Security Reader`n" +
                                 "• Reports Reader`n`n" +
                                 "Please ensure your account has these permissions and try again."
                
                [System.Windows.Forms.MessageBox]::Show($permissionError, "Permission Error", "OK", "Error")
                Update-GuiStatus "Sign-in data collection failed - insufficient permissions" ([System.Drawing.Color]::Red)
                return $null
            }
            else {
                throw # Re-throw if it's not a permission issue
            }
        }
        
        # FIXED: Load required assembly for URL encoding
        Add-Type -AssemblyName System.Web
        
        Update-GuiStatus "Querying Microsoft Graph for sign-in logs (optimized)..." ([System.Drawing.Color]::Orange)
        
        $signInLogs = @()
        $pageSize = 1000  # Conservative page size to avoid timeouts
        
        # FIXED: Simplified field selection - using only essential fields to avoid permission issues
        $selectFields = @(
            "userPrincipalName",
            "userDisplayName", 
            "createdDateTime",
            "ipAddress",
            "status",
            "appDisplayName",
            "isInteractive",
            "conditionalAccessStatus",
            "riskLevelDuringSignIn"
        ) -join ","
        
        # FIXED: Simplified filter to avoid complex queries that might cause issues
        $filterQuery = "createdDateTime ge $startDate"
        
        Write-Log "Date range: $startDate to $endDate" -Level "Info"
        Write-Log "Filter query: $filterQuery" -Level "Info"
        
        # FIXED: Use progressive fallback approach
        $pageCount = 0
        $nextLink = $null
        $fallbackUsed = $false
        
        do {
            $pageCount++
            Update-GuiStatus "Fetching page $pageCount of sign-in data..." ([System.Drawing.Color]::Orange)
            
            try {
                if ($pageCount -eq 1) {
                    # First page - try optimized query
                    if (-not $fallbackUsed) {
                        $requestParams = @{
                            Uri = "https://graph.microsoft.com/v1.0/auditLogs/signIns"
                            Method = "GET"
                            Headers = @{
                                'ConsistencyLevel' = 'eventual'
                            }
                        }
                        
                        # Build query parameters
                        $queryParams = @()
                        $queryParams += "`$filter=$filterQuery"
                        $queryParams += "`$top=$pageSize"
                        $queryParams += "`$select=$selectFields"
                        
                        $fullUri = $requestParams.Uri + "?" + ($queryParams -join "&")
                        $requestParams.Uri = $fullUri
                        
                        Write-Log "First page URI: $fullUri" -Level "Info"
                        $response = Invoke-MgGraphRequest @requestParams -ErrorAction Stop
                    }
                } else {
                    # Subsequent pages - use the nextLink
                    $response = Invoke-MgGraphRequest -Uri $nextLink -Method GET -ErrorAction Stop
                }
                
                $signInLogs += $response.value
                $nextLink = $response.'@odata.nextLink'
                
                Write-Log "Page $pageCount retrieved: $($response.value.Count) records" -Level "Info"
                
                # Show progress every few pages
                if ($pageCount % 3 -eq 0) {
                    Update-GuiStatus "Retrieved $($signInLogs.Count) sign-in records from $pageCount pages..." ([System.Drawing.Color]::Orange)
                }
            }
            catch {
                Write-Log "Error on page $pageCount : $($_.Exception.Message)" -Level "Error"
                
                # FIXED: More robust fallback handling
                if ($_.Exception.Message -like "*BadRequest*" -and $pageCount -eq 1 -and -not $fallbackUsed) {
                    Write-Log "BadRequest detected, trying simplified query..." -Level "Warning"
                    $fallbackUsed = $true
                    
                    # Fallback 1: Try without select fields
                    try {
                        Write-Log "Trying without select fields..." -Level "Info"
                        $fallbackUri = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=$filterQuery&`$top=100"
                        $response = Invoke-MgGraphRequest -Uri $fallbackUri -Method GET -Headers @{'ConsistencyLevel' = 'eventual'} -ErrorAction Stop
                        $signInLogs += $response.value
                        $nextLink = $response.'@odata.nextLink'
                        $pageSize = 100  # Reduce page size for fallback
                        Write-Log "Fallback query succeeded with $($response.value.Count) records" -Level "Info"
                        continue  # Continue with the loop
                    }
                    catch {
                        Write-Log "Fallback with simplified query failed: $($_.Exception.Message)" -Level "Error"
                        
                        # Fallback 2: Try minimal query (just recent data, no filters)
                        try {
                            Write-Log "Trying minimal query without date filter..." -Level "Info"
                            $minimalUri = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$top=100"
                            $response = Invoke-MgGraphRequest -Uri $minimalUri -Method GET -ErrorAction Stop
                            $signInLogs += $response.value
                            Write-Log "Minimal query succeeded - retrieved $($response.value.Count) recent records" -Level "Warning"
                            [System.Windows.Forms.MessageBox]::Show(
                                "Date filtering failed, but retrieved $($response.value.Count) recent sign-in records.`n`n" +
                                "This may be due to tenant limitations or permission restrictions.",
                                "Partial Success",
                                "OK",
                                "Warning"
                            )
                            break  # Exit the loop after getting some data
                        }
                        catch {
                            Write-Log "All fallback attempts failed: $($_.Exception.Message)" -Level "Error"
                            throw "Unable to retrieve sign-in data. Please verify permissions: AuditLog.Read.All and appropriate admin role required."
                        }
                    }
                } else {
                    # For other errors or if we've already tried fallbacks
                    throw
                }
            }
        } while ($nextLink -and $pageCount -lt 50)  # Safety limit
        
        if ($signInLogs.Count -eq 0) {
            Write-Log "No sign-in logs retrieved" -Level "Warning"
            Update-GuiStatus "No sign-in data found for the specified date range" ([System.Drawing.Color]::Orange)
            
            [System.Windows.Forms.MessageBox]::Show(
                "No sign-in data found.`n`n" +
                "This could be due to:`n" +
                "• No sign-in activity in the specified timeframe`n" +
                "• Insufficient permissions`n" +
                "• Tenant audit log configuration`n`n" +
                "Please verify your permissions and try again.",
                "No Data Found",
                "OK",
                "Warning"
            )
            return $null
        }
        
        Update-GuiStatus "Retrieved $($signInLogs.Count) total sign-in records. Starting parallel IP processing..." ([System.Drawing.Color]::Orange)
        Write-Log "Retrieved $($signInLogs.Count) sign-in records" -Level "Info"
        
        # Enhanced processing with parallel IP geolocation
        $results = @()
        $ipCache = [System.Collections.Concurrent.ConcurrentDictionary[string,object]]::new()
        
        # Group and filter unique IPs for geolocation
        Update-GuiStatus "Analyzing unique IP addresses for geolocation..." ([System.Drawing.Color]::Orange)
        $validSignIns = $signInLogs | Where-Object { 
            -not [string]::IsNullOrEmpty($_.ipAddress) -and 
            $_.ipAddress -ne "127.0.0.1" -and 
            $_.ipAddress -notmatch "^10\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.|^192\.168\."  # Skip private IPs
        }
        
        $ipGroups = $validSignIns | Group-Object -Property ipAddress
        $uniqueIPs = $ipGroups.Name | Where-Object { $_ -ne $null -and $_ -ne "" }
        
        Write-Log "Found $($uniqueIPs.Count) unique IP addresses requiring geolocation from $($validSignIns.Count) valid sign-ins" -Level "Info"
        Update-GuiStatus "Processing $($uniqueIPs.Count) unique IPs with parallel geolocation..." ([System.Drawing.Color]::Orange)
        
        if ($uniqueIPs.Count -gt 0) {
            # PARALLEL IP GEOLOCATION PROCESSING
            $maxThreads = [Math]::Min(10, [Math]::Max(2, [Environment]::ProcessorCount))
            $runspacePool = [runspacefactory]::CreateRunspacePool(1, $maxThreads)
            $runspacePool.Open()
            
            Write-Log "Starting parallel IP geolocation with $maxThreads threads" -Level "Info"
            
            # Split IPs into batches for parallel processing
            $batchSize = [Math]::Max(10, [Math]::Ceiling($uniqueIPs.Count / $maxThreads))
            $ipBatches = @()
            
            for ($i = 0; $i -lt $uniqueIPs.Count; $i += $batchSize) {
                $batch = $uniqueIPs[$i..([Math]::Min($i + $batchSize - 1, $uniqueIPs.Count - 1))]
                if ($batch) {
                    $ipBatches += ,@($batch)  # Force array creation
                }
            }
            
            Write-Log "Created $($ipBatches.Count) IP batches for parallel processing" -Level "Info"
            
            # Create parallel jobs for IP geolocation
            $jobs = @()
            $apiKey = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($ConfigData.IPStackAPIKey))
            
            foreach ($batch in $ipBatches) {
                $powerShell = [powershell]::Create()
                $powerShell.RunspacePool = $runspacePool
                
                # Geolocation script block
                [void]$powerShell.AddScript({
                    param($ips, $apiKey, $cache, $retryCount, $retryDelay)
                    
                    foreach ($ip in $ips) {
                        # Skip if already in cache
                        if ($cache.ContainsKey($ip)) {
                            continue
                        }
                        
                        $success = $false
                        $attempts = 0
                        
                        while (-not $success -and $attempts -lt $retryCount) {
                            $attempts++
                            try {
                                # Add jitter to prevent API rate limiting
                                $jitter = Get-Random -Minimum 100 -Maximum 300
                                Start-Sleep -Milliseconds $jitter
                                
                                $url = "https://api.ipstack.com/{0}?access_key=$apiKey" -f $ip
                                $result = Invoke-RestMethod -Method Get -Uri $url -TimeoutSec 15 -ErrorAction Stop
                                
                                # Validate response
                                if ($result -and $result.ip) {
                                    $cache[$ip] = @{
                                        Data = $result
                                        CachedAt = Get-Date
                                        Source = "API"
                                    }
                                    $success = $true
                                } else {
                                    throw "Invalid API response for IP $ip"
                                }
                            }
                            catch {
                                if ($attempts -lt $retryCount) {
                                    # Exponential backoff
                                    $waitTime = [Math]::Pow(2, $attempts - 1) * $retryDelay
                                    Start-Sleep -Seconds $waitTime
                                } else {
                                    # Create failure result after all retries
                                    $cache[$ip] = @{
                                        Data = [PSCustomObject]@{
                                            ip = $ip
                                            city = "Unknown"
                                            region_name = "Unknown"
                                            country_name = "Unknown"
                                            connection = @{ isp = "Unknown" }
                                        }
                                        CachedAt = Get-Date
                                        Source = "Failed"
                                    }
                                }
                            }
                        }
                    }
                })
                
                [void]$powerShell.AddParameter("ips", $batch)
                [void]$powerShell.AddParameter("apiKey", $apiKey)
                [void]$powerShell.AddParameter("cache", $ipCache)
                [void]$powerShell.AddParameter("retryCount", 3)
                [void]$powerShell.AddParameter("retryDelay", 2)
                
                $jobs += @{
                    PowerShell = $powerShell
                    Handle = $powerShell.BeginInvoke()
                    BatchSize = $batch.Count
                }
            }
            
            # Monitor parallel job progress
            $completedJobs = 0
            $totalJobs = $jobs.Count
            
            Update-GuiStatus "Running $totalJobs parallel geolocation jobs..." ([System.Drawing.Color]::Orange)
            
            while ($completedJobs -lt $totalJobs) {
                Start-Sleep -Seconds 2
                $newCompletedCount = ($jobs | Where-Object { $_.Handle.IsCompleted }).Count
                
                if ($newCompletedCount -gt $completedJobs) {
                    $completedJobs = $newCompletedCount
                    $percentage = [Math]::Round(($completedJobs / $totalJobs) * 100, 1)
                    $cachedCount = $ipCache.Count
                    Update-GuiStatus "Geolocation progress: $completedJobs/$totalJobs jobs completed ($percentage%) - $cachedCount IPs processed" ([System.Drawing.Color]::Orange)
                }
            }
            
            # Wait for all jobs to complete and cleanup
            Update-GuiStatus "Finalizing parallel geolocation processing..." ([System.Drawing.Color]::Orange)
            
            foreach ($job in $jobs) {
                try {
                    $job.PowerShell.EndInvoke($job.Handle)
                } catch {
                    Write-Log "Job completion warning: $($_.Exception.Message)" -Level "Warning"
                }
                $job.PowerShell.Dispose()
            }
            
            $runspacePool.Close()
            $runspacePool.Dispose()
            
            Write-Log "Parallel geolocation completed. Processed $($ipCache.Count) unique IPs" -Level "Info"
        }
        
        # Process sign-in records with cached geolocation data
        Update-GuiStatus "Processing sign-in records with geolocation data..." ([System.Drawing.Color]::Orange)
        
        $processedCount = 0
        $batchSize = $ConfigData.BatchSize * 2  # Larger batches since geolocation is done
        
        # Process all sign-ins (including those without valid IPs)
        for ($i = 0; $i -lt $signInLogs.Count; $i += $batchSize) {
            $batch = $signInLogs[$i..([Math]::Min($i + $batchSize - 1, $signInLogs.Count - 1))]
            
            $batchResults = foreach ($signIn in $batch) {
                $processedCount++
                
                # Update progress less frequently for better performance
                if ($processedCount % 500 -eq 0) {
                    $percentage = [Math]::Round(($processedCount / $signInLogs.Count) * 100, 1)
                    Update-GuiStatus "Processing sign-ins: $processedCount of $($signInLogs.Count) ($percentage%)" ([System.Drawing.Color]::Orange)
                }
                
                $ip = $signIn.ipAddress
                
                # Initialize default values
                $isUnusual = $false
                $city = "Unknown"
                $region = "Unknown"
                $country = "Unknown"
                $isp = "Unknown"
                
                # Get geolocation data from cache if available
                if (-not [string]::IsNullOrEmpty($ip) -and $ip -ne "127.0.0.1" -and $ipCache.ContainsKey($ip)) {
                    $geoData = $ipCache[$ip].Data
                    if ($geoData) {
                        $city = if ($geoData.city) { $geoData.city } else { "Unknown" }
                        $region = if ($geoData.region_name) { $geoData.region_name } else { "Unknown" }
                        $country = if ($geoData.country_name) { $geoData.country_name } else { "Unknown" }
                        $isp = if ($geoData.connection -and $geoData.connection.isp) { $geoData.connection.isp } else { "Unknown" }
                        
                        # Check if location is unusual
                        $isUnusual = $ConfigData.ExpectedCountries -notcontains $country
                    }
                } elseif (-not [string]::IsNullOrEmpty($ip)) {
                    # Handle private/local IPs
                    if ($ip -match "^10\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.|^192\.168\.|^127\.") {
                        $country = "Private/Local"
                        $city = "Private Network"
                        $region = "Private Network"
                        $isp = "Private Network"
                        $isUnusual = $false
                    }
                }
                
                # Create result object
                [PSCustomObject]@{
                    UserId = $signIn.userPrincipalName
                    UserDisplayName = $signIn.userDisplayName
                    CreationTime = [DateTime]::Parse($signIn.createdDateTime)
                    UserAgent = $signIn.userAgent
                    IP = $ip
                    ISP = $isp
                    City = $city
                    RegionName = $region
                    Country = $country
                    IsUnusualLocation = $isUnusual
                    Status = if ($signIn.status) { $signIn.status.errorCode } else { "0" }
                    FailureReason = if ($signIn.status) { $signIn.status.failureReason } else { "" }
                    ConditionalAccessStatus = $signIn.conditionalAccessStatus
                    RiskLevel = $signIn.riskLevelDuringSignIn
                    DeviceOS = if ($signIn.deviceDetail) { $signIn.deviceDetail.operatingSystem } else { "" }
                    DeviceBrowser = if ($signIn.deviceDetail) { $signIn.deviceDetail.browser } else { "" }
                    IsInteractive = $signIn.isInteractive
                    AppDisplayName = $signIn.appDisplayName
                }
            }
            
            $results += $batchResults
        }
        
        Update-GuiStatus "Exporting optimized sign-in data..." ([System.Drawing.Color]::Orange)
        
        # Export the results
        $results | Export-Csv -Path $OutputPath -NoTypeInformation -Force
        
        # Create filtered versions for analysis
        $unusualSignIns = $results | Where-Object { $_.IsUnusualLocation -eq $true }
        if ($unusualSignIns.Count -gt 0) {
            $unusualOutputPath = $OutputPath -replace '.csv$', '_Unusual.csv'
            $unusualSignIns | Export-Csv -Path $unusualOutputPath -NoTypeInformation -Force
            Write-Log "Found $($unusualSignIns.Count) sign-ins from unusual locations" -Level "Warning"
        }
        
        $failedSignIns = $results | Where-Object { $_.Status -ne "0" -and -not [string]::IsNullOrEmpty($_.Status) }
        if ($failedSignIns.Count -gt 0) {
            $failedOutputPath = $OutputPath -replace '.csv$', '_Failed.csv'
            $failedSignIns | Export-Csv -Path $failedOutputPath -NoTypeInformation -Force
            Write-Log "Found $($failedSignIns.Count) failed sign-in attempts" -Level "Warning"
        }
        
        # Performance summary
        $cacheStats = @{
            TotalIPs = $ipCache.Count
            SuccessfulGeo = ($ipCache.Values | Where-Object { $_.Source -eq "API" }).Count
            FailedGeo = ($ipCache.Values | Where-Object { $_.Source -eq "Failed" }).Count
        }
        
        Update-GuiStatus "OPTIMIZED sign-in collection completed! Processed $($results.Count) records with $($cacheStats.TotalIPs) geolocated IPs." ([System.Drawing.Color]::Green)
        Write-Log "Optimized sign-in data collection completed. Results saved to $OutputPath" -Level "Info"
        Write-Log "Geolocation stats: $($cacheStats.SuccessfulGeo) successful, $($cacheStats.FailedGeo) failed out of $($cacheStats.TotalIPs) total IPs" -Level "Info"
        
        return $results
    }
    catch {
        Update-GuiStatus "Error collecting sign-in data: $($_.Exception.Message)" ([System.Drawing.Color]::Red)
        Write-Log "Error collecting sign-in data: $($_.Exception.Message)" -Level "Error"
        
        # FIXED: Better error messages for common issues
        if ($_.Exception.Message -like "*Forbidden*") {
            [System.Windows.Forms.MessageBox]::Show(
                "Access Denied: Sign-in Logs`n`n" +
                "Your account does not have sufficient permissions.`n`n" +
                "Required: AuditLog.Read.All permission and Security Reader role or higher.",
                "Permission Error",
                "OK",
                "Error"
            )
        }
        
        return $null
    }
}

function Get-AdminAuditData {
    param (
        [Parameter(Mandatory = $false)]
        [int]$DaysBack = $ConfigData.DateRange,
        
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = (Join-Path -Path $ConfigData.WorkDir -ChildPath "AdminAuditLogs_HighRisk.csv")
    )
    
    Update-GuiStatus "Starting admin audit logs collection for the past $DaysBack days..." ([System.Drawing.Color]::Orange)
    
    $startDate = (Get-Date).AddDays(-$DaysBack).ToString("yyyy-MM-dd")
    $endDate = (Get-Date).ToString("yyyy-MM-dd")
    
    try {
        # Get directory audit logs using MS Graph
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
        
        Update-GuiStatus "Retrieved $($auditLogs.Count) admin audit records. Processing..." ([System.Drawing.Color]::Orange)
        Write-Log "Retrieved $($auditLogs.Count) admin audit log records" -Level "Info"
        
        # Process and enrich the audit logs with additional context
        $processedLogs = @()
        $counter = 0
        
        foreach ($log in $auditLogs) {
            $counter++
            if ($counter % 100 -eq 0) {
                $percentage = [math]::Round(($counter / $auditLogs.Count) * 100, 1)
                Update-GuiStatus "Processing admin audits: $counter of $($auditLogs.Count) ($percentage%)" ([System.Drawing.Color]::Orange)
            }
            
            # Add risk assessment based on operation type
            $riskLevel = "Low"
            $activityDisplayName = $log.activityDisplayName
            
            # Assign risk levels based on activity type
            switch -Regex ($activityDisplayName) {
                ".*[Aa]dd.*[Pp]ermission.*|.*[Aa]dd.*[Rr]ole.*" { $riskLevel = "High" }
                ".*[Aa]dd.*[Mm]ember.*" { $riskLevel = "High" }
                ".*[Cc]reate.*[Aa]pplication.*|.*[Cc]reate.*[Ss]ervice [Pp]rincipal.*" { $riskLevel = "Medium" }
                ".*[Uu]pdate.*[Aa]pplication.*" { $riskLevel = "Medium" }
                ".*[Dd]elete.*|.*[Rr]emove.*" { $riskLevel = "Medium" }
                default { $riskLevel = "Low" }
            }
            
            # Extract target information
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
                TargetResources = ($targetResources | ConvertTo-Json -Compress -Depth 10)
				AdditionalDetails = ($log.additionalDetails | ConvertTo-Json -Compress -Depth 10)
            }
            
            $processedLogs += $processedLog
        }
        
        Update-GuiStatus "Exporting admin audit data..." ([System.Drawing.Color]::Orange)
        
        # Export the results
        $processedLogs | Export-Csv -Path $OutputPath -NoTypeInformation -Force
        
        # Create filtered versions for different risk levels
        $highRiskLogs = $processedLogs | Where-Object { $_.RiskLevel -eq "High" }
        $highRiskPath = $OutputPath -replace '.csv$', '_Critical.csv'
        
        if ($highRiskLogs.Count -gt 0) {
            $highRiskLogs | Export-Csv -Path $highRiskPath -NoTypeInformation -Force
            Write-Log "Found $($highRiskLogs.Count) high-risk admin operations" -Level "Warning"
        }
        
        # Filter for failed operations
        $failedLogs = $processedLogs | Where-Object { $_.Result -ne "success" }
        $failedPath = $OutputPath -replace '.csv$', '_Failed.csv'
        
        if ($failedLogs.Count -gt 0) {
            $failedLogs | Export-Csv -Path $failedPath -NoTypeInformation -Force
            Write-Log "Found $($failedLogs.Count) failed admin operations" -Level "Warning"
        }
        
        Update-GuiStatus "Admin audit log collection completed successfully. Processed $($processedLogs.Count) records." ([System.Drawing.Color]::Green)
        Write-Log "Admin audit log collection completed. Results saved to $OutputPath" -Level "Info"
        return $processedLogs
    }
    catch {
        Update-GuiStatus "Error collecting admin audit logs: $($_.Exception.Message)" ([System.Drawing.Color]::Red)
        Write-Log "Error collecting admin audit logs: $($_.Exception.Message)" -Level "Error"
        return $null
    }
}

function Get-MessageTraceExchangeOnline {
    param (
        [Parameter(Mandatory = $false)]
        [int]$DaysBack = $ConfigData.DateRange,
        
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = (Join-Path -Path $ConfigData.WorkDir -ChildPath "MessageTraceResult.csv"),
        
        [Parameter(Mandatory = $false)]
        [int]$MaxMessages = 5000
    )
    
    Update-GuiStatus "Starting Exchange Online message trace collection using Get-MessageTraceV2..." ([System.Drawing.Color]::Orange)
    
    try {
        # Check Exchange Online connection
        $existingSession = Get-PSSession | Where-Object { $_.ConfigurationName -eq "Microsoft.Exchange" -and $_.State -eq "Opened" }
        
        if (-not $existingSession) {
            Update-GuiStatus "Connecting to Exchange Online..." ([System.Drawing.Color]::Orange)
            
            if (-not (Get-Module -Name ExchangeOnlineManagement)) {
                Import-Module ExchangeOnlineManagement -Force
            }
            
            Connect-ExchangeOnline -ShowProgress $true -ShowBanner:$false
            Write-Log "Connected to Exchange Online for message trace" -Level "Info"
        }
        
        # Calculate date range - keep it conservative
        $actualDaysBack = [Math]::Min($DaysBack, 7)
        $startDate = (Get-Date).AddDays(-$actualDaysBack)
        $endDate = Get-Date
        
        Write-Log "Message trace range: $($startDate.ToString('yyyy-MM-dd')) to $($endDate.ToString('yyyy-MM-dd'))" -Level "Info"
        
        if ($DaysBack -gt 7) {
            [System.Windows.Forms.MessageBox]::Show(
                "Date range adjusted to 7 days (Exchange Online limitation).",
                "Range Adjusted",
                "OK",
                "Information"
            )
        }
        
        # Use Get-MessageTraceV2 with correct parameters
        Update-GuiStatus "Calling Get-MessageTraceV2..." ([System.Drawing.Color]::Orange)
        Write-Log "Calling Get-MessageTraceV2 -StartDate $startDate -EndDate $endDate -ResultSize $MaxMessages" -Level "Info"
        
        $allMessages = Get-MessageTraceV2 -StartDate $startDate -EndDate $endDate -ResultSize $MaxMessages
        
        if (-not $allMessages) {
            $allMessages = @()
        }
        
        Write-Log "Get-MessageTraceV2 returned $($allMessages.Count) messages" -Level "Info"
        
        if ($allMessages.Count -eq 0) {
            Update-GuiStatus "No messages found in date range" ([System.Drawing.Color]::Orange)
            [System.Windows.Forms.MessageBox]::Show("No messages found for the specified date range.", "No Data", "OK", "Information")
            return @()
        }
        
        # Debug: Check what properties actually exist in Get-MessageTraceV2
        if ($allMessages.Count -gt 0) {
            $sampleMessage = $allMessages[0]
            $availableProperties = $sampleMessage | Get-Member -MemberType Properties | Select-Object -ExpandProperty Name
            Write-Log "Available properties in Get-MessageTraceV2: $($availableProperties -join ', ')" -Level "Info"
        }
        
        # Convert to ETR format
        Update-GuiStatus "Converting $($allMessages.Count) messages to ETR format..." ([System.Drawing.Color]::Orange)
        
        $etrMessages = @()
        foreach ($msg in $allMessages) {
            $etrMessage = [PSCustomObject]@{
                message_trace_id = if ($msg.MessageTraceId) { $msg.MessageTraceId } else { "" }
                sender_address = if ($msg.SenderAddress) { $msg.SenderAddress } else { "" }
                recipient_address = if ($msg.RecipientAddress) { $msg.RecipientAddress } else { "" }
                subject = if ($msg.Subject) { $msg.Subject } else { "" }
                status = if ($msg.Status) { $msg.Status } else { "" }
                to_ip = if ($msg.ToIP) { $msg.ToIP } else { "" }
                from_ip = if ($msg.FromIP) { $msg.FromIP } else { "" }
                message_size = if ($msg.Size) { $msg.Size } else { "" }
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
        $etrMessages | Export-Csv -Path $OutputPath -NoTypeInformation -Force
        
        Update-GuiStatus "Message trace complete! $($allMessages.Count) messages exported." ([System.Drawing.Color]::Green)
        Write-Log "Message trace completed: $($allMessages.Count) total messages processed with Get-MessageTraceV2" -Level "Info"
        
        [System.Windows.Forms.MessageBox]::Show(
            "Message Trace Complete!`n`nTotal: $($allMessages.Count) messages`n`nFile: MessageTraceResult.csv`n`nNote: Get-MessageTraceV2 doesn't provide direction classification",
            "Success",
            "OK",
            "Information"
        )
        
        return $etrMessages
        
    } catch {
        Update-GuiStatus "Error: $($_.Exception.Message)" ([System.Drawing.Color]::Red)
        Write-Log "Message trace error: $($_.Exception.Message)" -Level "Error"
        [System.Windows.Forms.MessageBox]::Show("Error: $($_.Exception.Message)", "Error", "OK", "Error")
        return $null
    }
}

function Get-MailboxRules {
    param (
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = (Join-Path -Path $ConfigData.WorkDir -ChildPath "InboxRules.csv")
    )
    
    Update-GuiStatus "Starting Exchange Online mailbox rules collection..." ([System.Drawing.Color]::Orange)
    
    try {
        # Check if Exchange Online module is available
        Update-GuiStatus "Checking Exchange Online PowerShell module..." ([System.Drawing.Color]::Orange)
        
        if (-not (Get-Module -Name ExchangeOnlineManagement -ListAvailable)) {
            Update-GuiStatus "Exchange Online module not found - prompting for installation..." ([System.Drawing.Color]::Orange)
            
            $installChoice = [System.Windows.Forms.MessageBox]::Show(
                "Exchange Online PowerShell module is required for mailbox rule collection.`n`n" +
                "This module provides more reliable access to mailbox rules than Microsoft Graph.`n`n" +
                "Install Exchange Online module now?`n`n" +
                "Note: This requires internet connection and may take a few minutes.",
                "Module Installation Required",
                "YesNo",
                "Question"
            )
            
            if ($installChoice -eq "Yes") {
                Update-GuiStatus "Installing Exchange Online PowerShell module..." ([System.Drawing.Color]::Orange)
                try {
                    Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser -Force -AllowClobber
                    Write-Log "Exchange Online module installed successfully" -Level "Info"
                    Update-GuiStatus "Exchange Online module installed successfully" ([System.Drawing.Color]::Green)
                } catch {
                    Write-Log "Failed to install Exchange Online module: $($_.Exception.Message)" -Level "Error"
                    Update-GuiStatus "Failed to install Exchange Online module" ([System.Drawing.Color]::Red)
                    [System.Windows.Forms.MessageBox]::Show("Failed to install Exchange Online module:`n$($_.Exception.Message)", "Installation Failed", "OK", "Error")
                    return @()
                }
            } else {
                Update-GuiStatus "Exchange Online module installation declined - skipping mailbox rules" ([System.Drawing.Color]::Orange)
                Write-Log "User declined Exchange Online module installation" -Level "Info"
                return @()
            }
        }
        
        # Import the module
        Update-GuiStatus "Loading Exchange Online PowerShell module..." ([System.Drawing.Color]::Orange)
        try {
            Import-Module ExchangeOnlineManagement -Force -ErrorAction Stop
            Write-Log "Exchange Online module loaded successfully" -Level "Info"
        } catch {
            Write-Log "Failed to load Exchange Online module: $($_.Exception.Message)" -Level "Error"
            Update-GuiStatus "Failed to load Exchange Online module" ([System.Drawing.Color]::Red)
            return @()
        }
        
        # FIXED: Single connection attempt with clear error handling
        Write-Log "Checking Exchange Online connection for mailbox rules..." -Level "Info"
        
        $connectionResult = Connect-ExchangeOnlineIfNeeded
        if (-not $connectionResult) {
            Update-GuiStatus "Exchange Online connection failed - skipping mailbox rules collection" ([System.Drawing.Color]::Red)
            
            [System.Windows.Forms.MessageBox]::Show(
                "Exchange Online Connection Required`n`n" +
                "Mailbox rules collection requires an active Exchange Online connection.`n`n" +
                "Please ensure you have Exchange Administrator permissions and try again.`n`n" +
                "This data collection will be skipped for now.",
                "Connection Required",
                "OK",
                "Warning"
            )
            
            return @()  # Return empty array instead of null to avoid downstream issues
        }
        
        # FIXED: Additional verification before proceeding
        try {
            # Quick test to ensure we can actually query Exchange Online
            $testMailbox = Get-Mailbox -ResultSize 1 -ErrorAction Stop | Select-Object -First 1
            if (-not $testMailbox) {
                throw "No mailboxes found or accessible"
            }
            Write-Log "Exchange Online access verified - proceeding with mailbox rules collection" -Level "Info"
        } catch {
            Write-Log "Exchange Online access test failed: $($_.Exception.Message)" -Level "Error"
            Update-GuiStatus "Exchange Online access verification failed" ([System.Drawing.Color]::Red)
            
            [System.Windows.Forms.MessageBox]::Show(
                "Exchange Online Access Test Failed`n`n" +
                "Unable to query mailboxes. This could be due to:`n" +
                "• Insufficient permissions`n" +
                "• Connection issues`n" +
                "• Service unavailability`n`n" +
                "Error: $($_.Exception.Message)",
                "Access Test Failed",
                "OK",
                "Error"
            )
            
            return @()
        }
        
        # Get all mailboxes
        Update-GuiStatus "Retrieving all mailboxes from Exchange Online..." ([System.Drawing.Color]::Orange)
        try {
            $mailboxes = Get-Mailbox -ResultSize Unlimited -ErrorAction Stop
            $totalMailboxes = $mailboxes.Count
            Write-Log "Found $totalMailboxes mailboxes to process" -Level "Info"
            Update-GuiStatus "Processing $totalMailboxes mailboxes for inbox rules..." ([System.Drawing.Color]::Orange)
        } catch {
            Write-Log "Failed to retrieve mailboxes: $($_.Exception.Message)" -Level "Error"
            Update-GuiStatus "Failed to retrieve mailboxes from Exchange Online" ([System.Drawing.Color]::Red)
            return @()
        }
        
        $allRules = @()
        $suspiciousRules = @()
        $processedCount = 0
        $successCount = 0
        $errorCount = 0
        $rulesFoundCount = 0
        
        foreach ($mailbox in $mailboxes) {
            $processedCount++
            
            # Progress update every 10 mailboxes for better responsiveness
            if ($processedCount % 10 -eq 0) {
                $percentage = [math]::Round(($processedCount / $totalMailboxes) * 100, 1)
                Update-GuiStatus "Processing: $processedCount/$totalMailboxes ($percentage%) - $rulesFoundCount rules found so far" ([System.Drawing.Color]::Orange)
                [System.Windows.Forms.Application]::DoEvents()  # Keep GUI responsive
            }
            
            try {
                # Get inbox rules for this mailbox
                $rules = Get-InboxRule -Mailbox $mailbox.PrimarySmtpAddress -ErrorAction Stop
                $successCount++
                
                if ($rules -and $rules.Count -gt 0) {
                    $rulesFoundCount += $rules.Count
                    Write-Log "Found $($rules.Count) rules for $($mailbox.PrimarySmtpAddress)" -Level "Info"
                    
                    foreach ($rule in $rules) {
                        $isSuspicious = $false
                        $suspiciousReasons = @()
                        
                        # Check for forwarding/redirecting
                        if ($rule.ForwardTo -or $rule.RedirectTo -or $rule.ForwardAsAttachmentTo) {
                            $isSuspicious = $true
                            $suspiciousReasons += "Forwards or redirects email"
                        }
                        
                        # Check for delete actions
                        if ($rule.DeleteMessage -eq $true) {
                            $isSuspicious = $true
                            $suspiciousReasons += "Deletes messages"
                        }
                        
                        # Check for move to deleted items
                        if ($rule.MoveToFolder -and $rule.MoveToFolder -like "*Deleted*") {
                            $isSuspicious = $true
                            $suspiciousReasons += "Moves to Deleted Items"
                        }
                        
                        # Check for stopping rule processing
                        if ($rule.StopProcessingRules -eq $true) {
                            $suspiciousReasons += "Stops processing other rules"
                        }
                        
                        # Check for external forwarding
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
                } else {
                    # Mailbox has no rules - this is normal, so we'll only log at verbose level
                    if ($processedCount % 50 -eq 0) {  # Only log every 50th mailbox to avoid spam
                        Write-Log "$($mailbox.PrimarySmtpAddress) has no inbox rules" -Level "Info"
                    }
                }
            } catch {
                $errorCount++
                Write-Log "Error getting rules for $($mailbox.PrimarySmtpAddress): $($_.Exception.Message)" -Level "Warning"
            }
        }
        
        # Export results
        Update-GuiStatus "Exporting Exchange Online mailbox rules data..." ([System.Drawing.Color]::Orange)
        
        if ($allRules.Count -gt 0) {
            # Export all rules
            $allRules | Export-Csv -Path $OutputPath -NoTypeInformation -Force
            
            # Export suspicious rules
            if ($suspiciousRules.Count -gt 0) {
                $suspiciousPath = $OutputPath -replace '.csv$', '_Suspicious.csv'
                $suspiciousRules | Export-Csv -Path $suspiciousPath -NoTypeInformation -Force
                Write-Log "Found $($suspiciousRules.Count) suspicious rules" -Level "Warning"
            }
            
            # Calculate statistics
            $usersWithRules = ($allRules | Group-Object -Property MailboxOwnerID).Count
            $enabledRules = @($allRules | Where-Object { $_.IsEnabled -eq $true })
            
            Update-GuiStatus "Exchange Online rules completed! $($allRules.Count) rules ($($enabledRules.Count) enabled, $($suspiciousRules.Count) suspicious) from $usersWithRules mailboxes." ([System.Drawing.Color]::Green)
            
            Write-Log "Exchange Online mailbox rules collection completed successfully" -Level "Info"
            Write-Log "Statistics: $($allRules.Count) total rules, $($enabledRules.Count) enabled, $($suspiciousRules.Count) suspicious" -Level "Info"
            Write-Log "Processing summary: $successCount successful, $errorCount errors out of $totalMailboxes mailboxes" -Level "Info"
            
            # Show summary
            $message = "Exchange Online Mailbox Rules Collection Complete!`n`n" +
                      "✅ Total Rules Found: $($allRules.Count)`n" +
                      "⚠️ Suspicious Rules: $($suspiciousRules.Count)`n" +
                      "📧 Mailboxes with Rules: $usersWithRules`n" +
                      "✅ Successfully Processed: $successCount/$totalMailboxes mailboxes`n`n" +
                      "Files created:`n• InboxRules.csv`n" +
                      $(if ($suspiciousRules.Count -gt 0) { "• InboxRules_Suspicious.csv" } else { "" })
            
            [System.Windows.Forms.MessageBox]::Show($message, "Collection Complete", "OK", "Information")
        } else {
            Update-GuiStatus "No mailbox rules found via Exchange Online." ([System.Drawing.Color]::Green)
            Write-Log "No mailbox rules found in any mailboxes" -Level "Info"
            Write-Log "Processing summary: $successCount successful, $errorCount errors out of $totalMailboxes mailboxes" -Level "Info"
            
            [System.Windows.Forms.MessageBox]::Show(
                "No inbox rules found in any mailboxes.`n`nThis could mean:`n• No users have created inbox rules`n• All rules were successfully processed`n• This is normal for many organizations",
                "No Rules Found",
                "OK",
                "Information"
            )
        }
        
        # Note: We intentionally DON'T disconnect Exchange Online here
        # because the user might want to run this multiple times
        # They can disconnect manually if needed
        
        return $allRules
        
    } catch {
        Update-GuiStatus "Error in Exchange Online mailbox rules collection: $($_.Exception.Message)" ([System.Drawing.Color]::Red)
        Write-Log "Error in Exchange Online mailbox rules collection: $($_.Exception.Message)" -Level "Error"
        
        [System.Windows.Forms.MessageBox]::Show(
            "Error during Exchange Online mailbox rules collection:`n`n$($_.Exception.Message)",
            "Collection Error",
            "OK",
            "Error"
        )
        
        return @()  # Return empty array instead of null to avoid downstream issues
    }
}

# Optional: Add a function to manually disconnect Exchange Online
function Disconnect-ExchangeOnlineSafely {
    try {
        $session = Get-PSSession | Where-Object { $_.ConfigurationName -eq "Microsoft.Exchange" -and $_.State -eq "Opened" }
        if ($session) {
            Disconnect-ExchangeOnline -Confirm:$false
            Write-Log "Disconnected from Exchange Online" -Level "Info"
            Update-GuiStatus "Disconnected from Exchange Online" ([System.Drawing.Color]::Green)
            [System.Windows.Forms.MessageBox]::Show("Disconnected from Exchange Online successfully.", "Disconnected", "OK", "Information")
        } else {
            Update-GuiStatus "No active Exchange Online session found" ([System.Drawing.Color]::Orange)
            [System.Windows.Forms.MessageBox]::Show("No active Exchange Online session found.", "No Session", "OK", "Information")
        }
    } catch {
        Write-Log "Error disconnecting from Exchange Online: $($_.Exception.Message)" -Level "Warning"
        Update-GuiStatus "Error disconnecting from Exchange Online" ([System.Drawing.Color]::Red)
    }
}

function Get-MailboxDelegationData {
    param (
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = (Join-Path -Path $ConfigData.WorkDir -ChildPath "MailboxDelegation.csv")
    )
    
    Update-GuiStatus "Starting mailbox delegation collection..." ([System.Drawing.Color]::Orange)
    
    try {
        # Get all users with mailboxes
        Update-GuiStatus "Retrieving users with mailboxes..." ([System.Drawing.Color]::Orange)
        $users = Get-MgUser -All -Property Id, UserPrincipalName, DisplayName, Mail | Where-Object { $_.Mail -ne $null }
        $totalCount = $users.Count
        $processedCount = 0
        $delegations = @()
        $suspiciousDelegations = @()
        
        Update-GuiStatus "Processing mailbox delegations for $totalCount users..." ([System.Drawing.Color]::Orange)
        
        foreach ($user in $users) {
            $processedCount++
            if ($processedCount % 10 -eq 0) {
                $percentage = [math]::Round(($processedCount / $totalCount) * 100, 1)
                Update-GuiStatus "Processing delegations: $processedCount of $totalCount users ($percentage%)" ([System.Drawing.Color]::Orange)
            }
            
            try {
                # Get mailbox settings including delegates
                $mailboxSettings = Get-MgUserMailboxSetting -UserId $user.Id -ErrorAction Stop
                
                if ($mailboxSettings.DelegatesSettings) {
                    foreach ($delegate in $mailboxSettings.DelegatesSettings) {
                        # Determine if the delegation is suspicious
                        $isSuspicious = $false
                        $suspiciousReasons = @()
                        
                        # Check if external delegate
                        $delegateEmail = $delegate.EmailAddress.Address
                        if ($delegateEmail -like "*@*" -and $delegateEmail -notlike "*onmicrosoft.com" -and $delegateEmail -notlike "*$((Get-MgOrganization).VerifiedDomains[0].Name)*") {
                            $isSuspicious = $true
                            $suspiciousReasons += "External delegate"
                        }
                        
                        # Check for high privilege access
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
                        
                        if ($isSuspicious) {
                            $suspiciousDelegations += $delegationEntry
                        }
                    }
                }
            }
            catch {
                # Silently continue if user doesn't have mailbox settings
                continue
            }
        }
        
        Update-GuiStatus "Exporting mailbox delegation data..." ([System.Drawing.Color]::Orange)
        
        # Export the results
        if ($delegations.Count -gt 0) {
            $delegations | Export-Csv -Path $OutputPath -NoTypeInformation -Force
            
            # Export suspicious delegations to a separate file
            if ($suspiciousDelegations.Count -gt 0) {
                $suspiciousPath = $OutputPath -replace '.csv$', '_Suspicious.csv'
                $suspiciousDelegations | Export-Csv -Path $suspiciousPath -NoTypeInformation -Force
                Write-Log "Found $($suspiciousDelegations.Count) suspicious delegations" -Level "Warning"
            }
            
            Update-GuiStatus "Mailbox delegation collection completed. Found $($delegations.Count) delegations." ([System.Drawing.Color]::Green)
        }
        else {
            Update-GuiStatus "No mailbox delegations found." ([System.Drawing.Color]::Green)
        }
        
        return $delegations
    }
    catch {
        Update-GuiStatus "Error collecting mailbox delegations: $($_.Exception.Message)" ([System.Drawing.Color]::Red)
        Write-Log "Error collecting mailbox delegations: $($_.Exception.Message)" -Level "Error"
        return $null
    }
}

function Get-AppRegistrationData {
    param (
        [Parameter(Mandatory = $false)]
        [int]$DaysBack = $ConfigData.DateRange,
        
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = (Join-Path -Path $ConfigData.WorkDir -ChildPath "AppRegistrations.csv")
    )
    
    Update-GuiStatus "Starting app registration collection for the past $DaysBack days..." ([System.Drawing.Color]::Orange)
    
    $startDate = (Get-Date).AddDays(-$DaysBack)
    
    try {
        # Get all applications and service principals
        Update-GuiStatus "Retrieving applications..." ([System.Drawing.Color]::Orange)
        $applications = Get-MgApplication -All
        
        Update-GuiStatus "Retrieving service principals..." ([System.Drawing.Color]::Orange)
        $servicePrincipals = Get-MgServicePrincipal -All
        
        Update-GuiStatus "Processing app registration data..." ([System.Drawing.Color]::Orange)
        
        $appRegs = @()
        $processedCount = 0
        
        # Process applications
        foreach ($app in $applications) {
            $processedCount++
            if ($processedCount % 50 -eq 0) {
                $percentage = [math]::Round(($processedCount / $applications.Count) * 100, 1)
                Update-GuiStatus "Processing applications: $processedCount of $($applications.Count) ($percentage%)" ([System.Drawing.Color]::Orange)
            }
            
            # Filter by creation date if within our date range
            if ($app.CreatedDateTime -ge $startDate) {
                
                # Find corresponding service principal
                $servicePrincipal = $servicePrincipals | Where-Object { $_.AppId -eq $app.AppId } | Select-Object -First 1
                
                # Assess risk based on permissions
                $riskLevel = "Low"
                $riskReasons = @()
                
                # Check required resource access (permissions)
                foreach ($resourceAccess in $app.RequiredResourceAccess) {
                    foreach ($permission in $resourceAccess.ResourceAccess) {
                        $permissionValue = $permission.Id
                        # Common high-risk permission IDs (these would need to be expanded)
                        if ($permissionValue -in @(
                            "570282fd-fa5c-430d-a7fd-fc8dc98a9dca", # Mail.ReadWrite
                            "024d486e-b451-40bb-833d-3e66d98c5c73", # Mail.Read
                            "75359482-378d-4052-8f01-80520e7db3cd", # Files.ReadWrite.All
                            "06da0dbc-49e2-44d2-8312-53746b5fccd9"  # Directory.Read.All
                        )) {
                            $riskLevel = "High"
                            $riskReasons += "High-privilege permissions requested"
                        }
                    }
                }
                
                # Check for suspicious app characteristics
                if ([string]::IsNullOrEmpty($app.Homepage) -and [string]::IsNullOrEmpty($app.PublisherDomain)) {
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
                    OwnerIds = ($app.Owners.Id -join "; ")
                }
                
                $appRegs += $appReg
            }
        }
        
        Update-GuiStatus "Exporting app registration data..." ([System.Drawing.Color]::Orange)
        
        # Export the results
        if ($appRegs.Count -gt 0) {
            $appRegs | Export-Csv -Path $OutputPath -NoTypeInformation -Force
            
            # Create filtered versions for different risk levels
            $highRiskApps = $appRegs | Where-Object { $_.RiskLevel -eq "High" }
            
            if ($highRiskApps.Count -gt 0) {
                $highRiskPath = $OutputPath -replace '.csv$', '_HighRisk.csv'
                $highRiskApps | Export-Csv -Path $highRiskPath -NoTypeInformation -Force
                Write-Log "Found $($highRiskApps.Count) high-risk app registrations" -Level "Warning"
            }
            
            Update-GuiStatus "App registration collection completed. Found $($appRegs.Count) app registrations." ([System.Drawing.Color]::Green)
        }
        else {
            Update-GuiStatus "No app registrations found in the provided date range." ([System.Drawing.Color]::Green)
        }
        
        return $appRegs
    }
    catch {
        Update-GuiStatus "Error collecting app registration data: $($_.Exception.Message)" ([System.Drawing.Color]::Red)
        Write-Log "Error collecting app registration data: $($_.Exception.Message)" -Level "Error"
        return $null
    }
}

function Get-ConditionalAccessData {
    param (
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = (Join-Path -Path $ConfigData.WorkDir -ChildPath "ConditionalAccess.csv")
    )
    
    Update-GuiStatus "Starting Conditional Access policy collection..." ([System.Drawing.Color]::Orange)
    
    try {
        # Get Conditional Access policies
        Update-GuiStatus "Retrieving Conditional Access policies..." ([System.Drawing.Color]::Orange)
        $caPolicies = Get-MgIdentityConditionalAccessPolicy -All
        
        $policies = @()
        $suspiciousPolicies = @()
        $processedCount = 0
        
        Update-GuiStatus "Processing $($caPolicies.Count) Conditional Access policies..." ([System.Drawing.Color]::Orange)
        
        foreach ($policy in $caPolicies) {
            $processedCount++
            if ($processedCount % 10 -eq 0) {
                $percentage = [math]::Round(($processedCount / $caPolicies.Count) * 100, 1)
                Update-GuiStatus "Processing CA policies: $processedCount of $($caPolicies.Count) ($percentage%)" ([System.Drawing.Color]::Orange)
            }
            
            # Determine if policy is suspicious
            $isSuspicious = $false
            $suspiciousReasons = @()
            
            # Check for recently modified policies
            if ($policy.ModifiedDateTime -ge (Get-Date).AddDays(-7)) {
                $suspiciousReasons += "Recently modified"
            }
            
            # Check for disabled policies that should be enabled
            if ($policy.State -eq "disabled") {
                $suspiciousReasons += "Policy is disabled"
                $isSuspicious = $true
            }
            
            # Check for policies excluding admins (could be bypass attempt)
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
            
            if ($isSuspicious) {
                $suspiciousPolicies += $policyEntry
            }
        }
        
        Update-GuiStatus "Exporting Conditional Access policy data..." ([System.Drawing.Color]::Orange)
        
        # Export results
        $policies | Export-Csv -Path $OutputPath -NoTypeInformation -Force
        
        if ($suspiciousPolicies.Count -gt 0) {
            $suspiciousPath = $OutputPath -replace '.csv$', '_Suspicious.csv'
            $suspiciousPolicies | Export-Csv -Path $suspiciousPath -NoTypeInformation -Force
            Write-Log "Found $($suspiciousPolicies.Count) suspicious Conditional Access policies" -Level "Warning"
        }
        
        Update-GuiStatus "Conditional Access policy collection completed. Found $($policies.Count) policies." ([System.Drawing.Color]::Green)
        return $policies
        
    }
    catch {
        Update-GuiStatus "Error collecting Conditional Access data: $($_.Exception.Message)" ([System.Drawing.Color]::Red)
        Write-Log "Error collecting Conditional Access data: $($_.Exception.Message)" -Level "Error"
        return $null
    }
}

#region ETR Analysis Functions

function Find-ETRFiles {
    <#
    .SYNOPSIS
    Automatically detects Exchange Trace Report files in the working directory
    #>
    param (
        [Parameter(Mandatory = $false)]
        [string]$WorkingDirectory = $ConfigData.WorkDir
    )
    
    $foundFiles = @()
    
    foreach ($pattern in $ConfigData.ETRAnalysis.FilePatterns) {
        $files = Get-ChildItem -Path $WorkingDirectory -Filter $pattern -ErrorAction SilentlyContinue
        $foundFiles += $files
    }
    
    # Remove duplicates and sort by creation time (newest first)
    $uniqueFiles = $foundFiles | Sort-Object FullName -Unique | Sort-Object CreationTime -Descending
    
    if ($uniqueFiles.Count -gt 0) {
        Write-Log "Found $($uniqueFiles.Count) ETR files in working directory" -Level "Info"
        foreach ($file in $uniqueFiles) {
            Write-Log "ETR File: $($file.Name) ($(Get-Date $file.CreationTime -Format 'yyyy-MM-dd HH:mm:ss'))" -Level "Info"
        }
    } else {
        Write-Log "No ETR files found matching common patterns" -Level "Warning"
    }
    
    return $uniqueFiles
}

function Get-ETRColumnMapping {
    <#
    .SYNOPSIS
    Analyzes ETR file headers to map column names to expected fields
    #>
    param (
        [Parameter(Mandatory = $true)]
        [array]$Headers
    )
    
    # Common variations of column names in message trace reports
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
    
    foreach ($field in $columnMappings.Keys) {
        $possibleNames = $columnMappings[$field]
        foreach ($possibleName in $possibleNames) {
            $matchedHeader = $Headers | Where-Object { $_.ToLower().Replace(" ", "").Replace("-", "").Replace("_", "") -eq $possibleName.Replace("_", "") }
            if ($matchedHeader) {
                $mapping[$field] = $matchedHeader
                break
            }
        }
    }
    
    Write-Log "ETR Column Mapping Results:" -Level "Info"
    foreach ($field in $mapping.Keys) {
        Write-Log "  $field -> $($mapping[$field])" -Level "Info"
    }
    
    return $mapping
}

function Analyze-ETRData {
    param (
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = (Join-Path -Path $ConfigData.WorkDir -ChildPath "ETRSpamAnalysis.csv"),
        
        [Parameter(Mandatory = $false)]
        [array]$RiskyIPs = @()
    )
    
    Update-GuiStatus "Starting ETR message trace analysis..." ([System.Drawing.Color]::Orange)
    
    try {
        # Force garbage collection before starting
        [System.GC]::Collect()
        
        # Find ETR files
        $etrFiles = Find-ETRFiles
        
        if ($etrFiles.Count -eq 0) {
            Update-GuiStatus "No ETR files found! Please place message trace files in the working directory." ([System.Drawing.Color]::Red)
            
            $message = "No Exchange Trace Report (ETR) files found!`n`n" +
                      "Expected file patterns:`n" +
                      ($ConfigData.ETRAnalysis.FilePatterns -join "`n") + "`n`n" +
                      "Please place your message trace files in:`n$($ConfigData.WorkDir)`n`n" +
                      "The analysis will continue without ETR data."
            
            [System.Windows.Forms.MessageBox]::Show($message, "ETR Files Not Found", "OK", "Warning")
            return $null
        }
        
        # Select file (use most recent if multiple)
        $selectedFile = $etrFiles[0]
        
        # Check file size and warn if large
        $fileSize = (Get-Item $selectedFile.FullName).Length / 1MB
        if ($fileSize -gt 100) {
            $result = [System.Windows.Forms.MessageBox]::Show(
                "The ETR file is very large ($([math]::Round($fileSize, 1)) MB). This may cause memory issues.`n`nContinue with analysis?",
                "Large File Warning",
                "YesNo",
                "Warning"
            )
            if ($result -eq "No") {
                return $null
            }
        }
        
        Update-GuiStatus "Analyzing ETR file: $($selectedFile.Name) ($([math]::Round($fileSize, 1)) MB)..." ([System.Drawing.Color]::Orange)
        
        # Load ETR data
        $etrData = Import-Csv -Path $selectedFile.FullName -ErrorAction Stop
        
        if (-not $etrData -or $etrData.Count -eq 0) {
            throw "ETR file appears to be empty or invalid"
        }
        
        # Check record count and warn if very large
        if ($etrData.Count -gt 500000) {
            $result = [System.Windows.Forms.MessageBox]::Show(
                "ETR file contains $($etrData.Count) records. Processing may take a very long time.`n`nContinue?",
                "Large Dataset Warning",
                "YesNo",
                "Warning"
            )
            if ($result -eq "No") {
                return $null
            }
        }
        
        Update-GuiStatus "Loaded $($etrData.Count) message trace records. Mapping columns..." ([System.Drawing.Color]::Orange)
        
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
            throw "ETR file missing essential columns: $($missingFields -join ', '). Available headers: $($headers -join ', ')"
        }
        
        Update-GuiStatus "Processing message trace data for spam patterns..." ([System.Drawing.Color]::Orange)
        
        # Use ArrayList for better performance
        $processedMessages = [System.Collections.ArrayList]::new($etrData.Count)
        $processingCount = 0
        
        foreach ($record in $etrData) {
            $processingCount++
            if ($processingCount % 10000 -eq 0) {
                $percentage = [math]::Round(($processingCount / $etrData.Count) * 100, 1)
                Update-GuiStatus "Processing ETR records: $processingCount of $($etrData.Count) ($percentage%)" ([System.Drawing.Color]::Orange)
                [System.Windows.Forms.Application]::DoEvents()
            }
            
            # Extract key fields using column mapping
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
        
        Update-GuiStatus "Analyzing $($processedMessages.Count) processed messages for spam indicators..." ([System.Drawing.Color]::Orange)
        
        # Focus on outbound messages for spam analysis
        $outboundMessages = $processedMessages.ToArray() | Where-Object { 
            $_.Direction -like "*outbound*" -or 
            $_.Direction -like "*send*" -or 
            [string]::IsNullOrEmpty($_.Direction)
        }
        
        Write-Log "Found $($outboundMessages.Count) outbound messages for spam analysis" -Level "Info"
        
        if ($outboundMessages.Count -eq 0) {
            Update-GuiStatus "No outbound messages found in ETR data for spam analysis" ([System.Drawing.Color]::Orange)
            return @()
        }
        
        # **CRITICAL FIX**: Use ArrayList for ALL spam indicators throughout
        $spamIndicators = [System.Collections.ArrayList]::new()
        
        # 1. EXCESSIVE VOLUME ANALYSIS - Use hashtable for better performance
        Update-GuiStatus "Analyzing message volume patterns..." ([System.Drawing.Color]::Orange)
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
        
        $volumeAnalysisCount = 0
        foreach ($sender in $senderCounts.Keys) {
            $messageCount = $senderCounts[$sender]
            if ($messageCount -gt $ConfigData.ETRAnalysis.MaxMessagesPerSender) {
                $senderMessages = $outboundMessages | Where-Object { $_.SenderAddress -eq $sender }
                
                $spamIndicator = [PSCustomObject]@{
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
                [void]$spamIndicators.Add($spamIndicator)
                $volumeAnalysisCount++
            }
        }
        Write-Log "Volume analysis completed: $volumeAnalysisCount excessive volume patterns found" -Level "Info"
        
        # 2. IDENTICAL SUBJECT ANALYSIS - Optimized with hashtables
        Update-GuiStatus "Analyzing identical subject patterns..." ([System.Drawing.Color]::Orange)
        $subjectGroups = @{}
        foreach ($msg in $outboundMessages) {
            if (-not [string]::IsNullOrEmpty($msg.Subject) -and $msg.Subject.Length -ge $ConfigData.ETRAnalysis.MinSubjectLength) {
                $normalizedSubject = $msg.Subject.ToLower().Trim()
                $key = "$($msg.SenderAddress)|$normalizedSubject"
                
                if ($subjectGroups.ContainsKey($key)) {
                    $subjectGroups[$key] += @($msg)
                } else {
                    $subjectGroups[$key] = @($msg)
                }
            }
        }
        
        $subjectAnalysisCount = 0
        foreach ($key in $subjectGroups.Keys) {
            $messages = $subjectGroups[$key]
            if ($messages.Count -ge $ConfigData.ETRAnalysis.MaxSameSubjectMessages) {
                $sender = $messages[0].SenderAddress
                $subject = $messages[0].Subject
                
                $spamIndicator = [PSCustomObject]@{
                    SenderAddress = $sender
                    RiskType = "IdenticalSubjects"
                    RiskLevel = "Critical"
                    MessageCount = $messages.Count
                    Description = "Identical subject spam: $($messages.Count) messages with subject '$subject'"
                    MessageIds = ($messages.MessageId | Where-Object { -not [string]::IsNullOrEmpty($_) } | Select-Object -First 10) -join "; "
                    Recipients = ($messages.RecipientAddress | Select-Object -Unique | Select-Object -First 10) -join "; "
                    Subjects = $subject
                    RiskScore = $ConfigData.ETRAnalysis.RiskWeights.ExcessiveVolume
                }
                [void]$spamIndicators.Add($spamIndicator)
                $subjectAnalysisCount++
            }
        }
        Write-Log "Subject analysis completed: $subjectAnalysisCount identical subject patterns found" -Level "Info"
        
        # 3. SPAM KEYWORD ANALYSIS - Optimized with batch processing
        Update-GuiStatus "Analyzing spam keywords..." ([System.Drawing.Color]::Orange)
        $keywordAnalysisCount = 0
        
        foreach ($keyword in $ConfigData.ETRAnalysis.SpamKeywords) {
            $keywordMessages = $outboundMessages | Where-Object { 
                $_.Subject -like "*$keyword*" -and -not [string]::IsNullOrEmpty($_.Subject) 
            }
            
            if ($keywordMessages.Count -gt 5) {
                # Use hashtable grouping instead of Group-Object
                $senderKeywordGroups = @{}
                foreach ($msg in $keywordMessages) {
                    $sender = $msg.SenderAddress
                    if (-not [string]::IsNullOrEmpty($sender)) {
                        if ($senderKeywordGroups.ContainsKey($sender)) {
                            $senderKeywordGroups[$sender] += @($msg)
                        } else {
                            $senderKeywordGroups[$sender] = @($msg)
                        }
                    }
                }
                
                foreach ($sender in $senderKeywordGroups.Keys) {
                    $senderMessages = $senderKeywordGroups[$sender]
                    if ($senderMessages.Count -gt 3) {
                        $spamIndicator = [PSCustomObject]@{
                            SenderAddress = $sender
                            RiskType = "SpamKeywords"
                            RiskLevel = "Medium"
                            MessageCount = $senderMessages.Count
                            Description = "Spam keyword detected: '$keyword' in $($senderMessages.Count) messages"
                            MessageIds = ($senderMessages.MessageId | Where-Object { -not [string]::IsNullOrEmpty($_) } | Select-Object -First 5) -join "; "
                            Recipients = ($senderMessages.RecipientAddress | Select-Object -Unique | Select-Object -First 5) -join "; "
                            Subjects = ($senderMessages.Subject | Select-Object -Unique | Select-Object -First 3) -join "; "
                            RiskScore = $ConfigData.ETRAnalysis.RiskWeights.SpamKeywords
                            DetectedKeyword = $keyword
                        }
                        [void]$spamIndicators.Add($spamIndicator)
                        $keywordAnalysisCount++
                    }
                }
            }
        }
        Write-Log "Keyword analysis completed: $keywordAnalysisCount spam keyword patterns found" -Level "Info"
        
        # 4. RISKY IP CORRELATION - OPTIMIZED with early exit and progress tracking
        $ipCorrelationCount = 0
        if ($RiskyIPs.Count -gt 0) {
            Update-GuiStatus "Correlating messages with previously identified risky IPs..." ([System.Drawing.Color]::Orange)
            
            $processedIPs = 0
            foreach ($riskyIP in $RiskyIPs) {
                $processedIPs++
                
                # Progress update for large IP lists
                if ($RiskyIPs.Count -gt 10 -and $processedIPs % 5 -eq 0) {
                    $ipPercentage = [math]::Round(($processedIPs / $RiskyIPs.Count) * 100, 1)
                    Update-GuiStatus "Processing risky IPs: $processedIPs of $($RiskyIPs.Count) ($ipPercentage%)" ([System.Drawing.Color]::Orange)
                    [System.Windows.Forms.Application]::DoEvents()
                }
                
                $riskyIPMessages = $outboundMessages | Where-Object { $_.FromIP -eq $riskyIP -or $_.ToIP -eq $riskyIP }
                
                if ($riskyIPMessages.Count -gt 0) {
                    $spamIndicator = [PSCustomObject]@{
                        SenderAddress = ($riskyIPMessages.SenderAddress | Select-Object -Unique) -join "; "
                        RiskType = "RiskyIPCorrelation"
                        RiskLevel = "Critical"
                        MessageCount = $riskyIPMessages.Count
                        Description = "Messages from/to risky IP $riskyIP identified in sign-in analysis"
                        MessageIds = ($riskyIPMessages.MessageId | Where-Object { -not [string]::IsNullOrEmpty($_) } | Select-Object -First 10) -join "; "
                        Recipients = ($riskyIPMessages.RecipientAddress | Select-Object -Unique | Select-Object -First 10) -join "; "
                        Subjects = ($riskyIPMessages.Subject | Select-Object -Unique | Select-Object -First 3) -join "; "
                        RiskScore = $ConfigData.ETRAnalysis.RiskWeights.RiskyIPMatch
                        RiskyIP = $riskyIP
                    }
                    [void]$spamIndicators.Add($spamIndicator)
                    $ipCorrelationCount++
                    Write-Log "Found $($riskyIPMessages.Count) messages correlated with risky IP $riskyIP" -Level "Warning"
                }
            }
        }
        Write-Log "IP correlation completed: $ipCorrelationCount risky IP correlations found" -Level "Info"
        
        # 5. FAILED DELIVERY ANALYSIS - Optimized with hashtable grouping
        Update-GuiStatus "Analyzing failed delivery patterns..." ([System.Drawing.Color]::Orange)
        $failedMessages = $processedMessages.ToArray() | Where-Object { 
            $_.Status -like "*failed*" -or 
            $_.Status -like "*bounce*" -or 
            $_.Status -like "*reject*" -or
            $_.Status -like "*blocked*"
        }
        
        $failureAnalysisCount = 0
        if ($failedMessages.Count -gt 0) {
            # Use hashtable grouping instead of Group-Object
            $failedSenderGroups = @{}
            foreach ($msg in $failedMessages) {
                $sender = $msg.SenderAddress
                if (-not [string]::IsNullOrEmpty($sender)) {
                    if ($failedSenderGroups.ContainsKey($sender)) {
                        $failedSenderGroups[$sender] += @($msg)
                    } else {
                        $failedSenderGroups[$sender] = @($msg)
                    }
                }
            }
            
            foreach ($sender in $failedSenderGroups.Keys) {
                $senderFailures = $failedSenderGroups[$sender]
                if ($senderFailures.Count -gt 10) {
                    $spamIndicator = [PSCustomObject]@{
                        SenderAddress = $sender
                        RiskType = "ExcessiveFailures"
                        RiskLevel = "Medium"
                        MessageCount = $senderFailures.Count
                        Description = "Excessive failed deliveries: $($senderFailures.Count) failed messages (potential spam attempts)"
                        MessageIds = ($senderFailures.MessageId | Where-Object { -not [string]::IsNullOrEmpty($_) } | Select-Object -First 10) -join "; "
                        Recipients = ($senderFailures.RecipientAddress | Select-Object -Unique | Select-Object -First 10) -join "; "
                        Subjects = ($senderFailures.Subject | Select-Object -Unique | Select-Object -First 3) -join "; "
                        RiskScore = $ConfigData.ETRAnalysis.RiskWeights.FailedDelivery
                    }
                    [void]$spamIndicators.Add($spamIndicator)
                    $failureAnalysisCount++
                }
            }
        }
        Write-Log "Failed delivery analysis completed: $failureAnalysisCount excessive failure patterns found" -Level "Info"
        
        Update-GuiStatus "Exporting ETR spam analysis results..." ([System.Drawing.Color]::Orange)
        
        # Convert ArrayList to regular array and sort
        $spamIndicatorsArray = @($spamIndicators.ToArray())
        
        # Sort by risk level and score
        $riskOrder = @{"Critical" = 0; "High" = 1; "Medium" = 2; "Low" = 3}
        $spamIndicatorsArray = $spamIndicatorsArray | Sort-Object @{Expression={$riskOrder[$_.RiskLevel]}}, @{Expression="RiskScore"; Descending=$true}
        
        # Export results
        if ($spamIndicatorsArray.Count -gt 0) {
            $spamIndicatorsArray | Export-Csv -Path $OutputPath -NoTypeInformation -Force
            
            # Create actionable report for message recall
            $recallReportPath = $OutputPath -replace '.csv$', '_MessageRecallReport.csv'
            $recallReport = $spamIndicatorsArray | Where-Object { $_.RiskLevel -in @("Critical", "High") -and -not [string]::IsNullOrEmpty($_.MessageIds) } |
                Select-Object SenderAddress, RiskType, RiskLevel, MessageCount, Description, MessageIds, Recipients, Subjects |
                Sort-Object RiskLevel, MessageCount -Descending
            
            if ($recallReport.Count -gt 0) {
                $recallReport | Export-Csv -Path $recallReportPath -NoTypeInformation -Force
                Write-Log "Created message recall report with $($recallReport.Count) high-risk entries" -Level "Warning"
            }
            
            # Create summary statistics
            $criticalCount = ($spamIndicatorsArray | Where-Object { $_.RiskLevel -eq "Critical" }).Count
            $highCount = ($spamIndicatorsArray | Where-Object { $_.RiskLevel -eq "High" }).Count
            $mediumCount = ($spamIndicatorsArray | Where-Object { $_.RiskLevel -eq "Medium" }).Count
            
            # Final summary
            $totalPatterns = $volumeAnalysisCount + $subjectAnalysisCount + $keywordAnalysisCount + $ipCorrelationCount + $failureAnalysisCount
            
            Update-GuiStatus "ETR analysis completed! Found $criticalCount critical, $highCount high, $mediumCount medium risk patterns." ([System.Drawing.Color]::Green)
            Write-Log "ETR analysis completed successfully" -Level "Info"
            Write-Log "Analysis summary: Volume($volumeAnalysisCount), Subjects($subjectAnalysisCount), Keywords($keywordAnalysisCount), IPs($ipCorrelationCount), Failures($failureAnalysisCount) = Total $totalPatterns patterns" -Level "Info"
            Write-Log "Final results: $criticalCount critical, $highCount high, $mediumCount medium risk patterns from $($etrData.Count) message trace records" -Level "Info"
            
            return $spamIndicatorsArray
        } else {
            Update-GuiStatus "No suspicious patterns detected in ETR analysis" ([System.Drawing.Color]::Green)
            Write-Log "No suspicious patterns detected in ETR analysis" -Level "Info"
            return @()
        }
        
    } catch {
        Update-GuiStatus "Error in ETR analysis: $($_.Exception.Message)" ([System.Drawing.Color]::Red)
        Write-Log "Error in ETR analysis: $($_.Exception.Message)" -Level "Error"
        [System.GC]::Collect()  # Force cleanup on error
        return $null
    }
}

#endregion

#region Analysis Functions
function Invoke-CompromiseDetection {
    param (
        [Parameter(Mandatory = $false)]
        [string]$ReportPath = (Join-Path -Path $ConfigData.WorkDir -ChildPath "SecurityReport.html")
    )
    
    Update-GuiStatus "Starting compromise detection analysis..." ([System.Drawing.Color]::Orange)
    
    # Helper function to safely convert imported CSV data to proper types
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
    
    # Define paths for each dataset
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
    }
    
    Update-GuiStatus "Checking for available data sources..." ([System.Drawing.Color]::Orange)
    
    # Check which data sources are available and load them
    $availableDataSources = @()
    foreach ($source in $dataSources.GetEnumerator()) {
        $sourceName = $source.Key
        $sourceInfo = $source.Value
        
        if (Test-Path -Path $sourceInfo.Path) {
            try {
                $rawData = Import-Csv -Path $sourceInfo.Path -ErrorAction Stop
                if ($rawData -and $rawData.Count -gt 0) {
                    
                    # Clean and normalize the data based on source type
                    switch ($sourceName) {
                        "SignInData" {
                            $cleanData = @()
                            foreach ($row in $rawData) {
                                $cleanRow = [PSCustomObject]@{
                                    UserId = ConvertTo-SafeString $row.UserId
                                    UserDisplayName = ConvertTo-SafeString $row.UserDisplayName
                                    CreationTime = ConvertTo-SafeString $row.CreationTime
                                    UserAgent = ConvertTo-SafeString $row.UserAgent
                                    IP = ConvertTo-SafeString $row.IP
                                    ISP = ConvertTo-SafeString $row.ISP
                                    City = ConvertTo-SafeString $row.City
                                    RegionName = ConvertTo-SafeString $row.RegionName
                                    Country = ConvertTo-SafeString $row.Country
                                    IsUnusualLocation = ConvertTo-SafeBoolean $row.IsUnusualLocation
                                    Status = ConvertTo-SafeString $row.Status
                                    FailureReason = ConvertTo-SafeString $row.FailureReason
                                    ConditionalAccessStatus = ConvertTo-SafeString $row.ConditionalAccessStatus
                                    RiskLevel = ConvertTo-SafeString $row.RiskLevel
                                    DeviceOS = ConvertTo-SafeString $row.DeviceOS
                                    DeviceBrowser = ConvertTo-SafeString $row.DeviceBrowser
                                    IsInteractive = ConvertTo-SafeBoolean $row.IsInteractive
                                    AppDisplayName = ConvertTo-SafeString $row.AppDisplayName
                                }
                                $cleanData += $cleanRow
                            }
                            $sourceInfo.Data = $cleanData
                        }
                        
                        "AdminAuditData" {
                            $cleanData = @()
                            foreach ($row in $rawData) {
                                $cleanRow = [PSCustomObject]@{
                                    Timestamp = ConvertTo-SafeString $row.Timestamp
                                    UserId = ConvertTo-SafeString $row.UserId
                                    UserDisplayName = ConvertTo-SafeString $row.UserDisplayName
                                    Activity = ConvertTo-SafeString $row.Activity
                                    Result = ConvertTo-SafeString $row.Result
                                    ResultReason = ConvertTo-SafeString $row.ResultReason
                                    Category = ConvertTo-SafeString $row.Category
                                    CorrelationId = ConvertTo-SafeString $row.CorrelationId
                                    LoggedByService = ConvertTo-SafeString $row.LoggedByService
                                    RiskLevel = ConvertTo-SafeString $row.RiskLevel
                                    TargetResources = ConvertTo-SafeString $row.TargetResources
                                    AdditionalDetails = ConvertTo-SafeString $row.AdditionalDetails
                                }
                                $cleanData += $cleanRow
                            }
                            $sourceInfo.Data = $cleanData
                        }
                        
                        "ConditionalAccessData" {
                            $cleanData = @()
                            foreach ($row in $rawData) {
                                $cleanRow = [PSCustomObject]@{
                                    DisplayName = ConvertTo-SafeString $row.DisplayName
                                    State = ConvertTo-SafeString $row.State
                                    CreatedDateTime = ConvertTo-SafeString $row.CreatedDateTime
                                    ModifiedDateTime = ConvertTo-SafeString $row.ModifiedDateTime
                                    Conditions = ConvertTo-SafeString $row.Conditions
                                    GrantControls = ConvertTo-SafeString $row.GrantControls
                                    SessionControls = ConvertTo-SafeString $row.SessionControls
                                    IsSuspicious = ConvertTo-SafeBoolean $row.IsSuspicious
                                    SuspiciousReasons = ConvertTo-SafeString $row.SuspiciousReasons
                                }
                                $cleanData += $cleanRow
                            }
                            $sourceInfo.Data = $cleanData
                        }
                        
                        default {
                            # For other data sources, do basic cleaning
                            $cleanData = @()
                            foreach ($row in $rawData) {
                                $cleanRow = [PSCustomObject]@{}
                                foreach ($property in $row.PSObject.Properties) {
                                    $cleanRow | Add-Member -NotePropertyName $property.Name -NotePropertyValue (ConvertTo-SafeString $property.Value)
                                }
                                $cleanData += $cleanRow
                            }
                            $sourceInfo.Data = $cleanData
                        }
                    }
                    
                    $sourceInfo.Available = $true
                    $availableDataSources += $sourceName
                    Write-Log "Loaded and cleaned ${sourceName}: $($sourceInfo.Data.Count) records" -Level "Info"
                } else {
                    Write-Log "${sourceName} file exists but contains no data" -Level "Warning"
                }
            }
            catch {
                Write-Log "Error loading ${sourceName} from $($sourceInfo.Path): $($_.Exception.Message)" -Level "Warning"
            }
        } else {
            Write-Log "${sourceName} not found at $($sourceInfo.Path)" -Level "Info"
        }
    }
    
    if ($availableDataSources.Count -eq 0) {
        Update-GuiStatus "No data sources found! Please run data collection first." ([System.Drawing.Color]::Red)
        [System.Windows.Forms.MessageBox]::Show("No data files found for analysis!`n`nPlease run the data collection functions first:", "No Data Available", "OK", "Warning")
        return $null
    }
    
    Update-GuiStatus "Found $($availableDataSources.Count) data sources: $($availableDataSources -join ', ')" ([System.Drawing.Color]::Green)
    
    # Create a master list of users with safe initialization
    $users = @{}
    $systemIssues = @()
    
    # Process sign-in data if available
    if ($dataSources.SignInData.Available) {
        Update-GuiStatus "Analyzing sign-in data..." ([System.Drawing.Color]::Orange)
        
        # Generate unique logins report FIRST
        Update-GuiStatus "Generating unique logins report..." ([System.Drawing.Color]::Orange)
        $uniqueLogins = @()
        $userLocationGroups = $dataSources.SignInData.Data | Group-Object -Property UserId
        
        foreach ($userGroup in $userLocationGroups) {
            $userId = $userGroup.Name
            $userSignIns = $userGroup.Group
            
            # Get unique combinations of location data per user
            $uniqueUserLocations = $userSignIns | 
                Select-Object UserId, UserDisplayName, IP, City, RegionName, Country, ISP -Unique |
                Where-Object { -not [string]::IsNullOrEmpty($_.IP) } |
                Sort-Object Country, RegionName, City, IP
            
            foreach ($location in $uniqueUserLocations) {
                # Count sign-ins from this location
                $signInCount = ($userSignIns | Where-Object { 
                    $_.IP -eq $location.IP -and 
                    $_.City -eq $location.City -and 
                    $_.Country -eq $location.Country 
                }).Count
                
                # Get first and last sign-in dates from this location
                $locationSignIns = $userSignIns | Where-Object { 
                    $_.IP -eq $location.IP -and 
                    $_.City -eq $location.City -and 
                    $_.Country -eq $location.Country 
                } | Sort-Object CreationTime
                
                $firstSeen = if ($locationSignIns.Count -gt 0) { $locationSignIns[0].CreationTime } else { "" }
                $lastSeen = if ($locationSignIns.Count -gt 0) { $locationSignIns[-1].CreationTime } else { "" }
                
                # Determine if this is an unusual location
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
                    DaysSinceFirst = if ($firstSeen -and $firstSeen -ne "") { 
                        try { [math]::Round(((Get-Date) - [DateTime]::Parse($firstSeen)).TotalDays, 1) } catch { 0 }
                    } else { 0 }
                    DaysSinceLast = if ($lastSeen -and $lastSeen -ne "") { 
                        try { [math]::Round(((Get-Date) - [DateTime]::Parse($lastSeen)).TotalDays, 1) } catch { 0 }
                    } else { 0 }
                }
                
                $uniqueLogins += $uniqueLogin
            }
        }
        
        # Export unique logins report
        if ($uniqueLogins.Count -gt 0) {
            $uniqueLoginsPath = (Join-Path -Path $ConfigData.WorkDir -ChildPath "UniqueSignInLocations.csv")
            $uniqueLogins | Sort-Object UserId, Country, RegionName, City | 
                Export-Csv -Path $uniqueLoginsPath -NoTypeInformation -Force
            
            # Create unusual locations summary
            $unusualUniqueLogins = $uniqueLogins | Where-Object { $_.IsUnusualLocation -eq $true }
            if ($unusualUniqueLogins.Count -gt 0) {
                $unusualUniquePath = (Join-Path -Path $ConfigData.WorkDir -ChildPath "UniqueSignInLocations_Unusual.csv")
                $unusualUniqueLogins | Sort-Object UserId, Country, RegionName, City |
                    Export-Csv -Path $unusualUniquePath -NoTypeInformation -Force
                Write-Log "Created unusual unique locations report: $($unusualUniqueLogins.Count) unusual locations found" -Level "Warning"
            }
            
            Write-Log "Created unique logins report with $($uniqueLogins.Count) unique locations across $($userLocationGroups.Count) users" -Level "Info"
            Update-GuiStatus "Unique logins report created: $($uniqueLogins.Count) unique locations found" ([System.Drawing.Color]::Green)
        }
        
        # Now process sign-in data for risk analysis
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
                    RiskScore = 0
                }
            }
            
            # Determine if sign-in was successful
            $isSuccessfulSignIn = ($signIn.Status -eq "0" -or [string]::IsNullOrEmpty($signIn.Status))
            $isFailedSignIn = (-not [string]::IsNullOrEmpty($signIn.Status) -and $signIn.Status -ne "0")
            
            # Check for unusual locations - ONLY for SUCCESSFUL sign-ins
            $isUnusual = $signIn.IsUnusualLocation -eq $true
            
            # Only flag unusual locations for SUCCESSFUL sign-ins
            if ($isUnusual -and $isSuccessfulSignIn) {
                $users[$userId].UnusualSignIns += $signIn
                $users[$userId].RiskScore += 5
            }
            
            # Track failed sign-ins for reporting but DO NOT add to risk score
            if ($isFailedSignIn) {
                $users[$userId].FailedSignIns += $signIn
            }
            
            # Add risk for high-risk successful sign-ins only
            if ($signIn.RiskLevel -and $signIn.RiskLevel -eq "high" -and $isSuccessfulSignIn) {
                $users[$userId].RiskScore += 15
            }
        }
        Write-Log "Processed sign-in data for $($users.Count) users" -Level "Info"
    }
    
    # Process admin audit data if available
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
                    RiskScore = 0
                }
            }
            
            if ($auditLog.RiskLevel -eq "High") {
                $users[$userId].HighRiskOps += $auditLog
                $users[$userId].RiskScore += 10
            }
        }
        Write-Log "Processed admin audit data" -Level "Info"
    }
    
    # Process inbox rules if available
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
                        RiskScore = 0
                    }
                }
                
                $users[$userId].SuspiciousRules += $rule
                $users[$userId].RiskScore += 15
            }
        }
        Write-Log "Processed inbox rules data" -Level "Info"
    }
    
    # Process mailbox delegations if available
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
                        RiskScore = 0
                    }
                }
                
                $users[$userId].SuspiciousDelegations += $delegation
                $users[$userId].RiskScore += 8
            }
        }
        Write-Log "Processed mailbox delegation data" -Level "Info"
    }
    
    # Process app registrations if available
    if ($dataSources.AppRegData.Available) {
        Update-GuiStatus "Analyzing app registrations..." ([System.Drawing.Color]::Orange)
        
        foreach ($appReg in $dataSources.AppRegData.Data) {
            if ($appReg.RiskLevel -eq "High") {
                $systemIssues += $appReg
                
                # Add to a general "system" risk category
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
                        RiskScore = 0
                    }
                }
                
                $users[$systemUser].HighRiskAppRegs += $appReg
                $users[$systemUser].RiskScore += 20
            }
        }
        Write-Log "Processed app registration data" -Level "Info"
    }
    
    # Process conditional access data if available
    if ($dataSources.ConditionalAccessData.Available) {
        Update-GuiStatus "Analyzing conditional access policies..." ([System.Drawing.Color]::Orange)
        
        $suspiciousPolicies = $dataSources.ConditionalAccessData.Data | Where-Object { 
            (ConvertTo-SafeBoolean $_.IsSuspicious) -eq $true
        }
        
        if ($suspiciousPolicies.Count -gt 0) {
            $systemIssues += $suspiciousPolicies
            Write-Log "Found $($suspiciousPolicies.Count) suspicious conditional access policies" -Level "Warning"
        }
    }
    
	# Process ETR data if available
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
                SpamActivity = @()
                ETRSpamActivity = @()
                RiskScore = 0
            }
        }
        
        # Add ETR spam activity to user record
        $users[$userId].ETRSpamActivity += $etrRecord
        
        # Add to risk score based on ETR findings
        $riskScore = if ($etrRecord.RiskScore) { [int]$etrRecord.RiskScore } else { 0 }
        $users[$userId].RiskScore += $riskScore
        
        # Log critical findings
        if ($etrRecord.RiskLevel -eq "Critical") {
            Write-Log "Critical ETR finding for $userId : $($etrRecord.Description)" -Level "Error"
        }
    }
    Write-Log "Processed ETR analysis data for $($dataSources.ETRData.Data.Count) records" -Level "Info"
}

Update-GuiStatus "Calculating risk scores and generating results..." ([System.Drawing.Color]::Orange)
	
    Update-GuiStatus "Calculating risk scores and generating results..." ([System.Drawing.Color]::Orange)
    
    # Create final results with risk assessment
    $results = @()
    
    foreach ($userId in $users.Keys) {
        $userData = $users[$userId]
        $riskLevel = "Low"
        
        if ($userData.RiskScore -ge 50) {
            $riskLevel = "Critical"
        }
        elseif ($userData.RiskScore -ge 30) {
            $riskLevel = "High"
        }
        elseif ($userData.RiskScore -ge 15) {
            $riskLevel = "Medium"
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
        }
        
        $results += $resultObject
    }
    
    # Sort by risk score descending
    $results = $results | Sort-Object -Property RiskScore -Descending
    
    Update-GuiStatus "Exporting analysis results..." ([System.Drawing.Color]::Orange)
    
    # Export the results to CSV
    $csvPath = $ReportPath -replace '.html$', '.csv'
    $results | Select-Object -Property UserId, UserDisplayName, RiskScore, RiskLevel, UnusualSignInCount, FailedSignInCount, HighRiskOperationsCount, SuspiciousRulesCount, SuspiciousDelegationsCount, HighRiskAppRegistrationsCount |
        Export-Csv -Path $csvPath -NoTypeInformation -Force
    
    Update-GuiStatus "Generating HTML report..." ([System.Drawing.Color]::Orange)
    
    # Generate HTML report
    $htmlReport = Generate-HTMLReport -Data $results
    $htmlReport | Out-File -FilePath $ReportPath -Force -Encoding UTF8
    
    Update-GuiStatus "Analysis completed! Generated report with $($results.Count) users analyzed." ([System.Drawing.Color]::Green)
    Write-Log "Compromise detection analysis completed. Report saved to $ReportPath" -Level "Info"
    Write-Log "Analysis used data sources: $($availableDataSources -join ', ')" -Level "Info"
    
    return $results
}

function Generate-HTMLReport {
    param (
        [Parameter(Mandatory = $true)]
        $Data
    )
    
    # Safely filter users by risk level using Where-Object
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
    <title>Microsoft 365 Security Analysis Report - Enhanced MS Graph Edition</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background-color: #fff;
            padding: 30px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
            border-radius: 8px;
        }
        h1, h2, h3 {
            color: #0078d4;
        }
        h1 {
            border-bottom: 3px solid #0078d4;
            padding-bottom: 10px;
        }
        .summary-box {
            display: flex;
            justify-content: space-between;
            margin-bottom: 30px;
            gap: 15px;
        }
        .summary-item {
            flex: 1;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .summary-item h3 {
            margin-top: 0;
            font-size: 1.2em;
        }
        .summary-item p {
            font-size: 2em;
            font-weight: bold;
            margin: 10px 0;
        }
        .critical {
            background: linear-gradient(135deg, #d13438, #ff6b6b);
            color: white;
        }
        .high {
            background: linear-gradient(135deg, #ff8c00, #ffa500);
            color: white;
        }
        .medium {
            background: linear-gradient(135deg, #fce100, #ffed4e);
            color: #333;
        }
        .low {
            background: linear-gradient(135deg, #107c10, #4caf50);
            color: white;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        th, td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background: linear-gradient(135deg, #0078d4, #106ebe);
            color: white;
            font-weight: 600;
        }
        tr:hover {
            background-color: #f8f9fa;
        }
        tr:nth-child(even) {
            background-color: #f9f9f9;
        }
        .detail-section {
            margin-top: 20px;
            padding: 20px;
            background-color: #f9f9f9;
            border-left: 5px solid #0078d4;
            border-radius: 0 8px 8px 0;
        }
        .collapsible {
            background: linear-gradient(135deg, #0078d4, #106ebe);
            color: white;
            cursor: pointer;
            padding: 18px 20px;
            width: 100%;
            border: none;
            text-align: left;
            outline: none;
            font-size: 16px;
            margin-top: 15px;
            border-radius: 8px;
            font-weight: 600;
            transition: all 0.3s ease;
        }
        .active, .collapsible:hover {
            background: linear-gradient(135deg, #005a9e, #0078d4);
            transform: translateY(-2px);
            box-shadow: 0 4px 15px rgba(0,120,212,0.3);
        }
        .content {
            padding: 0 20px;
            display: none;
            overflow: hidden;
            background-color: #f9f9f9;
            border-radius: 0 0 8px 8px;
        }
        .risk-badge {
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
        }
        .risk-critical { background-color: #d13438; color: white; }
        .risk-high { background-color: #ff8c00; color: white; }
        .risk-medium { background-color: #fce100; color: #333; }
        .risk-low { background-color: #107c10; color: white; }
        .metadata {
            background-color: #e3f2fd;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            border-left: 5px solid #2196f3;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Microsoft 365 Security Analysis Report</h1>
        <div class="metadata">
            <strong>Report Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")<br>
            <strong>Analysis Engine:</strong> Enhanced Microsoft Graph PowerShell Module<br>
            <strong>Script Version:</strong> $ScriptVer<br>
            <strong>Analyzed Tenant:</strong> $($Global:ConnectionState.TenantName) ($($Global:ConnectionState.TenantId))<br>
            <strong>Connected As:</strong> $($Global:ConnectionState.Account)
        </div>
        
        <div class="summary-box">
            <div class="summary-item critical">
                <h3>🚨 Critical Risk</h3>
                <p>$($criticalUsers.Count)</p>
                <small>Users requiring immediate attention</small>
            </div>
            <div class="summary-item high">
                <h3>⚠️ High Risk</h3>
                <p>$($highRiskUsers.Count)</p>
                <small>Users with elevated risk indicators</small>
            </div>
            <div class="summary-item medium">
                <h3>⚡ Medium Risk</h3>
                <p>$($mediumRiskUsers.Count)</p>
                <small>Users with moderate risk indicators</small>
            </div>
            <div class="summary-item low">
                <h3>✅ Low Risk</h3>
                <p>$($lowRiskUsers.Count)</p>
                <small>Users with minimal risk indicators</small>
            </div>
        </div>
        
        <h2>Executive Risk Summary</h2>
        <table>
            <tr>
                <th>User ID</th>
                <th>Risk Level</th>
                <th>Risk Score</th>
                <th>Unusual Locations</th>
                <th>Failed Sign-ins</th>
                <th>Admin Operations</th>
                <th>Suspicious Rules</th>
                <th>Delegations</th>
                <th>Risky Apps</th>
            </tr>
"@

    foreach ($user in $Data) {
        $riskClass = "risk-" + $user.RiskLevel.ToLower()
        $html += @"
            <tr>
                <td><strong>$($user.UserId)</strong></td>
                <td><span class="risk-badge $riskClass">$($user.RiskLevel)</span></td>
                <td><strong>$($user.RiskScore)</strong></td>
                <td>$($user.UnusualSignInCount)</td>
                <td>$($user.FailedSignInCount)</td>
                <td>$($user.HighRiskOperationsCount)</td>
                <td>$($user.SuspiciousRulesCount)</td>
                <td>$($user.SuspiciousDelegationsCount)</td>
                <td>$($user.HighRiskAppRegistrationsCount)</td>
            </tr>
"@
    }

    $html += @"
        </table>
        
        <h2>Detailed Security Analysis</h2>
"@

    # FIXED: Use array concatenation with proper PowerShell syntax
    $detailedUsers = @()
    $detailedUsers += $criticalUsers
    $detailedUsers += $highRiskUsers
    
    # Add detailed sections for critical and high-risk users
    foreach ($user in $detailedUsers) {
        $riskClass = "risk-" + $user.RiskLevel.ToLower()
        $html += @"
        <button class="collapsible">
            <span class="risk-badge $riskClass">$($user.RiskLevel)</span>
            $($user.UserId) - Risk Score: $($user.RiskScore)
        </button>
        <div class="content">
"@

        if ($user.UnusualSignInCount -gt 0 -and $user.UnusualSignIns) {
            $html += @"
            <div class="detail-section">
                <h3>🌍 Unusual Sign-In Locations</h3>
                <table>
                    <tr>
                        <th>Date/Time</th>
                        <th>IP Address</th>
                        <th>Location</th>
                        <th>Country</th>
                        <th>Risk Level</th>
                        <th>Application</th>
                    </tr>
"@
            foreach ($signIn in $user.UnusualSignIns) {
                $html += @"
                    <tr>
                        <td>$(if ($signIn.CreationTime) { $signIn.CreationTime } else { "N/A" })</td>
                        <td>$(if ($signIn.IP) { $signIn.IP } else { "N/A" })</td>
                        <td>$(if ($signIn.City) { $signIn.City } else { "Unknown" }), $(if ($signIn.RegionName) { $signIn.RegionName } else { "Unknown" })</td>
                        <td>$(if ($signIn.Country) { $signIn.Country } else { "Unknown" })</td>
                        <td>$(if ($signIn.RiskLevel) { $signIn.RiskLevel } else { "Unknown" })</td>
                        <td>$(if ($signIn.AppDisplayName) { $signIn.AppDisplayName } else { "Unknown" })</td>
                    </tr>
"@
            }
            $html += @"
                </table>
            </div>
"@
        }
        
        if ($user.FailedSignInCount -gt 0 -and $user.FailedSignIns) {
            $html += @"
            <div class="detail-section">
                <h3>⛔ Failed Sign-In Attempts</h3>
                <table>
                    <tr>
                        <th>Date/Time</th>
                        <th>IP Address</th>
                        <th>Location</th>
                        <th>Failure Reason</th>
                        <th>Application</th>
                    </tr>
"@
            # Safely get first 10 failed sign-ins
            $failedSignInsToShow = @($user.FailedSignIns | Select-Object -First 10)
            foreach ($signIn in $failedSignInsToShow) {
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
                </table>
            </div>
"@
        }
        
        if ($user.HighRiskOperationsCount -gt 0 -and $user.HighRiskOperations) {
            $html += @"
            <div class="detail-section">
                <h3>⚙️ High-Risk Administrative Operations</h3>
                <table>
                    <tr>
                        <th>Date/Time</th>
                        <th>Activity</th>
                        <th>Result</th>
                        <th>Category</th>
                    </tr>
"@
            foreach ($op in $user.HighRiskOperations) {
                $html += @"
                    <tr>
                        <td>$(if ($op.Timestamp) { $op.Timestamp } else { "N/A" })</td>
                        <td>$(if ($op.Activity) { $op.Activity } else { "N/A" })</td>
                        <td>$(if ($op.Result) { $op.Result } else { "N/A" })</td>
                        <td>$(if ($op.Category) { $op.Category } else { "N/A" })</td>
                    </tr>
"@
            }
            $html += @"
                </table>
            </div>
"@
        }
        
        if ($user.SuspiciousRulesCount -gt 0 -and $user.SuspiciousRules) {
            $html += @"
            <div class="detail-section">
                <h3>📧 Suspicious Inbox Rules</h3>
                <table>
                    <tr>
                        <th>Rule Name</th>
                        <th>Enabled</th>
                        <th>Suspicious Reasons</th>
                    </tr>
"@
            foreach ($rule in $user.SuspiciousRules) {
                $html += @"
                    <tr>
                        <td>$(if ($rule.RuleName) { $rule.RuleName } else { "N/A" })</td>
                        <td>$(if ($rule.IsEnabled) { $rule.IsEnabled } else { "N/A" })</td>
                        <td>$(if ($rule.SuspiciousReasons) { $rule.SuspiciousReasons } else { "N/A" })</td>
                    </tr>
"@
            }
            $html += @"
                </table>
            </div>
"@
        }
        
        if ($user.SuspiciousDelegationsCount -gt 0 -and $user.SuspiciousDelegations) {
            $html += @"
            <div class="detail-section">
                <h3>👥 Suspicious Mailbox Delegations</h3>
                <table>
                    <tr>
                        <th>Delegate Name</th>
                        <th>Delegate Email</th>
                        <th>Permissions</th>
                        <th>Reasons</th>
                    </tr>
"@
            foreach ($delegation in $user.SuspiciousDelegations) {
                $html += @"
                    <tr>
                        <td>$(if ($delegation.DelegateName) { $delegation.DelegateName } else { "N/A" })</td>
                        <td>$(if ($delegation.DelegateEmail) { $delegation.DelegateEmail } else { "N/A" })</td>
                        <td>$(if ($delegation.Permissions) { $delegation.Permissions } else { "N/A" })</td>
                        <td>$(if ($delegation.SuspiciousReasons) { $delegation.SuspiciousReasons } else { "N/A" })</td>
                    </tr>
"@
            }
            $html += @"
                </table>
            </div>
"@
        }
        
        if ($user.HighRiskAppRegistrationsCount -gt 0 -and $user.HighRiskAppRegistrations) {
            $html += @"
            <div class="detail-section">
                <h3>🔧 High-Risk Application Registrations</h3>
                <table>
                    <tr>
                        <th>Application Name</th>
                        <th>Created</th>
                        <th>Publisher</th>
                        <th>Risk Reasons</th>
                    </tr>
"@
            foreach ($app in $user.HighRiskAppRegistrations) {
                $html += @"
                    <tr>
                        <td>$(if ($app.DisplayName) { $app.DisplayName } else { "N/A" })</td>
                        <td>$(if ($app.CreatedDateTime) { $app.CreatedDateTime } else { "N/A" })</td>
                        <td>$(if ($app.PublisherDomain) { $app.PublisherDomain } else { "N/A" })</td>
                        <td>$(if ($app.RiskReasons) { $app.RiskReasons } else { "N/A" })</td>
                    </tr>
"@
            }
            $html += @"
                </table>
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
            
            // Auto-expand critical risk users
            document.addEventListener("DOMContentLoaded", function() {
                var criticalButtons = document.querySelectorAll('.collapsible .risk-critical');
                criticalButtons.forEach(function(button) {
                    var collapsible = button.parentElement;
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
            • Performance optimizations include IP caching and batch processing
        </div>
    </div>
</body>
</html>
"@

    return $html
}

function Show-MainGUI {
    # Ensure Windows Forms assemblies are loaded
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    # Create main form
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Microsoft 365 Security Analysis Tool - v$ScriptVer"
    $form.Size = New-Object System.Drawing.Size(820, 750)
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = "FixedSingle"
    $form.MaximizeBox = $false
    $form.BackColor = [System.Drawing.Color]::FromArgb(240, 248, 255)

    # Set global form reference
    $Global:MainForm = $form

    # Header
    $headerLabel = New-Object System.Windows.Forms.Label
    $headerLabel.Text = "Microsoft 365 Security Analysis Tool"
    $headerLabel.Font = New-Object System.Drawing.Font("Segoe UI", 16, [System.Drawing.FontStyle]::Bold)
    $headerLabel.ForeColor = [System.Drawing.Color]::FromArgb(0, 120, 212)
    $headerLabel.Size = New-Object System.Drawing.Size(780, 40)
    $headerLabel.Location = New-Object System.Drawing.Point(20, 20)
    $headerLabel.TextAlign = "MiddleCenter"
    $form.Controls.Add($headerLabel)

    # Version
    $versionLabel = New-Object System.Windows.Forms.Label
    $versionLabel.Text = "Enhanced MS Graph PowerShell Edition - Version $ScriptVer"
    $versionLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $versionLabel.ForeColor = [System.Drawing.Color]::Gray
    $versionLabel.Size = New-Object System.Drawing.Size(780, 20)
    $versionLabel.Location = New-Object System.Drawing.Point(20, 60)
    $versionLabel.TextAlign = "MiddleCenter"
    $form.Controls.Add($versionLabel)

    # Pacific Office Automation Disclaimer
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

    # Status Panel - Enhanced with date range and proper spacing
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

    # Status bar at bottom
    $Global:StatusLabel = New-Object System.Windows.Forms.Label
    $Global:StatusLabel.Text = "Ready - Please connect to Microsoft Graph to begin"
    $Global:StatusLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $Global:StatusLabel.Size = New-Object System.Drawing.Size(780, 25)
    $Global:StatusLabel.Location = New-Object System.Drawing.Point(20, 580)
    $Global:StatusLabel.ForeColor = [System.Drawing.Color]::FromArgb(108, 117, 125)
    $form.Controls.Add($Global:StatusLabel)

    # Helper function to create buttons with enhanced error handling
    function New-GuiButton($text, $x, $y, $width, $height, $color, $action) {
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
        
        # Store the action in the button's Tag property to avoid closure issues
        $button.Tag = $action
        
        # Enhanced click handler with proper script block execution
        $button.Add_Click({
            try {
                $actionBlock = $this.Tag
                if ($actionBlock -and $actionBlock -is [scriptblock]) {
                    # Execute the script block in the current scope
                    . $actionBlock
                } else {
                    throw "Invalid or missing action script block"
                }
            }
            catch {
                # Use fully qualified function name to ensure it's found
                & ([scriptblock]::Create("Update-GuiStatus `"Button action failed: $($_.Exception.Message)`" ([System.Drawing.Color]::Red)"))
                [System.Windows.Forms.MessageBox]::Show("An error occurred: $($_.Exception.Message)", "Error", "OK", "Error")
            }
        })
        return $button
    }

    # Row 1 - Setup buttons (adjusted for date range button)
$btnWorkDir = New-GuiButton "Set Working Directory" 30 340 140 35 ([System.Drawing.Color]::FromArgb(108, 117, 125)) {
    $folder = Get-Folder -initialDirectory $ConfigData.WorkDir
    if ($folder) {
        Update-WorkingDirectoryDisplay -NewWorkDir $folder
        Update-GuiStatus "Working directory updated successfully" ([System.Drawing.Color]::Green)
        
        # Show confirmation with warning if connected to tenant
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

    $btnDateRange = New-GuiButton "Change Date Range" 180 340 140 35 ([System.Drawing.Color]::FromArgb(75, 0, 130)) {
        $newRange = Get-DateRangeInput -CurrentValue $ConfigData.DateRange
        if ($newRange -ne $null) {
            $oldRange = $ConfigData.DateRange
            $ConfigData.DateRange = $newRange
            $Global:DateRangeLabel.Text = "Date Range: $($ConfigData.DateRange) days back"
            $Global:DateRangeLabel.Refresh()
            Update-GuiStatus "Date range updated from $oldRange to $newRange days" ([System.Drawing.Color]::Green)
            
            # Show confirmation with impact information
            $message = "Date range updated successfully!`n`nOld range: $oldRange days`nNew range: $newRange days`n`nNote: This will affect all future data collection operations."
            [System.Windows.Forms.MessageBox]::Show($message, "Date Range Updated", "OK", "Information")
        }
    }
    $form.Controls.Add($btnDateRange)

    $btnConnect = New-GuiButton "Connect to Microsoft Graph" 330 340 140 35 ([System.Drawing.Color]::FromArgb(0, 120, 212)) {
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

    $btnDisconnect = New-GuiButton "Disconnect" 480 340 100 35 ([System.Drawing.Color]::FromArgb(220, 53, 69)) {
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

    # Row 2 - Data collection buttons
    $btnSignIn = New-GuiButton "Collect Sign-In Data" 30 390 180 35 ([System.Drawing.Color]::FromArgb(40, 167, 69)) {
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
                Update-GuiStatus "Sign-in data collected successfully! Processed $($result.Count) records." ([System.Drawing.Color]::Green)
            }
        }
        finally {
            $btnSignIn.Enabled = $true
            $btnSignIn.Text = $originalText
        }
    }
    $form.Controls.Add($btnSignIn)

    $btnAudit = New-GuiButton "Collect Admin Audits" 220 390 180 35 ([System.Drawing.Color]::FromArgb(40, 167, 69)) {
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
                Update-GuiStatus "Admin audit data collected successfully! Processed $($result.Count) records." ([System.Drawing.Color]::Green)
            }
        }
        finally {
            $btnAudit.Enabled = $true
            $btnAudit.Text = $originalText
        }
    }
    $form.Controls.Add($btnAudit)

    $btnRules = New-GuiButton "Collect Inbox Rules" 410 390 180 35 ([System.Drawing.Color]::FromArgb(40, 167, 69)) {
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
                Update-GuiStatus "Inbox rules collected successfully! Found $($result.Count) rules." ([System.Drawing.Color]::Green)
            }
        }
        finally {
            $btnRules.Enabled = $true
            $btnRules.Text = $originalText
        }
    }
    $form.Controls.Add($btnRules)

    $btnDelegation = New-GuiButton "Collect Delegations" 600 390 180 35 ([System.Drawing.Color]::FromArgb(40, 167, 69)) {
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
                Update-GuiStatus "Delegation data collected successfully! Found $($result.Count) delegations." ([System.Drawing.Color]::Green)
            }
        }
        finally {
            $btnDelegation.Enabled = $true
            $btnDelegation.Text = $originalText
        }
    }
    $form.Controls.Add($btnDelegation)

    # Row 3 - More data collection buttons
    $btnApps = New-GuiButton "Collect App Registrations" 30 440 180 35 ([System.Drawing.Color]::FromArgb(40, 167, 69)) {
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
                Update-GuiStatus "App registration data collected successfully! Found $($result.Count) apps." ([System.Drawing.Color]::Green)
            }
        }
        finally {
            $btnApps.Enabled = $true
            $btnApps.Text = $originalText
        }
    }
    $form.Controls.Add($btnApps)

    $btnConditionalAccess = New-GuiButton "Conditional Access" 220 440 180 35 ([System.Drawing.Color]::FromArgb(40, 167, 69)) {
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
                Update-GuiStatus "Conditional access data collected successfully! Found $($result.Count) policies." ([System.Drawing.Color]::Green)
            }
        }
        finally {
            $btnConditionalAccess.Enabled = $true
            $btnConditionalAccess.Text = $originalText
        }
    }
    $form.Controls.Add($btnConditionalAccess)

$btnETRAnalysis = New-GuiButton "Analyze ETR Files" 410 440 180 35 ([System.Drawing.Color]::FromArgb(75, 0, 130)) {
    # ETR analysis works with local CSV files only - no Graph connection required
    $btnETRAnalysis.Enabled = $false
    $originalText = $btnETRAnalysis.Text
    $btnETRAnalysis.Text = "Analyzing ETR..."
    
    try {
        # Get risky IPs from any existing sign-in analysis (optional correlation)
        $riskyIPs = @()
        $signInDataPath = Join-Path -Path $ConfigData.WorkDir -ChildPath "UserLocationData.csv"
        if (Test-Path $signInDataPath) {
            try {
                $signInData = Import-Csv -Path $signInDataPath
                $riskyIPs = $signInData | Where-Object { $_.IsUnusualLocation -eq "True" -and -not [string]::IsNullOrEmpty($_.IP) } | 
                           Select-Object -ExpandProperty IP -Unique
                Write-Log "Using $($riskyIPs.Count) risky IPs from previous sign-in analysis for ETR correlation" -Level "Info"
                Update-GuiStatus "Found previous sign-in data - will correlate with $($riskyIPs.Count) risky IPs" ([System.Drawing.Color]::Green)
            } catch {
                Write-Log "Could not load previous sign-in analysis for IP correlation: $($_.Exception.Message)" -Level "Warning"
                Update-GuiStatus "No previous sign-in data found - analyzing ETR patterns only" ([System.Drawing.Color]::Orange)
            }
        } else {
            Update-GuiStatus "No previous sign-in data found - analyzing ETR patterns only" ([System.Drawing.Color]::Orange)
        }
        
        $result = Analyze-ETRData -RiskyIPs $riskyIPs
        if ($result) {
            $criticalCount = ($result | Where-Object { $_.RiskLevel -eq "Critical" }).Count
            $highCount = ($result | Where-Object { $_.RiskLevel -eq "High" }).Count
            Update-GuiStatus "ETR analysis completed! Found $criticalCount critical and $highCount high-risk patterns." ([System.Drawing.Color]::Green)
            
            # Show summary of actionable findings
            if ($criticalCount -gt 0 -or $highCount -gt 0) {
                $actionableFindings = $result | Where-Object { $_.RiskLevel -in @("Critical", "High") -and -not [string]::IsNullOrEmpty($_.MessageIds) }
                if ($actionableFindings.Count -gt 0) {
                    $message = "ETR Analysis Complete!`n`n" +
                              "Critical Risks: $criticalCount`n" +
                              "High Risks: $highCount`n`n" +
                              "Actionable findings with Message IDs: $($actionableFindings.Count)`n`n" +
                              "Check the MessageRecallReport.csv for specific Message IDs to recall."
                    [System.Windows.Forms.MessageBox]::Show($message, "ETR Analysis Results", "OK", "Information")
                }
            }
        } else {
            Update-GuiStatus "ETR analysis completed but found no suspicious patterns" ([System.Drawing.Color]::Green)
        }
    }
    catch {
        Update-GuiStatus "ETR analysis error: $($_.Exception.Message)" ([System.Drawing.Color]::Red)
        [System.Windows.Forms.MessageBox]::Show("ETR analysis error: $($_.Exception.Message)", "ETR Analysis Error", "OK", "Error")
    }
    finally {
        $btnETRAnalysis.Enabled = $true
        $btnETRAnalysis.Text = $originalText
    }
}

$form.Controls.Add($btnETRAnalysis)

$btnMessageTrace = New-GuiButton "Collect Message Trace" 600 440 180 35 ([System.Drawing.Color]::FromArgb(75, 0, 130)) {
    $btnMessageTrace.Enabled = $false
    $originalText = $btnMessageTrace.Text
    $btnMessageTrace.Text = "Running Trace..."
    
    try {
        $result = Get-MessageTraceExchangeOnline
        if ($result) {
            Update-GuiStatus "Message trace collected successfully! Processed $($result.Count) messages in ETR format." ([System.Drawing.Color]::Green)
            
            # Suggest running ETR analysis next
            $runAnalysis = [System.Windows.Forms.MessageBox]::Show(
                "Message trace collection complete!`n`n$($result.Count) messages saved in ETR-compatible format.`n`nRun ETR analysis now to detect spam patterns?",
                "Run Analysis?",
                "YesNo",
                "Question"
            )
            
            if ($runAnalysis -eq "Yes") {
                # Get risky IPs from sign-in data if available
                $riskyIPs = @()
                $signInDataPath = Join-Path -Path $ConfigData.WorkDir -ChildPath "UserLocationData.csv"
                if (Test-Path $signInDataPath) {
                    try {
                        $signInData = Import-Csv -Path $signInDataPath
                        $riskyIPs = $signInData | Where-Object { $_.IsUnusualLocation -eq "True" -and -not [string]::IsNullOrEmpty($_.IP) } | 
                                   Select-Object -ExpandProperty IP -Unique
                    } catch { }
                }
                
                # Run your existing ETR analysis
                $etrResult = Analyze-ETRData -RiskyIPs $riskyIPs
                if ($etrResult) {
                    Update-GuiStatus "ETR analysis completed on message trace data!" ([System.Drawing.Color]::Green)
                }
            }
        } else {
            Update-GuiStatus "Message trace completed but no data returned" ([System.Drawing.Color]::Orange)
        }
    }
    catch {
        Update-GuiStatus "Message trace error: $($_.Exception.Message)" ([System.Drawing.Color]::Red)
        [System.Windows.Forms.MessageBox]::Show("Message trace error: $($_.Exception.Message)", "Message Trace Error", "OK", "Error")
    }
    finally {
        $btnMessageTrace.Enabled = $true
        $btnMessageTrace.Text = $originalText
    }
}
$form.Controls.Add($btnMessageTrace)

# Then continue with your existing Row 4 buttons (Run All, Analyze Data, etc.)

    # Row 4 - Bulk operations
    $btnRunAll = New-GuiButton "Run All Data Collection" 30 500 280 45 ([System.Drawing.Color]::FromArgb(255, 193, 7)) {
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
            @{Name="Delegations"; Function="Get-MailboxDelegationData"},
            @{Name="App Registrations"; Function="Get-AppRegistrationData"},
            @{Name="Conditional Access"; Function="Get-ConditionalAccessData"}
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
                    "Get-MailboxDelegationData" { Get-MailboxDelegationData | Out-Null }
                    "Get-AppRegistrationData" { Get-AppRegistrationData | Out-Null }
                    "Get-ConditionalAccessData" { Get-ConditionalAccessData | Out-Null }
					"Analyze-ETRData" { Analyze-ETRData | Out-Null }
                }
                $completed++
                Update-GuiStatus "Completed: $($task.Name) ($completed/$($tasks.Count))" ([System.Drawing.Color]::Green)
            }
            catch {
                Write-Log "Error in $($task.Name) collection: $($_.Exception.Message)" -Level "Error"
                Update-GuiStatus "Error in $($task.Name): $($_.Exception.Message)" ([System.Drawing.Color]::Red)
            }
        }
        
        $btnRunAll.Enabled = $true
        $btnRunAll.Text = $originalText
        Update-GuiStatus "Data collection completed! Finished $completed of $($tasks.Count) tasks successfully." ([System.Drawing.Color]::Green)
        [System.Windows.Forms.MessageBox]::Show("Data collection completed!`n`nFinished $completed out of $($tasks.Count) tasks successfully.", "Collection Complete", "OK", "Information")
    }
    $form.Controls.Add($btnRunAll)

    $btnAnalyze = New-GuiButton "Analyze Data" 330 500 150 45 ([System.Drawing.Color]::FromArgb(220, 53, 69)) {
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
                
                Update-GuiStatus "Analysis completed - $critical critical, $high high, $medium medium risk users found" ([System.Drawing.Color]::Green)
                
                $message = "Security Analysis Completed!`n`nRisk Summary:`n• Critical Risk: $critical users`n• High Risk: $high users`n• Medium Risk: $medium users`n`nTotal Users Analyzed: $($results.Count)`n`nOpen the detailed HTML report now?"
                $result = [System.Windows.Forms.MessageBox]::Show($message, "Analysis Complete", "YesNo", "Information")
                
                if ($result -eq "Yes") {
                    Start-Process $reportPath
                }
            } else {
                Update-GuiStatus "Analysis failed - no data available for analysis" ([System.Drawing.Color]::Red)
                [System.Windows.Forms.MessageBox]::Show("Analysis failed or no data available.`n`nPlease ensure you have collected data first by running the data collection tasks.", "Analysis Failed", "OK", "Warning")
            }
        }
        catch {
            Update-GuiStatus "Analysis error: $($_.Exception.Message)" ([System.Drawing.Color]::Red)
            [System.Windows.Forms.MessageBox]::Show("Analysis error: $($_.Exception.Message)", "Analysis Error", "OK", "Error")
        }
        finally {
            $btnAnalyze.Enabled = $true
            $btnAnalyze.Text = $originalText
        }
    }
    $form.Controls.Add($btnAnalyze)

    $btnViewReports = New-GuiButton "View Reports" 500 500 140 45 ([System.Drawing.Color]::FromArgb(102, 16, 242)) {
        Update-GuiStatus "Looking for reports in working directory..." ([System.Drawing.Color]::Orange)
        
        $reports = Get-ChildItem -Path $ConfigData.WorkDir -Filter "*.html" -ErrorAction SilentlyContinue
        
        if ($reports.Count -eq 0) {
            Update-GuiStatus "No reports found in working directory" ([System.Drawing.Color]::Orange)
            [System.Windows.Forms.MessageBox]::Show("No HTML reports found in the working directory:`n$($ConfigData.WorkDir)`n`nPlease run the analysis first to generate reports.", "No Reports Found", "OK", "Information")
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
                $listBox.Items.Add($item)
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

    # Exit button
    $btnExit = New-GuiButton "Exit Application" 660 500 120 45 ([System.Drawing.Color]::FromArgb(108, 117, 125)) {
        $result = [System.Windows.Forms.MessageBox]::Show("Are you sure you want to exit the application?`n`nThis will disconnect from Microsoft Graph and close the tool.", "Confirm Exit", "YesNo", "Question")
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


    # Enhanced form cleanup with better error handling
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

    # Handle unexpected application termination
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

    # Update connection status on form load
    $form.Add_Shown({
        # Check for existing connection when GUI loads
        Test-ExistingGraphConnection | Out-Null
        Update-ConnectionStatus
        
        if ($Global:ConnectionState.IsConnected) {
            Update-GuiStatus "Application ready - Using existing Microsoft Graph connection" ([System.Drawing.Color]::Green)
        } else {
            Update-GuiStatus "Application ready - Please connect to Microsoft Graph to begin" ([System.Drawing.Color]::Orange)
        }
    })

    # Show the form
    [void]$form.ShowDialog()
}

#endregion

#region Main Script

# Initialize environment
Initialize-Environment

Write-Log "Starting Enhanced Microsoft 365 Security Analysis Tool v$ScriptVer" -Level "Info"
Write-Log "Enhanced features: Improved sign-in processing, detailed GUI progress, clean Graph disconnection, tenant context display" -Level "Info"

# Display main GUI
Show-MainGUI

# Final cleanup before exit
Write-Log "Performing final cleanup..." -Level "Info"

# Ensure clean disconnect
try {
    if ($Global:ConnectionState.IsConnected -or (Get-MgContext -ErrorAction SilentlyContinue)) {
        Write-Log "Final disconnect from Microsoft Graph" -Level "Info"
        Disconnect-MgGraph -ErrorAction SilentlyContinue
    }
}
catch {
    Write-Log "Final cleanup warning: $($_.Exception.Message)" -Level "Warning"
}

# Stop transcript
try {
    Stop-Transcript -ErrorAction SilentlyContinue
    Write-Host "Script execution completed. Log file saved to working directory." -ForegroundColor Green
}
catch {
    Write-Host "Script execution completed." -ForegroundColor Green
}

Write-Host "Thank you for using the Enhanced Microsoft 365 Security Analysis Tool!" -ForegroundColor Cyan

#endregion