# Grabs Sharepoint Permissions for all sites and saves them to CSV - checks for folders with unique permissions
#
# For the Admin URL use the url from the sharepoint admin center ie: https://contoso-admin.sharepoint.com/
#
# Requires PNPOnline Module 

# Function to check and install PnP.Powershell module if not already installed

# Function to check the PowerShell version

Clear
Write-Host "This script will grab all the Sharepoint Permissions for all sites and save them to CSV to a path you choose"
Write-Host "for the Admin URL use the url from the sharepoint admin center ie: https://contoso-admin.sharepoint.com/"
Write-Host "Requires PNPOnline Module"
Pause


Function Ensure-PowerShellVersion {
    $version = $PSVersionTable.PSVersion
    if ($version.Major -lt 7) {
        Write-Host "This script requires PowerShell 7 or later. Current version: $($version)"
        Pause
        exit
    }
    else {
        Write-Host "Running on PowerShell version: $($version)"
    }
}

# Ensure it's running in PowerShell greater than 7
Ensure-PowerShellVersion

Function Ensure-Module {
    param (
        [string]$ModuleName,
        [string]$MinVersion = "1.0.0"
    )
    
    if (-Not (Get-Module -ListAvailable -Name $ModuleName -ErrorAction SilentlyContinue)) {
        Write-Host "Module $ModuleName not found. Installing..."
        Install-Module -Name $ModuleName -MinimumVersion $MinVersion -Force -AllowClobber
    } else {
        Write-Host "Module $ModuleName is already installed."
    }
    Import-Module $ModuleName -MinimumVersion $MinVersion -Force
}

# Ensure PnP.Powershell module is available
Ensure-Module -ModuleName "PnP.PowerShell" -MinVersion "1.0.0"


Add-Type -AssemblyName System.Windows.Forms

# Function for creating input dialog box
Function Show-InputDialog {
    param (
        [string]$Message,
        [string]$Title
    )
    
    $form = New-Object Windows.Forms.Form
    $form.Text = $Title
    $form.Width = 400
    $form.Height = 200

    $label = New-Object Windows.Forms.Label
    $label.Text = $Message
    $label.AutoSize = $true
    $label.Left = 10
    $label.Top = 20
    $form.Controls.Add($label)

    $textbox = New-Object Windows.Forms.TextBox
    $textbox.Left = 10
    $textbox.Top = 50
    $textbox.Width = 360
    $form.Controls.Add($textbox)

    $okButton = New-Object Windows.Forms.Button
    $okButton.Text = "OK"
    $okButton.Left = 296
    $okButton.Top = 120
    $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.AcceptButton = $okButton
    $form.Controls.Add($okButton)

    $form.StartPosition = "CenterScreen"
    $form.Topmost = $true
    $dialogResult = $form.ShowDialog()

    if ($dialogResult -eq [System.Windows.Forms.DialogResult]::OK) {
        return $textbox.Text
    } else {
        return $null
    }
}

# Prompt to enter the Tenant Admin URL
$TenantAdminURL = Show-InputDialog -Message "Enter the Tenant Admin URL:" -Title "Tenant Admin URL"

# Prompt for the root directory for the report files
$ReportRootDirectory = Show-InputDialog -Message "Enter the root directory for the report files:" -Title "Report Root Directory"

if ($TenantAdminURL -ne $null -and $TenantAdminURL -ne "" -and $ReportRootDirectory -ne $null -and $ReportRootDirectory -ne "") {
    # Function to Get Permissions Applied on a particular Object, such as: Web, List, or Folder
    Function Get-PnPPermissions([Microsoft.SharePoint.Client.SecurableObject]$Object) {
        Switch ($Object.TypedObject.ToString()) {
            "Microsoft.SharePoint.Client.Web" {
                $ObjectType = "Site"
                $ObjectURL = $Object.URL
                $ObjectTitle = $Object.Title
            }
            "Microsoft.SharePoint.Client.ListItem" {
                $ObjectType = "Folder"
                $Folder = Get-PnPProperty -ClientObject $Object -Property Folder
                $ObjectTitle = $Object.Folder.Name
                $ObjectURL = $("{0}{1}" -f $Web.Url.Replace($Web.ServerRelativeUrl, ''), $Object.Folder.ServerRelativeUrl)
            }
            Default {
                $ObjectType = $Object.BaseType
                $ObjectTitle = $Object.Title
                $RootFolder = Get-PnPProperty -ClientObject $Object -Property RootFolder
                $ObjectURL = $("{0}{1}" -f $Web.Url.Replace($Web.ServerRelativeUrl, ''), $RootFolder.ServerRelativeUrl)
            }
        }

        Get-PnPProperty -ClientObject $Object -Property HasUniqueRoleAssignments, RoleAssignments
        $HasUniquePermissions = $Object.HasUniqueRoleAssignments
        $PermissionCollection = @()
        Foreach ($RoleAssignment in $Object.RoleAssignments) {
            Get-PnPProperty -ClientObject $RoleAssignment -Property RoleDefinitionBindings, Member
            $PermissionType = $RoleAssignment.Member.PrincipalType
            $PermissionLevels = $RoleAssignment.RoleDefinitionBindings | Select -ExpandProperty Name
            $PermissionLevels = ($PermissionLevels | Where { $_ -ne "Limited Access" }) -join "; "
            If ($PermissionLevels.Length -eq 0) { Continue }

            If ($PermissionType -eq "SharePointGroup") {
                $GroupMembers = Get-PnPGroupMember -Identity $RoleAssignment.Member.LoginName
                If ($GroupMembers.count -eq 0) { Continue }
                $GroupUsers = ($GroupMembers | Select -ExpandProperty Title | Where { $_ -ne "System Account" }) -join "; "
                If ($GroupUsers.Length -eq 0) { Continue }

                $Permissions = New-Object PSObject
                $Permissions | Add-Member NoteProperty Object($ObjectType)
                $Permissions | Add-Member NoteProperty Title($ObjectTitle)
                $Permissions | Add-Member NoteProperty URL($ObjectURL)
                $Permissions | Add-Member NoteProperty HasUniquePermissions($HasUniquePermissions)
                $Permissions | Add-Member NoteProperty Users($GroupUsers)
                $Permissions | Add-Member NoteProperty Type($PermissionType)
                $Permissions | Add-Member NoteProperty Permissions($PermissionLevels)
                $Permissions | Add-Member NoteProperty GrantedThrough("SharePoint Group: $($RoleAssignment.Member.LoginName)")
                $PermissionCollection += $Permissions
            } else {
                $Permissions = New-Object PSObject
                $Permissions | Add-Member NoteProperty Object($ObjectType)
                $Permissions | Add-Member NoteProperty Title($ObjectTitle)
                $Permissions | Add-Member NoteProperty URL($ObjectURL)
                $Permissions | Add-Member NoteProperty HasUniquePermissions($HasUniquePermissions)
                $Permissions | Add-Member NoteProperty Users($RoleAssignment.Member.Title)
                $Permissions | Add-Member NoteProperty Type($PermissionType)
                $Permissions | Add-Member NoteProperty Permissions($PermissionLevels)
                $Permissions | Add-Member NoteProperty GrantedThrough("Direct Permissions")
                $PermissionCollection += $Permissions
            }
        }
        $PermissionCollection | Export-CSV $ReportFile -NoTypeInformation -Append
    }

    # Function to generate SharePoint Online site permissions report
    Function Generate-PnPSitePermissionRpt() {
        [cmdletbinding()]
        Param (
            [Parameter(Mandatory=$false)] [String] $SiteURL,
            [Parameter(Mandatory=$false)] [String] $ReportFile,        
            [Parameter(Mandatory=$false)] [switch] $Recursive,
            [Parameter(Mandatory=$false)] [switch] $ScanFolders,
            [Parameter(Mandatory=$false)] [switch] $IncludeInheritedPermissions
        )

        Try {
            Connect-PnPOnline -URL $SiteURL -Interactive
            $Web = Get-PnPWeb

            Write-host -f Yellow "Getting Site Collection Administrators..."
            $SiteAdmins = Get-PnPSiteCollectionAdmin
            $SiteCollectionAdmins = ($SiteAdmins | Select -ExpandProperty Title) -join "; "

            $Permissions = New-Object PSObject
            $Permissions | Add-Member NoteProperty Object("Site Collection")
            $Permissions | Add-Member NoteProperty Title($Web.Title)
            $Permissions | Add-Member NoteProperty URL($Web.URL)
            $Permissions | Add-Member NoteProperty HasUniquePermissions("TRUE")
            $Permissions | Add-Member NoteProperty Users($SiteCollectionAdmins)
            $Permissions | Add-Member NoteProperty Type("Site Collection Administrators")
            $Permissions | Add-Member NoteProperty Permissions("Site Owner")
            $Permissions | Add-Member NoteProperty GrantedThrough("Direct Permissions")

            $Permissions | Export-CSV $ReportFile -NoTypeInformation

            Function Get-PnPFolderPermission([Microsoft.SharePoint.Client.List]$List) {
                Write-host -f Yellow "`t `t Getting Permissions of Folders in the List:" $List.Title
                $ListItems = Get-PnPListItem -List $List -PageSize 2000
                $Folders = $ListItems | Where { ($_.FileSystemObjectType -eq "Folder") -and ($_.FieldValues.FileLeafRef -ne "Forms") -and (-Not($_.FieldValues.FileLeafRef.StartsWith("_")))}

                $ItemCounter = 0
                ForEach ($Folder in $Folders) {
                    If ($IncludeInheritedPermissions) {
                        Get-PnPPermissions -Object $Folder
                    } else {
                        $HasUniquePermissions = Get-PnPProperty -ClientObject $Folder -Property HasUniqueRoleAssignments
                        If ($HasUniquePermissions -eq $True) {
                            Get-PnPPermissions -Object $Folder
                        }
                    }
                    $ItemCounter++
                    Write-Progress -PercentComplete ($ItemCounter / ($Folders.Count) * 100) -Activity "Getting Permissions of Folders in List '$($List.Title)'" -Status "Processing Folder '$($Folder.FieldValues.FileLeafRef)' at '$($Folder.FieldValues.FileRef)' ($ItemCounter of $($Folders.Count))" -Id 2 -ParentId 1
                }
            }

            Function Get-PnPListPermission([Microsoft.SharePoint.Client.Web]$Web) {
                $Lists = Get-PnPProperty -ClientObject $Web -Property Lists
                $ExcludedLists = @("Access Requests","App Packages","appdata","appfiles","Apps in Testing","Cache Profiles","Composed Looks","Content and Structure Reports","Content type publishing error log","Converted Forms",
                "Device Channels","Form Templates","fpdatasources","Get started with Apps for Office and SharePoint","List Template Gallery","Long Running Operation Status","Maintenance Log Library", "Images", "site collection images"
                ,"Master Docs","Master Page Gallery","MicroFeed","NintexFormXml","Quick Deploy Items","Relationships List","Reusable Content","Reporting Metadata", "Reporting Templates", "Search Config List","Site Assets","Preservation Hold Library",
                "Site Pages", "Solution Gallery","Style Library","Suggested Content Browser Locations","Theme Gallery", "TaxonomyHiddenList","User Information List","Web Part Gallery","wfpub","wfsvc","Workflow History","Workflow Tasks", "Pages")

                $Counter = 0
                ForEach ($List in $Lists) {
                    If ($List.Hidden -eq $False -and $ExcludedLists -notcontains $List.Title) {
                        $Counter++
                        Write-Progress -PercentComplete ($Counter / ($Lists.Count) * 100) -Activity "Exporting Permissions from List '$($List.Title)' in $($Web.URL)" -Status "Processing Lists $Counter of $($Lists.Count)" -Id 1

                        If ($ScanFolders) {
                            Get-PnPFolderPermission -List $List
                        }

                        If ($IncludeInheritedPermissions) {
                            Get-PnPPermissions -Object $List
                        } else {
                            $HasUniquePermissions = Get-PnPProperty -ClientObject $List -Property HasUniqueRoleAssignments
                            If ($HasUniquePermissions -eq $True) {
                                Get-PnPPermissions -Object $List
                            }
                        }
                    }
                }
            }

            Function Get-PnPWebPermission([Microsoft.SharePoint.Client.Web]$Web) {
                Write-host -f Yellow "Getting Permissions of the Web: $($Web.URL)..."
                Get-PnPPermissions -Object $Web
                Write-host -f Yellow "`t Getting Permissions of Lists and Libraries..."
                Get-PnPListPermission($Web)

                If ($Recursive) {
                    $Subwebs = Get-PnPProperty -ClientObject $Web -Property Webs
                    ForEach ($Subweb in $web.Webs) {
                        If ($IncludeInheritedPermissions) {
                            Get-PnPWebPermission($Subweb)
                        } else {
                            $HasUniquePermissions = Get-PnPProperty -ClientObject $SubWeb -Property HasUniqueRoleAssignments
                            If ($HasUniquePermissions -eq $true) {
                                Get-PnPWebPermission($Subweb)
                            }
                        }
                    }
                }
            }

            Get-PnPWebPermission $Web
            Write-host -f Green "`n*** Site Permission Report Generated Successfully!***"
        } Catch {
            write-host -f Red "Error Generating Site Permission Report!" $_.Exception.Message
        }
    }

    # Connecting to Admin Center using the provided URL
    Connect-PnPOnline -Url $TenantAdminURL -interactive

    # Get all site collections excluding specific templates
    $SitesCollections = Get-PnPTenantSite | Where -Property Template -NotIn ("SRCHCEN#0","REDIRECTSITE#0", "SPSMSITEHOST#0", "APPCATALOG#0", "POINTPUBLISHINGHUB#0", "EDISC#0", "STS#-1")

    # Loop through each site collection
    ForEach ($Site in $SitesCollections) {
        # Connect to site collection
        $SiteConn = Connect-PnPOnline -Url $Site.Url -interactive
        Write-host "Generating Report for Site:" $Site.Url

        # Call the function for site collection
        $ReportFile = "$ReportRootDirectory\$($Site.URL.Replace('https://','').Replace('/','_')).CSV"
        Generate-PnPSitePermissionRpt -SiteURL $Site.URL -ReportFile $ReportFile -Recursive -ScanFolders
    }
} else {
    Write-Host "Operation canceled by user."
}