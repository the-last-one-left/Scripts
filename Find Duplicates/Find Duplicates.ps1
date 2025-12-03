#Grabs a folder path
function Get-Folder($initialDirectory="") {
    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms")|Out-Null
    $foldername = New-Object System.Windows.Forms.FolderBrowserDialog
    $foldername.Description = "Select a working folder for logs"
    $foldername.rootfolder = "MyComputer"
    $foldername.SelectedPath = $initialDirectory
    if($foldername.ShowDialog() -eq "OK")
    {
        $folder += $foldername.SelectedPath
    }
    return $folder
}

#Saves a file
Function Save-File ([string]$initialDirectory) {
    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
    
    $OpenFileDialog = New-Object System.Windows.Forms.SaveFileDialog
    $OpenFileDialog.filter = "CSV (*.csv)| *.csv"
    $OpenFileDialog.ShowDialog() | Out-Null

    return $OpenFileDialog.filename
}

#Courtesy of Joshua Honig (https://social.technet.microsoft.com/profile/joshua%20honig) - directly stolen from his Technet Post
function Blink-Message {
 param([String]$Message,[int]$Delay,[int]$Count,[ConsoleColor[]]$Colors) 
    $startColor = [Console]::ForegroundColor
    $startLeft  = [Console]::CursorLeft
    $startTop   = [Console]::CursorTop
    $colorCount = $Colors.Length
    for($i = 0; $i -lt $Count; $i++) {
        [Console]::CursorLeft = $startLeft
        [Console]::CursorTop  = $startTop
        [Console]::ForegroundColor = $Colors[$($i % $colorCount)]
        [Console]::WriteLine($Message)
        Start-Sleep -Milliseconds $Delay
    }
    [Console]::ForegroundColor = $startColor
}

Clear
Blink-Message "This script will ask you for a location to search for duplicate files, display them and allow you to save a csv report"  250 10 Red, White, DarkRed, Green
Pause



$Path = Get-Folder

$group = Get-ChildItem -Path $Path -File -Recurse -ErrorAction Ignore |
    Where-Object Length -gt 0 |
    Group-Object -Property Length -AsHashTable 
    
$candidates = foreach($pile in $group.Values)
{
    if ($pile.Count -gt 1)
    {
        $pile
    }
}
    
$candidates

$SaveMyFile = Save-File
$candidates | Export-Csv -Path $SaveMyFile -NoTypeInformation