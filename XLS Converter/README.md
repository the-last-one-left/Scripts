# XLS to XLSX Converter

## Overview
PowerShell script that batch converts legacy Excel files (.xls) to modern Excel format (.xlsx) using Microsoft Excel COM automation.

## Purpose
Converts older Excel 97-2003 format files (.xls) to modern Office Open XML format (.xlsx) for improved compatibility, reduced file size, and better integration with modern Office 365 environments.

## Requirements
- Microsoft Excel must be installed on the system
- PowerShell 5.0 or later
- Sufficient disk space for converted files
- Administrative privileges recommended

## Features
- Batch conversion of all .xls files in target directory
- Recursive scanning of subdirectories
- Automatic creation of "converted" folder for original files
- Visible Excel instance for monitoring (debugging/verification)
- Progress messages during conversion
- Automatic resource cleanup

## Usage
```powershell
.\XLS.ps1
```

## Configuration
Default configuration:
- **Source Directory**: `C:\Temp\*`
- **File Pattern**: `*xls`
- **Output Format**: `.xlsx` (OpenXML Workbook)
- **Archive Folder**: `converted` (created in source directory)

## Process Flow
1. Changes directory to `C:\Temp`
2. Opens Excel application (visible instance)
3. Recursively scans for .xls files
4. For each .xls file:
   - Opens the workbook
   - Saves as .xlsx format
   - Closes the workbook
   - Creates "converted" folder if needed
   - Moves original .xls file to "converted" folder

## File Handling
- **Original files**: Moved to `.\converted\` subdirectory
- **New files**: Saved in original location with .xlsx extension
- **Naming**: Maintains original filename (only extension changes)

## Technical Details

### Excel COM Automation
```powershell
$excel = New-Object -ComObject excel.application
$excel.visible = $true  # Shows Excel window during conversion
```

### File Format
Uses `xlOpenXMLWorkbook` format (Excel 2007-2019 .xlsx format)

### Resource Management
- Proper Excel COM object disposal
- Garbage collection invoked
- Waits for pending finalizers to prevent file locks

## Common Use Cases
- Migrating legacy file shares to modern formats
- Office 365 migration preparation
- Compliance with document format policies
- Improving file compatibility across systems
- Reducing storage usage (xlsx is compressed)

## Benefits of XLSX Format
- Smaller file sizes (zip compression)
- Better corruption recovery
- Increased row/column limits (1M rows vs 65K)
- Modern Office 365 compatibility
- Improved performance in Excel Online
- Better XML structure for automation

## Limitations
- Requires Excel installation (not Excel-free)
- Single-threaded processing (processes files one at a time)
- Excel must be able to open and save the file
- No error handling for corrupted files
- No conversion validation
- Hard-coded to C:\Temp directory

## Customization Options

### Change Source Directory
```powershell
$folderpath = "D:\YourPath\*"
```

### Change File Pattern
```powershell
$filetype = "*xls"  # Default
$filetype = "Report*.xls"  # Only files starting with "Report"
```

### Hide Excel Window
```powershell
$excel.visible = $false  # Faster, no GUI
```

### Different Output Format
```powershell
# For macro-enabled workbooks
$xlFixedFormat = [Microsoft.Office.Interop.Excel.XlFileFormat]::xlOpenXMLWorkbookMacroEnabled
```

## Performance Considerations
- Processing time depends on file size and complexity
- Large files (10MB+) may take several seconds each
- Excel window visibility impacts performance (hidden is faster)
- Network drives significantly slower than local storage

### Estimated Processing Times
- Small files (<1MB): 2-3 seconds each
- Medium files (1-10MB): 5-10 seconds each
- Large files (10MB+): 15-30 seconds each

## Error Scenarios

### Excel Not Installed
Script will fail with COM object creation error. Excel must be installed.

### File In Use
If Excel workbook is already open, conversion will fail or display prompt.

### Password Protected Files
Password-protected files will prompt for password and may hang the script.

### Corrupted Files
Corrupted .xls files may cause Excel to hang or crash.

## Best Practices
1. **Test on Sample First**: Test with a few files before batch processing
2. **Backup Original Files**: Keep a copy before conversion
3. **Close Excel First**: Ensure no Excel instances are running
4. **Run During Off-Hours**: Processing may lock Excel for extended periods
5. **Monitor First Run**: Watch for password prompts or errors
6. **Check Disk Space**: Ensure adequate space for converted files

## Enhanced Error Handling (Recommended Addition)
Consider adding try-catch blocks for production use:
```powershell
try {
    $workbook = $excel.workbooks.open($_.fullname)
    $workbook.saveas($path, $xlFixedFormat)
    $workbook.close()
} catch {
    Write-Warning "Failed to convert: $($_.fullname) - $($_.Exception.Message)"
}
```

## Troubleshooting

### Excel Won't Close
- Check Task Manager for lingering EXCEL.EXE processes
- Manually kill processes if needed
- Reboot if COM objects are locked

### Converted Folder Not Created
- Verify write permissions to source directory
- Check if folder already exists with files

### Files Not Converting
- Verify Excel can manually open the files
- Check for password protection
- Review file corruption

### Performance Issues
- Set `$excel.visible = $false` for headless operation
- Process smaller batches
- Use local drives instead of network paths

## Alternative Approaches
For environments without Excel:
- **EPPlus**: .NET library for Excel manipulation
- **ClosedXML**: Another .NET Excel library
- **LibreOffice**: Command-line conversion
- **Cloud conversion services**: Microsoft Graph API

## Security Notes
- Macros in .xls files are not preserved in standard .xlsx
- Use .xlsm format to preserve macros if needed
- Review security settings before converting sensitive files
- Disable automatic macro execution during batch conversion

## Post-Conversion Validation
Recommended checks after conversion:
1. Verify file count matches
2. Spot-check converted files in Excel
3. Compare file sizes (xlsx should be smaller)
4. Test formulas and calculations
5. Review any data validation rules
6. Check for missing VBA macros (if applicable)

## Cleanup
After successful conversion:
- Review files in "converted" folder
- Delete archived .xls files if no longer needed
- Document conversion for change management

## Author
Pacific Office Automation - Problem Solved
