# Find Duplicates

## Overview
Interactive PowerShell script that scans a selected directory for duplicate files based on file size and exports results to CSV format.

## Purpose
Identifies potential duplicate files in large directory structures to help with storage cleanup, file management, and data deduplication efforts.

## Requirements
- Windows operating system
- PowerShell 5.0 or later
- .NET Framework (for Windows Forms dialogs)

## Features
- Interactive folder selection via GUI dialog
- Recursive scanning of selected directory
- Groups files by size to identify potential duplicates
- Ignores zero-byte files
- Visual blinking message notification
- CSV export with save dialog
- Detailed results displayed in console

## Usage
```powershell
.\Find Duplicates.ps1
```

## How It Works
1. Displays animated warning message about script functionality
2. Prompts user to select a directory to scan
3. Recursively scans all files in selected directory
4. Groups files by size (only sizes with multiple files are candidates)
5. Displays results in PowerShell console
6. Prompts user to save results as CSV file

## Detection Method
The script identifies potential duplicates by:
- Grouping files by **file size only**
- Filtering out zero-byte files
- Identifying groups where 2+ files have identical size

**Important**: This script uses file size as the primary indicator of duplicates. Files with the same size are not necessarily identical. For true duplicate detection, consider hash comparison as a follow-up step.

## Output Format
CSV export includes standard `Get-ChildItem` file properties:
- FullName (full path)
- Length (file size)
- LastWriteTime
- CreationTime
- Attributes
- Directory
- Name
- Extension

## GUI Features
- Folder browser dialog for directory selection
- File save dialog for CSV export location
- Colored blinking message using console manipulation

## Notes
- Performance scales with directory size and file count
- Large directory structures may take significant time to scan
- The script continues even if individual files cannot be accessed (uses `-ErrorAction Ignore`)
- Results are grouped by file size, not by content hash

## Use Cases
- Pre-cleanup analysis before storage optimization
- Identifying backup file duplicates
- File server maintenance
- Data migration preparation

## Limitations
- Size-based detection only (not content-based)
- Does not automatically verify files are true duplicates
- Requires manual review of results
- Does not provide deletion functionality

## Author
Pacific Office Automation - Problem Solved

Credits: Blink-Message function courtesy of Joshua Honig
