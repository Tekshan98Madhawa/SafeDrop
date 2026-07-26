# SafeDrop — External Download Safety Checker for IT Teams

A lightweight PowerShell toolkit that helps IT teams control, check, and audit external file downloads before they reach users' machines.

## The Problem
Most companies have no structured process for external file downloads. Files arrive via email links, WeTransfer, Dropbox, and other platforms — and staff open them without any checks. One malicious file is all it takes.

## What SafeDrop Does
- Checks files and URLs against 70+ antivirus engines via VirusTotal
- Detects high-risk file types, shortened URLs, and suspicious patterns locally
- Provides a structured approval workflow — staff request, IT approves
- Logs all activity to CSV for audit and reporting
- Generates a dashboard summary for IT managers

## Scripts

| Script | Purpose | Who Uses It |
|---|---|---|
| `Invoke-SafeDropCheck.ps1` | Check a file or URL | IT staff |
| `Submit-DownloadRequest.ps1` | Request download approval | All staff |
| `Approve-DownloadRequest.ps1` | Approve or reject requests | IT staff |
| `Get-SafeDropDashboard.ps1` | View activity summary | IT manager |

## Setup

1. Clone or download this repository
2. Add your VirusTotal API key to `config.txt` (free at virustotal.com)
3. Run scripts with PowerShell

```powershell
# Allow scripts to run (one time)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

## Usage Examples

```powershell
# Check a file
.\Invoke-SafeDropCheck.ps1 -FilePath "C:\Downloads\report.zip" -ExportLog

# Check a URL
.\Invoke-SafeDropCheck.ps1 -URL "https://we.tl/t-xxxxx" -ExportLog

# Submit a download request (staff)
.\Submit-DownloadRequest.ps1

# Review pending requests (IT)
.\Approve-DownloadRequest.ps1

# View dashboard (last 30 days)
.\Get-SafeDropDashboard.ps1

# View dashboard (last 7 days)
.\Get-SafeDropDashboard.ps1 -Days 7
```

## Folder Structure

```
SafeDrop/
    ├── Invoke-SafeDropCheck.ps1
    ├── Submit-DownloadRequest.ps1
    ├── Approve-DownloadRequest.ps1
    ├── Get-SafeDropDashboard.ps1
    ├── config.txt
    ├── README.md
    └── Logs/
        ├── SafeDropLog_YYYYMMDD.csv
        └── DownloadRequests.csv
```

## Requirements
- Windows PowerShell 5.0+
- VirusTotal free API key (optional but recommended)

## Author
Built by an IT Support professional to solve a real operational gap in external file intake management.

---
*SafeDrop is an open source personal project.*
