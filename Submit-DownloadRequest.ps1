<#
.SYNOPSIS
    SafeDrop - Submit a Download Request for IT Approval
.DESCRIPTION
    Staff use this script to submit a download request before
    downloading any external file. IT reviews and approves or rejects.
.EXAMPLE
    .\Submit-DownloadRequest.ps1
.NOTES
    Tool    : SafeDrop
    Version : 1.0
    GitHub  : https://github.com/yourusername/SafeDrop
#>

Write-Host ""
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "   SafeDrop - Download Request Submission" -ForegroundColor Cyan
Write-Host "   $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Fill in the details below. IT will review your request." -ForegroundColor White
Write-Host ""

# Collect request details
$requestor  = $env:USERNAME
$fileName   = Read-Host "  File name (e.g. report.zip)"
$sourceURL  = Read-Host "  Source URL (where you're downloading from)"
$reason     = Read-Host "  Business reason for this download"
$department = Read-Host "  Your department (e.g. Finance, HR, Operations)"

if (-not $fileName -or -not $sourceURL -or -not $reason -or -not $department) {
    Write-Host ""
    Write-Host "  All fields are required. Request not submitted." -ForegroundColor Red
    exit
}

# Build request entry
$requestID = "REQ-$(Get-Date -Format 'yyyyMMddHHmmss')-$requestor"
$entry = [PSCustomObject]@{
    RequestID  = $requestID
    Time       = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    Requestor  = $requestor
    Department = $department
    FileName   = $fileName
    SourceURL  = $sourceURL
    Reason     = $reason
    Status     = 'PENDING'
    ReviewedBy = ''
    ReviewNote = ''
    ReviewTime = ''
}

# Save to requests log
$logDir = Join-Path $PSScriptRoot "Logs"
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
$logPath = Join-Path $logDir "DownloadRequests.csv"
$entry | Export-Csv -Path $logPath -NoTypeInformation -Append

Write-Host ""
Write-Host "  -------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "  Request submitted successfully." -ForegroundColor Green
Write-Host "  Request ID : $requestID" -ForegroundColor Cyan
Write-Host "  Status     : PENDING - Awaiting IT approval" -ForegroundColor Yellow
Write-Host "  -------------------------------------------------------" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  Do NOT download the file until IT approves your request." -ForegroundColor Yellow
Write-Host ""
