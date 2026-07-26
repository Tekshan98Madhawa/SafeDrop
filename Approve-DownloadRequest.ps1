<#
.SYNOPSIS
    SafeDrop - IT Approval Tool for Download Requests
.DESCRIPTION
    IT staff use this to review, approve, or reject pending download requests
    submitted by users via Submit-DownloadRequest.ps1
.EXAMPLE
    .\Approve-DownloadRequest.ps1
.NOTES
    Tool    : SafeDrop
    Version : 1.0
    GitHub  : https://github.com/yourusername/SafeDrop
#>

Write-Host ""
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "   SafeDrop - IT Download Request Review" -ForegroundColor Cyan
Write-Host "   $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan

$logDir  = Join-Path $PSScriptRoot "Logs"
$logPath = Join-Path $logDir "DownloadRequests.csv"

if (-not (Test-Path $logPath)) {
    Write-Host ""
    Write-Host "  No requests found. Log file does not exist yet." -ForegroundColor Yellow
    exit
}

# Load all requests
$allRequests = Import-Csv -Path $logPath
$pending     = $allRequests | Where-Object { $_.Status -eq 'PENDING' }

if (-not $pending) {
    Write-Host ""
    Write-Host "  No pending requests at this time." -ForegroundColor Green
    exit
}

Write-Host ""
Write-Host "  Pending requests: $($pending.Count)" -ForegroundColor Yellow
Write-Host ""

foreach ($req in $pending) {
    Write-Host "  -------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  Request ID  : $($req.RequestID)" -ForegroundColor Cyan
    Write-Host "  Submitted   : $($req.Time)" -ForegroundColor White
    Write-Host "  User        : $($req.Requestor) ($($req.Department))" -ForegroundColor White
    Write-Host "  File        : $($req.FileName)" -ForegroundColor White
    Write-Host "  Source URL  : $($req.SourceURL)" -ForegroundColor White
    Write-Host "  Reason      : $($req.Reason)" -ForegroundColor White
    Write-Host ""

    $decision = ""
    while ($decision -notin @('A','R','S')) {
        $decision = (Read-Host "  Decision: [A] Approve  [R] Reject  [S] Skip").ToUpper()
    }

    if ($decision -eq 'S') {
        Write-Host "  Skipped." -ForegroundColor DarkGray
        Write-Host ""
        continue
    }

    $note      = Read-Host "  Note (optional)"
    $reviewedBy = $env:USERNAME
    $reviewTime = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    $status     = if ($decision -eq 'A') { 'APPROVED' } else { 'REJECTED' }

    # Update the matching entry in CSV
    $updated = $allRequests | ForEach-Object {
        if ($_.RequestID -eq $req.RequestID) {
            $_.Status     = $status
            $_.ReviewedBy = $reviewedBy
            $_.ReviewNote = $note
            $_.ReviewTime = $reviewTime
        }
        $_
    }

    $updated | Export-Csv -Path $logPath -NoTypeInformation -Force

    if ($status -eq 'APPROVED') {
        Write-Host "  APPROVED by $reviewedBy" -ForegroundColor Green
    }
    else {
        Write-Host "  REJECTED by $reviewedBy" -ForegroundColor Red
    }
    Write-Host ""
}

Write-Host "  Review complete." -ForegroundColor Cyan
Write-Host ""
