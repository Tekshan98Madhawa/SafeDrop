<#
.SYNOPSIS
    SafeDrop - Dashboard Report
.DESCRIPTION
    Reads SafeDrop logs and generates a summary report for IT teams.
    Shows check totals, risk breakdown, top flagged file types,
    most active users, and pending approval requests.
.EXAMPLE
    .\Get-SafeDropDashboard.ps1
    .\Get-SafeDropDashboard.ps1 -Days 7
.NOTES
    Tool    : SafeDrop
    Version : 1.0
    GitHub  : https://github.com/yourusername/SafeDrop
#>

param(
    [int]$Days = 30
)

$logDir      = Join-Path $PSScriptRoot "Logs"
$checkLogs   = Get-ChildItem -Path $logDir -Filter "SafeDropLog_*.csv" -ErrorAction SilentlyContinue
$requestLog  = Join-Path $logDir "DownloadRequests.csv"
$cutoffDate  = (Get-Date).AddDays(-$Days)

Write-Host ""
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "   SafeDrop - Dashboard Report" -ForegroundColor Cyan
Write-Host "   Period  : Last $Days days" -ForegroundColor Cyan
Write-Host "   Generated : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan

if (-not $checkLogs) {
    Write-Host ""
    Write-Host "  No check logs found in: $logDir" -ForegroundColor Yellow
    Write-Host "  Run Invoke-SafeDropCheck.ps1 with -ExportLog to start logging." -ForegroundColor DarkGray
}
else {
    # Load and filter all check entries
    $allChecks = $checkLogs | ForEach-Object { Import-Csv $_.FullName } |
        Where-Object { [datetime]$_.Time -ge $cutoffDate }

    $total     = @($allChecks).Count
    $safe      = @($allChecks | Where-Object { $_.Level -eq 'SAFE' }).Count
    $review    = @($allChecks | Where-Object { $_.Level -eq 'REVIEW' }).Count
    $highRisk  = @($allChecks | Where-Object { $_.Level -eq 'HIGH RISK' }).Count
    $urlChecks = @($allChecks | Where-Object { $_.Type -eq 'URL' }).Count
    $fileChecks= @($allChecks | Where-Object { $_.Type -eq 'File' }).Count

    Write-Host ""
    Write-Host "  CHECKS SUMMARY" -ForegroundColor White
    Write-Host "  -------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  Total checks    : $total"
    Write-Host "  File checks     : $fileChecks"
    Write-Host "  URL checks      : $urlChecks"
    Write-Host ""
    Write-Host "  SAFE            : $safe" -ForegroundColor Green
    Write-Host "  REVIEW          : $review" -ForegroundColor Yellow
    Write-Host "  HIGH RISK       : $highRisk" -ForegroundColor Red

    if ($total -gt 0) {
        $safePercent     = [math]::Round(($safe / $total) * 100)
        $reviewPercent   = [math]::Round(($review / $total) * 100)
        $highRiskPercent = [math]::Round(($highRisk / $total) * 100)
        Write-Host ""
        Write-Host "  Risk breakdown  : $safePercent% Safe | $reviewPercent% Review | $highRiskPercent% High Risk"
    }

    # Most active users
    Write-Host ""
    Write-Host "  TOP USERS (by check volume)" -ForegroundColor White
    Write-Host "  -------------------------------------------------------" -ForegroundColor DarkGray
    $allChecks | Group-Object User | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object {
        Write-Host "  $($_.Name.PadRight(20)) $($_.Count) checks"
    }

    # Most flagged file types
    $flagged = $allChecks | Where-Object { $_.Level -ne 'SAFE' }
    if ($flagged) {
        Write-Host ""
        Write-Host "  MOST FLAGGED ITEMS" -ForegroundColor White
        Write-Host "  -------------------------------------------------------" -ForegroundColor DarkGray
        $flagged | Select-Object -First 5 | ForEach-Object {
            $levelColor = if ($_.Level -eq 'HIGH RISK') { 'Red' } else { 'Yellow' }
            Write-Host "  [$($_.Level)]  $($_.Name)" -ForegroundColor $levelColor
            Write-Host "           $($_.Detail)" -ForegroundColor DarkGray
        }
    }

    # Daily activity
    Write-Host ""
    Write-Host "  DAILY ACTIVITY (last 7 days)" -ForegroundColor White
    Write-Host "  -------------------------------------------------------" -ForegroundColor DarkGray
    $last7 = (Get-Date).AddDays(-7)
    $allChecks | Where-Object { [datetime]$_.Time -ge $last7 } |
        Group-Object { ([datetime]$_.Time).ToString('yyyy-MM-dd') } |
        Sort-Object Name |
        ForEach-Object {
            $bar = '#' * $_.Count
            Write-Host "  $($_.Name)  $bar ($($_.Count))"
        }
}

# Approval requests summary
Write-Host ""
Write-Host "  DOWNLOAD REQUESTS" -ForegroundColor White
Write-Host "  -------------------------------------------------------" -ForegroundColor DarkGray

if (Test-Path $requestLog) {
    $requests  = @(Import-Csv $requestLog)
    $pending   = @($requests | Where-Object { $_.Status -eq 'PENDING' }).Count
    $approved  = @($requests | Where-Object { $_.Status -eq 'APPROVED' }).Count
    $rejected  = @($requests | Where-Object { $_.Status -eq 'REJECTED' }).Count
    $totalReqs = $requests.Count

    Write-Host "  Total requests  : $totalReqs"
    Write-Host "  Pending         : $pending" -ForegroundColor Yellow
    Write-Host "  Approved        : $approved" -ForegroundColor Green
    Write-Host "  Rejected        : $rejected" -ForegroundColor Red

    if ($pending -gt 0) {
        Write-Host ""
        Write-Host "  ! $pending request(s) awaiting IT review." -ForegroundColor Yellow
        Write-Host "    Run Approve-DownloadRequest.ps1 to review." -ForegroundColor DarkGray
    }
}
else {
    Write-Host "  No requests submitted yet." -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "   End of Report" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host ""