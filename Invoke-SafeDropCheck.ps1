<#
.SYNOPSIS
    SafeDrop - External Download Safety Checker
.DESCRIPTION
    Checks files and URLs against local risk rules and VirusTotal
    before allowing downloads. Built for IT teams managing external
    file intake across departments.
.EXAMPLES
    .\Invoke-SafeDropCheck.ps1 -FilePath "C:\Downloads\report.zip"
    .\Invoke-SafeDropCheck.ps1 -URL "https://example.com/invoice.exe"
    .\Invoke-SafeDropCheck.ps1 -FilePath "C:\Downloads\file.pdf" -ExportLog
.NOTES
    Tool    : SafeDrop
    Version : 1.0
    Author  : Your Name
    GitHub  : https://github.com/yourusername/SafeDrop
#>

param (
    [string]$FilePath,
    [string]$URL,
    [string]$VirusTotalApiKey = "",
    [switch]$ExportLog
)

# ── Load API key from config file if not passed as parameter
if ($VirusTotalApiKey -eq "") {
    $configPath = Join-Path $PSScriptRoot "config.txt"
    if (Test-Path $configPath) {
        $configLines = Get-Content $configPath
        foreach ($line in $configLines) {
            if ($line -match '^VT_API_KEY=(.+)$') {
                $VirusTotalApiKey = $matches[1].Trim()
                break
            }
        }
    }
}

# ── Colour helpers
function Write-Safe   { param($msg) Write-Host "  [SAFE]  $msg" -ForegroundColor Green }
function Write-Warn   { param($msg) Write-Host "  [WARN]  $msg" -ForegroundColor Yellow }
function Write-Risk   { param($msg) Write-Host "  [RISK]  $msg" -ForegroundColor Red }
function Write-Info   { param($msg) Write-Host "  [INFO]  $msg" -ForegroundColor Cyan }
function Write-Header { param($msg) Write-Host "`n$msg" -ForegroundColor White }

# ── Extension lists
$HighRiskExt   = @('exe','vbs','bat','ps1','cmd','js','jar','msi','scr','pif','com','wsf','hta','iso','img','dll','reg','inf','cpl','sh','lnk')
$MediumRiskExt = @('zip','rar','7z','tar','gz','cab','ace','doc','docm','xls','xlsm','ppt','pptm')
$SafeExt       = @('pdf','xlsx','docx','pptx','csv','txt','png','jpg','jpeg','gif','bmp','svg','mp4','mp3','wav')

# ── Log
$LogEntries = [System.Collections.Generic.List[PSCustomObject]]::new()

function Add-LogEntry {
    param($Type, $Name, $Level, $Detail)
    $LogEntries.Add([PSCustomObject]@{
        Time   = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        Type   = $Type
        Name   = $Name
        Level  = $Level
        Detail = $Detail
        User   = $env:USERNAME
    })
}

# ════════════════════════════════
#  FILE CHECK
# ════════════════════════════════
function Invoke-FileCheck {
    param([string]$Path)

    Write-Host ""
    Write-Host "== FILE CHECK ==================================" -ForegroundColor Cyan

    if (-not (Test-Path $Path)) {
        Write-Risk "File not found: $Path"
        return
    }

    $file    = Get-Item $Path
    $ext     = $file.Extension.TrimStart('.').ToLower()
    $sizeMB  = [math]::Round($file.Length / 1MB, 2)
    $sizeKB  = [math]::Round($file.Length / 1KB, 1)
    $display = if ($sizeMB -lt 0.1) { "$sizeKB KB" } else { "$sizeMB MB" }
    $name    = $file.Name
    $overall = 'SAFE'

    Write-Info "File : $($file.FullName)"
    Write-Info "Size : $display"

    # 1. Extension
    Write-Header "  [1] Extension check"
    if ($HighRiskExt -contains $ext) {
        Write-Risk ".$ext is a HIGH-RISK file type. Do NOT open without IT approval."
        Add-LogEntry 'File' $name 'HIGH RISK' "High-risk extension: .$ext"
        $overall = 'HIGH RISK'
    }
    elseif ($MediumRiskExt -contains $ext) {
        Write-Warn ".$ext can contain macros or embedded code. Disable macros before opening."
        Add-LogEntry 'File' $name 'REVIEW' "Medium-risk extension: .$ext"
        if ($overall -eq 'SAFE') { $overall = 'REVIEW' }
    }
    elseif ($SafeExt -contains $ext) {
        Write-Safe ".$ext is a generally safe file format."
        Add-LogEntry 'File' $name 'SAFE' "Safe extension: .$ext"
    }
    else {
        Write-Warn ".$ext is unrecognised. Treat as suspicious."
        Add-LogEntry 'File' $name 'REVIEW' "Unknown extension: .$ext"
        if ($overall -eq 'SAFE') { $overall = 'REVIEW' }
    }

    # 2. File size
    Write-Header "  [2] Size check"
    if ($file.Length -gt 50MB) {
        Write-Warn "File is $display - unusually large files may contain hidden payloads."
        if ($overall -eq 'SAFE') { $overall = 'REVIEW' }
    }
    else {
        Write-Safe "File size ($display) is within normal range."
    }

    # 3. Double extension
    Write-Header "  [3] Double extension check"
    $allParts = $name -split '\.'
    if ($allParts.Count -gt 2) {
        $innerExt = $allParts[-2].ToLower()
        if (($HighRiskExt -contains $innerExt) -or ($HighRiskExt -contains $ext)) {
            Write-Risk "Double extension detected ($name). Common trick to disguise malicious files."
            $overall = 'HIGH RISK'
        }
        else {
            Write-Safe "No dangerous double extension detected."
        }
    }
    else {
        Write-Safe "Single extension only - no masking detected."
    }

    # 4. Suspicious name
    Write-Header "  [4] File name check"
    $suspiciousNames = @('invoice','payment','urgent','refund','receipt','statement','order','confirmation')
    $matchedName = $suspiciousNames | Where-Object { $name -match $_ }
    if ($matchedName -and (($HighRiskExt -contains $ext) -or ($MediumRiskExt -contains $ext))) {
        Write-Warn "File name uses a financial/urgency keyword ('$($matchedName -join ', ')') with a risk-prone format."
        if ($overall -eq 'SAFE') { $overall = 'REVIEW' }
    }
    else {
        Write-Safe "File name looks normal."
    }

    # 5. SHA256 hash
    Write-Header "  [5] File hash"
    try {
        $hash = (Get-FileHash -Path $Path -Algorithm SHA256).Hash
        Write-Info "SHA256 : $hash"
        Write-Info "Manual check : https://www.virustotal.com/gui/file/$hash"
    }
    catch {
        Write-Warn "Could not compute file hash."
    }

    # 6. VirusTotal
    if ($VirusTotalApiKey -ne "") {
        Write-Header "  [6] VirusTotal scan"
        try {
            $hash = (Get-FileHash -Path $Path -Algorithm SHA256).Hash
            $vtHeaders = @{ "x-apikey" = $VirusTotalApiKey }
            $vtResponse = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/files/$hash" -Headers $vtHeaders -Method GET -ErrorAction Stop
            $stats      = $vtResponse.data.attributes.last_analysis_stats
            $malicious  = $stats.malicious
            $suspicious = $stats.suspicious
            $harmless   = $stats.harmless
            $total      = $malicious + $suspicious + $harmless + $stats.undetected

            Write-Info "Engines scanned : $total"
            Write-Info "Malicious       : $malicious"
            Write-Info "Suspicious      : $suspicious"
            Write-Info "Harmless        : $harmless"

            if ($malicious -gt 0) {
                Write-Risk "VirusTotal: $malicious/$total engines flagged this file as MALICIOUS."
                $overall = 'HIGH RISK'
            }
            elseif ($suspicious -gt 0) {
                Write-Warn "VirusTotal: $suspicious/$total engines flagged this file as suspicious."
                if ($overall -eq 'SAFE') { $overall = 'REVIEW' }
            }
            else {
                Write-Safe "VirusTotal: No engines flagged this file. ($harmless harmless)"
            }
        }
        catch {
            if ($_.Exception.Response.StatusCode -eq 404) {
                Write-Warn "File not seen by VirusTotal before. Submitting for fresh scan..."
                try {
                    $fileBytes  = [System.IO.File]::ReadAllBytes($Path)
                    $boundary   = [System.Guid]::NewGuid().ToString()
                    $bodyLines  = @(
                        "--$boundary",
                        "Content-Disposition: form-data; name=`"file`"; filename=`"$($file.Name)`"",
                        "Content-Type: application/octet-stream",
                        "",
                        [System.Text.Encoding]::UTF8.GetString($fileBytes),
                        "--$boundary--"
                    )
                    $body = $bodyLines -join "`r`n"
                    $uploadHeaders = @{
                        "x-apikey"     = $VirusTotalApiKey
                        "Content-Type" = "multipart/form-data; boundary=$boundary"
                    }
                    $uploadResp = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/files" -Method POST -Headers $uploadHeaders -Body $body -ErrorAction Stop
                    Write-Info "Submitted for fresh scan. Check results at: https://www.virustotal.com/gui/file/$hash"
                    Write-Warn "File was unknown to VT - treat with caution until scan completes."
                    if ($overall -eq 'SAFE') { $overall = 'REVIEW' }
                }
                catch {
                    Write-Warn "Could not submit file to VirusTotal: $($_.Exception.Message)"
                }
            }
            else {
                Write-Warn "VirusTotal lookup failed: $($_.Exception.Message)"
            }
        }
    }
    else {
        Write-Host ""
        Write-Host "  -- VirusTotal not configured --" -ForegroundColor DarkGray
        Write-Host "  Add VT_API_KEY=YOUR_KEY to config.txt to enable live scanning." -ForegroundColor DarkGray
    }

    # Result
    Write-Host ""
    Write-Host "== RESULT: " -NoNewline
    if ($overall -eq 'SAFE') { Write-Host "SAFE - File appears low-risk." -ForegroundColor Green }
    elseif ($overall -eq 'REVIEW') { Write-Host "REVIEW - Check findings above before opening." -ForegroundColor Yellow }
    else { Write-Host "HIGH RISK - Do NOT open. Escalate to IT immediately." -ForegroundColor Red }
    Write-Host "================================================" -ForegroundColor Cyan
}

# ════════════════════════════════
#  URL CHECK
# ════════════════════════════════
function Invoke-URLCheck {
    param([string]$RawURL)

    Write-Host ""
    Write-Host "== URL CHECK ===================================" -ForegroundColor Cyan
    Write-Info "URL: $RawURL"

    $overall = 'SAFE'

    try { $uri = [System.Uri]$RawURL }
    catch { Write-Risk "Invalid URL format."; return }

    $uriHost = $uri.Host.ToLower()
    $scheme  = $uri.Scheme.ToLower()
    $path    = $uri.AbsolutePath.ToLower()
    $ext     = ($path -split '\.')[-1]

    Write-Header "  [1] Protocol check"
    if ($scheme -eq 'https') { Write-Safe "HTTPS - connection is encrypted." }
    else { Write-Warn "HTTP - connection is NOT encrypted."; if ($overall -eq 'SAFE') { $overall = 'REVIEW' } }

    Write-Header "  [2] Domain check"
    if ($uriHost -match '^\d{1,3}(\.\d{1,3}){3}$') { Write-Risk "IP address used instead of domain - common in phishing."; $overall = 'HIGH RISK' }
    else { Write-Safe "Domain name used: $uriHost" }

    Write-Header "  [3] Shortened URL check"
    $shorteners = @('bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','shorturl.at','tiny.cc','rebrand.ly','cutt.ly','we.tl','soo.gd','s.id','buff.ly','dlvr.it','su.pr','snip.ly','bl.ink','short.io')
    $isShortened = $false
    foreach ($s in $shorteners) { if ($uriHost -eq $s) { $isShortened = $true; break } }
    if ($isShortened) { Write-Warn "Shortened URL ($uriHost) - real destination is hidden. Expand at https://checkshorturl.com"; if ($overall -eq 'SAFE') { $overall = 'REVIEW' } }
    else { Write-Safe "No URL shortener detected." }

    Write-Header "  [4] Keyword check"
    $suspiciousKeywords = @('login','signin','verify','account','secure','update','confirm','password','banking')
    $matchedKW = $suspiciousKeywords | Where-Object { $RawURL -match $_ }
    if ($matchedKW) { Write-Warn "Suspicious keyword(s): $($matchedKW -join ', ') - possible phishing."; if ($overall -eq 'SAFE') { $overall = 'REVIEW' } }
    else { Write-Safe "No suspicious keywords found." }

    Write-Header "  [5] TLD check"
    $suspiciousTLDs = @('tk','ml','ga','cf','gq','xyz','top','click','link','work','loan','win','download')
    $tld = ($uriHost -split '\.')[-1]
    if ($suspiciousTLDs -contains $tld) { Write-Warn ".$tld is a commonly abused TLD."; if ($overall -eq 'SAFE') { $overall = 'REVIEW' } }
    else { Write-Safe "TLD .$tld looks normal." }

    Write-Header "  [6] Platform check"
    $fileSharingHosts = @('mediafire.com','mega.nz','anonfiles.com','file.io','gofile.io','transfer.sh','wetransfer.com','we.tl','dropbox.com','1drv.ms','drive.google.com','sendspace.com','zippyshare.com','uploadfiles.io','filebin.net')
    $isSharingHost = $false
    foreach ($fsh in $fileSharingHosts) { if ($uriHost -like "*$fsh*") { $isSharingHost = $true; break } }
    if ($isSharingHost) { Write-Warn "$uriHost is a file-sharing platform. Verify the sender before downloading."; if ($overall -eq 'SAFE') { $overall = 'REVIEW' } }
    else { Write-Safe "Not a known file-sharing platform." }

    Write-Header "  [7] File type in URL"
    if ($ext -and $ext.Length -le 5) {
        if ($HighRiskExt -contains $ext) { Write-Risk "URL points to a .$ext file - HIGH RISK. Do NOT download without IT approval."; $overall = 'HIGH RISK' }
        elseif ($MediumRiskExt -contains $ext) { Write-Warn "URL points to a .$ext file - scan before opening."; if ($overall -eq 'SAFE') { $overall = 'REVIEW' } }
        elseif ($SafeExt -contains $ext) { Write-Safe "URL points to a .$ext file - generally safe format." }
    }
    else { Write-Safe "No specific file extension detected in URL." }

    # VirusTotal
    if ($VirusTotalApiKey -ne "") {
        Write-Header "  [8] VirusTotal scan"
        try {
            $vtHeaders = @{ "x-apikey" = $VirusTotalApiKey }
            $urlBytes  = [System.Text.Encoding]::UTF8.GetBytes($RawURL)
            $urlBase64 = [Convert]::ToBase64String($urlBytes).TrimEnd('=').Replace('+','-').Replace('/','_')
            try {
                $vtResponse = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/urls/$urlBase64" -Headers $vtHeaders -Method GET -ErrorAction Stop
                $stats      = $vtResponse.data.attributes.last_analysis_stats
                $malicious  = $stats.malicious
                $suspicious = $stats.suspicious
                $harmless   = $stats.harmless
                $total      = $malicious + $suspicious + $harmless + $stats.undetected

                Write-Info "Engines scanned : $total"
                Write-Info "Malicious       : $malicious"
                Write-Info "Suspicious      : $suspicious"
                Write-Info "Harmless        : $harmless"

                if ($malicious -gt 0) { Write-Risk "VirusTotal: $malicious/$total engines flagged this URL as MALICIOUS."; $overall = 'HIGH RISK' }
                elseif ($suspicious -gt 0) { Write-Warn "VirusTotal: $suspicious/$total engines flagged this URL as suspicious."; if ($overall -eq 'SAFE') { $overall = 'REVIEW' } }
                else { Write-Safe "VirusTotal: No engines flagged this URL. ($harmless harmless)" }
            }
            catch {
                Write-Warn "URL not seen before by VirusTotal. Submitting for fresh scan..."
                $submitBody    = "url=$([System.Uri]::EscapeDataString($RawURL))"
                $submitHeaders = @{ "x-apikey" = $VirusTotalApiKey; "Content-Type" = "application/x-www-form-urlencoded" }
                $submitResp    = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/urls" -Method POST -Headers $submitHeaders -Body $submitBody -ErrorAction Stop
                Write-Info "Submitted. Check results at: https://www.virustotal.com/gui/url/$urlBase64"
                Write-Warn "URL was unknown to VT - treat with caution until scan completes."
                if ($overall -eq 'SAFE') { $overall = 'REVIEW' }
            }
        }
        catch { Write-Warn "VirusTotal scan failed: $($_.Exception.Message)" }
    }
    else {
        Write-Host ""
        Write-Host "  -- VirusTotal not configured --" -ForegroundColor DarkGray
        Write-Host "  Add VT_API_KEY=YOUR_KEY to config.txt to enable live scanning." -ForegroundColor DarkGray
    }

    Add-LogEntry 'URL' $RawURL $overall "URL risk assessment"

    Write-Host ""
    Write-Host "== RESULT: " -NoNewline
    if ($overall -eq 'SAFE') { Write-Host "SAFE - URL appears low-risk." -ForegroundColor Green }
    elseif ($overall -eq 'REVIEW') { Write-Host "REVIEW - Check findings above before downloading." -ForegroundColor Yellow }
    else { Write-Host "HIGH RISK - Do NOT download. Escalate to IT immediately." -ForegroundColor Red }
    Write-Host "================================================" -ForegroundColor Cyan
}

# ════════════════════════════════
#  EXPORT LOG
# ════════════════════════════════
function Export-CheckLog {
    $logDir = Join-Path $PSScriptRoot "Logs"
    if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
    $logPath = Join-Path $logDir "SafeDropLog_$(Get-Date -Format 'yyyyMMdd').csv"
    $LogEntries | Export-Csv -Path $logPath -NoTypeInformation -Append
    Write-Host ""
    Write-Host "  Log saved to: $logPath" -ForegroundColor Cyan
}

# ════════════════════════════════
#  ENTRY POINT
# ════════════════════════════════
Write-Host ""
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "   SafeDrop - External Download Safety Checker" -ForegroundColor Cyan
Write-Host "   Built for IT Teams | github.com/yourusername/SafeDrop" -ForegroundColor Cyan
Write-Host "   $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan

if (-not $FilePath -and -not $URL) {
    Write-Host ""
    Write-Host "  Usage examples:" -ForegroundColor Yellow
    Write-Host "    Check a file : .\Invoke-SafeDropCheck.ps1 -FilePath 'C:\Downloads\report.zip'"
    Write-Host "    Check a URL  : .\Invoke-SafeDropCheck.ps1 -URL 'https://example.com/file.exe'"
    Write-Host "    Export log   : .\Invoke-SafeDropCheck.ps1 -URL '...' -ExportLog"
    Write-Host ""
    exit
}

if ($FilePath) { Invoke-FileCheck -Path $FilePath }
if ($URL)      { Invoke-URLCheck -RawURL $URL }
if ($ExportLog) { Export-CheckLog }

Write-Host ""
