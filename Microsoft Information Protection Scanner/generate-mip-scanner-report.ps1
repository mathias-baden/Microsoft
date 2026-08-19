# ==============================================================
# MIPUserReport.ps1
# Microsoft Purview Information Protection Scanner
# User-level SIT findings report with share breakdown
#
# MIT License
# Copyright (c) 2026 Mathias Baden Frederiksen
# https://mathiasbaden.com
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation
# files (the "Software"), to deal in the Software without
# restriction, including without limitation the rights to use,
# copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following
# conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
# ==============================================================
#
# USAGE
# -----
# Run from PowerShell, passing the customer name and (optionally) the
# path to the scanner's DetailedReport CSV:
#
#   .\MIPUserReport.ps1 -Organisation "Contoso A/S" -CsvPath "C:\Reports\DetailedReport_2026-08-19.csv"
#
# -Organisation   <-- put the CUSTOMER NAME here (shown in the report title/header)
# -CsvPath        <-- put the path to the DetailedReport_*.csv file here
#                     If omitted, the script auto-picks the newest
#                     DetailedReport_*.csv from the default scanner folder
#                     for whichever account runs the script:
#                     C:\Users\<current account>\AppData\Local\Microsoft\MSIP\Scanner\Reports
#                     (normally the svc-mipscanner service account)
# -ServiceAccount <-- (optional) if you're NOT signed in / running as the
#                     scanner's service account, set this to its username
#                     instead, e.g. -ServiceAccount "svc-mipscanner". The
#                     script will then look under C:\Users\svc-mipscanner\...
#                     even though you're logged in as someone else.
#                     (Requires read access to that profile's AppData folder.)
# -OutputPath     <-- (optional) where to save the generated .html report
#                     If omitted, it's saved next to the CSV file.
# -OpenInBrowser  <-- (optional) add this switch to open the report automatically
#
# Example, letting the script find the CSV automatically and open the report:
#
#   .\MIPUserReport.ps1 -Organisation "Contoso A/S" -OpenInBrowser
#
# Example, running as your own account but reading the service account's reports:
#
#   .\MIPUserReport.ps1 -Organisation "Contoso A/S" -ServiceAccount "svc-mipscanner"
#
param(
    [string]$CsvPath        = "",   # <-- CSV PATH: set a default here if you always scan the same location
    [string]$OutputPath     = "",
    [string]$Organisation   = "",   # <-- CUSTOMER NAME: set a default here, e.g. "Contoso A/S"
    [string]$ServiceAccount = "",   # <-- SERVICE ACCOUNT: set this if not running as the account itself, e.g. "svc-mipscanner"
    [switch]$OpenInBrowser
)

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Web

# ── Find CSV ──────────────────────────────────────────────────────
if (-not $CsvPath) {
    if ($ServiceAccount) {
        # Explicit account name given — use it, even if we're logged in
        # as someone else. Needs read access to that profile's folder.
        $reportsDir = "C:\Users\$ServiceAccount\AppData\Local\Microsoft\MSIP\Scanner\Reports"
    }
    else {
        # No account name given — fall back to whichever account is
        # actually running this script. $env:USERPROFILE resolves to
        # C:\Users\<current account>, e.g. C:\Users\svc-mipscanner.
        $reportsDir = Join-Path $env:USERPROFILE "AppData\Local\Microsoft\MSIP\Scanner\Reports"
    }

    if (-not (Test-Path $reportsDir)) {
        Write-Error "Report folder not found: $reportsDir. Run as the MIP scanner service account (e.g. svc-mipscanner), or pass -ServiceAccount `"<name>`" to point at its report folder — currently running as $env:USERNAME."
        exit 1
    }

    $latest = Get-ChildItem $reportsDir -Filter "DetailedReport_*.csv" |
              Sort-Object LastWriteTime -Descending |
              Select-Object -First 1

    if (-not $latest) {
        Write-Error "No DetailedReport_*.csv found."
        exit 1
    }

    $CsvPath = $latest.FullName
    Write-Host "Using: $CsvPath" -ForegroundColor Cyan
}

if (-not (Test-Path $CsvPath)) {
    Write-Error "File not found: $CsvPath"
    exit 1
}

if (-not $OutputPath) {
    $ts = Get-Date -Format "yyyy-MM-dd_HH-mm"
    $OutputPath = Join-Path (Split-Path $CsvPath) "MIPUserReport_$ts.html"
}

# ── Load CSV ──────────────────────────────────────────────────────
Write-Host "Loading data..." -ForegroundColor Cyan

$firstLine = Get-Content -Path $CsvPath -TotalCount 1 -Encoding UTF8

if (-not $firstLine -or $firstLine.Length -eq 0) {
    $firstLine = Get-Content -Path $CsvPath -TotalCount 1 -Encoding Unicode
}

$delimiter = if ($firstLine -match ";") { ";" } else { "," }

[System.Collections.ArrayList]$rows = @()

try {
    $imported = Import-Csv -Path $CsvPath -Delimiter $delimiter -Encoding UTF8
    foreach ($r in $imported) {
        [void]$rows.Add($r)
    }
}
catch {
    $imported = Import-Csv -Path $CsvPath -Delimiter $delimiter -Encoding Unicode
    foreach ($r in $imported) {
        [void]$rows.Add($r)
    }
}

if ($rows.Count -eq 0) {
    Write-Error "CSV is empty or could not be read."
    exit 1
}

Write-Host "Loaded $($rows.Count) rows" -ForegroundColor Cyan

$scanDate = (Get-Item $CsvPath).LastWriteTime.ToString("d. MMMM yyyy", [System.Globalization.CultureInfo]::GetCultureInfo("da-DK"))
$genDate  = Get-Date -Format "d. MMMM yyyy HH:mm"
$now      = Get-Date

# ── Aggregate ──────────────────────────────────────────────────────
Write-Host "Aggregating..." -ForegroundColor Cyan

$total = $rows.Count
$withSIT = @(
    $rows | Where-Object {
        $_.'Information Type Name' -and $_.'Information Type Name'.Trim() -ne ""
    }
).Count

$userHash  = @{}
$userFiles = @{}

foreach ($r in $rows) {
    $mb = ""
    if ($r.'Last Modified By') {
        $mb = $r.'Last Modified By'.Trim()
    }

    if ($mb -eq "" -or $mb.Length -ge 60 -or $mb.StartsWith([char]0)) {
        continue
    }

    $sit = ""
    if ($r.'Information Type Name') {
        $sit = $r.'Information Type Name'.Trim().Trim('"')
    }

    if ($sit -eq "") {
        continue
    }

    $repo = ""
    if ($r.Repository) {
        $repo = $r.Repository.Trim()
    }

    $fname = ""
    if ($r.'File Name') {
        $fname = $r.'File Name'.Trim()
    }

    if (-not $userHash.ContainsKey($mb)) {
        $userHash[$mb] = @{
            sitTotal   = 0
            over5Total = 0
            shares     = @{}
            sitMap     = @{}
        }

        $userFiles[$mb] = [System.Collections.ArrayList]::new()
    }

    $userHash[$mb].sitTotal++

    if ($userHash[$mb].sitMap.ContainsKey($sit)) {
        $userHash[$mb].sitMap[$sit]++
    }
    else {
        $userHash[$mb].sitMap[$sit] = 1
    }

    $isOver5 = $false
    $lm = ""

    if ($r.'Last Modified') {
        $lm = $r.'Last Modified'.Trim()
    }

    if ($lm) {
        try {
            $dt = [DateTime]::Parse($lm)
            if (($now - $dt).TotalDays / 365.25 -gt 5) {
                $isOver5 = $true
            }
        }
        catch { }
    }

    if ($isOver5) {
        $userHash[$mb].over5Total++
    }

    if (-not $userHash[$mb].shares.ContainsKey($repo)) {
        $userHash[$mb].shares[$repo] = @{
            sit   = 0
            over5 = 0
        }
    }

    $userHash[$mb].shares[$repo].sit++

    if ($isOver5) {
        $userHash[$mb].shares[$repo].over5++
    }

    # Store file for modal. Capped at 1000 files per user to keep HTML size manageable.
    if ($userFiles[$mb].Count -lt 1000) {
        $shortName = if ($fname -match '([^\\]+)$') { $matches[1] } else { $fname }
        $shareName = $repo -replace '\\\\[^\\]+\\', '' -replace '^[A-Z]:\\', 'Local: '
        $folderPath = if ($fname -match '^(.+)\\[^\\]+$') { $matches[1] } else { $repo }

        [void]$userFiles[$mb].Add(@{
            file   = $shortName
            path   = $fname
            folder = $folderPath
            share  = $shareName
            repo   = $repo
            sit    = $sit
            lm     = $lm
            over5  = $isOver5
        })
    }
}

$allUsers = $userHash.GetEnumerator() | Sort-Object { $_.Value.sitTotal } -Descending

$totalUsers   = $userHash.Count
$usersWithSIT = $totalUsers

$totalOver5 = ($userHash.Values | ForEach-Object { $_.over5Total } | Measure-Object -Sum).Sum
if ($null -eq $totalOver5) {
    $totalOver5 = 0
}

# ── Helpers ────────────────────────────────────────────────────────
function HtmlEnc([string]$s) {
    return [System.Web.HttpUtility]::HtmlEncode($s)
}

function HtmlAttrEnc([string]$s) {
    return [System.Web.HttpUtility]::HtmlAttributeEncode($s)
}

function Get-Initials([string]$name) {
    $parts = $name -split '[\s\.\-_]' | Where-Object { $_.Length -gt 0 }
    $initials = ($parts | ForEach-Object { $_[0].ToString().ToUpper() } | Select-Object -First 2) -join ''

    if ($initials) {
        return $initials
    }

    return "??"
}

function Get-ShareName([string]$repo) {
    return $repo -replace '\\\\[^\\]+\\', '' -replace '^[A-Z]:\\', 'Local: '
}

# ── Build JS data blob ─────────────────────────────────────────────
function Build-UserDataJS {
    $obj = [ordered]@{}

    foreach ($entry in $allUsers) {
        $fileList = @()
        $files = $userFiles[$entry.Key]

        if ($files) {
            foreach ($f in $files) {
                $fileList += [ordered]@{
                    file   = [string]$f.file
                    path   = [string]$f.path
                    folder = [string]$f.folder
                    share  = [string]$f.share
                    repo   = [string]$f.repo
                    sit    = [string]$f.sit
                    lm     = [string]$f.lm
                    over5  = [bool]$f.over5
                }
            }
        }

        $obj[$entry.Key] = $fileList
    }

    $json = $obj | ConvertTo-Json -Depth 8 -Compress
    return "var USER_FILES = $json;`n"
}

# ── Build rows ─────────────────────────────────────────────────────
function Build-UserRows {
    $sb = [System.Text.StringBuilder]::new()

    $maxSit = ($allUsers | ForEach-Object { $_.Value.sitTotal } | Measure-Object -Maximum).Maximum

    if ($null -eq $maxSit -or $maxSit -eq 0) {
        $maxSit = 1
    }

    if (-not ($allUsers | Select-Object -First 1)) {
        [void]$sb.Append('<tr><td colspan="5" style="color:#9CA3AF;text-align:center;padding:24px;">No users with SIT findings</td></tr>')
        return $sb.ToString()
    }

    $rank = 0

    foreach ($entry in $allUsers) {
        $rank++

        $name       = HtmlEnc $entry.Key
        $initials   = Get-Initials $entry.Key
        $sit        = [int]$entry.Value.sitTotal
        $over5      = [int]$entry.Value.over5Total
        $barPct     = [math]::Round(($sit / $maxSit) * 100)
        $over5Pct   = if ($sit -gt 0) { [math]::Round(($over5 / $sit) * 100) } else { 0 }
        $shareCount = $entry.Value.shares.Count

        $rColor = if ($sit -gt 100 -or $over5Pct -ge 50) {
            "#C00000"
        }
        elseif ($sit -gt 10 -or $over5Pct -ge 20) {
            "#D35400"
        }
        else {
            "#2E75B6"
        }

        $o5Color = if ($over5Pct -ge 50) {
            "#C00000"
        }
        elseif ($over5Pct -ge 20) {
            "#D35400"
        }
        else {
            "#1D6A39"
        }

        # Share breakdown
        $shareHtml = ""
        $sortedShares = @($entry.Value.shares.GetEnumerator() | Sort-Object { $_.Value.sit } -Descending)

        foreach ($sh in $sortedShares) {
            $shKey      = [string]$sh.Key
            $shSit      = [int]$sh.Value.sit
            $shOver5    = [int]$sh.Value.over5
            $shName     = HtmlEnc (Get-ShareName $shKey)
            $shPath     = HtmlEnc $shKey
            $shBarPct   = [math]::Round(($shSit / $sit) * 100)
            $shOver5Pct = if ($shSit -gt 0) { [math]::Round(($shOver5 / $shSit) * 100) } else { 0 }

            $shO5Color = if ($shOver5Pct -ge 50) {
                "#C00000"
            }
            elseif ($shOver5Pct -ge 20) {
                "#D35400"
            }
            else {
                "#1D6A39"
            }

            $shareHtml += @"
              <div class="sh-row">
                <div class="sh-name">
                  <span class="sh-arrow">↳</span>
                  <div class="sh-labels">
                    <span class="sh-short">$shName</span>
                    <span class="sh-path">$shPath</span>
                  </div>
                </div>
                <div class="sh-bar">
                  <div class="sh-bar-track"><div class="sh-bar-fill" style="width:$($shBarPct)%;background:$rColor;"></div></div>
                </div>
                <div class="sh-sit" style="color:$rColor;">$shSit</div>
                <div class="sh-old" style="color:$shO5Color;">$shOver5 <span class="sh-pct">($shOver5Pct%)</span></div>
              </div>
"@
        }

        # Build SIT type pills
        $sitPills = ""
        $sortedSits = @($entry.Value.sitMap.GetEnumerator() | Sort-Object { $_.Value } -Descending)

        foreach ($ts in $sortedSits) {
            $tsKey = HtmlEnc ([string]$ts.Key)
            $tsVal = [string]$ts.Value
            $sitPills += "<span class='pill'>$tsKey <strong>$tsVal</strong></span>"
        }

        # Generate a real JavaScript string and then HTML attribute encode it.
        $nameJson = $entry.Key | ConvertTo-Json -Compress
        $nameAttr = HtmlAttrEnc $nameJson

        [void]$sb.Append(@"
        <tr onclick="openModal($nameAttr)" style="cursor:pointer;" title="Click to view files">
          <td style="text-align:center;font-size:12px;color:var(--muted);font-weight:600;width:36px;vertical-align:top;padding:14px 8px;">$rank</td>
          <td style="vertical-align:top;padding:14px 16px;">
            <div class="user-header">
              <div class="avatar" style="background:$rColor;">$initials</div>
              <div>
                <div class="user-name">$name</div>
                <div class="user-meta">$shareCount share(s) &nbsp;&middot;&nbsp; <span class="click-hint">Click to view files &#8599;</span></div>
              </div>
            </div>
            <div class="sh-table">
              <div class="sh-cols">
                <div>Share</div>
                <div></div>
                <div style="text-align:center;">SIT files</div>
                <div style="text-align:center;">Over 5y</div>
              </div>
              $shareHtml
            </div>
            <div class="pills">$sitPills</div>
          </td>
          <td style="text-align:center;font-size:22px;font-weight:700;color:$rColor;width:90px;vertical-align:top;padding:14px 8px;">$sit</td>
          <td style="width:100px;vertical-align:top;padding:20px 12px 14px;">
            <div class="stat-bar-wrap" style="margin:0;">
              <div class="stat-bar-fill" style="width:$($barPct)%;background:$rColor;"></div>
            </div>
          </td>
          <td style="text-align:center;width:110px;vertical-align:top;padding:14px 8px;">
            <div style="font-size:18px;font-weight:700;color:$o5Color;line-height:1;">$over5</div>
            <div style="font-size:10px;color:var(--muted);margin-top:3px;">$over5Pct% of SIT files</div>
          </td>
        </tr>
"@)
    }

    return $sb.ToString()
}

Write-Host "Generating HTML..." -ForegroundColor Cyan

$userRows   = Build-UserRows
$userDataJS = Build-UserDataJS

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SIT Findings Report — $Organisation</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  :root {
    --navy:   #0f172a;
    --navy2:  #1e293b;
    --slate:  #475569;
    --muted:  #94a3b8;
    --border: #e2e8f0;
    --bg:     #f8fafc;
    --white:  #ffffff;
    --red:    #dc2626;
    --amber:  #d97706;
    --green:  #16a34a;
    --blue:   #2563eb;
    --red-bg: #fef2f2;
    --amb-bg: #fffbeb;
  }

  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: var(--bg);
    color: var(--navy);
    font-size: 14px;
    line-height: 1.6;
  }

  .nav {
    background: var(--white);
    border-bottom: 1px solid var(--border);
    padding: 0 40px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    height: 52px;
  }

  .nav-brand {
    font-size: 13px;
    font-weight: 600;
    color: var(--navy);
    letter-spacing: -0.2px;
  }

  .nav-brand span {
    color: var(--muted);
    font-weight: 400;
  }

  .nav-meta {
    font-size: 12px;
    color: var(--muted);
  }

  .hero {
    background: var(--white);
    border-bottom: 1px solid var(--border);
    padding: 48px 40px 40px;
  }

  .hero-eyebrow {
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 1px;
    text-transform: uppercase;
    color: var(--muted);
    margin-bottom: 10px;
  }

  .hero h1 {
    font-size: 28px;
    font-weight: 700;
    color: var(--navy);
    letter-spacing: -0.5px;
    line-height: 1.2;
    margin-bottom: 8px;
  }

  .hero-sub {
    font-size: 14px;
    color: var(--slate);
    margin-bottom: 20px;
  }

  .hero-badges {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
  }

  .badge {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    font-size: 11px;
    font-weight: 500;
    padding: 3px 10px;
    border-radius: 20px;
    border: 1px solid var(--border);
    color: var(--slate);
    background: var(--bg);
  }

  .badge.ok {
    color: var(--green);
    border-color: #bbf7d0;
    background: #f0fdf4;
  }

  .badge.info {
    color: var(--blue);
    border-color: #bfdbfe;
    background: #eff6ff;
  }

  .container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 32px 40px;
  }

  .kpi-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 16px;
    margin-bottom: 32px;
  }

  .kpi {
    background: var(--white);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 20px;
  }

  .kpi-num {
    font-size: 32px;
    font-weight: 700;
    color: var(--navy);
    line-height: 1;
    letter-spacing: -1px;
    margin-bottom: 4px;
  }

  .kpi-num.red {
    color: var(--red);
  }

  .kpi-num.amber {
    color: var(--amber);
  }

  .kpi-label {
    font-size: 12px;
    font-weight: 600;
    color: var(--navy);
    margin-bottom: 2px;
  }

  .kpi-sub {
    font-size: 11px;
    color: var(--muted);
  }

  .card {
    background: var(--white);
    border: 1px solid var(--border);
    border-radius: 8px;
    margin-bottom: 24px;
    overflow: hidden;
  }

  .card-header {
    padding: 16px 20px;
    border-bottom: 1px solid var(--border);
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    gap: 12px;
  }

  .card-title {
    font-size: 13px;
    font-weight: 600;
    color: var(--navy);
  }

  .card-count {
    font-size: 12px;
    color: var(--muted);
    white-space: nowrap;
  }

  table {
    width: 100%;
    border-collapse: collapse;
  }

  th {
    text-align: left;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: .5px;
    color: var(--muted);
    padding: 10px 20px;
    border-bottom: 1px solid var(--border);
    background: var(--bg);
  }

  td {
    padding: 0;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
  }

  tbody tr:last-child td {
    border-bottom: none;
  }

  tbody tr {
    cursor: pointer;
    transition: background 0.1s;
  }

  tbody tr:hover {
    background: var(--bg);
  }

  .user-header {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 12px;
  }

  .avatar {
    width: 36px;
    height: 36px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 12px;
    font-weight: 700;
    color: white;
    flex-shrink: 0;
    font-family: monospace;
  }

  .user-name {
    font-size: 14px;
    font-weight: 600;
    color: var(--navy);
  }

  .user-meta {
    font-size: 11px;
    color: var(--muted);
    margin-top: 1px;
  }

  .click-hint {
    color: var(--blue);
    font-size: 10px;
  }

  .sh-table {
    margin-left: 48px;
  }

  .sh-cols {
    display: grid;
    grid-template-columns: 1fr 100px 64px 88px;
    gap: 6px;
    padding: 3px 0 6px;
    border-bottom: 1px solid var(--border);
    margin-bottom: 2px;
    font-size: 10px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: .4px;
    color: var(--muted);
  }

  .sh-row {
    display: grid;
    grid-template-columns: 1fr 100px 64px 88px;
    gap: 6px;
    padding: 4px 0;
    border-bottom: 1px dashed var(--border);
    align-items: center;
  }

  .sh-row:last-child {
    border-bottom: none;
  }

  .sh-name {
    display: flex;
    gap: 5px;
    align-items: flex-start;
    min-width: 0;
  }

  .sh-arrow {
    color: var(--border);
    font-size: 11px;
    flex-shrink: 0;
    margin-top: 1px;
  }

  .sh-short {
    font-size: 12px;
    font-weight: 500;
    color: var(--navy2);
    display: block;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .sh-path {
    font-family: monospace;
    font-size: 9px;
    color: var(--muted);
    display: block;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .sh-bar {
    display: flex;
    align-items: center;
  }

  .sh-bar-track {
    background: var(--border);
    border-radius: 2px;
    height: 4px;
    width: 100%;
  }

  .sh-bar-fill {
    height: 100%;
    border-radius: 2px;
    min-width: 2px;
  }

  .sh-sit {
    text-align: center;
    font-size: 13px;
    font-weight: 600;
  }

  .sh-old {
    text-align: center;
    font-size: 13px;
    font-weight: 600;
  }

  .sh-pct {
    font-size: 10px;
    font-weight: 400;
    color: var(--muted);
  }

  .pills {
    margin-left: 48px;
    margin-top: 8px;
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
  }

  .pill {
    font-size: 10px;
    padding: 2px 8px;
    border-radius: 20px;
    border: 1px solid var(--border);
    color: var(--slate);
    background: var(--bg);
  }

  .pill strong {
    color: var(--red);
    margin-left: 2px;
  }

  .stat-bar-wrap {
    background: var(--border);
    border-radius: 3px;
    height: 4px;
    width: 80px;
    margin: 8px auto 0;
  }

  .stat-bar-fill {
    height: 100%;
    border-radius: 3px;
    min-width: 2px;
  }

  .notice {
    background: #f0f9ff;
    border: 1px solid #bae6fd;
    border-left: 3px solid var(--blue);
    border-radius: 6px;
    padding: 12px 16px;
    font-size: 12px;
    color: #0c4a6e;
    margin-bottom: 24px;
  }

  .notice strong {
    display: block;
    margin-bottom: 2px;
    font-size: 13px;
  }

  .footer {
    border-top: 1px solid var(--border);
    padding: 20px 40px;
    font-size: 11px;
    color: var(--muted);
    display: flex;
    justify-content: space-between;
    align-items: center;
    background: var(--white);
    margin-top: 40px;
  }

  .footer a {
    color: var(--muted);
    text-decoration: none;
  }

  .footer a:hover {
    color: var(--navy);
  }

  #overlay {
    position: fixed;
    inset: 0;
    background: rgba(15, 23, 42, 0.6);
    backdrop-filter: blur(2px);
    z-index: 1000;
  }

  #modalbox {
    position: fixed;
    top: 5vh;
    left: 50%;
    transform: translateX(-50%);
    width: 94%;
    max-width: 1080px;
    height: 88vh;
    background: var(--white);
    border-radius: 10px;
    box-shadow: 0 24px 80px rgba(15,23,42,0.3);
    z-index: 1001;
    flex-direction: column;
    overflow: hidden;
  }

  .modal-head {
    padding: 18px 24px;
    border-bottom: 1px solid var(--border);
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    flex-shrink: 0;
  }

  .modal-title {
    font-size: 16px;
    font-weight: 700;
    color: var(--navy);
  }

  .modal-sub {
    font-size: 11px;
    color: var(--muted);
    margin-top: 2px;
  }

  .modal-close {
    background: none;
    border: 1px solid var(--border);
    color: var(--slate);
    width: 30px;
    height: 30px;
    border-radius: 6px;
    font-size: 16px;
    cursor: pointer;
    flex-shrink: 0;
    line-height: 0;
    padding: 0;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .modal-close:hover {
    background: var(--bg);
  }

  .modal-toolbar {
    padding: 10px 24px;
    border-bottom: 1px solid var(--border);
    display: flex;
    gap: 10px;
    align-items: center;
    flex-shrink: 0;
    background: var(--bg);
  }

  .modal-search {
    flex: 1;
    padding: 7px 12px;
    border: 1px solid var(--border);
    border-radius: 6px;
    font-size: 13px;
    outline: none;
    background: var(--white);
  }

  .modal-search:focus {
    border-color: var(--blue);
  }

  .modal-chk {
    display: flex;
    align-items: center;
    gap: 5px;
    font-size: 12px;
    color: var(--slate);
    cursor: pointer;
    white-space: nowrap;
  }

  .modal-export {
    background: var(--navy);
    color: white;
    border: none;
    padding: 7px 14px;
    border-radius: 6px;
    font-size: 12px;
    font-weight: 600;
    cursor: pointer;
    white-space: nowrap;
    flex-shrink: 0;
  }

  .modal-export:hover {
    background: var(--navy2);
  }

  .modal-count {
    font-size: 11px;
    color: var(--muted);
    white-space: nowrap;
  }

  .modal-body {
    overflow-y: auto;
    flex: 1;
  }

  .modal-foot {
    padding: 8px 24px;
    border-top: 1px solid var(--border);
    font-size: 10px;
    color: var(--muted);
    text-align: right;
    flex-shrink: 0;
    background: var(--bg);
  }

  .modal-th {
    position: sticky;
    top: 0;
    background: var(--bg);
    z-index: 1;
    text-align: left;
    font-size: 10px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: .4px;
    color: var(--muted);
    padding: 8px 16px;
    border-bottom: 1px solid var(--border);
  }

  .modal-td {
    padding: 7px 16px;
    font-size: 12px;
    border-bottom: 1px solid var(--border);
    vertical-align: middle;
  }

  .tag-sit {
    background: var(--amb-bg);
    color: var(--amber);
    font-size: 10px;
    padding: 2px 7px;
    border-radius: 20px;
    font-weight: 500;
  }

  .tag-old {
    background: var(--red-bg);
    color: var(--red);
    font-size: 10px;
    padding: 2px 7px;
    border-radius: 20px;
    font-weight: 600;
  }

  .tag-new {
    background: #f0fdf4;
    color: var(--green);
    font-size: 10px;
    padding: 2px 7px;
    border-radius: 20px;
  }

  @media print {
    body {
      background: white;
    }

    .nav,
    .footer {
      -webkit-print-color-adjust: exact;
      print-color-adjust: exact;
    }
  }
</style>
</head>
<body>

<nav class="nav">
  <div class="nav-brand">
    MIP Scanner <span>/ User Findings Report</span>
  </div>
  <div class="nav-meta">$Organisation</div>
</nav>

<div class="hero">
  <div class="hero-eyebrow">Microsoft Purview Information Protection Scanner</div>
  <h1>User SIT Findings</h1>
  <div class="hero-sub">
    Sensitive information type matches per user, broken down by share, with file-level detail on click.
  </div>
  <div class="hero-badges">
    <span class="badge ok">&#10003; Discovery mode</span>
    <span class="badge ok">&#10003; No files modified</span>
    <span class="badge info">Scan date: $scanDate</span>
    <span class="badge info">Generated: $genDate</span>
  </div>
</div>

<div class="container">

  <div class="notice">
    <strong>Read-only scan, no files have been modified, labelled, or protected</strong>
    The scanner read file contents and matched against your configured sensitive information types. Nothing was written to disk.
  </div>

  <div class="kpi-grid">
    <div class="kpi">
      <div class="kpi-num">$total</div>
      <div class="kpi-label">Files scanned</div>
      <div class="kpi-sub">total across all repositories</div>
    </div>
    <div class="kpi">
      <div class="kpi-num red">$withSIT</div>
      <div class="kpi-label">Files with SIT matches</div>
      <div class="kpi-sub">contain sensitive content</div>
    </div>
    <div class="kpi">
      <div class="kpi-num">$usersWithSIT</div>
      <div class="kpi-label">Users with findings</div>
      <div class="kpi-sub">of $totalUsers active users</div>
    </div>
    <div class="kpi">
      <div class="kpi-num amber">$totalOver5</div>
      <div class="kpi-label">SIT files over 5 years</div>
      <div class="kpi-sub">GDPR art. 5(1)(e) concern</div>
    </div>
  </div>

  <div class="card">
    <div class="card-header">
      <div class="card-title">All users with SIT findings</div>
      <div class="card-count">Sorted by SIT file count &middot; click any row to view files</div>
    </div>
    <table>
      <thead>
        <tr>
          <th style="width:36px;padding-left:20px;">#</th>
          <th>User &middot; share breakdown</th>
          <th style="text-align:center;width:90px;">SIT files</th>
          <th style="width:100px;">Exposure</th>
          <th style="text-align:center;width:110px;">Over 5 years</th>
        </tr>
      </thead>
      <tbody>$userRows</tbody>
    </table>
  </div>

</div>

<footer class="footer">
  <span>MIPUserReport.ps1 &middot; MIT License &middot; <a href="https://mathiasbaden.com" target="_blank">mathiasbaden.com</a></span>
  <span>$scanDate &middot; No data left the server to generate this report</span>
</footer>

<!-- OVERLAY -->
<div id="overlay" onclick="closeModal()" style="display:none;"></div>

<!-- MODAL -->
<div id="modalbox" style="display:none;">
  <div class="modal-head">
    <div>
      <div id="modal-title" class="modal-title"></div>
      <div id="modal-sub" class="modal-sub"></div>
    </div>
    <button class="modal-close" onclick="closeModal()">&#215;</button>
  </div>

  <div class="modal-toolbar">
    <input id="modal-search" class="modal-search" type="text" placeholder="Filter by file, folder, or SIT type&#x2026;" oninput="doFilter()">
    <label class="modal-chk">
      <input type="checkbox" id="modal-old" onchange="doFilter()"> Over 5 years only
    </label>
    <button class="modal-export" onclick="doExport()">&#11015; Export CSV</button>
    <span id="modal-count" class="modal-count"></span>
  </div>

  <div class="modal-body">
    <table style="width:100%;border-collapse:collapse;">
      <thead>
        <tr>
          <th class="modal-th">File</th>
          <th class="modal-th">Folder path</th>
          <th class="modal-th">SIT type</th>
          <th class="modal-th">Last modified</th>
          <th class="modal-th" style="text-align:center;">Age</th>
        </tr>
      </thead>
      <tbody id="modal-body"></tbody>
    </table>
  </div>

  <div class="modal-foot">
    MIPUserReport.ps1 &middot; MIT License &middot; mathiasbaden.com &middot; No data left the server
  </div>
</div>

<script>
var PLACEHOLDER_USERDATA = 1;

var cur = [];
var curName = '';

function openModal(name) {
  curName = name;
  cur = USER_FILES[name] || [];

  document.getElementById('modal-title').textContent = name;
  document.getElementById('modal-search').value = '';
  document.getElementById('modal-old').checked = false;

  render(cur);

  document.getElementById('overlay').style.display = 'block';
  document.getElementById('modalbox').style.display = 'flex';
}

function closeModal() {
  document.getElementById('overlay').style.display = 'none';
  document.getElementById('modalbox').style.display = 'none';
}

function doFilter() {
  var q = document.getElementById('modal-search').value.toLowerCase();
  var o = document.getElementById('modal-old').checked;

  render(cur.filter(function(f) {
    var file = (f.file || '').toLowerCase();
    var folder = (f.folder || '').toLowerCase();
    var sit = (f.sit || '').toLowerCase();

    if (o && !f.over5) return false;

    if (q &&
        file.indexOf(q) < 0 &&
        folder.indexOf(q) < 0 &&
        sit.indexOf(q) < 0) {
      return false;
    }

    return true;
  }));
}

function render(files) {
  var o5 = files.filter(function(f) {
    return f.over5;
  }).length;

  document.getElementById('modal-sub').textContent = files.length + ' files · ' + o5 + ' over 5 years';
  document.getElementById('modal-count').textContent = files.length + ' shown';

  var html = '';

  for (var i = 0; i < files.length; i++) {
    var f = files[i];
    var bg = f.over5 ? '#fef2f2' : (i % 2 ? '#ffffff' : '#f8fafc');
    var lm = f.lm ? f.lm.replace('Z','').replace('T',' ').substring(0,16) : '—';

    var age = f.over5
      ? '<span class="tag-old">+5 yrs</span>'
      : '<span class="tag-new">recent</span>';

    html += '<tr style="background:' + bg + ';">'
      + '<td class="modal-td" title="' + esc(f.path) + '" style="max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">' + esc(f.file) + '</td>'
      + '<td class="modal-td" style="font-family:monospace;font-size:10px;color:#64748b;">' + esc(f.folder) + '</td>'
      + '<td class="modal-td"><span class="tag-sit">' + esc(f.sit) + '</span></td>'
      + '<td class="modal-td" style="color:#64748b;">' + esc(lm) + '</td>'
      + '<td class="modal-td" style="text-align:center;">' + age + '</td>'
      + '</tr>';
  }

  document.getElementById('modal-body').innerHTML = html ||
    '<tr><td colspan="5" style="text-align:center;padding:32px;color:#94a3b8;">No files match the current filter</td></tr>';
}

function doExport() {
  var q = document.getElementById('modal-search').value.toLowerCase();
  var o = document.getElementById('modal-old').checked;

  var res = cur.filter(function(f) {
    var file = (f.file || '').toLowerCase();
    var folder = (f.folder || '').toLowerCase();
    var sit = (f.sit || '').toLowerCase();

    if (o && !f.over5) return false;

    if (q &&
        file.indexOf(q) < 0 &&
        folder.indexOf(q) < 0 &&
        sit.indexOf(q) < 0) {
      return false;
    }

    return true;
  });

  var q2 = function(v) {
    return '"' + (v || '').replace(/"/g, '""') + '"';
  };

  var lines = [
    ['User','File Name','Folder','SIT Type','Last Modified','Over 5 Years'].map(q2).join(',')
  ];

  for (var i = 0; i < res.length; i++) {
    var f = res[i];

    lines.push([
      q2(curName),
      q2(f.file),
      q2(f.folder),
      q2(f.sit),
      q2(f.lm ? f.lm.replace('Z','').replace('T',' ').substring(0,16) : ''),
      q2(f.over5 ? 'Yes' : 'No')
    ].join(','));
  }

  var csv = '\uFEFF' + lines.join('\r\n');
  var blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
  var url = URL.createObjectURL(blob);
  var a = document.createElement('a');

  a.href = url;
  a.download = 'SIT_' + curName.replace(/[^a-zA-Z0-9_\-\.æøåÆØÅ]/g, '_') + '.csv';

  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function esc(s) {
  return (s || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

document.addEventListener('keydown', function(e) {
  if (e.key === 'Escape') {
    closeModal();
  }
});
</script>

</body>
</html>
"@

# Inject user data JS safely outside the here-string
$html = $html.Replace('var PLACEHOLDER_USERDATA = 1;', $userDataJS)

$html | Out-File -FilePath $OutputPath -Encoding UTF8
$size = [math]::Round((Get-Item $OutputPath).Length / 1KB, 1)

Write-Host ""
Write-Host "==================================================" -ForegroundColor Green
Write-Host " User report generated!" -ForegroundColor Green
Write-Host "==================================================" -ForegroundColor Green
Write-Host " File:    $OutputPath" -ForegroundColor Cyan
Write-Host " Size:    $size KB" -ForegroundColor Cyan
Write-Host " Users:   $usersWithSIT" -ForegroundColor Cyan
Write-Host " Over 5y: $totalOver5 SIT files" -ForegroundColor Cyan
Write-Host ""

if ($OpenInBrowser) {
    Start-Process $OutputPath
}