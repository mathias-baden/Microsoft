# MIPUserReport.ps1

A PowerShell script that turns a Microsoft Purview Information Protection (MIP) Scanner
**DetailedReport CSV** into a single, self-contained HTML report — one row per user, with
a share-by-share breakdown of Sensitive Information Type (SIT) findings and a click-to-view
file browser.

![Demo](docs/assets/demo.gif)

- 100% client-side — no data leaves the machine that opens the report
- No files are modified, labelled, or protected — read-only reporting
- Per-user breakdown by share, with SIT type counts
- Flags files with sensitive data **not modified in over 5 years** (GDPR art. 5(1)(e) risk)
- Click any user row to browse their individual files, filter, and export to CSV

## Requirements

- Windows PowerShell 5.1+ (or PowerShell 7+)
- A `DetailedReport_*.csv` file produced by the MIP Scanner
  (default location: `C:\Users\svc-mipscanner\AppData\Local\Microsoft\MSIP\Scanner\Reports`)

## Usage

```powershell
.\scripts\MIPUserReport.ps1 -Organisation "Contoso A/S" -CsvPath "C:\Reports\DetailedReport_2026-08-19.csv"
```

| Parameter         | Required    | Description |
|--------------------|:-----------:|-------------|
| `-Organisation`    | Recommended | Customer/company name shown in the report title and header |
| `-CsvPath`         | No | Path to the scanner's `DetailedReport_*.csv`. If omitted, the newest one is auto-detected |
| `-ServiceAccount`  | No | If not running as the scanner's service account, set this to its username (e.g. `svc-mipscanner`) so the script reads its report folder instead |
| `-OutputPath`      | No | Where to save the generated `.html` report. Defaults to the same folder as the CSV |
| `-OpenInBrowser`   | No | Switch — opens the finished report automatically |

### Examples

```powershell
.\scripts\MIPUserReport.ps1 -Organisation "Contoso A/S" -OpenInBrowser
```

```powershell
.\scripts\MIPUserReport.ps1 -Organisation "Contoso A/S" -ServiceAccount "svc-mipscanner"
```

## Output

A single `.html` file containing:

- KPI summary (files scanned, files with SIT matches, users with findings, files over 5 years old)
- A sortable table of every user with SIT findings, broken down by share
- A per-user modal (click any row) listing every matching file, with search/filter and CSV export

## License

MIT License — Copyright (c) 2026 Mathias Baden Frederiksen — https://mathiasbaden.com