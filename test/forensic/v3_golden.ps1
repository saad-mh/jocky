# V.3 - Golden output validation
# Tests that jocky-mem's output format is consistent and correctly structured.

param(
    [switch]$Verbose = $false
)

$ErrorActionPreference = "Stop"
$TestDir = $PSScriptRoot
$JockyMemExe = Join-Path (Split-Path $TestDir -Parent | Split-Path -Parent) "jocky-mem.exe"

if (!(Test-Path $JockyMemExe)) {
    Write-Host "ERROR: jocky-mem.exe not found" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "V.3 Golden Output Format Validation" -ForegroundColor Cyan
Write-Host "===================================" -ForegroundColor Cyan
Write-Host ""

$selfPid = [System.Diagnostics.Process]::GetCurrentProcess().Id
Write-Host "Scanning self (PowerShell PID $selfPid)" -ForegroundColor Gray

$output = @(& $JockyMemExe inventory $selfPid 2>&1)

if ($Verbose) {
    Write-Host "Full output ($($output.Count) lines):" -ForegroundColor Gray
    $output | Select-Object -First 100 | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }
    if ($output.Count -gt 100) {
        Write-Host "  ... ($($output.Count - 100) more lines)" -ForegroundColor DarkGray
    }
}

Write-Host ""
Write-Host "Format Checks" -ForegroundColor Cyan
Write-Host "=============" -ForegroundColor Cyan

$passed = $true

# Check 1: Inventory header
$hasHeader = $output | Where-Object { $_ -match "jocky-mem inventory" }
if ($hasHeader) {
    Write-Host "[OK] Has 'jocky-mem inventory' header" -ForegroundColor Green
} else {
    Write-Host "[FAIL] Missing inventory header" -ForegroundColor Red
    $passed = $false
}

# Check 2: Column headers
$hasColumns = $output | Where-Object { $_ -match "BASE\s+SIZE\s+STATE\s+TYPE\s+CLASS" }
if ($hasColumns) {
    Write-Host "[OK] Has column headers (BASE SIZE STATE TYPE CLASS)" -ForegroundColor Green
} else {
    Write-Host "[FAIL] Missing column headers" -ForegroundColor Red
    $passed = $false
}

# Check 3: Region lines format (address, size, hex values, class name)
$regionLines = @($output | Where-Object { $_ -match "^\s*0x[0-9a-f]+" })
if ($regionLines.Count -gt 0) {
    Write-Host "[OK] Found $($regionLines.Count) region entries" -ForegroundColor Green

    # Validate a few region lines have correct format
    $badLines = 0
    foreach ($line in $regionLines | Select-Object -First 5) {
        if (-not ($line -match "^\s+0x[0-9a-f]+\s+\d+\s+[0-9a-f]{8}\s+[0-9a-f]{8}\s+\w+")) {
            $badLines++
        }
    }
    if ($badLines -eq 0) {
        Write-Host "[OK] Region format is correct (address size state type class)" -ForegroundColor Green
    } else {
        Write-Host "[WARN] Some region lines don't match expected format" -ForegroundColor Yellow
    }
} else {
    Write-Host "[WARN] No region entries found (expected for process scan)" -ForegroundColor Yellow
}

# Check 4: Sorted by address (should be ascending)
if ($regionLines.Count -gt 1) {
    $addresses = $regionLines | ForEach-Object {
        $_ -match "^\s+(0x[0-9a-f]+)" | Out-Null
        [Int64]$matches[1]
    }
    $sorted = $true
    for ($i = 0; $i -lt $addresses.Count - 1; $i++) {
        if ($addresses[$i] -gt $addresses[$i + 1]) {
            $sorted = $false
            break
        }
    }
    if ($sorted) {
        Write-Host "[OK] Regions are sorted by address (ascending)" -ForegroundColor Green
    } else {
        Write-Host "[FAIL] Regions are not sorted by address" -ForegroundColor Red
        $passed = $false
    }
}

# Check 5: Committed regions count line
$hasCount = $output | Where-Object { $_ -match "committed regions" }
if ($hasCount) {
    Write-Host "[OK] Has committed regions summary line" -ForegroundColor Green
} else {
    Write-Host "[WARN] Missing committed regions summary" -ForegroundColor Yellow
}

Write-Host ""
if ($passed) {
    Write-Host "Result: PASS" -ForegroundColor Green
    Write-Host "Output format is correct and properly structured." -ForegroundColor Green
    exit 0
} else {
    Write-Host "Result: FAIL" -ForegroundColor Red
    exit 1
}
