# V.1 Fixture-driven test harness (simplified version using PowerShell fixtures)

param(
    [string]$FixtureName = "",
    [switch]$ListOnly = $false,
    [switch]$Verbose = $false
)

$ErrorActionPreference = "Stop"
$TestDir = $PSScriptRoot
$FixturesDir = Join-Path $TestDir "fixtures"
$JockyMemExe = Join-Path (Split-Path $TestDir -Parent | Split-Path -Parent) "jocky-mem.exe"

$Fixtures = @(
    @{
        name = "f5_1_rwx"
        script = "f5_1_rwx.ps1"
        techniques = @("rwx", "write-exec")
        expectedReasons = @("rwx", "write-exec")
        description = "F.5.1: RWX and write-then-exec detection"
    },
    @{
        name = "f5_2_exec_private"
        script = "f5_2_exec_private.ps1"
        techniques = @()
        expectedReasons = @("exec-private")
        description = "F.5.2: Executable private memory (unbacked)"
    },
    @{
        name = "f5_4_pe_sig"
        script = "f5_4_pe_sig.ps1"
        techniques = @()
        expectedReasons = @("pe-sig")
        description = "F.5.4: PE signature out of module list"
    },
    @{
        name = "f5_7_thread_anomaly"
        script = "f5_7_thread_anomaly.ps1"
        techniques = @()
        expectedReasons = @("thread-addr")
        description = "F.5.7: Thread start address anomaly"
    },
    @{
        name = "f5_10_single_page_exec"
        script = "f5_10_single_page_exec.ps1"
        techniques = @()
        expectedReasons = @("single-page-exec")
        description = "F.5.10: Single-page executable"
    }
)

function Run-FixtureTest {
    param(
        [object]$Fixture,
        [string]$Technique = ""
    )

    $scriptPath = Join-Path $FixturesDir $Fixture.script
    if (!(Test-Path $scriptPath)) {
        Write-Host "  ERROR: Script not found: $scriptPath" -ForegroundColor Red
        return @{ passed = $false; error = "Script not found" }
    }

    if (!(Test-Path $JockyMemExe)) {
        Write-Host "  ERROR: jocky-mem.exe not found" -ForegroundColor Red
        return @{ passed = $false; error = "jocky-mem not found" }
    }

    Write-Host "Testing: $($Fixture.name) $Technique" -ForegroundColor Cyan
    Write-Host "  $($Fixture.description)" -ForegroundColor Gray

    # Build command line arguments for the fixture script
    $fixtureArgs = @()
    if ($Technique) {
        $fixtureArgs += $Technique
    }

    # Start the fixture process
    Write-Host "  Spawning fixture..." -ForegroundColor Gray
    $argList = @(
        '-NoProfile',
        '-NonInteractive',
        '-File',
        $scriptPath
    ) + $fixtureArgs
    $proc = Start-Process powershell.exe -ArgumentList $argList -PassThru

    $targetPid = $proc.Id
    Write-Host "  PID: $targetPid" -ForegroundColor Gray

    # Wait for injection to complete
    Start-Sleep -Milliseconds 500

    # Run jocky-mem scan
    Write-Host "  Running jocky-mem inventory..." -ForegroundColor Gray
    $scanOutput = & $JockyMemExe inventory $targetPid 2>&1

    # Kill the fixture process
    try {
        $proc | Stop-Process -Force -ErrorAction SilentlyContinue
        $proc | Wait-Process -ErrorAction SilentlyContinue
    } catch { }

    if ($Verbose) {
        Write-Host "  Scan output:" -ForegroundColor Gray
        $scanOutput | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
    }

    # Parse findings
    $findings = @()
    $inFindings = $false
    foreach ($line in $scanOutput) {
        if ($line -match "^Findings:") {
            $inFindings = $true
            continue
        }
        if ($inFindings -and $line -match "0x[0-9a-f]+\s+\d+\s+(\S+)\s+\(severity") {
            $reason = $matches[1]
            if ($reason -notin $findings) {
                $findings += $reason
            }
        }
    }

    Write-Host "  Found findings: $($findings -join ', ')" -ForegroundColor Green

    # Verify expected findings
    $passed = $true
    foreach ($expected in $Fixture.expectedReasons) {
        if ($findings -notcontains $expected) {
            Write-Host "  FAIL: Expected '$expected' not found" -ForegroundColor Red
            $passed = $false
        } else {
            Write-Host "  OK: Found '$expected'" -ForegroundColor Green
        }
    }

    return @{ passed = $passed; findings = $findings }
}

# Main
Write-Host ""
Write-Host "V.1 Fixture-Driven Detection Tests" -ForegroundColor Cyan
Write-Host "===================================" -ForegroundColor Cyan
Write-Host ""

if ($ListOnly) {
    Write-Host "Available fixtures:" -ForegroundColor Cyan
    foreach ($fixture in $Fixtures) {
        Write-Host "  $($fixture.name)" -ForegroundColor White
        Write-Host "    $($fixture.description)" -ForegroundColor Gray
    }
    exit 0
}

if ($FixtureName) {
    $fixture = $Fixtures | Where-Object { $_.name -eq $FixtureName }
    if (!$fixture) {
        Write-Host "Unknown fixture: $FixtureName" -ForegroundColor Red
        exit 1
    }

    $results = @()
    if ($fixture.techniques.Count -gt 0) {
        foreach ($tech in $fixture.techniques) {
            $result = Run-FixtureTest $fixture $tech
            $results += $result
            if (!$result.passed) {
                exit 1
            }
        }
    } else {
        $result = Run-FixtureTest $fixture ""
        $results += $result
        if (!$result.passed) {
            exit 1
        }
    }
    exit 0
}

# Run all
$allResults = @()
foreach ($fixture in $Fixtures) {
    if ($fixture.techniques.Count -gt 0) {
        foreach ($tech in $fixture.techniques) {
            $result = Run-FixtureTest $fixture $tech
            $allResults += @{
                fixture = $fixture.name
                technique = $tech
                passed = $result.passed
            }
        }
    } else {
        $result = Run-FixtureTest $fixture ""
        $allResults += @{
            fixture = $fixture.name
            technique = ""
            passed = $result.passed
        }
    }
    Write-Host ""
}

$passed = $allResults | Where-Object { $_.passed } | Measure-Object | Select-Object -ExpandProperty Count
$failed = $allResults | Where-Object { !$_.passed } | Measure-Object | Select-Object -ExpandProperty Count

Write-Host "Summary" -ForegroundColor Cyan
Write-Host "=======" -ForegroundColor Cyan
Write-Host "$passed passed, $failed failed" -ForegroundColor $(if ($failed -eq 0) { "Green" } else { "Red" })

exit $(if ($failed -eq 0) { 0 } else { 1 })
