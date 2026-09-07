# V.1 Fixture-driven test harness (in-process injection)
# Injects code in the current process, then spawns a subprocess to scan this process.

param(
    [string]$FixtureName = "",
    [switch]$ListOnly = $false,
    [switch]$Verbose = $false
)

$ErrorActionPreference = "Stop"
$TestDir = $PSScriptRoot
$JockyMemExe = Join-Path (Split-Path $TestDir -Parent | Split-Path -Parent) "jocky-mem.exe"

# P/Invoke for memory ops
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class MemOps {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualFree(IntPtr lpAddress, uint dwSize, uint dwFreeType);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll")]
    public static extern uint GetCurrentProcessId();

    public const uint MEM_COMMIT = 0x1000;
    public const uint MEM_RELEASE = 0x8000;
    public const uint PAGE_EXECUTE_READWRITE = 0x40;
    public const uint PAGE_READWRITE = 0x04;
    public const uint PAGE_EXECUTE_READ = 0x20;
}
"@

$Fixtures = @(
    @{
        name = "f5_1_rwx"
        techniques = @("rwx", "write-exec")
        expectedReasons = @("rwx", "write-exec")
        description = "F.5.1: RWX and write-then-exec detection"
        inject = {
            param([string]$Technique)
            $buf = New-Object byte[] 4096
            for ($i = 0; $i -lt 4096; $i++) { $buf[$i] = 0x90 }

            if ($Technique -eq "rwx") {
                $mem = [MemOps]::VirtualAlloc([IntPtr]::Zero, 4096, [MemOps]::MEM_COMMIT, [MemOps]::PAGE_EXECUTE_READWRITE)
                if ($mem -eq 0) { throw "VirtualAlloc failed" }
                [System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $mem, 4096)
                Write-Host "RWX at $([String]::Format('0x{0:X}', [Int64]$mem))"
            } elseif ($Technique -eq "write-exec") {
                $mem = [MemOps]::VirtualAlloc([IntPtr]::Zero, 4096, [MemOps]::MEM_COMMIT, [MemOps]::PAGE_READWRITE)
                if ($mem -eq 0) { throw "VirtualAlloc failed" }
                [System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $mem, 4096)
                [uint32]$oldProt = 0
                [MemOps]::VirtualProtect($mem, 4096, [MemOps]::PAGE_EXECUTE_READ, [ref]$oldProt) | Out-Null
                Write-Host "RW->RX at $([String]::Format('0x{0:X}', [Int64]$mem))"
            }
            $mem
        }
    },
    @{
        name = "f5_2_exec_private"
        techniques = @()
        expectedReasons = @("exec-private")
        description = "F.5.2: Executable private memory (unbacked)"
        inject = {
            $buf = New-Object byte[] 4096
            [Array]::Fill($buf, 0x90)
            $mem = [MemOps]::VirtualAlloc([IntPtr]::Zero, 4096, [MemOps]::MEM_COMMIT, [MemOps]::PAGE_EXECUTE_READ)
            if ($mem -eq 0) { throw "VirtualAlloc failed" }
            [System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $mem, 4096)
            Write-Host "Private exec at $([String]::Format('0x{0:X}', [Int64]$mem))"
            $mem
        }
    },
    @{
        name = "f5_4_pe_sig"
        techniques = @()
        expectedReasons = @("pe-sig")
        description = "F.5.4: PE signature out of module list"
        inject = {
            $mem = [MemOps]::VirtualAlloc([IntPtr]::Zero, 4096, [MemOps]::MEM_COMMIT, [MemOps]::PAGE_READWRITE)
            if ($mem -eq 0) { throw "VirtualAlloc failed" }
            $hdr = @(0x4D, 0x5A) + @(0x00) * 27 + @(0x40, 0x00, 0x00, 0x00)
            [System.Runtime.InteropServices.Marshal]::Copy($hdr, 0, $mem, $hdr.Length)
            $pe = @(0x50, 0x45, 0x00, 0x00)
            [System.Runtime.InteropServices.Marshal]::Copy($pe, 0, [IntPtr]($mem.ToInt64() + 0x40), $pe.Length)
            Write-Host "PE header at $([String]::Format('0x{0:X}', [Int64]$mem))"
            $mem
        }
    },
    @{
        name = "f5_7_thread_anomaly"
        techniques = @()
        expectedReasons = @("thread-addr")
        description = "F.5.7: Thread start address anomaly"
        inject = {
            $buf = New-Object byte[] 4096
            [Array]::Fill($buf, 0x90)
            $mem = [MemOps]::VirtualAlloc([IntPtr]::Zero, 4096, [MemOps]::MEM_COMMIT, [MemOps]::PAGE_EXECUTE_READ)
            if ($mem -eq 0) { throw "VirtualAlloc failed" }
            [System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $mem, 4096)
            $tid = 0
            $thread = [MemOps]::CreateThread([IntPtr]::Zero, 0, $mem, [IntPtr]::Zero, 0, [ref]$tid)
            if ($thread -eq [IntPtr]::Zero) { throw "CreateThread failed" }
            Write-Host "Thread anomaly at $([String]::Format('0x{0:X}', [Int64]$mem)) tid=$tid"
            [MemOps]::CloseHandle($thread) | Out-Null
            $mem
        }
    },
    @{
        name = "f5_10_single_page_exec"
        techniques = @()
        expectedReasons = @("single-page-exec")
        description = "F.5.10: Single-page executable"
        inject = {
            $buf = New-Object byte[] 4096
            [Array]::Fill($buf, 0x90)
            $mem = [MemOps]::VirtualAlloc([IntPtr]::Zero, 4096, [MemOps]::MEM_COMMIT, [MemOps]::PAGE_EXECUTE_READ)
            if ($mem -eq 0) { throw "VirtualAlloc failed" }
            [System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $mem, 4096)
            Write-Host "Single-page exec at $([String]::Format('0x{0:X}', [Int64]$mem))"
            $mem
        }
    }
)

function Run-FixtureTest {
    param(
        [object]$Fixture,
        [string]$Technique = ""
    )

    if (!(Test-Path $JockyMemExe)) {
        Write-Host "  ERROR: jocky-mem.exe not found" -ForegroundColor Red
        return @{ passed = $false; error = "jocky-mem not found" }
    }

    Write-Host "Testing: $($Fixture.name) $Technique" -ForegroundColor Cyan
    Write-Host "  $($Fixture.description)" -ForegroundColor Gray

    # Perform injection in this process
    Write-Host "  Injecting..." -ForegroundColor Gray
    try {
        $injectionArgs = @()
        if ($Technique) {
            $injectionArgs = @($Technique)
        }
        & $Fixture.inject @injectionArgs
    } catch {
        Write-Host "  ERROR: Injection failed: $_" -ForegroundColor Red
        return @{ passed = $false; error = "Injection failed: $_" }
    }

    # Get our current PID and scan ourselves
    $ourPid = [MemOps]::GetCurrentProcessId()
    Write-Host "  Scanning PID $ourPid..." -ForegroundColor Gray
    $scanOutput = & $JockyMemExe inventory $ourPid 2>&1

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
Write-Host "V.1 Fixture-Driven Detection Tests (In-Process)" -ForegroundColor Cyan
Write-Host "===============================================" -ForegroundColor Cyan
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
            $allResults += @{ fixture = $fixture.name; technique = $tech; passed = $result.passed }
        }
    } else {
        $result = Run-FixtureTest $fixture ""
        $allResults += @{ fixture = $fixture.name; technique = ""; passed = $result.passed }
    }
    Write-Host ""
}

$passed = $allResults | Where-Object { $_.passed } | Measure-Object | Select-Object -ExpandProperty Count
$failed = $allResults | Where-Object { !$_.passed } | Measure-Object | Select-Object -ExpandProperty Count

Write-Host "Summary" -ForegroundColor Cyan
Write-Host "=======" -ForegroundColor Cyan
Write-Host "$passed passed, $failed failed" -ForegroundColor $(if ($failed -eq 0) { "Green" } else { "Red" })

exit $(if ($failed -eq 0) { 0 } else { 1 })
