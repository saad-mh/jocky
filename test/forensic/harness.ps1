# Fixture-driven test harness for forensic memory tool (V.1)
# PowerShell-based fixtures that inject code into child processes for testing.

param(
    [string]$FixtureName = "",
    [switch]$ListOnly = $false,
    [switch]$Verbose = $false
)

$ErrorActionPreference = "Stop"
$TestDir = $PSScriptRoot
$JockyMemExe = Join-Path (Split-Path $TestDir -Parent | Split-Path -Parent) "jocky-mem.exe"

# Define test fixtures with memory injection techniques
$Fixtures = @(
    @{
        name = "f5_1_rwx"
        description = "F.5.1: RWX and write-then-exec detection"
        expectedReasons = @("rwx", "write-exec")
        techniques = @(
            @{ name = "rwx"; action = { Inject-RWX } },
            @{ name = "write-exec"; action = { Inject-WriteExec } }
        )
    },
    @{
        name = "f5_2_exec_private"
        description = "F.5.2: Executable private memory (unbacked)"
        expectedReasons = @("exec-private")
        techniques = @(
            @{ name = "exec-private"; action = { Inject-ExecPrivate } }
        )
    },
    @{
        name = "f5_4_pe_sig"
        description = "F.5.4: PE signature out of module list"
        expectedReasons = @("pe-sig")
        techniques = @(
            @{ name = "pe-sig"; action = { Inject-PESignature } }
        )
    },
    @{
        name = "f5_7_thread_anomaly"
        description = "F.5.7: Thread start address anomaly"
        expectedReasons = @("thread-addr")
        techniques = @(
            @{ name = "thread-addr"; action = { Inject-ThreadAnomaly } }
        )
    },
    @{
        name = "f5_10_single_page_exec"
        description = "F.5.10: Single-page executable (small corroborator)"
        expectedReasons = @("single-page-exec")
        techniques = @(
            @{ name = "single-page-exec"; action = { Inject-SinglePageExec } }
        )
    }
)

# P/Invoke signatures for memory operations
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

    public const uint MEM_COMMIT = 0x1000;
    public const uint MEM_RELEASE = 0x8000;
    public const uint PAGE_EXECUTE_READWRITE = 0x40;
    public const uint PAGE_READWRITE = 0x04;
    public const uint PAGE_EXECUTE_READ = 0x20;
}
"@

# F.5.1: Allocate RWX memory and write shellcode
function Inject-RWX {
    $mem = [MemOps]::VirtualAlloc([IntPtr]::Zero, 4096, [MemOps]::MEM_COMMIT, [MemOps]::PAGE_EXECUTE_READWRITE)
    if ($mem -eq 0) {
        throw "VirtualAlloc failed"
    }

    # Write NOP sled
    [System.Runtime.InteropServices.Marshal]::Copy(@(0x90 * 4096 | % { $_ -band 0xFF }), 0, $mem, 4096)

    Write-Host "Allocated RWX at $([String]::Format('0x{0:X}', [Int64]$mem))" -ForegroundColor Cyan
    Start-Sleep -Seconds 2  # Keep alive for scanning

    [MemOps]::VirtualFree($mem, 0, [MemOps]::MEM_RELEASE) | Out-Null
}

# F.5.1: Allocate RW, write, then change to RX
function Inject-WriteExec {
    $mem = [MemOps]::VirtualAlloc([IntPtr]::Zero, 4096, [MemOps]::MEM_COMMIT, [MemOps]::PAGE_READWRITE)
    if ($mem -eq 0) {
        throw "VirtualAlloc failed"
    }

    # Write NOP sled
    [System.Runtime.InteropServices.Marshal]::Copy(@(0x90 * 4096 | % { $_ -band 0xFF }), 0, $mem, 4096)

    # Change to RX
    [uint32]$oldProt = 0
    [MemOps]::VirtualProtect($mem, 4096, [MemOps]::PAGE_EXECUTE_READ, [ref]$oldProt) | Out-Null

    Write-Host "Allocated RW->RX at $([String]::Format('0x{0:X}', [Int64]$mem))" -ForegroundColor Cyan
    Start-Sleep -Seconds 2

    [MemOps]::VirtualFree($mem, 0, [MemOps]::MEM_RELEASE) | Out-Null
}

# F.5.2: Allocate private executable memory (unbacked)
function Inject-ExecPrivate {
    $mem = [MemOps]::VirtualAlloc([IntPtr]::Zero, 4096, [MemOps]::MEM_COMMIT, [MemOps]::PAGE_EXECUTE_READ)
    if ($mem -eq 0) {
        throw "VirtualAlloc failed"
    }

    # Write NOP sled
    [System.Runtime.InteropServices.Marshal]::Copy(@(0x90 * 4096 | % { $_ -band 0xFF }), 0, $mem, 4096)

    Write-Host "Allocated private exec at $([String]::Format('0x{0:X}', [Int64]$mem))" -ForegroundColor Cyan
    Start-Sleep -Seconds 2

    [MemOps]::VirtualFree($mem, 0, [MemOps]::MEM_RELEASE) | Out-Null
}

# F.5.4: Write PE header (MZ + PE signature)
function Inject-PESignature {
    $mem = [MemOps]::VirtualAlloc([IntPtr]::Zero, 4096, [MemOps]::MEM_COMMIT, [MemOps]::PAGE_READWRITE)
    if ($mem -eq 0) {
        throw "VirtualAlloc failed"
    }

    # Write DOS header: MZ signature
    $hdr = @(
        0x4D, 0x5A  # "MZ"
        + @(0x00) * 27
        + @(0x40, 0x00, 0x00, 0x00)  # e_lfanew = 0x40
    )
    [System.Runtime.InteropServices.Marshal]::Copy($hdr, 0, $mem, $hdr.Length)

    # Write PE signature at offset 0x40
    $pe = @(0x50, 0x45, 0x00, 0x00)  # "PE\0\0"
    [System.Runtime.InteropServices.Marshal]::Copy($pe, 0, [IntPtr]($mem.ToInt64() + 0x40), $pe.Length)

    Write-Host "Wrote PE header at $([String]::Format('0x{0:X}', [Int64]$mem))" -ForegroundColor Cyan
    Start-Sleep -Seconds 2

    [MemOps]::VirtualFree($mem, 0, [MemOps]::MEM_RELEASE) | Out-Null
}

# F.5.7: Create thread with anomalous start address
function Inject-ThreadAnomaly {
    $mem = [MemOps]::VirtualAlloc([IntPtr]::Zero, 4096, [MemOps]::MEM_COMMIT, [MemOps]::PAGE_EXECUTE_READ)
    if ($mem -eq 0) {
        throw "VirtualAlloc failed"
    }

    # Write NOP sled
    [System.Runtime.InteropServices.Marshal]::Copy(@(0x90 * 4096 | % { $_ -band 0xFF }), 0, $mem, 4096)

    # Create thread that starts at this fake address
    $threadId = 0
    $thread = [MemOps]::CreateThread([IntPtr]::Zero, 0, $mem, [IntPtr]::Zero, 0, [ref]$threadId)
    if ($thread -eq [IntPtr]::Zero) {
        [MemOps]::VirtualFree($mem, 0, [MemOps]::MEM_RELEASE) | Out-Null
        throw "CreateThread failed"
    }

    Write-Host "Created thread with anomalous start address at $([String]::Format('0x{0:X}', [Int64]$mem))" -ForegroundColor Cyan
    Start-Sleep -Seconds 2

    [MemOps]::CloseHandle($thread) | Out-Null
    [MemOps]::VirtualFree($mem, 0, [MemOps]::MEM_RELEASE) | Out-Null
}

# F.5.10: Allocate single-page executable
function Inject-SinglePageExec {
    $mem = [MemOps]::VirtualAlloc([IntPtr]::Zero, 4096, [MemOps]::MEM_COMMIT, [MemOps]::PAGE_EXECUTE_READ)
    if ($mem -eq 0) {
        throw "VirtualAlloc failed"
    }

    # Write NOP sled
    [System.Runtime.InteropServices.Marshal]::Copy(@(0x90 * 4096 | % { $_ -band 0xFF }), 0, $mem, 4096)

    Write-Host "Allocated single-page exec at $([String]::Format('0x{0:X}', [Int64]$mem))" -ForegroundColor Cyan
    Start-Sleep -Seconds 2

    [MemOps]::VirtualFree($mem, 0, [MemOps]::MEM_RELEASE) | Out-Null
}

# Spawn a child process running an injection function and scan it
function Run-FixtureTest {
    param(
        [object]$Fixture,
        [object]$Technique
    )

    Write-Host "Testing: $($Fixture.name) - $($Technique.name)" -ForegroundColor Cyan
    Write-Host "  $($Fixture.description)" -ForegroundColor Gray

    if (!(Test-Path $JockyMemExe)) {
        Write-Host "  ERROR: jocky-mem.exe not found at $JockyMemExe" -ForegroundColor Red
        return @{ passed = $false; error = "jocky-mem not found" }
    }

    # Create a temporary PowerShell script that runs the injection and sleeps
    $scriptContent = {
        param($ScriptBlock)
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

    public const uint MEM_COMMIT = 0x1000;
    public const uint MEM_RELEASE = 0x8000;
    public const uint PAGE_EXECUTE_READWRITE = 0x40;
    public const uint PAGE_READWRITE = 0x04;
    public const uint PAGE_EXECUTE_READ = 0x20;
}
"@
        & $ScriptBlock
    }

    # Start child PowerShell process running the injection
    $proc = Start-Process powershell.exe -ArgumentList @(
        '-NoProfile',
        '-NonInteractive',
        '-Command',
        "& {`n$($scriptContent)`n} $($Technique.action)"
    ) -PassThru

    $targetPid = $proc.Id
    Write-Host "  Process PID: $targetPid" -ForegroundColor Gray

    # Wait for injection to happen
    Start-Sleep -Milliseconds 500

    # Run jocky-mem scan
    Write-Host "  Running jocky-mem inventory..." -ForegroundColor Gray
    $scanOutput = & $JockyMemExe inventory $targetPid 2>&1
    $scanExit = $LASTEXITCODE

    # Terminate the process
    $proc | Stop-Process -Force -ErrorAction SilentlyContinue
    $proc | Wait-Process -ErrorAction SilentlyContinue

    if ($Verbose) {
        Write-Host "  Scan output:" -ForegroundColor Gray
        $scanOutput | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
    }

    # Parse findings from output
    $findings = @()
    $inFindings = $false
    foreach ($line in $scanOutput) {
        if ($line -match "^Findings:") {
            $inFindings = $true
            continue
        }
        if ($inFindings -and $line -match "0x[0-9a-f]+\s+\d+\s+(\S+)\s+\(severity") {
            $findings += $matches[1]
        }
    }

    Write-Host "  Found $($findings.Count) findings: $($findings -join ', ')" -ForegroundColor Green

    # Check for expected findings
    $passed = $true
    foreach ($expected in $Fixture.expectedReasons) {
        if ($findings -notcontains $expected) {
            Write-Host "  FAIL: Expected '$expected' not found" -ForegroundColor Red
            $passed = $false
        }
    }

    return @{ passed = $passed; findings = $findings }
}

# Main execution
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
        Write-Error "Unknown fixture: $FixtureName"
        exit 1
    }

    $results = @()
    foreach ($technique in $fixture.techniques) {
        $result = Run-FixtureTest $fixture $technique
        $results += $result
    }

    $allPassed = $results | Where-Object { !$_.passed } | Measure-Object | Select-Object -ExpandProperty Count
    exit $(if ($allPassed -eq 0) { 0 } else { 1 })
}

# Run all fixtures
$allResults = @()
foreach ($fixture in $Fixtures) {
    foreach ($technique in $fixture.techniques) {
        $result = Run-FixtureTest $fixture $technique
        $allResults += @{
            fixture = $fixture.name
            technique = $technique.name
            passed = $result.passed
            findings = $result.findings
        }
    }
    Write-Host ""
}

# Summary
Write-Host "Summary" -ForegroundColor Cyan
Write-Host "=======" -ForegroundColor Cyan
$passed = $allResults | Where-Object { $_.passed } | Measure-Object | Select-Object -ExpandProperty Count
$failed = $allResults | Where-Object { !$_.passed } | Measure-Object | Select-Object -ExpandProperty Count
Write-Host "$passed passed, $failed failed" -ForegroundColor $(if ($failed -eq 0) { "Green" } else { "Red" })

exit $(if ($failed -eq 0) { 0 } else { 1 })
