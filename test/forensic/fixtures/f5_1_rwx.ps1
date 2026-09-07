# F.5.1 injection fixtures: RWX and write-then-exec

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

    public const uint MEM_COMMIT = 0x1000;
    public const uint MEM_RELEASE = 0x8000;
    public const uint PAGE_EXECUTE_READWRITE = 0x40;
    public const uint PAGE_READWRITE = 0x04;
    public const uint PAGE_EXECUTE_READ = 0x20;
}
"@

param([string]$Technique = "rwx")

$mem = [IntPtr]::Zero

if ($Technique -eq "rwx") {
    $mem = [MemOps]::VirtualAlloc([IntPtr]::Zero, 4096, [MemOps]::MEM_COMMIT, [MemOps]::PAGE_EXECUTE_READWRITE)
    if ($mem -eq 0) { throw "VirtualAlloc failed" }
    [System.Runtime.InteropServices.Marshal]::Copy(@(0x90 * 4096 | ForEach-Object { $_ -band 0xFF }), 0, $mem, 4096)
    Write-Host "RWX at $([String]::Format('0x{0:X}', [Int64]$mem))"
} elseif ($Technique -eq "write-exec") {
    $mem = [MemOps]::VirtualAlloc([IntPtr]::Zero, 4096, [MemOps]::MEM_COMMIT, [MemOps]::PAGE_READWRITE)
    if ($mem -eq 0) { throw "VirtualAlloc failed" }
    [System.Runtime.InteropServices.Marshal]::Copy(@(0x90 * 4096 | ForEach-Object { $_ -band 0xFF }), 0, $mem, 4096)
    [uint32]$oldProt = 0
    [MemOps]::VirtualProtect($mem, 4096, [MemOps]::PAGE_EXECUTE_READ, [ref]$oldProt) | Out-Null
    Write-Host "RW->RX at $([String]::Format('0x{0:X}', [Int64]$mem))"
}

# Keep process alive so memory can be scanned
Start-Sleep -Seconds 300

# Cleanup (rarely reached)
if ($mem -ne [IntPtr]::Zero) {
    [MemOps]::VirtualFree($mem, 0, [MemOps]::MEM_RELEASE) | Out-Null
}
