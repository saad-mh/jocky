# F.5.7: Thread start address anomaly

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class MemOps {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualFree(IntPtr lpAddress, uint dwSize, uint dwFreeType);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    public const uint MEM_COMMIT = 0x1000;
    public const uint MEM_RELEASE = 0x8000;
    public const uint PAGE_EXECUTE_READ = 0x20;
}
"@

$mem = [MemOps]::VirtualAlloc([IntPtr]::Zero, 4096, [MemOps]::MEM_COMMIT, [MemOps]::PAGE_EXECUTE_READ)
if ($mem -eq 0) { throw "VirtualAlloc failed" }
[System.Runtime.InteropServices.Marshal]::Copy(@(0x90 * 4096 | ForEach-Object { $_ -band 0xFF }), 0, $mem, 4096)

$tid = 0
$thread = [MemOps]::CreateThread([IntPtr]::Zero, 0, $mem, [IntPtr]::Zero, 0, [ref]$tid)
if ($thread -eq [IntPtr]::Zero) {
    [MemOps]::VirtualFree($mem, 0, [MemOps]::MEM_RELEASE) | Out-Null
    throw "CreateThread failed"
}

Write-Host "Thread anomaly at $([String]::Format('0x{0:X}', [Int64]$mem)) tid=$tid"
Start-Sleep -Seconds 300
[MemOps]::CloseHandle($thread) | Out-Null
[MemOps]::VirtualFree($mem, 0, [MemOps]::MEM_RELEASE) | Out-Null
