# F.5.4: PE signature detection

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class MemOps {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualFree(IntPtr lpAddress, uint dwSize, uint dwFreeType);

    public const uint MEM_COMMIT = 0x1000;
    public const uint MEM_RELEASE = 0x8000;
    public const uint PAGE_READWRITE = 0x04;
}
"@

$mem = [MemOps]::VirtualAlloc([IntPtr]::Zero, 4096, [MemOps]::MEM_COMMIT, [MemOps]::PAGE_READWRITE)
if ($mem -eq 0) { throw "VirtualAlloc failed" }

# Write MZ header
$hdr = @(0x4D, 0x5A) + @(0x00) * 27 + @(0x40, 0x00, 0x00, 0x00)
[System.Runtime.InteropServices.Marshal]::Copy($hdr, 0, $mem, $hdr.Length)

# Write PE signature at 0x40
$pe = @(0x50, 0x45, 0x00, 0x00)
[System.Runtime.InteropServices.Marshal]::Copy($pe, 0, [IntPtr]($mem.ToInt64() + 0x40), $pe.Length)

Write-Host "PE header at $([String]::Format('0x{0:X}', [Int64]$mem))"
Start-Sleep -Seconds 300
[MemOps]::VirtualFree($mem, 0, [MemOps]::MEM_RELEASE) | Out-Null
