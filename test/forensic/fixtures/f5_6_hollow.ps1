# F.5.6: Process hollowing fixture
# Simulates code injection via process hollowing (unmap main image, write different PE)

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Diagnostics;

public class ProcessHollow {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect, out IntPtr lpAlloc);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetModuleInformation(IntPtr hProcess, IntPtr hModule, out MODULEINFO lpmodinfo, uint cb);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetProcessTimes(IntPtr hProcess, out uint lpCreationTime, out uint lpExitTime, out uint lpKernelTime, out uint lpUserTime);

    [StructLayout(LayoutKind.Sequential)]
    public struct MODULEINFO {
        public IntPtr lpBaseOfDll;
        public uint SizeOfImage;
        public IntPtr EntryPoint;
    }

    public const uint MEM_COMMIT = 0x1000;
    public const uint MEM_RESERVE = 0x2000;
    public const uint PAGE_EXECUTE_READWRITE = 0x40;
    public const uint PAGE_READWRITE = 0x04;
}
"@

# For this v1 fixture, we'll simulate hollowing by:
# 1. Allocating executable private memory
# 2. Writing a fake PE header + shellcode-like pattern
# 3. This demonstrates the concept without full process manipulation

$currentProcess = [ProcessHollow]::GetCurrentProcess()

# Allocate memory for a "hollowed" image
$shellcodeSize = 8192
$shellcodeMem = [IntPtr]::Zero

try {
    # Allocate RWX memory to simulate a hollowed region
    $allocResult = [ProcessHollow]::VirtualAllocEx($currentProcess, [IntPtr]::Zero, $shellcodeSize,
                                                     [ProcessHollow]::MEM_COMMIT -bor [ProcessHollow]::MEM_RESERVE,
                                                     [ProcessHollow]::PAGE_EXECUTE_READWRITE, [ref]$shellcodeMem)

    if ($allocResult) {
        # Create a fake PE header pattern to simulate a hollowed/injected binary
        $fakeHeader = @()
        # MZ header
        $fakeHeader += 0x4D, 0x5A  # "MZ"
        # Pad to reach e_lfanew field (offset 0x3c)
        for ($i = 2; $i -lt 0x3c; $i++) { $fakeHeader += 0x90 }  # NOP padding
        # e_lfanew = 0x40 (point to PE at offset 0x40)
        $fakeHeader += 0x40, 0x00, 0x00, 0x00
        # Pad to offset 0x40
        while ($fakeHeader.Count -lt 0x40) { $fakeHeader += 0x90 }
        # PE signature
        $fakeHeader += 0x50, 0x45, 0x00, 0x00  # "PE\0\0"
        # Pad to shellcode area with NOP (0x90) and RET (0xC3)
        while ($fakeHeader.Count -lt $shellcodeSize) { $fakeHeader += 0x90 }

        $headerBytes = [byte[]]$fakeHeader

        # Write the fake PE + shellcode into the allocated memory
        $bytesWritten = 0
        [ProcessHollow]::WriteProcessMemory($currentProcess, $shellcodeMem, $headerBytes, $headerBytes.Length, [ref]$bytesWritten) | Out-Null

        Write-Host "Hollowed region at $([String]::Format('0x{0:X}', [Int64]$shellcodeMem))"
    }
} catch {
    Write-Host "Error: $_"
}

# Keep process alive for scanning
Start-Sleep -Seconds 300
