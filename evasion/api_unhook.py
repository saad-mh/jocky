"""
API Unhooking — detects and restores EDR/AV hooks in ntdll.dll by comparing
the on-disk export bytes against the in-memory loaded copy.
"""
from __future__ import annotations
import ctypes
import ctypes.wintypes
import os
import struct
import sys
from typing import Optional

if sys.platform != "win32":
    raise ImportError("api_unhook requires Windows")

# ── PE parsing helpers ────────────────────────────────────────────────────────

def _read_file(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()

def _get_exports(pe_bytes: bytes) -> dict[str, int]:
    """Parse PE export table. Returns {function_name: RVA}."""
    exports: dict[str, int] = {}
    try:
        e_lfanew = struct.unpack_from("<I", pe_bytes, 0x3C)[0]
        # optional header data directories
        machine = struct.unpack_from("<H", pe_bytes, e_lfanew + 4)[0]
        is_pe32_plus = machine == 0x8664 or struct.unpack_from("<H", pe_bytes, e_lfanew + 24)[0] == 0x20B
        optional_hdr_off = e_lfanew + 24
        dd_off = optional_hdr_off + (112 if is_pe32_plus else 96)
        export_rva = struct.unpack_from("<I", pe_bytes, dd_off)[0]
        export_size = struct.unpack_from("<I", pe_bytes, dd_off + 4)[0]
        if export_rva == 0 or export_size == 0:
            return exports
        # Resolve RVA to file offset — scan section headers
        num_sections = struct.unpack_from("<H", pe_bytes, e_lfanew + 6)[0]
        section_hdr_off = optional_hdr_off + struct.unpack_from("<H", pe_bytes, e_lfanew + 20)[0]

        def rva_to_off(rva: int) -> int:
            for i in range(num_sections):
                s = section_hdr_off + i * 40
                vaddr = struct.unpack_from("<I", pe_bytes, s + 12)[0]
                vsz   = struct.unpack_from("<I", pe_bytes, s + 16)[0]
                raw   = struct.unpack_from("<I", pe_bytes, s + 20)[0]
                if vaddr <= rva < vaddr + vsz:
                    return raw + (rva - vaddr)
            return rva

        eoff = rva_to_off(export_rva)
        num_funcs  = struct.unpack_from("<I", pe_bytes, eoff + 20)[0]
        num_names  = struct.unpack_from("<I", pe_bytes, eoff + 24)[0]
        addr_tbl   = rva_to_off(struct.unpack_from("<I", pe_bytes, eoff + 28)[0])
        name_tbl   = rva_to_off(struct.unpack_from("<I", pe_bytes, eoff + 32)[0])
        ord_tbl    = rva_to_off(struct.unpack_from("<I", pe_bytes, eoff + 36)[0])

        for i in range(num_names):
            name_rva = struct.unpack_from("<I", pe_bytes, name_tbl + i * 4)[0]
            name_off = rva_to_off(name_rva)
            end = pe_bytes.index(b"\x00", name_off)
            name = pe_bytes[name_off:end].decode("ascii", errors="replace")
            ordinal = struct.unpack_from("<H", pe_bytes, ord_tbl + i * 2)[0]
            if ordinal < num_funcs:
                func_rva = struct.unpack_from("<I", pe_bytes, addr_tbl + ordinal * 4)[0]
                exports[name] = func_rva
    except Exception:
        pass
    return exports

# ── Memory helpers ────────────────────────────────────────────────────────────

def _get_module_base(name: str) -> int:
    """Get the base address of a loaded module by name using kernel32!GetModuleHandleW."""
    k32 = ctypes.windll.kernel32
    h = k32.GetModuleHandleW(name)
    return h  # HMODULE == base for DLLs loaded by the loader

def _read_mem(addr: int, size: int) -> Optional[bytes]:
    buf = ctypes.create_string_buffer(size)
    read = ctypes.c_size_t(0)
    ok = ctypes.windll.kernel32.ReadProcessMemory(
        ctypes.windll.kernel32.GetCurrentProcess(),
        ctypes.c_void_p(addr), buf, size, ctypes.byref(read)
    )
    if ok:
        return bytes(buf[:read.value])
    return None

def _write_mem(addr: int, data: bytes) -> bool:
    k32 = ctypes.windll.kernel32
    proc = k32.GetCurrentProcess()
    old_prot = ctypes.wintypes.DWORD(0)
    size = len(data)
    # Make writable
    if not k32.VirtualProtectEx(proc, ctypes.c_void_p(addr), size, 0x40, ctypes.byref(old_prot)):
        return False
    written = ctypes.c_size_t(0)
    ok = k32.WriteProcessMemory(proc, ctypes.c_void_p(addr), data, size, ctypes.byref(written))
    k32.VirtualProtectEx(proc, ctypes.c_void_p(addr), size, old_prot, ctypes.byref(old_prot))
    return bool(ok)

# ── Hook detection ────────────────────────────────────────────────────────────

_JMP_OPCODES = {0xE9, 0xFF, 0xEB, 0xE8}
_HOTPATCH    = {0xCC, 0x90}

def _is_hooked(mem_bytes: bytes) -> bool:
    if len(mem_bytes) < 5:
        return False
    # Classic jmp hook
    if mem_bytes[0] in _JMP_OPCODES:
        return True
    # 2-byte hotpatch: MOV EDI,EDI (0x8B 0xFF)
    if mem_bytes[0] == 0x8B and mem_bytes[1] == 0xFF:
        return True
    # INT3 / NOP sled
    if mem_bytes[0] in _HOTPATCH:
        return True
    # push+ret shellcode
    if mem_bytes[0] == 0x68 and mem_bytes[5] == 0xC3:
        return True
    return False

# ── Main unhooking logic ──────────────────────────────────────────────────────

NTDLL_PATH = os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "System32", "ntdll.dll")

class ApiUnhooker:
    def __init__(self, target_dll_path: str = NTDLL_PATH) -> None:
        self._dll_path  = target_dll_path
        self._dll_name  = os.path.basename(target_dll_path)
        self._disk_bytes: bytes = b""
        self._disk_exports: dict[str, int] = {}
        self._mem_base: int = 0

    def _load_disk(self) -> bool:
        try:
            self._disk_bytes = _read_file(self._dll_path)
            self._disk_exports = _get_exports(self._disk_bytes)
            return True
        except OSError:
            return False

    def _get_mem_base(self) -> bool:
        base = _get_module_base(self._dll_name)
        if base == 0:
            return False
        self._mem_base = base
        return True

    def audit(self) -> list[dict]:
        """Audit loaded DLL for hooks. Returns list of hooked exports."""
        if not self._load_disk() or not self._get_mem_base():
            return []

        results = []
        for name, rva in self._disk_exports.items():
            disk_off = rva  # approximate — works for flat-mapped disk reads
            try:
                disk_stub = self._disk_bytes[disk_off:disk_off + 16]
            except Exception:
                continue
            mem_addr = self._mem_base + rva
            mem_stub = _read_mem(mem_addr, 16)
            if mem_stub is None:
                continue
            if disk_stub[:8] != mem_stub[:8] and _is_hooked(mem_stub):
                results.append({
                    "function": name,
                    "rva":      rva,
                    "mem_addr": mem_addr,
                    "disk_bytes": disk_stub.hex(),
                    "mem_bytes":  mem_stub.hex(),
                })
        return results

    def unhook(self, hooks: Optional[list[dict]] = None) -> dict[str, bool]:
        """Restore hooked exports from on-disk bytes. Returns {function: success}."""
        if hooks is None:
            hooks = self.audit()
        if not self._disk_bytes:
            if not self._load_disk():
                return {}
        if not self._mem_base:
            if not self._get_mem_base():
                return {}

        results: dict[str, bool] = {}
        for h in hooks:
            rva  = h["rva"]
            addr = self._mem_base + rva
            try:
                disk_stub = self._disk_bytes[rva:rva + 16]
            except Exception:
                results[h["function"]] = False
                continue
            ok = _write_mem(addr, disk_stub)
            results[h["function"]] = ok
            status = "RESTORED" if ok else "FAILED"
            print(f"[UNHOOK] {h['function']:40s} @ 0x{addr:016X}  {status}")
        return results

    def full_unhook(self) -> None:
        """Detect and restore all hooks in target DLL."""
        print(f"[UNHOOK] Auditing {self._dll_name} ...")
        hooks = self.audit()
        print(f"[UNHOOK] Detected {len(hooks)} hook(s)")
        if hooks:
            self.unhook(hooks)
        else:
            print("[UNHOOK] No hooks found — ntdll appears clean")
