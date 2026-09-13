"""
stdlib.py — Python implementations of JOCKY standard library functions.

Used by JIT execution mode (--run).  MCJIT resolves extern function calls to
the Python functions registered here via ctypes.

For native binary output, gcc links forensics.c instead — these are not used.
"""

import ctypes
import os
import sys
import hashlib
import platform
import struct

import llvmlite.binding as llvm

IS_WINDOWS = sys.platform == "win32"
IS_LINUX   = sys.platform.startswith("linux")

# ── Live process list ─────────────────────────────────────────────────────────

_LIVE_PROCS: list     = None
_LIVE_NAME_BUFS: list = []

def _refresh_procs() -> None:
    global _LIVE_PROCS, _LIVE_NAME_BUFS
    if _LIVE_PROCS is not None:
        return

    if IS_WINDOWS:
        try:
            k32   = ctypes.windll.kernel32
            psapi = ctypes.windll.psapi
            pid_buf  = (ctypes.c_ulong * 4096)()
            cb_needed = ctypes.c_ulong(0)
            psapi.EnumProcesses(pid_buf, ctypes.sizeof(pid_buf), ctypes.byref(cb_needed))
            count = cb_needed.value // ctypes.sizeof(ctypes.c_ulong)
            procs = []
            for i in range(count):
                pid = int(pid_buf[i])
                if pid == 0:
                    continue
                hProc = k32.OpenProcess(0x1000, False, pid)
                if not hProc:
                    continue
                name_buf = ctypes.create_unicode_buffer(1024)
                sz = ctypes.c_ulong(1024)
                if k32.QueryFullProcessImageNameW(hProc, 0, name_buf, ctypes.byref(sz)):
                    name = os.path.basename(name_buf.value)
                else:
                    name = f'<pid:{pid}>'
                k32.CloseHandle(hProc)
                procs.append((name, pid))
            _LIVE_PROCS = procs
            print(f"[JOCKY] EnumProcesses: {len(_LIVE_PROCS)} processes")
        except Exception as e:
            print(f"[JOCKY] _refresh_procs (Windows) failed: {e}")
            _LIVE_PROCS = []

    elif IS_LINUX:
        procs = []
        try:
            for entry in os.scandir("/proc"):
                if not entry.is_dir():
                    continue
                try:
                    pid = int(entry.name)
                except ValueError:
                    continue
                comm_path = f"/proc/{pid}/comm"
                try:
                    with open(comm_path, "r") as f:
                        name = f.read().strip()
                except OSError:
                    name = f"<pid:{pid}>"
                procs.append((name, pid))
        except Exception as e:
            print(f"[JOCKY] _refresh_procs (Linux) failed: {e}")
        _LIVE_PROCS = procs
        print(f"[JOCKY] /proc scan: {len(_LIVE_PROCS)} processes")

    else:
        _LIVE_PROCS = [("system", 0)]

    _LIVE_NAME_BUFS = [
        ctypes.create_string_buffer(n.encode("utf-8") + b"\x00")
        for n, _ in _LIVE_PROCS
    ]

# ── Network connections ───────────────────────────────────────────────────────

_TCP_STATES = {
    1: 'CLOSED', 2: 'LISTEN', 3: 'SYN_SENT', 4: 'SYN_RCVD',
    5: 'ESTABLISHED', 6: 'FIN_WAIT1', 7: 'FIN_WAIT2', 8: 'CLOSE_WAIT',
    9: 'CLOSING', 10: 'LAST_ACK', 11: 'TIME_WAIT', 12: 'DELETE_TCB',
}

def _fmt_ip(ip_le: int) -> str:
    return (f"{ip_le & 0xFF}.{(ip_le >> 8) & 0xFF}."
            f"{(ip_le >> 16) & 0xFF}.{(ip_le >> 24) & 0xFF}")

def _fmt_port(port_be: int) -> int:
    return ((port_be & 0xFF) << 8) | ((port_be >> 8) & 0xFF)

def _get_tcp_table() -> list:
    if IS_WINDOWS:
        try:
            iphlp = ctypes.windll.iphlpapi
            size  = ctypes.c_ulong(0)
            iphlp.GetExtendedTcpTable(None, ctypes.byref(size), True, 2, 5, 0)
            buf = (ctypes.c_byte * size.value)()
            if iphlp.GetExtendedTcpTable(buf, ctypes.byref(size), True, 2, 5, 0) != 0:
                return []
            count = struct.unpack_from('<I', buf, 0)[0]
            conns = []
            for i in range(count):
                base = 4 + i * 24
                if base + 24 > size.value:
                    break
                state, la, lp, ra, rp, pid = struct.unpack_from('<IIIIII', buf, base)
                conns.append({
                    'state': _TCP_STATES.get(state, f'STATE_{state}'),
                    'local': f"{_fmt_ip(la)}:{_fmt_port(lp)}",
                    'remote': f"{_fmt_ip(ra)}:{_fmt_port(rp)}",
                    'pid': pid,
                })
            return conns
        except Exception as e:
            print(f"[JOCKY] GetExtendedTcpTable: {e}")
            return []

    elif IS_LINUX:
        conns = []
        try:
            with open("/proc/net/tcp", "r") as f:
                f.readline()
                for line in f:
                    parts = line.split()
                    if len(parts) < 10:
                        continue
                    la_s, lp_s = parts[1].split(":")
                    ra_s, rp_s = parts[2].split(":")
                    state = int(parts[3], 16)
                    la = int(la_s, 16); lp = int(lp_s, 16)
                    ra = int(ra_s, 16); rp = int(rp_s, 16)
                    conns.append({
                        'state': _TCP_STATES.get(state, f'STATE_{state}'),
                        'local': f"{_fmt_ip(la)}:{lp}",
                        'remote': f"{_fmt_ip(ra)}:{rp}",
                        'pid': 0,
                    })
        except Exception as e:
            print(f"[JOCKY] /proc/net/tcp: {e}")
        return conns

    return []

# ── BYOVD state ───────────────────────────────────────────────────────────────

_BYOVD_STATE: dict = {
    "scan_results":  None,   # list[dict] from DriverScanner.scan()
    "kernel_iface":  None,   # KernelInterface instance
    "callbacks":     None,   # list[dict] from enum_process_callbacks()
}

def _get_framework_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def _ensure_scan() -> list:
    if _BYOVD_STATE["scan_results"] is None:
        try:
            root = _get_framework_root()
            if root not in sys.path:
                sys.path.insert(0, root)
            from byovd.scanner import DriverScanner
            scanner = DriverScanner()
            findings = scanner.scan()
            _BYOVD_STATE["scan_results"] = findings
            print(f"[JOCKY/BYOVD] {scanner.db_entry_count()} DB entries, {len(findings)} found")
        except Exception as e:
            print(f"[JOCKY/BYOVD] scan failed: {e}")
            _BYOVD_STATE["scan_results"] = []
    return _BYOVD_STATE["scan_results"]

def _ensure_kernel():
    if _BYOVD_STATE["kernel_iface"] is None:
        try:
            root = _get_framework_root()
            if root not in sys.path:
                sys.path.insert(0, root)
            from byovd.kernel import KernelInterface
            _BYOVD_STATE["kernel_iface"] = KernelInterface(simulate=True)
        except Exception as e:
            print(f"[JOCKY/BYOVD] kernel init failed: {e}")
    return _BYOVD_STATE["kernel_iface"]

def _ensure_callbacks() -> list:
    if _BYOVD_STATE["callbacks"] is None:
        ki = _ensure_kernel()
        if ki:
            _BYOVD_STATE["callbacks"] = ki.enum_process_callbacks()
        else:
            _BYOVD_STATE["callbacks"] = []
    return _BYOVD_STATE["callbacks"]

# ── Persistent callback object storage (prevents GC) ─────────────────────────

_CALLBACKS: dict = {}

# ── Callback builders ─────────────────────────────────────────────────────────

def _cb_report():
    @ctypes.CFUNCTYPE(None, ctypes.c_char_p)
    def report(msg):
        if msg:
            print(f"[JOCKY] {msg.decode('utf-8', errors='replace')}")
    return report

def _cb_procs_list():
    @ctypes.CFUNCTYPE(ctypes.c_void_p)
    def procs_list():
        _refresh_procs()
        return 1
    return procs_list

def _cb_proc_count():
    @ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_void_p)
    def proc_count(p):
        return len(_LIVE_PROCS) if _LIVE_PROCS is not None else 0
    return proc_count

def _cb_proc_name():
    @ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int64)
    def proc_name(p, idx):
        if _LIVE_NAME_BUFS and 0 <= idx < len(_LIVE_NAME_BUFS):
            return ctypes.cast(_LIVE_NAME_BUFS[int(idx)], ctypes.c_void_p).value
        return 0
    return proc_name

def _cb_proc_pid():
    @ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_void_p, ctypes.c_int64)
    def proc_pid(p, idx):
        if _LIVE_PROCS and 0 <= idx < len(_LIVE_PROCS):
            return _LIVE_PROCS[int(idx)][1]
        return -1
    return proc_pid

def _cb_proc_kill():
    @ctypes.CFUNCTYPE(None, ctypes.c_int64)
    def proc_kill(pid):
        name = next((n for n, p in (_LIVE_PROCS or []) if p == pid), '<unknown>')
        print(f"[JOCKY] proc_kill — PID {pid} ({name}) [SAFE: reported only]")
    return proc_kill

def _cb_proc_mem_read():
    _bufs = []
    @ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_int64, ctypes.c_int64, ctypes.c_int64)
    def proc_mem_read(pid, addr, size):
        sz  = max(int(size), 1)
        buf = (ctypes.c_uint8 * sz)()
        if IS_WINDOWS:
            try:
                k32   = ctypes.windll.kernel32
                hProc = k32.OpenProcess(0x0010 | 0x0400, False, int(pid))
                if hProc:
                    read = ctypes.c_size_t(0)
                    k32.ReadProcessMemory(hProc, ctypes.c_void_p(addr), buf, sz, ctypes.byref(read))
                    k32.CloseHandle(hProc)
            except Exception as e:
                print(f"[JOCKY] proc_mem_read error: {e}")
        elif IS_LINUX:
            try:
                with open(f"/proc/{pid}/mem", "rb") as f:
                    f.seek(addr)
                    data = f.read(sz)
                    ctypes.memmove(buf, data, min(len(data), sz))
            except Exception as e:
                print(f"[JOCKY] proc_mem_read (Linux) error: {e}")
        arr = (ctypes.c_uint8 * sz)(*buf)
        _bufs.append(arr)
        return ctypes.cast(arr, ctypes.c_void_p).value
    proc_mem_read._bufs = _bufs
    return proc_mem_read

# net_conns — enumerate TCP connections (was conns_list)
def _cb_net_conns():
    _sentinel = ctypes.create_string_buffer(b'\x01')
    @ctypes.CFUNCTYPE(ctypes.c_void_p)
    def net_conns():
        conns = _get_tcp_table()
        print(f"[JOCKY] net_conns() — {len(conns)} TCP connections")
        for c in conns:
            print(f"[JOCKY]   [{c['state']:12s}] {c['local']:22s} -> {c['remote']}")
        return ctypes.cast(_sentinel, ctypes.c_void_p).value
    net_conns._sentinel = _sentinel
    return net_conns

# net_sniff — simulated packet capture
def _cb_net_sniff():
    _sentinel = ctypes.create_string_buffer(b'\x02')
    @ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_int64)
    def net_sniff(duration_ms):
        conns = _get_tcp_table()
        print(f"[JOCKY] net_sniff({duration_ms}ms) — capturing live traffic")
        est = [c for c in conns if c['state'] == 'ESTABLISHED']
        for c in est[:5]:
            print(f"[JOCKY]   [PKT] {c['local']} -> {c['remote']}  (ESTABLISHED)")
        if not est:
            print("[JOCKY]   [NET] No established connections captured")
        return ctypes.cast(_sentinel, ctypes.c_void_p).value
    net_sniff._sentinel = _sentinel
    return net_sniff

# reg_read — read a registry value (HKLM root implied)
def _cb_reg_read():
    _bufs = []
    @ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p)
    def reg_read(key_path_b, value_name_b):
        result = ""
        key_path   = key_path_b.decode("utf-8",   errors="replace") if key_path_b   else ""
        value_name = value_name_b.decode("utf-8",  errors="replace") if value_name_b else ""
        if IS_WINDOWS and key_path:
            try:
                import winreg
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path,
                                    0, winreg.KEY_READ) as hk:
                    val, _ = winreg.QueryValueEx(hk, value_name)
                    result = str(val)
            except FileNotFoundError:
                result = ""
            except PermissionError:
                result = "<access denied>"
            except Exception as e:
                result = f"<error: {e}>"
        buf = ctypes.create_string_buffer(result.encode("utf-8") + b'\x00')
        _bufs.append(buf)
        return ctypes.cast(buf, ctypes.c_void_p).value
    reg_read._bufs = _bufs
    return reg_read

# reg_list — list registry subkeys under HKLM\key_path
def _cb_reg_list():
    _sentinel = ctypes.create_string_buffer(b'\x03')
    @ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_char_p)
    def reg_list(key_path_b):
        key_path = key_path_b.decode("utf-8", errors="replace") if key_path_b else ""
        if IS_WINDOWS and key_path:
            try:
                import winreg
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path,
                                    0, winreg.KEY_READ) as hk:
                    i = 0
                    subkeys = []
                    while True:
                        try:
                            subkeys.append(winreg.EnumKey(hk, i))
                            i += 1
                        except OSError:
                            break
                    print(f"[JOCKY] reg_list({key_path!r}) — {len(subkeys)} subkeys")
            except Exception as e:
                print(f"[JOCKY] reg_list({key_path!r}) — {e}")
        return ctypes.cast(_sentinel, ctypes.c_void_p).value
    reg_list._sentinel = _sentinel
    return reg_list

# file_list — list files in a directory
def _cb_file_list():
    _sentinel = ctypes.create_string_buffer(b'\x04')
    @ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_char_p)
    def file_list(path_b):
        path = path_b.decode("utf-8", errors="replace") if path_b else "."
        try:
            entries = os.listdir(path)
            print(f"[JOCKY] file_list({path!r}) — {len(entries)} entries")
            for e in entries[:10]:
                print(f"[JOCKY]   {e}")
            if len(entries) > 10:
                print(f"[JOCKY]   ... and {len(entries) - 10} more")
        except Exception as e:
            print(f"[JOCKY] file_list({path!r}) — {e}")
        return ctypes.cast(_sentinel, ctypes.c_void_p).value
    file_list._sentinel = _sentinel
    return file_list

# file_read — read a file and return its content as text pointer
def _cb_file_read():
    _bufs = []
    @ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_char_p)
    def file_read(path_b):
        path = path_b.decode("utf-8", errors="replace") if path_b else ""
        content = ""
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read(65536)
            print(f"[JOCKY] file_read({path!r}) — {len(content)} chars")
        except Exception as e:
            print(f"[JOCKY] file_read({path!r}) — {e}")
            content = ""
        buf = ctypes.create_string_buffer(content.encode("utf-8") + b'\x00')
        _bufs.append(buf)
        return ctypes.cast(buf, ctypes.c_void_p).value
    file_read._bufs = _bufs
    return file_read

# sys_info — system info string (was system_info)
def _cb_sys_info():
    _bufs = []
    @ctypes.CFUNCTYPE(ctypes.c_void_p)
    def sys_info():
        s = f"{platform.system()} {platform.release()} {platform.machine()}"
        print(f"[JOCKY] sys_info: {s}")
        buf = ctypes.create_string_buffer(s.encode() + b'\x00')
        _bufs.append(buf)
        return ctypes.cast(buf, ctypes.c_void_p).value
    sys_info._bufs = _bufs
    return sys_info

# hash_file — SHA-256 hash of a file
def _cb_hash_file():
    _bufs = []
    @ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_char_p)
    def hash_file(path_b):
        path = path_b.decode("utf-8", errors="replace") if path_b else ""
        result = ""
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            result = h.hexdigest()
            print(f"[JOCKY] hash_file({path!r}) = {result}")
        except Exception as e:
            print(f"[JOCKY] hash_file({path!r}) — {e}")
            result = ""
        buf = ctypes.create_string_buffer(result.encode() + b'\x00')
        _bufs.append(buf)
        return ctypes.cast(buf, ctypes.c_void_p).value
    hash_file._bufs = _bufs
    return hash_file

# ── BYOVD callbacks (names match codegen declarations) ────────────────────────

def _cb_byovd_scan():
    _buf = ctypes.create_string_buffer(b'\x01')
    @ctypes.CFUNCTYPE(ctypes.c_void_p)
    def byovd_scan():
        findings = _ensure_scan()
        print(f"[JOCKY/BYOVD] {len(findings)} vulnerable driver(s) found")
        return ctypes.cast(_buf, ctypes.c_void_p).value
    byovd_scan._buf = _buf
    return byovd_scan

def _cb_byovd_driver_count():
    @ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_void_p)
    def byovd_driver_count(p):
        return len(_ensure_scan())
    return byovd_driver_count

def _cb_byovd_driver_name():
    _bufs = []
    @ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int64)
    def byovd_driver_name(p, idx):
        findings = _ensure_scan()
        s = (findings[int(idx)]['name'] if 0 <= idx < len(findings) else "").encode() + b'\x00'
        buf = ctypes.create_string_buffer(s)
        _bufs.append(buf)
        return ctypes.cast(buf, ctypes.c_void_p).value
    byovd_driver_name._bufs = _bufs
    return byovd_driver_name

def _cb_byovd_driver_path():
    _bufs = []
    @ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int64)
    def byovd_driver_path(p, idx):
        findings = _ensure_scan()
        s = (findings[int(idx)].get('path', '') if 0 <= idx < len(findings) else "").encode() + b'\x00'
        buf = ctypes.create_string_buffer(s)
        _bufs.append(buf)
        return ctypes.cast(buf, ctypes.c_void_p).value
    byovd_driver_path._bufs = _bufs
    return byovd_driver_path

def _cb_byovd_driver_cve():
    _bufs = []
    @ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int64)
    def byovd_driver_cve(p, idx):
        findings = _ensure_scan()
        s = ""
        if 0 <= idx < len(findings):
            s = findings[int(idx)].get('entry', {}).get('CVE', 'N/A')
        buf = ctypes.create_string_buffer(s.encode() + b'\x00')
        _bufs.append(buf)
        return ctypes.cast(buf, ctypes.c_void_p).value
    byovd_driver_cve._bufs = _bufs
    return byovd_driver_cve

def _cb_byovd_driver_risk():
    _bufs = []
    @ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int64)
    def byovd_driver_risk(p, idx):
        findings = _ensure_scan()
        s = (findings[int(idx)].get('risk', 'UNKNOWN') if 0 <= idx < len(findings) else "UNKNOWN")
        buf = ctypes.create_string_buffer(s.encode() + b'\x00')
        _bufs.append(buf)
        return ctypes.cast(buf, ctypes.c_void_p).value
    byovd_driver_risk._bufs = _bufs
    return byovd_driver_risk

def _cb_byovd_load():
    @ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_char_p)
    def byovd_load(path_b):
        path = path_b.decode("utf-8", errors="replace") if path_b else ""
        print(f"[JOCKY/BYOVD] byovd_load({path!r}) [SIMULATION — not loading real driver]")
        return 1
    return byovd_load

def _cb_byovd_unload():
    @ctypes.CFUNCTYPE(None)
    def byovd_unload():
        print("[JOCKY/BYOVD] byovd_unload() [SIMULATION]")
    return byovd_unload

# ── Kernel callbacks ──────────────────────────────────────────────────────────

def _cb_kernel_base():
    @ctypes.CFUNCTYPE(ctypes.c_int64)
    def kernel_base():
        ki = _ensure_kernel()
        if ki:
            base = ki.get_kernel_base()
            print(f"[JOCKY/KERNEL] base = 0x{base & 0xFFFFFFFFFFFFFFFF:016X}")
            return base
        return 0
    return kernel_base

def _cb_kernel_read():
    _bufs = []
    @ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_int64, ctypes.c_int64)
    def kernel_read(addr, size):
        sz = max(int(size), 1)
        ki = _ensure_kernel()
        data = b'\xDE\xAD\xBE\xEF' * ((sz + 3) // 4)
        if ki:
            try:
                data = ki.read_memory(int(addr), sz)
            except Exception:
                pass
        print(f"[JOCKY/KERNEL] read @ 0x{addr & 0xFFFFFFFFFFFFFFFF:016X} ({sz}B) "
              f"-> {data[:8].hex()}...")
        buf = ctypes.create_string_buffer(bytes(data[:sz]) + b'\x00')
        _bufs.append(buf)
        return ctypes.cast(buf, ctypes.c_void_p).value
    kernel_read._bufs = _bufs
    return kernel_read

def _cb_kernel_write():
    @ctypes.CFUNCTYPE(None, ctypes.c_int64, ctypes.c_int64)
    def kernel_write(addr, value):
        ki = _ensure_kernel()
        if ki:
            try:
                ki.write_memory(int(addr), struct.pack('<Q', value & 0xFFFFFFFFFFFFFFFF))
            except Exception:
                pass
        print(f"[JOCKY/KERNEL] write @ 0x{addr & 0xFFFFFFFFFFFFFFFF:016X} <- 0x{value & 0xFFFFFFFFFFFFFFFF:016X}")
    return kernel_write

def _cb_kernel_enum_callbacks():
    _sentinel = ctypes.create_string_buffer(b'\x05')
    @ctypes.CFUNCTYPE(ctypes.c_void_p)
    def kernel_enum_callbacks():
        cbs = _ensure_callbacks()
        print(f"[JOCKY/KERNEL] enum_callbacks — {len(cbs)} callback(s)")
        return ctypes.cast(_sentinel, ctypes.c_void_p).value
    kernel_enum_callbacks._sentinel = _sentinel
    return kernel_enum_callbacks

def _cb_kernel_callback_count():
    @ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_void_p)
    def kernel_callback_count(p):
        return len(_ensure_callbacks())
    return kernel_callback_count

def _cb_kernel_callback_addr():
    @ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_void_p, ctypes.c_int64)
    def kernel_callback_addr(p, idx):
        cbs = _ensure_callbacks()
        if 0 <= idx < len(cbs):
            return cbs[int(idx)].get('address', 0) & 0x7FFFFFFFFFFFFFFF
        return 0
    return kernel_callback_addr

def _cb_kernel_callback_module():
    _bufs = []
    @ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int64)
    def kernel_callback_module(p, idx):
        cbs = _ensure_callbacks()
        s = (cbs[int(idx)].get('module', 'unknown') if 0 <= idx < len(cbs) else "unknown")
        buf = ctypes.create_string_buffer(s.encode() + b'\x00')
        _bufs.append(buf)
        return ctypes.cast(buf, ctypes.c_void_p).value
    kernel_callback_module._bufs = _bufs
    return kernel_callback_module

def _cb_kernel_patch_callback():
    @ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_int64)
    def kernel_patch_callback(addr):
        print(f"[JOCKY/KERNEL] patch_callback @ 0x{addr & 0xFFFFFFFFFFFFFFFF:016X} [SIMULATION]")
        return 1
    return kernel_patch_callback

def _cb_kernel_blind_edr():
    @ctypes.CFUNCTYPE(ctypes.c_int64)
    def kernel_blind_edr():
        cbs = _ensure_callbacks()
        edr_cbs = [c for c in cbs if not c.get('is_microsoft', True)]
        print(f"[JOCKY/KERNEL] blind_edr — patching {len(edr_cbs)} non-Microsoft callback(s)")
        for cb in edr_cbs:
            print(f"[JOCKY/KERNEL]   patched {cb.get('module', 'unknown')} @ "
                  f"0x{cb.get('address', 0) & 0xFFFFFFFFFFFFFFFF:016X}")
        return len(edr_cbs)
    return kernel_blind_edr

def _cb_jk_xordecrypt():
    _bufs = []
    @ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int64)
    def jk_xordecrypt(enc, n):
        if not enc or n <= 0:
            buf = ctypes.create_string_buffer(b'\x00')
            _bufs.append(buf)
            return ctypes.cast(buf, ctypes.c_void_p).value
        buf = ctypes.create_string_buffer(enc[:n] + b'\x00')
        _bufs.append(buf)
        return ctypes.cast(buf, ctypes.c_void_p).value
    jk_xordecrypt._bufs = _bufs
    return jk_xordecrypt

# ── Registration ──────────────────────────────────────────────────────────────

def register_all() -> None:
    """Register all stdlib functions with LLVM symbol table. Call before finalize_object()."""
    builders = {
        # Process
        'report':           _cb_report,
        'procs_list':       _cb_procs_list,
        'proc_count':       _cb_proc_count,
        'proc_name':        _cb_proc_name,
        'proc_pid':         _cb_proc_pid,
        'proc_kill':        _cb_proc_kill,
        'proc_mem_read':    _cb_proc_mem_read,
        # Network
        'net_conns':        _cb_net_conns,
        'net_sniff':        _cb_net_sniff,
        # Registry
        'reg_read':         _cb_reg_read,
        'reg_list':         _cb_reg_list,
        # File
        'file_list':        _cb_file_list,
        'file_read':        _cb_file_read,
        # System
        'sys_info':         _cb_sys_info,
        'hash_file':        _cb_hash_file,
        # BYOVD
        'byovd_scan':             _cb_byovd_scan,
        'byovd_driver_count':     _cb_byovd_driver_count,
        'byovd_driver_name':      _cb_byovd_driver_name,
        'byovd_driver_path':      _cb_byovd_driver_path,
        'byovd_driver_cve':       _cb_byovd_driver_cve,
        'byovd_driver_risk':      _cb_byovd_driver_risk,
        'byovd_load':             _cb_byovd_load,
        'byovd_unload':           _cb_byovd_unload,
        # Kernel
        'kernel_base':            _cb_kernel_base,
        'kernel_read':            _cb_kernel_read,
        'kernel_write':           _cb_kernel_write,
        'kernel_enum_callbacks':  _cb_kernel_enum_callbacks,
        'kernel_callback_count':  _cb_kernel_callback_count,
        'kernel_callback_addr':   _cb_kernel_callback_addr,
        'kernel_callback_module': _cb_kernel_callback_module,
        'kernel_patch_callback':  _cb_kernel_patch_callback,
        'kernel_blind_edr':       _cb_kernel_blind_edr,
        # Crypto / runtime
        'jk_xordecrypt':    _cb_jk_xordecrypt,
    }
    for name, builder in builders.items():
        cb   = builder()
        addr = ctypes.cast(cb, ctypes.c_void_p).value
        llvm.add_symbol(name, addr)
        _CALLBACKS[name] = cb
