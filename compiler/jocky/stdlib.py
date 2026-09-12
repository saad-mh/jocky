"""
stdlib.py — Python implementations of JOCKY's standard library functions.

Used by the JIT execution mode (--run flag).  When LLVM JIT executes compiled
JOCKY code and encounters a call to report(), procs_list(), etc., it resolves
those calls to the Python functions registered here via ctypes callbacks.

For native binary output mode, the linker instead links in stdlib/forensics.c
(compiled by gcc), so these Python implementations are not involved at all.
"""

import ctypes
import llvmlite.binding as llvm

# ── Simulated process list (used in --run / JIT mode) ────────────────────────
# In a real deployment, procs_list() would call Windows API EnumProcesses().
_PROCESS_TABLE = [
    ('svchost.exe',  1234),
    ('explorer.exe', 5678),
    ('lsass.exe',    9012),
    ('winlogon.exe', 3456),
    ('csrss.exe',    7890),
    ('cmd.exe',      2222),
    ('python.exe',   3333),
]

# Pre-encode process names into stable C-compatible byte buffers.
# Must stay alive for the entire duration of JIT execution.
_NAME_BUFS: list[ctypes.Array] = [
    ctypes.create_string_buffer(name.encode('utf-8') + b'\x00')
    for name, _ in _PROCESS_TABLE
]

# All ctypes callback objects kept here to prevent garbage collection.
_CALLBACKS: dict[str, object] = {}


# ── Callback implementations ─────────────────────────────────────────────────

def _cb_report():
    @ctypes.CFUNCTYPE(None, ctypes.c_char_p)
    def report(msg: bytes) -> None:
        if msg:
            print(f"[JOCKY] {msg.decode('utf-8', errors='replace')}")
    return report


def _cb_procs_list():
    @ctypes.CFUNCTYPE(ctypes.c_void_p)
    def procs_list() -> int:
        return 1   # non-null sentinel; Python side ignores the value
    return procs_list


def _cb_proc_count():
    @ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_void_p)
    def proc_count(procs: int) -> int:
        return len(_PROCESS_TABLE)
    return proc_count


def _cb_proc_name():
    @ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int64)
    def proc_name(procs: int, idx: int) -> int:
        if 0 <= idx < len(_NAME_BUFS):
            return ctypes.cast(_NAME_BUFS[idx], ctypes.c_void_p).value
        return 0
    return proc_name


def _cb_proc_pid():
    @ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_void_p, ctypes.c_int64)
    def proc_pid(procs: int, idx: int) -> int:
        if 0 <= idx < len(_PROCESS_TABLE):
            return _PROCESS_TABLE[idx][1]
        return -1
    return proc_pid


def _cb_proc_kill():
    @ctypes.CFUNCTYPE(None, ctypes.c_int64)
    def proc_kill(pid: int) -> None:
        print(f"[JOCKY] proc_kill({pid})")
    return proc_kill


def _cb_proc_mem_read():
    @ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_int64, ctypes.c_int64, ctypes.c_int64)
    def proc_mem_read(pid: int, addr: int, size: int) -> int:
        print(f"[JOCKY] proc_mem_read(pid={pid}, addr=0x{addr:x}, size={size})")
        buf = (ctypes.c_uint8 * max(size, 1))()
        return ctypes.cast(buf, ctypes.c_void_p).value
    return proc_mem_read


def _cb_net_conns():
    @ctypes.CFUNCTYPE(ctypes.c_void_p)
    def net_conns() -> int:
        print("[JOCKY] net_conns()")
        return ctypes.cast((ctypes.c_uint8 * 1)(), ctypes.c_void_p).value
    return net_conns


def _cb_net_sniff():
    @ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_int64)
    def net_sniff(duration_ms: int) -> int:
        print(f"[JOCKY] net_sniff({duration_ms}ms)")
        return ctypes.cast((ctypes.c_uint8 * 1)(), ctypes.c_void_p).value
    return net_sniff


def _cb_reg_read():
    _empty = ctypes.create_string_buffer(b'\x00')

    @ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p)
    def reg_read(key: bytes, value_name: bytes) -> int:
        k = key.decode('utf-8', errors='replace') if key else ''
        v = value_name.decode('utf-8', errors='replace') if value_name else ''
        print(f"[JOCKY] reg_read({k!r}, {v!r})")
        return ctypes.cast(_empty, ctypes.c_void_p).value
    _cb_reg_read._empty = _empty
    return reg_read


def _cb_reg_list():
    @ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_char_p)
    def reg_list(key: bytes) -> int:
        k = key.decode('utf-8', errors='replace') if key else ''
        print(f"[JOCKY] reg_list({k!r})")
        return ctypes.cast((ctypes.c_uint8 * 1)(), ctypes.c_void_p).value
    return reg_list


def _cb_file_list():
    @ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_char_p)
    def file_list(path: bytes) -> int:
        p = path.decode('utf-8', errors='replace') if path else ''
        print(f"[JOCKY] file_list({p!r})")
        return ctypes.cast((ctypes.c_uint8 * 1)(), ctypes.c_void_p).value
    return file_list


def _cb_file_read():
    @ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_char_p)
    def file_read(path: bytes) -> int:
        p = path.decode('utf-8', errors='replace') if path else ''
        print(f"[JOCKY] file_read({p!r})")
        return ctypes.cast((ctypes.c_uint8 * 1)(), ctypes.c_void_p).value
    return file_read


def _cb_sys_info():
    @ctypes.CFUNCTYPE(ctypes.c_void_p)
    def sys_info() -> int:
        print("[JOCKY] sys_info()")
        return ctypes.cast((ctypes.c_uint8 * 64)(), ctypes.c_void_p).value
    return sys_info


def _cb_hash_file():
    @ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_char_p)
    def hash_file(path: bytes) -> int:
        p = path.decode('utf-8', errors='replace') if path else ''
        print(f"[JOCKY] hash_file({p!r})")
        return ctypes.cast((ctypes.c_uint8 * 32)(), ctypes.c_void_p).value
    return hash_file


# ── BYOVD / Kernel callbacks ─────────────────────────────────────────────────
# These integrate with the byovd package when available; fall back gracefully.

def _get_byovd_scanner():
    """Lazy-import the BYOVD scanner (only available in full install)."""
    try:
        import sys, os
        app_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        if app_dir not in sys.path:
            sys.path.insert(0, app_dir)
        from byovd.scanner import BYOVDScanner
        return BYOVDScanner()
    except Exception:
        return None

def _get_byovd_loader():
    try:
        import sys, os
        app_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        if app_dir not in sys.path:
            sys.path.insert(0, app_dir)
        from byovd.loader import DriverLoader
        from byovd.kernel import KernelOps
        loader = DriverLoader(simulate=True)  # simulation mode for JIT
        return loader, KernelOps(loader)
    except Exception:
        return None, None

# Persistent state for JIT BYOVD session
_BYOVD_STATE: dict = {
    "scan_results": None,
    "loader":       None,
    "kernel_ops":   None,
    "callbacks":    None,
}

def _ensure_scan():
    if _BYOVD_STATE["scan_results"] is None:
        scanner = _get_byovd_scanner()
        if scanner:
            _BYOVD_STATE["scan_results"] = scanner.scan()
        else:
            _BYOVD_STATE["scan_results"] = {
                "vulnerable_drivers": [], "all_drivers": [],
                "vulnerable_count": 0, "total_drivers": 0,
            }
    return _BYOVD_STATE["scan_results"]

def _ensure_kernel():
    if _BYOVD_STATE["loader"] is None:
        loader, kops = _get_byovd_loader()
        _BYOVD_STATE["loader"]     = loader
        _BYOVD_STATE["kernel_ops"] = kops
    return _BYOVD_STATE["loader"], _BYOVD_STATE["kernel_ops"]


def _cb_byovd_scan():
    _scan_buf = ctypes.create_string_buffer(b'\x01')  # non-null sentinel

    @ctypes.CFUNCTYPE(ctypes.c_void_p)
    def byovd_scan() -> int:
        results = _ensure_scan()
        vuln = results.get("vulnerable_drivers", [])
        n = len(vuln)
        print(f"[JOCKY/BYOVD] scan complete — {results.get('total_drivers',0)} drivers scanned, "
              f"{n} vulnerable found")
        return ctypes.cast(_scan_buf, ctypes.c_void_p).value

    _cb_byovd_scan._scan_buf = _scan_buf
    return byovd_scan


def _cb_byovd_driver_count():
    @ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_void_p)
    def byovd_driver_count(handle: int) -> int:
        results = _ensure_scan()
        return len(results.get("vulnerable_drivers", []))
    return byovd_driver_count


def _cb_byovd_driver_name():
    _bufs: list = []

    @ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int64)
    def byovd_driver_name(handle: int, idx: int) -> int:
        results = _ensure_scan()
        vuln = results.get("vulnerable_drivers", [])
        if 0 <= idx < len(vuln):
            name = vuln[idx].filename.encode("utf-8") + b'\x00'
        else:
            name = b'\x00'
        buf = ctypes.create_string_buffer(name, len(name))
        _bufs.append(buf)
        return ctypes.cast(buf, ctypes.c_void_p).value

    byovd_driver_name._bufs = _bufs
    return byovd_driver_name


def _cb_byovd_driver_path():
    _bufs: list = []

    @ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int64)
    def byovd_driver_path(handle: int, idx: int) -> int:
        results = _ensure_scan()
        vuln = results.get("vulnerable_drivers", [])
        if 0 <= idx < len(vuln):
            path = vuln[idx].full_path.encode("utf-8") + b'\x00'
        else:
            path = b'\x00'
        buf = ctypes.create_string_buffer(path, len(path))
        _bufs.append(buf)
        return ctypes.cast(buf, ctypes.c_void_p).value

    byovd_driver_path._bufs = _bufs
    return byovd_driver_path


def _cb_byovd_driver_cve():
    _bufs: list = []

    @ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int64)
    def byovd_driver_cve(handle: int, idx: int) -> int:
        results = _ensure_scan()
        vuln = results.get("vulnerable_drivers", [])
        if 0 <= idx < len(vuln):
            cve = (vuln[idx].cve or "N/A").encode("utf-8") + b'\x00'
        else:
            cve = b'\x00'
        buf = ctypes.create_string_buffer(cve, len(cve))
        _bufs.append(buf)
        return ctypes.cast(buf, ctypes.c_void_p).value

    byovd_driver_cve._bufs = _bufs
    return byovd_driver_cve


def _cb_byovd_driver_risk():
    _bufs: list = []

    @ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int64)
    def byovd_driver_risk(handle: int, idx: int) -> int:
        results = _ensure_scan()
        vuln = results.get("vulnerable_drivers", [])
        if 0 <= idx < len(vuln):
            risk = vuln[idx].risk_level().encode("utf-8") + b'\x00'
        else:
            risk = b'\x00'
        buf = ctypes.create_string_buffer(risk, len(risk))
        _bufs.append(buf)
        return ctypes.cast(buf, ctypes.c_void_p).value

    byovd_driver_risk._bufs = _bufs
    return byovd_driver_risk


def _cb_byovd_load():
    @ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_char_p)
    def byovd_load(path: bytes) -> int:
        p = path.decode("utf-8", errors="replace") if path else ""
        loader, _ = _ensure_kernel()
        if loader is None:
            print(f"[JOCKY/BYOVD] byovd_load({p!r}) — BYOVD module not available")
            return 0
        try:
            loader.driver_path = p
            ok = loader.load()
            if ok:
                loader.open_device()
            print(f"[JOCKY/BYOVD] byovd_load({p!r}) — {'OK' if ok else 'FAILED'}")
            return 1 if ok else 0
        except Exception as e:
            print(f"[JOCKY/BYOVD] byovd_load error: {e}")
            return 0
    return byovd_load


def _cb_byovd_unload():
    @ctypes.CFUNCTYPE(None)
    def byovd_unload() -> None:
        loader, _ = _BYOVD_STATE.get("loader"), _BYOVD_STATE.get("kernel_ops")
        if loader:
            loader.unload()
        print("[JOCKY/BYOVD] byovd_unload() — driver unloaded")
    return byovd_unload


def _cb_kernel_read():
    @ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_int64, ctypes.c_int64)
    def kernel_read(addr: int, size: int) -> int:
        _, kops = _ensure_kernel()
        buf = ctypes.create_string_buffer(max(int(size), 8))
        if kops:
            try:
                val = kops.read_qword(addr)
                import struct
                packed = struct.pack("<Q", val)
                buf[:8] = packed
                print(f"[JOCKY/KERNEL] READ 0x{addr:016X} ({size}B) → 0x{val:016X}")
            except Exception as e:
                print(f"[JOCKY/KERNEL] kernel_read error: {e}")
        return ctypes.cast(buf, ctypes.c_void_p).value
    return kernel_read


def _cb_kernel_write():
    @ctypes.CFUNCTYPE(None, ctypes.c_int64, ctypes.c_int64)
    def kernel_write(addr: int, value: int) -> None:
        _, kops = _ensure_kernel()
        if kops:
            try:
                kops.write_dword(addr, value & 0xFFFFFFFF)
                print(f"[JOCKY/KERNEL] WRITE 0x{addr:016X} ← 0x{value:08X}")
            except Exception as e:
                print(f"[JOCKY/KERNEL] kernel_write error: {e}")
    return kernel_write


def _cb_kernel_base():
    @ctypes.CFUNCTYPE(ctypes.c_int64)
    def kernel_base() -> int:
        _, kops = _ensure_kernel()
        if kops:
            base = kops.get_kernel_base()
            print(f"[JOCKY/KERNEL] ntoskrnl base = 0x{base:016X}")
            return base
        return 0
    return kernel_base


def _cb_kernel_enum_callbacks():
    _cb_buf = ctypes.create_string_buffer(b'\x02')

    @ctypes.CFUNCTYPE(ctypes.c_void_p)
    def kernel_enum_callbacks() -> int:
        _, kops = _ensure_kernel()
        if kops:
            cbs = kops.enum_process_callbacks(0)
            _BYOVD_STATE["callbacks"] = cbs
            print(f"[JOCKY/KERNEL] Enumerated {len(cbs)} process-notify callbacks")
        return ctypes.cast(_cb_buf, ctypes.c_void_p).value

    _cb_kernel_enum_callbacks._cb_buf = _cb_buf
    return kernel_enum_callbacks


def _cb_kernel_callback_count():
    @ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_void_p)
    def kernel_callback_count(handle: int) -> int:
        cbs = _BYOVD_STATE.get("callbacks") or []
        return len(cbs)
    return kernel_callback_count


def _cb_kernel_callback_addr():
    @ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_void_p, ctypes.c_int64)
    def kernel_callback_addr(handle: int, idx: int) -> int:
        cbs = _BYOVD_STATE.get("callbacks") or []
        if 0 <= idx < len(cbs):
            return cbs[idx].get("address", 0)
        return 0
    return kernel_callback_addr


def _cb_kernel_callback_module():
    _bufs: list = []

    @ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int64)
    def kernel_callback_module(handle: int, idx: int) -> int:
        cbs = _BYOVD_STATE.get("callbacks") or []
        if 0 <= idx < len(cbs):
            mod = cbs[idx].get("module", "unknown").encode("utf-8") + b'\x00'
        else:
            mod = b"unknown\x00"
        buf = ctypes.create_string_buffer(mod, len(mod))
        _bufs.append(buf)
        return ctypes.cast(buf, ctypes.c_void_p).value

    kernel_callback_module._bufs = _bufs
    return kernel_callback_module


def _cb_kernel_patch_callback():
    @ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_int64)
    def kernel_patch_callback(idx: int) -> int:
        _, kops = _ensure_kernel()
        if kops:
            ok = kops.patch_callback(0, int(idx))
            print(f"[JOCKY/KERNEL] Patched callback[{idx}] — {'OK' if ok else 'FAIL'}")
            return 1 if ok else 0
        return 0
    return kernel_patch_callback


def _cb_kernel_blind_edr():
    @ctypes.CFUNCTYPE(ctypes.c_int64)
    def kernel_blind_edr() -> int:
        _, kops = _ensure_kernel()
        if kops:
            n = kops.disable_non_microsoft_callbacks(0)
            print(f"[JOCKY/KERNEL] kernel_blind_edr() — {n} EDR callback(s) patched")
            return n
        return 0
    return kernel_blind_edr


def _cb_jk_xordecrypt():
    # In JIT mode obfuscation never runs so _jocky_xor_key stays 0.
    # XOR with 0 is identity, so we just copy the string as-is.
    # Buffers are kept alive in _bufs for the duration of the JIT session.
    _bufs: list = []

    @ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int64)
    def jk_xordecrypt(enc: bytes, n: int) -> int:
        if not enc or n <= 0:
            buf = ctypes.create_string_buffer(b'\x00')
            _bufs.append(buf)
            return ctypes.cast(buf, ctypes.c_void_p).value
        raw = enc[:n]
        buf = ctypes.create_string_buffer(raw + b'\x00')
        _bufs.append(buf)
        return ctypes.cast(buf, ctypes.c_void_p).value

    jk_xordecrypt._bufs = _bufs
    return jk_xordecrypt


# ── Registration ─────────────────────────────────────────────────────────────

def register_all() -> None:
    """
    Register every stdlib function with LLVM's global symbol table so the
    MCJIT engine can resolve calls from compiled JOCKY code.

    Must be called BEFORE engine.finalize_object().
    """
    builders = {
        'report':          _cb_report,
        'procs_list':      _cb_procs_list,
        'proc_count':      _cb_proc_count,
        'proc_name':       _cb_proc_name,
        'proc_pid':        _cb_proc_pid,
        'proc_kill':       _cb_proc_kill,
        'proc_mem_read':   _cb_proc_mem_read,
        'net_conns':       _cb_net_conns,
        'net_sniff':       _cb_net_sniff,
        'reg_read':        _cb_reg_read,
        'reg_list':        _cb_reg_list,
        'file_list':       _cb_file_list,
        'file_read':       _cb_file_read,
        'sys_info':        _cb_sys_info,
        'hash_file':       _cb_hash_file,
        'jk_xordecrypt':   _cb_jk_xordecrypt,
        # BYOVD / Kernel functions
        'byovd_scan':             _cb_byovd_scan,
        'byovd_driver_count':     _cb_byovd_driver_count,
        'byovd_driver_name':      _cb_byovd_driver_name,
        'byovd_driver_path':      _cb_byovd_driver_path,
        'byovd_driver_cve':       _cb_byovd_driver_cve,
        'byovd_driver_risk':      _cb_byovd_driver_risk,
        'byovd_load':             _cb_byovd_load,
        'byovd_unload':           _cb_byovd_unload,
        'kernel_read':            _cb_kernel_read,
        'kernel_write':           _cb_kernel_write,
        'kernel_base':            _cb_kernel_base,
        'kernel_enum_callbacks':  _cb_kernel_enum_callbacks,
        'kernel_callback_count':  _cb_kernel_callback_count,
        'kernel_callback_addr':   _cb_kernel_callback_addr,
        'kernel_callback_module': _cb_kernel_callback_module,
        'kernel_patch_callback':  _cb_kernel_patch_callback,
        'kernel_blind_edr':       _cb_kernel_blind_edr,
    }
    for name, builder_fn in builders.items():
        cb   = builder_fn()
        addr = ctypes.cast(cb, ctypes.c_void_p).value
        llvm.add_symbol(name, addr)
        _CALLBACKS[name] = cb   # keep alive
