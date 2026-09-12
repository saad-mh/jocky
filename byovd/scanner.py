"""
scanner.py — BYOVD Driver Scanner

Enumerates all installed/running kernel drivers on the system, computes their
SHA-256 hashes, and cross-references against the bundled LOLDrivers database
(and optionally a live fetch from loldrivers.io).

Works on Windows without admin privileges — reads the registry and hashes
files in the drivers directory.
"""

import os
import sys
import json
import hashlib
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

DB_PATH = Path(__file__).parent / "db" / "loldrivers.json"
LOLDRIVERS_URL = "https://www.loldrivers.io/api/drivers.json"


@dataclass
class DriverInfo:
    service_name: str
    filename: str
    full_path: str
    sha256: Optional[str]
    is_vulnerable: bool
    vuln_entry: Optional[dict] = None
    tags: list = field(default_factory=list)
    cve: str = ""
    vendor: str = ""
    description: str = ""

    def risk_level(self) -> str:
        if not self.is_vulnerable:
            return "CLEAN"
        tags = self.tags
        if any(t in tags for t in ["AV-Kill", "EDR-Bypass", "Ransomware"]):
            return "CRITICAL"
        if any(t in tags for t in ["Kernel-RW", "DKOM", "APT"]):
            return "HIGH"
        return "MEDIUM"


class BYOVDScanner:
    def __init__(self, use_live_db: bool = False):
        self._db: list[dict] = []
        self._hash_index: dict[str, dict] = {}
        self._name_index: dict[str, dict] = {}
        self._load_db(use_live_db)

    # ── Database loading ──────────────────────────────────────────────────────

    def _load_db(self, use_live: bool) -> None:
        data = None
        if use_live:
            data = self._fetch_live_db()
        if data is None:
            data = self._load_bundled_db()
        if data:
            self._db = data
            self._build_index()

    def _fetch_live_db(self) -> Optional[list]:
        try:
            req = urllib.request.Request(
                LOLDRIVERS_URL,
                headers={"User-Agent": "JOCKY-BYOVD-Scanner/1.0"},
            )
            with urllib.request.urlopen(req, timeout=8) as r:
                return json.loads(r.read().decode())
        except Exception:
            return None

    def _load_bundled_db(self) -> list:
        try:
            return json.loads(DB_PATH.read_text(encoding="utf-8"))
        except Exception:
            return []

    def _build_index(self) -> None:
        for entry in self._db:
            name = entry.get("Name", "").lower()
            if name:
                self._name_index[name] = entry
            for sample in entry.get("KnownVulnerableSamples", []):
                sha = sample.get("SHA256", "").lower()
                if sha:
                    self._hash_index[sha] = entry

    # ── Driver enumeration ────────────────────────────────────────────────────

    def enumerate_system_drivers(self) -> list[DriverInfo]:
        """
        Enumerate all kernel drivers installed on this system by reading the
        Windows service registry key. Resolves paths and computes SHA-256.
        """
        if sys.platform != "win32":
            return self._mock_drivers()

        drivers = []
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Services",
            )
            i = 0
            while True:
                try:
                    svc_name = winreg.EnumKey(key, i)
                    i += 1
                except OSError:
                    break
                try:
                    svc_key = winreg.OpenKey(key, svc_name)
                    try:
                        svc_type, _ = winreg.QueryValueEx(svc_key, "Type")
                        if svc_type not in (1, 2):  # 1=kernel, 2=filesystem driver
                            continue
                        try:
                            image_path, _ = winreg.QueryValueEx(svc_key, "ImagePath")
                        except OSError:
                            continue
                        real_path = self._resolve_driver_path(image_path)
                        sha256 = self._hash_file(real_path)
                        info = self._check_driver(svc_name, real_path, sha256)
                        drivers.append(info)
                    except OSError:
                        pass
                    finally:
                        winreg.CloseKey(svc_key)
                except OSError:
                    pass
            winreg.CloseKey(key)
        except Exception as e:
            pass

        return drivers

    def _resolve_driver_path(self, image_path: str) -> str:
        sysroot = os.environ.get("SystemRoot", r"C:\Windows")
        path = image_path
        # Replace common path prefixes
        for prefix in (r"\SystemRoot", r"%SystemRoot%", r"\Windows"):
            if path.lower().startswith(prefix.lower()):
                path = sysroot + path[len(prefix):]
                break
        # Handle kernel-style paths like \??\C:\...
        if path.startswith("\\??\\"):
            path = path[4:]
        return path

    def _hash_file(self, path: str) -> Optional[str]:
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                while chunk := f.read(65536):
                    h.update(chunk)
            return h.hexdigest().lower()
        except Exception:
            return None

    def _check_driver(self, svc_name: str, path: str, sha256: Optional[str]) -> DriverInfo:
        filename = os.path.basename(path)
        vuln_entry = None

        # Check by SHA256 first (most reliable)
        if sha256 and sha256 in self._hash_index:
            vuln_entry = self._hash_index[sha256]

        # Fallback: check by filename
        if vuln_entry is None and filename.lower() in self._name_index:
            vuln_entry = self._name_index[filename.lower()]

        if vuln_entry:
            return DriverInfo(
                service_name=svc_name,
                filename=filename,
                full_path=path,
                sha256=sha256,
                is_vulnerable=True,
                vuln_entry=vuln_entry,
                tags=vuln_entry.get("Tags", []),
                cve=vuln_entry.get("CVE", ""),
                vendor=vuln_entry.get("Vendor", ""),
                description=vuln_entry.get("Description", ""),
            )

        return DriverInfo(
            service_name=svc_name,
            filename=filename,
            full_path=path,
            sha256=sha256,
            is_vulnerable=False,
        )

    # ── Mock drivers (non-Windows / demo) ─────────────────────────────────────

    def _mock_drivers(self) -> list[DriverInfo]:
        mock_list = [
            ("ntfs",        "ntfs.sys",        r"C:\Windows\System32\drivers\ntfs.sys"),
            ("disk",        "disk.sys",         r"C:\Windows\System32\drivers\disk.sys"),
            ("RTCore64",    "RTCore64.sys",     r"C:\Windows\System32\drivers\RTCore64.sys"),
            ("WinRing0_1_2_0", "WinRing0x64.sys", r"C:\Windows\System32\drivers\WinRing0x64.sys"),
        ]
        results = []
        for svc, filename, path in mock_list:
            vuln_entry = self._name_index.get(filename.lower())
            if vuln_entry:
                results.append(DriverInfo(
                    service_name=svc,
                    filename=filename,
                    full_path=path,
                    sha256="[simulated]",
                    is_vulnerable=True,
                    vuln_entry=vuln_entry,
                    tags=vuln_entry.get("Tags", []),
                    cve=vuln_entry.get("CVE", ""),
                    vendor=vuln_entry.get("Vendor", ""),
                    description=vuln_entry.get("Description", ""),
                ))
            else:
                results.append(DriverInfo(
                    service_name=svc,
                    filename=filename,
                    full_path=path,
                    sha256="[simulated]",
                    is_vulnerable=False,
                ))
        return results

    # ── Scan summary ──────────────────────────────────────────────────────────

    def scan(self, use_live_db: bool = False) -> dict:
        """Run a full scan and return a structured result dict."""
        if use_live_db:
            self._load_db(use_live=True)

        drivers = self.enumerate_system_drivers()
        vulnerable = [d for d in drivers if d.is_vulnerable]
        critical   = [d for d in vulnerable if d.risk_level() == "CRITICAL"]
        high       = [d for d in vulnerable if d.risk_level() == "HIGH"]

        return {
            "total_drivers":      len(drivers),
            "vulnerable_count":   len(vulnerable),
            "critical_count":     len(critical),
            "high_count":         len(high),
            "all_drivers":        drivers,
            "vulnerable_drivers": vulnerable,
        }

    def db_size(self) -> int:
        return len(self._db)
