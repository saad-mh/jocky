"""
BYOVD Driver Scanner — cross-references installed kernel drivers against the
LOLDrivers vulnerability database using both filename and SHA-256 hash.
"""
from __future__ import annotations
import hashlib
import json
import os
import pathlib
import platform
import sys
from typing import Optional

_DB_PATH = pathlib.Path(__file__).parent / "db" / "loldrivers.json"

# ── Database loading ──────────────────────────────────────────────────────────

def _load_db() -> list[dict]:
    if not _DB_PATH.exists():
        return []
    with open(_DB_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

def _build_indices(db: list[dict]) -> tuple[dict, dict]:
    """Return (name_index, hash_index) where keys are lowercased."""
    name_idx: dict[str, dict] = {}
    hash_idx: dict[str, dict] = {}
    for entry in db:
        name_idx[entry["Name"].lower()] = entry
        for sample in entry.get("KnownVulnerableSamples", []):
            sha = sample.get("SHA256", "").lower()
            if sha and len(sha) == 64:
                hash_idx[sha] = entry
    return name_idx, hash_idx

# ── File hashing ──────────────────────────────────────────────────────────────

def _sha256_file(path: str) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None

# ── Risk scoring ──────────────────────────────────────────────────────────────

_TAG_RISK: dict[str, int] = {
    "Kernel-RW":              10,
    "AV-Kill":                10,
    "EDR-Bypass":             9,
    "Code-Execution":         9,
    "DKOM":                   8,
    "Physical-Memory":        7,
    "Privilege-Escalation":   7,
    "MMIO":                   5,
    "APT":                    6,
    "Ransomware":             8,
}

def _risk_score(entry: dict) -> int:
    return min(10, sum(_TAG_RISK.get(t, 1) for t in entry.get("Tags", [])) // max(1, len(entry.get("Tags", [])) - 1))

def _risk_label(score: int) -> str:
    if score >= 9:
        return "CRITICAL"
    if score >= 7:
        return "HIGH"
    if score >= 5:
        return "MEDIUM"
    return "LOW"

# ── Windows scanner ───────────────────────────────────────────────────────────

def _windows_driver_dirs() -> list[str]:
    windir = os.environ.get("WINDIR", r"C:\Windows")
    return [
        os.path.join(windir, "System32", "drivers"),
        os.path.join(windir, "SysWOW64", "drivers"),
    ]

def _scan_windows(name_idx: dict, hash_idx: dict) -> list[dict]:
    findings = []
    seen: set[str] = set()

    for driver_dir in _windows_driver_dirs():
        if not os.path.isdir(driver_dir):
            continue
        try:
            entries_iter = os.scandir(driver_dir)
        except PermissionError:
            continue
        for de in entries_iter:
            if not de.is_file():
                continue
            fname = de.name.lower()
            if not fname.endswith(".sys"):
                continue
            if de.path in seen:
                continue
            seen.add(de.path)

            match_entry = None
            match_method = None

            # Method 1: SHA-256 cross-reference (authoritative)
            sha = _sha256_file(de.path)
            if sha and sha in hash_idx:
                match_entry = hash_idx[sha]
                match_method = f"SHA256:{sha[:16]}..."

            # Method 2: filename fallback (less reliable — recompiled/renamed drivers may differ)
            if match_entry is None and fname in name_idx:
                match_entry = name_idx[fname]
                match_method = "filename"

            if match_entry is None:
                continue

            score = _risk_score(match_entry)
            findings.append({
                "path":   de.path,
                "name":   de.name,
                "sha256": sha or "unavailable",
                "match":  match_method,
                "entry":  match_entry,
                "risk":   _risk_label(score),
                "score":  score,
            })

    findings.sort(key=lambda x: x["score"], reverse=True)
    return findings

# ── Linux scanner ─────────────────────────────────────────────────────────────

def _linux_module_dirs() -> list[str]:
    dirs = []
    try:
        import subprocess
        kr = subprocess.check_output(["uname", "-r"], text=True).strip()
        dirs.append(f"/lib/modules/{kr}/kernel/drivers")
        dirs.append(f"/lib/modules/{kr}")
    except Exception:
        dirs.append("/lib/modules")
    return dirs

def _scan_linux(name_idx: dict, hash_idx: dict) -> list[dict]:
    findings = []
    seen: set[str] = set()

    for base in _linux_module_dirs():
        for root, _, files in os.walk(base):
            for fname in files:
                if not (fname.endswith(".ko") or fname.endswith(".ko.xz") or fname.endswith(".ko.gz")):
                    continue
                fpath = os.path.join(root, fname)
                if fpath in seen:
                    continue
                seen.add(fpath)

                # strip extensions
                bare = fname
                for ext in (".ko.xz", ".ko.gz", ".ko"):
                    if bare.endswith(ext):
                        bare = bare[: -len(ext)]
                        break

                match_entry = None
                match_method = None

                sha = _sha256_file(fpath)
                if sha and sha in hash_idx:
                    match_entry = hash_idx[sha]
                    match_method = f"SHA256:{sha[:16]}..."

                if match_entry is None and bare.lower() in name_idx:
                    match_entry = name_idx[bare.lower()]
                    match_method = "filename"

                if match_entry is None:
                    continue

                score = _risk_score(match_entry)
                findings.append({
                    "path":   fpath,
                    "name":   fname,
                    "sha256": sha or "unavailable",
                    "match":  match_method,
                    "entry":  match_entry,
                    "risk":   _risk_label(score),
                    "score":  score,
                })

    findings.sort(key=lambda x: x["score"], reverse=True)
    return findings

# ── Public interface ──────────────────────────────────────────────────────────

class DriverScanner:
    def __init__(self) -> None:
        self._db = _load_db()
        self._name_idx, self._hash_idx = _build_indices(self._db)

    def scan(self) -> list[dict]:
        """Scan the current platform's driver directories. Returns sorted findings."""
        if sys.platform.startswith("linux"):
            return _scan_linux(self._name_idx, self._hash_idx)
        return _scan_windows(self._name_idx, self._hash_idx)

    def db_entry_count(self) -> int:
        return len(self._db)

    def print_report(self, findings: Optional[list[dict]] = None) -> None:
        if findings is None:
            findings = self.scan()
        print(f"\n[SCANNER] LOLDrivers DB: {self.db_entry_count()} entries")
        print(f"[SCANNER] Found {len(findings)} vulnerable driver(s) on this system\n")
        for f in findings:
            e = f["entry"]
            print(f"  [{f['risk']:8s}] {f['name']}")
            print(f"           CVE      : {e.get('CVE','N/A')}")
            print(f"           Tags     : {', '.join(e.get('Tags',[]))}")
            print(f"           Match    : {f['match']}")
            print(f"           SHA256   : {f['sha256']}")
            print(f"           Path     : {f['path']}")
            print(f"           Desc     : {e.get('Description','')}")
            print()


if __name__ == "__main__":
    scanner = DriverScanner()
    scanner.print_report()
