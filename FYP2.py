import os
import sys
import time
import json
import math
import shutil
import stat
import hashlib
import threading
import queue
import itertools
import logging
import atexit
import platform
import tempfile
from pathlib import Path
from collections import deque
from typing import Optional

import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

try:
    import tkinter as tk
    from tkinter import ttk, messagebox
    _GUI_AVAILABLE = True
except ImportError:
    _GUI_AVAILABLE = False

if not _GUI_AVAILABLE:
    print("[ERROR] tkinter not available. "
          "This tool requires a GUI environment (Windows/Linux Desktop). "
          "Cannot run in headless/server mode.")
    sys.exit(1)

# ============================================================
# CONFIG & GLOBALS
# ============================================================
CONFIG_FILE   = str(Path(__file__).parent / "ransomware_config.json")
QUARANTINE_DIR = str(Path(__file__).parent / "quarantine")
FORENSIC_DIR   = str(Path(__file__).parent / "forensic_evidence")
SHADOW_COPY_DIR = str(Path(__file__).parent / "shadow_copies")
IS_WINDOWS     = platform.system() == "Windows"

DEFAULT_CONFIG = {
    "enabled": True,
    "white_list_paths": [],
    "whitelist_tier1_processes": [
        "svchost.exe", "explorer.exe", "system", "wininit.exe",
        "services.exe", "lsass.exe", "dwm.exe", "csrss.exe", "smss.exe",
        "winlogon.exe", "taskhostw.exe", "runtimebroker.exe",
        "searchindexer.exe", "systemd", "launchd", "init", "kthreadd",
    ],
    "white_list_procs": [],
    "whitelist_match_mode": "exact",

    "whitelist_tier1_trusted_dirs": [
        r"c:\windows\system32", r"c:\windows\syswow64", r"c:\windows",
        "/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/lib/systemd",
    ],

    "shadow_copy_enabled": True,
    "shadow_copy_retention_days": 7,

    "threshold_1s":  5,
    "threshold_1h":  50,
    "threshold_24h": 200,

    "entropy_threshold":        7.2,
    "entropy_delta_threshold":  1.5,
    "high_alert_entropy_threshold": 6.5,

    "suspicious_exts": [
        ".encrypted", ".locked", ".crypt", ".crypto",
        ".ransom", ".zepto", ".wallet", ".enc"
    ],
    "monitored_exts": [
        ".docx", ".xlsx", ".pptx", ".pdf", ".txt",
        ".csv", ".sql", ".db", ".doc", ".xls", ".ppt"
    ],

    "hardware_cpu_threshold":    80.0,
    "hardware_mem_threshold":    85.0,
    "hardware_check_interval_sec": 1,
    "hardware_snapshot_interval_sec": 5,
    "hardware_confirm_window_sec":   10,

    "weight_cpu":       0.05,
    "weight_freq":      0.25,
    "weight_entropy":   0.25,
    "weight_signature": 0.45,
    "risk_alert_threshold": 0.4,

    "signature_min_files_touched": 3,
    "signature_min_entropy_trend": 2,

    "baseline_max_files": 100000,

    "honeypot_filenames": [
        "!000_killme.txt",
        "!000_killme.doc",
        "!000_ransom_trap.txt"
    ],

    "registry_poll_interval_sec": 5,

    "suspicious_parent_child": {
        "winword.exe":  ["cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe", "cscript.exe"],
        "excel.exe":    ["cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe", "cscript.exe"],
        "powerpnt.exe": ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"],
        "outlook.exe":  ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"]
    },

    "enc_sequence_window_events": 12,
    "enc_sequence_min_pairs": 3,

    "forensic_high_risk_threshold": 10,
    "forensic_medium_risk_threshold": 3
}

baseline_lock = threading.Lock()


def load_config():
    import copy
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                loaded = json.load(f)
            known_keys = set(DEFAULT_CONFIG.keys())
            filtered = {k: v for k, v in loaded.items() if k in known_keys}
            cfg.update(filtered)
        except Exception as e:
            logging.warning(f"Failed to load config: {e}, using defaults")
    return cfg


# ============================================================
# UTILITIES & ALGORITHMS
# ============================================================
FILE_MAGIC_SIGNATURES = {
    ".docx": b"PK",
    ".xlsx": b"PK",
    ".pptx": b"PK",
    ".pdf":  b"%PDF",
}

_CRITICAL_KEYWORDS = (
    "honeypot", "operation sequence confirmed",
    "encryption sequence",
)

_HIGH_KEYWORDS = (
    "header mismatch",
    "autorun", "shadow copy", "suspicious extension",
    "temp directory", "suspicious process lineage", "bulk deletion",
)

TIER_PRIORITY = {"critical": 0, "high": 1, "low": 2}


def classify_alert_tier(reason: str) -> str:
    reason_l = (reason or "").lower()
    if any(k in reason_l for k in _CRITICAL_KEYWORDS):
        return "critical"
    if any(k in reason_l for k in _HIGH_KEYWORDS):
        return "high"
    return "low"


def is_high_confidence_alert(reason: str) -> bool:
    """Back-compat convenience: True for critical or high tier."""
    return classify_alert_tier(reason) in ("critical", "high")


def _safe_get_exe_path(pid: int) -> Optional[str]:
    """Best-effort psutil exe() lookup for whitelist path verification; None if unavailable."""
    if not pid:
        return None
    try:
        return psutil.Process(pid).exe()
    except Exception:
        return None


def get_whitelist_tier(proc_name: str, config: dict, exe_path: str = None) -> str:
    """Classifies a process into tier1/tier2/none trust level, requiring tier1 matches to also resolve to a trusted directory."""
    if not proc_name:
        return "none"
    name_l = proc_name.lower()

    if name_l in (p.lower() for p in config.get("whitelist_tier1_processes", [])):
        if exe_path:
            trusted_dirs = config.get("whitelist_tier1_trusted_dirs", [])
            exe_l = str(exe_path).lower()
            if any(exe_l.startswith(d.lower()) for d in trusted_dirs):
                return "tier1"
            return "none"
        return "tier1"

    w_procs = config.get("white_list_procs", [])
    mode = config.get("whitelist_match_mode", "exact")
    if mode == "exact":
        if name_l in (p.lower() for p in w_procs):
            return "tier2"
    else:
        if any(p.lower() in name_l for p in w_procs):
            return "tier2"

    return "none"


def adjust_tier_for_whitelist(base_tier: str, proc_name: str, config: dict, exe_path: str = None) -> str:
    """Softens an alert's tier based on whitelist trust as a score adjustment, never a detection bypass."""
    if base_tier == "critical":
        return base_tier
    wl_tier = get_whitelist_tier(proc_name, config, exe_path)
    if wl_tier == "tier1" and base_tier == "high":
        return "low"
    if wl_tier == "tier2" and base_tier == "low":
        return "quiet"
    return base_tier


def check_file_header(file_path: str) -> Optional[str]:
    """Returns a reason string if the file's magic bytes don't match its extension, else None."""
    ext = os.path.splitext(file_path)[1].lower()
    sig = FILE_MAGIC_SIGNATURES.get(ext)
    if not sig:
        return None
    try:
        with open(file_path, "rb") as fh:
            head = fh.read(len(sig))
    except Exception:
        return None
    if len(head) < len(sig) or head != sig:
        return (f"File header mismatch: {Path(file_path).name} no longer "
                f"matches expected '{ext}' signature (possible encryption)")
    return None


def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    length = len(data)
    entropy = 0.0
    for c in counts:
        if c > 0:
            p = c / length
            entropy -= p * math.log2(p)
    return entropy


def get_file_entropy_sampled(file_path: str) -> float:
    """Computes entropy by sampling several evenly-spread chunks of the file."""
    try:
        size = os.path.getsize(file_path)
        if size == 0:
            return 0.0
        if size <= 5 * 1024 * 1024:
            with open(file_path, "rb") as f:
                return calculate_entropy(f.read())

        num_points = 6
        chunk = 256 * 1024
        data = bytearray()
        with open(file_path, "rb") as f:
            for i in range(num_points):
                frac = i / (num_points - 1)
                offset = max(0, min(size - chunk, int(size * frac)))
                f.seek(offset)
                data += f.read(chunk)
        return calculate_entropy(bytes(data))
    except Exception as e:
        logging.debug(f"Entropy sampling failed {file_path}: {e}")
        return 0.0


def compute_file_hash(file_path: str) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        logging.debug(f"Hash failed for {file_path}: {e}")
        return None


def build_baseline(monitor_path: str, max_files: int = 100000) -> dict:
    """Returns {abs_path: {"hash": str, "entropy": float}}"""
    baseline = {}
    p = Path(monitor_path)
    if not p.exists():
        return baseline
    for file in p.rglob("*"):
        if len(baseline) >= max_files:
            logging.warning(
                f"Baseline capped at {max_files} files; "
                "some files will not be baselined."
            )
            break
        try:
            if file.is_file():
                f_abs = str(file.resolve())
                baseline[f_abs] = {
                    "hash":    compute_file_hash(f_abs),
                    "entropy": get_file_entropy_sampled(f_abs)
                }
        except Exception as e:
            logging.debug(f"Skipping {file} during baseline: {e}")
    return baseline


def cleanup_expired_shadow_copies(config: dict) -> int:
    """Deletes shadow copy snapshots older than the configured retention period."""
    retention_days = config.get("shadow_copy_retention_days", 7)
    root = Path(SHADOW_COPY_DIR)
    if not root.exists():
        return 0

    cutoff = time.time() - retention_days * 86400
    removed = 0
    for entry in root.iterdir():
        try:
            if not entry.is_dir() or entry.stat().st_mtime >= cutoff:
                continue
            for f in entry.rglob("*"):
                try:
                    os.chmod(f, stat.S_IWRITE if IS_WINDOWS else 0o755)
                except Exception:
                    pass
            os.chmod(entry, stat.S_IWRITE if IS_WINDOWS else 0o755)
            shutil.rmtree(entry, ignore_errors=True)
            removed += 1
        except Exception as e:
            logging.debug(f"Failed to check/remove shadow copy {entry}: {e}")

    if removed:
        logging.info(
            f"Removed {removed} expired shadow cop{'y' if removed == 1 else 'ies'} "
            f"older than {retention_days} day(s).")
    return removed


def create_shadow_copy(monitor_path: str, config: dict) -> Optional[str]:
    """Creates a timestamped, read-only snapshot of the monitored folder."""
    if not config.get("shadow_copy_enabled", True):
        return None

    cleanup_expired_shadow_copies(config)

    ts = time.strftime("%Y%m%d_%H%M%S")
    dest = Path(SHADOW_COPY_DIR) / f"snapshot_{ts}"
    try:
        Path(SHADOW_COPY_DIR).mkdir(parents=True, exist_ok=True)
        shutil.copytree(monitor_path, dest, dirs_exist_ok=True)
        ProcessTerminator.lock_monitor_folder(str(dest))
        logging.info(f"Shadow copy created: {dest}")
        return str(dest)
    except Exception as e:
        logging.error(f"Shadow copy creation failed: {e}")
        return None


# ============================================================
# PROCESS CONTROL & QUARANTINE
# ============================================================
class ProcessTerminator:
    _INTERPRETER_HOSTS = {
        "python.exe", "python3.exe", "pythonw.exe", "python3",
        "python", "python3.10", "python3.11", "python3.12", "python3.13",
        "powershell.exe", "pwsh.exe", "cmd.exe",
        "wscript.exe", "cscript.exe", "mshta.exe",
        "node.exe", "node", "perl.exe", "perl", "ruby.exe", "ruby",
        "bash", "sh", "dash", "zsh",
    }

    _SYSTEM_DIRS = (
        "c:\\windows\\", "c:\\program files\\", "c:\\program files (x86)\\",
        "/usr/bin/", "/usr/lib/", "/usr/sbin/", "/usr/local/bin/",
        "/bin/", "/sbin/", "/lib/", "/lib64/",
    )

    @staticmethod
    def _is_protected_host_binary(exe_path: str) -> bool:
        """Returns True if exe_path is a shared interpreter or system binary that must never be quarantined."""
        if not exe_path:
            return False

        raw_l = str(exe_path).lower().replace("/", "\\")
        raw_l_fwd = str(exe_path).lower().replace("\\", "/")

        try:
            src = Path(exe_path).resolve()
            if src.name.lower() in ProcessTerminator._INTERPRETER_HOSTS:
                return True
            resolved_l = str(src).lower()
        except Exception:
            resolved_l = raw_l_fwd

        base_name = raw_l_fwd.rsplit("/", 1)[-1]
        if base_name in ProcessTerminator._INTERPRETER_HOSTS:
            return True

        for d in ProcessTerminator._SYSTEM_DIRS:
            d_bslash = d.replace("/", "\\")
            if resolved_l.startswith(d) or raw_l.startswith(d_bslash) or raw_l_fwd.startswith(d):
                return True
        return False

    _SCRIPT_PAYLOAD_EXTS = (".py", ".pyw", ".ps1", ".bat", ".cmd",
                             ".js", ".vbs", ".vbe", ".wsf", ".sh")

    @staticmethod
    def _extract_script_payload(cmdline: list, monitor_path=None):
        """Finds a script file passed as an argument to a shared interpreter, to quarantine instead."""
        if not cmdline or len(cmdline) < 2:
            return None
        for arg in cmdline[1:]:
            if not isinstance(arg, str) or not arg:
                continue
            if not arg.lower().endswith(ProcessTerminator._SCRIPT_PAYLOAD_EXTS):
                continue
            try:
                arg_path = Path(arg).resolve()
                if not (arg_path.exists() and arg_path.is_file()):
                    continue
            except Exception:
                continue
            if ProcessTerminator._is_protected_host_binary(str(arg_path)):
                continue
            if monitor_path:
                try:
                    mp = Path(monitor_path).resolve()
                    if str(arg_path).lower().startswith(str(mp).lower()):
                        continue
                except Exception:
                    pass
            return arg_path
        return None

    @staticmethod
    def suspend_process(pid: int) -> bool:
        try:
            psutil.Process(pid).suspend()
            logging.info(f"SUSPENDED PID {pid}")
            return True
        except Exception as e:
            logging.error(f"Failed to suspend PID {pid}: {e}")
            return False

    @staticmethod
    def resume_process(pid: int) -> bool:
        try:
            psutil.Process(pid).resume()
            logging.info(f"RESUMED PID {pid}")
            return True
        except Exception as e:
            logging.error(f"Failed to resume PID {pid}: {e}")
            return False

    @staticmethod
    def lock_monitor_folder(monitor_path: str) -> int:
        """Strips write permission from every file and the folder itself; returns the number of files locked."""
        locked = 0
        root = Path(monitor_path)
        try:
            for f in root.rglob("*"):
                try:
                    if f.is_file():
                        os.chmod(f, stat.S_IREAD if IS_WINDOWS else 0o444)
                        locked += 1
                except Exception as e:
                    logging.debug(f"Failed to lock {f}: {e}")
            os.chmod(root, stat.S_IREAD if IS_WINDOWS else 0o555)
        except Exception as e:
            logging.error(f"Failed to lock monitor folder {monitor_path}: {e}")
        logging.info(f"Monitor folder locked read-only: {locked} files under {monitor_path}")
        return locked

    @staticmethod
    def unlock_monitor_folder(monitor_path: str) -> int:
        """Restores normal read/write permissions on the monitored folder."""
        unlocked = 0
        root = Path(monitor_path)
        try:
            os.chmod(root, stat.S_IWRITE | stat.S_IREAD if IS_WINDOWS else 0o755)
            for f in root.rglob("*"):
                try:
                    if f.is_file():
                        os.chmod(f, stat.S_IWRITE | stat.S_IREAD if IS_WINDOWS else 0o644)
                        unlocked += 1
                except Exception as e:
                    logging.debug(f"Failed to unlock {f}: {e}")
        except Exception as e:
            logging.error(f"Failed to unlock monitor folder {monitor_path}: {e}")
        logging.info(f"Monitor folder unlocked: {unlocked} files under {monitor_path}")
        return unlocked

    @staticmethod
    def terminate_and_quarantine(pid: int, ui_log_callback=None, monitor_path=None) -> bool:
        exe_path  = None
        proc_name = "Unknown"
        cmdline   = []
        terminated = False
        try:
            p         = psutil.Process(pid)
            proc_name = p.name()
            exe_path  = p.exe()
            cmdline   = p.cmdline()
        except Exception as e:
            logging.debug(f"Failed to get process info before kill: {e}")

        try:
            _proc = psutil.Process(pid)
            _proc.terminate()
            _proc.wait(timeout=3)
            terminated = True 
            msg = f"TERMINATED: {proc_name} (PID {pid})"
            logging.info(msg)
            if ui_log_callback:
                ui_log_callback(msg + "\n", "critical")
        except Exception:
            try:
                psutil.Process(pid).kill()
                terminated = True 
                logging.info(f"FORCE-KILLED PID {pid}")
            except Exception as e:
                logging.error(f"Force-kill failed: {e}")

        if not terminated:
            logging.error(f"Unable to terminate PID {pid}, aborting quarantine.")
            return False

        if exe_path and os.path.exists(exe_path):
            src  = Path(exe_path).resolve()

            if ProcessTerminator._is_protected_host_binary(exe_path):
                msg = (f"SKIPPED QUARANTINE (shared interpreter/system "
                       f"binary, not the payload): {src}")
                logging.warning(msg)
                if ui_log_callback:
                    ui_log_callback(msg + "\n", "warning")

                payload_path = ProcessTerminator._extract_script_payload(
                    cmdline, monitor_path=monitor_path)
                if payload_path:
                    quarantine_dir = Path(QUARANTINE_DIR).resolve()
                    quarantine_dir.mkdir(parents=True, exist_ok=True)
                    dest = quarantine_dir / f"{pid}_payload_{payload_path.name}.quarantine"
                    try:
                        shutil.move(str(payload_path), str(dest))
                        pmsg = f"QUARANTINED PAYLOAD SCRIPT: {dest} (host interpreter preserved)"
                        logging.info(pmsg)
                        if ui_log_callback:
                            ui_log_callback(pmsg + "\n", "success")
                    except Exception as e:
                        logging.warning(f"Payload quarantine failed: {e}")
                else:
                    logging.info(
                        "No safely-quarantinable script payload found in "
                        "cmdline (fileless attack, script already gone, or "
                        "it lives inside the protected monitor folder). "
                        "cmdline is preserved in the forensic report.")
                return True

            quarantine_dir = Path(QUARANTINE_DIR).resolve()
            quarantine_dir.mkdir(parents=True, exist_ok=True)
            dest = quarantine_dir / f"{pid}_{src.name}.quarantine"
            try:
                shutil.move(str(src), str(dest))
                msg = f"QUARANTINED: {dest}"
                logging.info(msg)
                if ui_log_callback:
                    ui_log_callback(msg + "\n", "success")
                return True
            except Exception as e:
                logging.warning(f"Move failed: {e}. Trying copy+delete.")
                try:
                    shutil.copy2(str(src), str(dest))
                except Exception as e:
                    logging.error(f"Copy failed: {e}")
                    return False
                try: 
                    os.remove(str(src))
                    return True 
                except Exception as ce:
                    logging.error(f"Copy+delete failed: {ce}")
                    if IS_WINDOWS:
                        import ctypes
                        _MoveFileExW = ctypes.windll.kernel32.MoveFileExW
                        _MoveFileExW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32]
                        _MoveFileExW.restype  = ctypes.c_bool
                        result = _MoveFileExW(str(src), None, 0x00000004)
                        if result: 
                            logging.info("Scheduled deletion on reboot.")
                        else:
                            logging.warning("Failed to schedule deletion on reboot.")
                    else:
                        def cleanup(_src=str(src)):
                            try:
                                if os.path.exists(_src):
                                    os.remove(_src)
                            except Exception as e:
                                logging.debug(f"Atexit cleanup failed for {_src}: {e}")
                        atexit.register(cleanup)
                    return True
        return terminated


# ============================================================
# PER-PID STATISTICAL STORE
# ============================================================
class PerPidStore:
    def __init__(self, config=None):
        self.lock = threading.Lock()
        self.history = {}
        self._seq_window = (config or {}).get("enc_sequence_window_events", 30)

    def _cleanup_store(self, store):
        now = time.time()

        while store["q_1s"] and now - store["q_1s"][0] > 1:
            store["q_1s"].popleft()

        while store["q_1h"] and now - store["q_1h"][0] > 3600:
            store["q_1h"].popleft()

        while store["q_24h"] and now - store["q_24h"][0] > 86400:
            store["q_24h"].popleft()

    def record(self, pid, proc_name, event_type, file_path, is_entropy_anomaly=False):
        is_new_pid = False
        with self.lock:
            if pid not in self.history:
                is_new_pid = True
                self.history[pid] = {
                    "name": proc_name,
                    "q_1s": deque(),
                    "q_1h": deque(),
                    "q_24h": deque(),
                    "entropy_anomaly_count": 0,
                    "touched_files": deque(maxlen=200),
                    "action_seq": deque(maxlen=self._seq_window),
                    "entropy_pending_files": set(),
                    "entropy_delta_trend": deque(maxlen=10),
                }
            else:
                stored_name = self.history[pid]["name"]
                if (proc_name and stored_name and
                        proc_name.lower() != stored_name.lower() and
                        proc_name not in ("unknown", "unattributed(pid=0)")):
                    logging.warning(
                        f"PID {pid} reuse detected: was '{stored_name}' "
                        f"now '{proc_name}'. Resetting attribution store."
                    )
                    is_new_pid = True
                    self.history[pid] = {
                        "name": proc_name,
                        "q_1s": deque(),
                        "q_1h": deque(),
                        "q_24h": deque(),
                        "entropy_anomaly_count": 0,
                        "touched_files": deque(maxlen=200),
                        "action_seq": deque(maxlen=self._seq_window)
                    }

            store = self.history[pid]
            self._cleanup_store(store)

            now = time.time()
            store["q_1s"].append(now)
            store["q_1h"].append(now)
            store["q_24h"].append(now)

            if file_path not in store["touched_files"]:
                store["touched_files"].append(file_path)

            if is_entropy_anomaly:
                store["entropy_anomaly_count"] += 1

            store["action_seq"].append(event_type)

        if is_new_pid and pid:
            try:
                psutil.Process(pid).cpu_percent(interval=None)
            except Exception as e:
                logging.debug(f"cpu_percent warmup failed for pid {pid}: {e}")

    def mark_entropy_anomaly(self, pid):
        """Increments the entropy anomaly counter for a pid."""
        with self.lock:
            if pid in self.history:
                self.history[pid]["entropy_anomaly_count"] += 1

    def mark_entropy_pending(self, pid, file_path, delta=None):
        """Marks a file as pending entropy evidence for a pid, for file-operation detection to confirm later."""
        with self.lock:
            if pid in self.history:
                self.history[pid]["entropy_pending_files"].add(file_path)
                if delta is not None:
                    self.history[pid]["entropy_delta_trend"].append(delta)

    def get_entropy_pending_count(self, pid):
        with self.lock:
            if pid not in self.history:
                return 0
            return len(self.history[pid]["entropy_pending_files"])

    def resolve_entropy_pending(self, pid):
        """Clears a pid's pending entropy evidence after file-operation detection confirms it."""
        with self.lock:
            if pid in self.history:
                self.history[pid]["entropy_pending_files"].clear()

    def get_entropy_trend(self, pid):
        """Returns a pid's recent signed entropy deltas (the hardware signature's directionality signal)."""
        with self.lock:
            if pid not in self.history:
                return []
            return list(self.history[pid]["entropy_delta_trend"])

    def get_touched_file_count(self, pid):
        """Returns how many distinct files a pid has touched recently (the signature's repetition component)."""
        with self.lock:
            if pid not in self.history:
                return 0
            return len(self.history[pid]["touched_files"])

    def get_action_sequence(self, pid):
        with self.lock:
            if pid not in self.history:
                return []
            return list(self.history[pid].get("action_seq", []))

    def detect_encryption_sequence(self, pid, min_pairs=3):
        """Detects a repeated encrypt/rename or write-then-delete pattern typical of ransomware."""
        seq = self.get_action_sequence(pid)
        if len(seq) < min_pairs + 1:
            return False
        pairs = 0
        for i in range(len(seq) - 1):
            a, b = seq[i], seq[i + 1]
            if a in ("modified", "created") and b in ("moved", "modified"):
                pairs += 1
            elif a in ("created", "deleted") and b in ("created", "deleted") and a != b:
                pairs += 1
        return pairs >= min_pairs

    def clean_and_get_counts(self, pid):
        with self.lock:
            if pid not in self.history:
                return 0, 0, 0, 0

            store = self.history[pid]
            self._cleanup_store(store)

            return (
                len(store["q_1s"]),
                len(store["q_1h"]),
                len(store["q_24h"]),
                store["entropy_anomaly_count"]
            )

    def get_all_active_pids(self):
        with self.lock:
            return list(self.history.keys())

    def prune_dead_pids(self):
        try:
            alive = {p.pid for p in psutil.process_iter(['pid'])}
        except Exception:
            return

        with self.lock:
            dead = [pid for pid in self.history if pid not in alive]
            for pid in dead:
                del self.history[pid]


# ============================================================
# FORENSIC ENGINE
# ============================================================
class ForensicEngine:
    def __init__(self, config, baseline):
        self.config = config
        self.baseline = baseline
        self.alert_queue = queue.PriorityQueue(maxsize=2000)
        self._alert_seq = itertools.count()

        self._last_report_lock = threading.Lock()
        self._last_report_text = None
        self._last_report_path = None

    def get_last_report(self):
        with self._last_report_lock:
            return self._last_report_text, self._last_report_path

    def set_baseline(self, b):
        self.baseline = b

    def push_alert_to_ui(self, alert_dict):
        priority = TIER_PRIORITY.get(alert_dict.get("tier", "high"), 1)
        try:
            self.alert_queue.put_nowait(
                (priority, next(self._alert_seq), alert_dict)
            )
        except queue.Full:
            logging.critical(
                "ALERT QUEUE FULL — forensic alert DROPPED. "
                "Increase alert_queue maxsize or reduce event rate."
            )

    def _classify_depth(self, reason: str, recent_files: list) -> str:
        """Decides how much forensic evidence to capture based on the alert's estimated risk."""
        reason_l = (reason or "").lower()
        high_keywords = (
            "honeypot", "registry", "autorun", "shadow copy",
            "header mismatch", "encryption sequence",
            "process lineage", "temp directory",
            "suspicious extension"
        )
        high_file_count = self.config.get("forensic_high_risk_threshold", 10)
        medium_file_count = self.config.get("forensic_medium_risk_threshold", 3)

        if any(k in reason_l for k in high_keywords) or len(recent_files) >= high_file_count:
            return "full"
        if len(recent_files) >= medium_file_count:
            return "medium"
        return "basic"

    def _capture_process_lineage(self, pid: int, max_depth: int = 3) -> list:
        """Walks up parent processes to build an attack-chain lineage list."""
        chain = []
        try:
            proc = psutil.Process(pid)
            chain.append({"pid": proc.pid, "name": proc.name()})
            current = proc
            for _ in range(max_depth):
                parent = current.parent()
                if not parent:
                    break
                chain.insert(0, {"pid": parent.pid, "name": parent.name()})
                current = parent
        except Exception as e:
            logging.debug(f"Process lineage capture failed for pid {pid}: {e}")
        return chain

    def _capture_network_connections(self, pid: int) -> list:
        conns = []
        try:
            proc = psutil.Process(pid)
            try:
                raw = proc.net_connections(kind="inet")
            except AttributeError:
                raw = proc.connections(kind="inet")
            for c in raw[:50]:
                conns.append({
                    "local_addr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else None,
                    "remote_addr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else None,
                    "status": c.status
                })
        except Exception as e:
            logging.debug(f"Network connection capture failed for pid {pid}: {e}")
        return conns

    def _capture_memory_info(self, pid: int) -> dict:
        """Captures a process's memory usage without a full memory dump."""
        info = {}
        try:
            proc = psutil.Process(pid)
            mem = proc.memory_info()
            info["rss_bytes"] = mem.rss
            info["vms_bytes"] = mem.vms
            try:
                maps = proc.memory_maps()
                info["mapped_region_count"] = len(maps)
                info["sample_regions"] = [m.path for m in maps[:10] if getattr(m, "path", None)]
            except Exception as e:
                logging.debug(f"memory_maps failed for pid {pid}: {e}")
        except Exception as e:
            logging.debug(f"Memory info capture failed for pid {pid}: {e}")
        return info

    def _capture_open_handles(self, pid: int) -> list:
        """Lists files currently open by the suspect process."""
        handles = []
        try:
            proc = psutil.Process(pid)
            for f in proc.open_files()[:50]:
                handles.append(f.path)
        except Exception as e:
            logging.debug(f"Open handle capture failed for pid {pid}: {e}")
        return handles

    def _build_narrative_report(self, evidence: dict, json_path: Path) -> str:
        """Turns raw evidence into a readable, narrative incident report."""
        sep, sub = "=" * 70, "-" * 70
        lines = [
            sep,
            "          AEGIS SHIELD - RANSOMWARE INCIDENT REPORT",
            sep,
            "",
            f"Report Generated : {evidence.get('forensic_timestamp', '?')}",
            f"Report Location  : {json_path}",
            "",
        ]

        sp = evidence.get("suspect_process", {})
        ia = evidence.get("impact_assessment", {})
        manifest = ia.get("modified_files_manifest", [])
        tampered = [m for m in manifest if m.get("status") == "tampered"]

        who = (f"process '{sp.get('name', 'unknown')}' (PID {sp.get('pid')})"
               if sp.get("pid") else "a process that could not be identified")

        lines += [
            sub, "1. SUMMARY", sub,
            f"Suspicious activity consistent with ransomware behavior was "
            f"detected, attributed to {who}. The monitored folder was "
            f"automatically locked read-only to stop further damage.",
            "",
            sub, "2. DETECTION TRIGGER", sub,
            f"Trigger Reason : {evidence.get('trigger_reason', '?')}",
            f"Capture Depth  : {evidence.get('capture_depth', '?')}",
            f"Files Affected : {ia.get('total_files_affected', 0)}",
            "",
            sub, "3. SUSPECT PROCESS", sub,
            f"Process Name    : {sp.get('name', 'Unknown')}",
            f"PID             : {sp.get('pid', 'Unknown')}",
            f"Executable      : {sp.get('executable', 'Unknown')}",
        ]
        if "cmdline" in sp:
            lines.append(f"Command Line    : {sp['cmdline']}")
        if "create_time" in sp:
            lines.append(f"Process Started : {sp['create_time']}")
        if "ppid" in sp:
            lines.append(f"Parent PID      : {sp['ppid']}")
        lines.append("")

        if "process_lineage" in evidence:
            lines += [sub, "4. ATTACK PATH (PROCESS LINEAGE)", sub]
            chain = evidence["process_lineage"]
            lines.append(
                " -> ".join(f"{c['name']}({c['pid']})" for c in chain)
                if chain else "(lineage unavailable)")
            lines.append("")

        lines += [sub, "5. AFFECTED FILES", sub]
        if manifest:
            for m in manifest[:50]:
                extra = (f" (entropy delta: {m['entropy_delta']})"
                         if m.get("entropy_delta") is not None else "")
                lines.append(f"[{m.get('status', '?').upper()}] {m.get('path')}{extra}")
            if len(manifest) > 50:
                lines.append(f"... and {len(manifest) - 50} more files (see JSON for full list)")
            lines.append(f"\nSummary: {len(tampered)} of {len(manifest)} files confirmed tampered.")
        else:
            lines.append("(no files recorded)")
        lines.append("")

        if any(k in evidence for k in ("network_connections", "memory_info", "open_handles")):
            lines += [sub, "6. ADDITIONAL VOLATILE EVIDENCE", sub]
            if "memory_info" in evidence:
                mi = evidence["memory_info"]
                lines.append(f"Memory Usage       : RSS={mi.get('rss_bytes', '?')} bytes, "
                              f"VMS={mi.get('vms_bytes', '?')} bytes")
            if "network_connections" in evidence:
                conns = evidence["network_connections"]
                lines.append(f"Network Connections: {len(conns)} active")
                for c in conns[:10]:
                    lines.append(f"  {c.get('local_addr')} -> {c.get('remote_addr')} [{c.get('status')}]")
            if "open_handles" in evidence:
                lines.append(f"Open File Handles  : {len(evidence['open_handles'])}")
            lines.append("")

        lines += [sep, "End of report.", sep]
        return "\n".join(lines)

    def record_decision(self, pid, proc_name, reason, recent_files, decision):
        """Writes a lightweight audit record of the user's trust/not-trust decision."""
        record = {
            "record_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "trigger_reason": reason,
            "pid": pid,
            "proc_name": proc_name,
            "affected_files": recent_files,
            "user_decision": decision,
        }
        Path(FORENSIC_DIR).mkdir(parents=True, exist_ok=True)
        out = Path(FORENSIC_DIR) / f"decision_pid_{pid}_{int(time.time())}.json"
        try:
            with open(out, 'w') as f:
                json.dump(record, f, indent=4)
            logging.info(f"Decision record: {out}")
        except Exception as e:
            logging.error(f"Decision record write failed: {e}")
        return out

    def generate_evidence_summary(self, pid: int, proc_name: str, reason: str, recent_files: list):
        depth = self._classify_depth(reason, recent_files)

        evidence = {
            "forensic_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "capture_depth": depth,
            "suspect_process": {
                "pid": pid,
                "name": proc_name,
                "executable": "Unknown"
            },
            "trigger_reason": reason,
            "impact_assessment": {
                "total_files_affected": len(recent_files),
                "modified_files_manifest": []
            }
        }
        if pid == 0:
            evidence["suspect_process"]["executable"] = "Unknown (responsible process could not be identified)"
        else:
            try:
                p = psutil.Process(pid)
                try:
                    evidence["suspect_process"]["executable"] = p.exe()
                except Exception as e:
                    logging.debug(f"Failed to get executable: {e}")
                try:
                    evidence["suspect_process"]["cmdline"] = " ".join(p.cmdline())
                except Exception as e:
                    logging.debug(f"Failed to get cmdline: {e}")
                try:
                    evidence["suspect_process"]["create_time"] = time.strftime(
                        "%Y-%m-%d %H:%M:%S", time.localtime(p.create_time()))
                except Exception as e:
                    logging.debug(f"Failed to get create_time: {e}")
                try:
                    evidence["suspect_process"]["ppid"] = p.ppid()
                except Exception as e:
                    logging.debug(f"Failed to get ppid: {e}")
            except psutil.NoSuchProcess:
                evidence["suspect_process"]["executable"] = "Process no longer running (exited before evidence capture)"

        if pid and depth in ("medium", "full"):
            evidence["process_lineage"] = self._capture_process_lineage(pid)
        if pid and depth == "full":
            evidence["network_connections"] = self._capture_network_connections(pid)
            evidence["memory_info"] = self._capture_memory_info(pid)
            evidence["open_handles"] = self._capture_open_handles(pid)

        for f_path in recent_files:
            try:
                if not os.path.exists(f_path):
                    evidence["impact_assessment"]["modified_files_manifest"].append({
                        "path": f_path, "status": "deleted_or_moved"
                    })
                    continue
                curr_entropy = get_file_entropy_sampled(f_path)
                curr_hash = compute_file_hash(f_path)
                with baseline_lock:
                    base = self.baseline.get(str(Path(f_path).resolve()))
                orig_hash = base["hash"] if base else None
                base_entropy = base["entropy"] if base else None
                matched = (curr_hash == orig_hash) if orig_hash else False
                evidence["impact_assessment"]["modified_files_manifest"].append({
                    "path": f_path,
                    "status": "unchanged" if matched else "tampered",
                    "current_entropy": round(curr_entropy, 2),
                    "baseline_hash": orig_hash,
                    "current_hash": curr_hash,
                    "entropy_delta": round(abs(curr_entropy - base_entropy), 2) if base_entropy is not None else None,
                    "baseline_matched": matched
                })
            except Exception as e:
                logging.debug(f"Skipping {f_path} in evidence capture: {e}")
                evidence["impact_assessment"]["modified_files_manifest"].append({
                    "path": f_path, "status": "capture_error"
                })

        Path(FORENSIC_DIR).mkdir(parents=True, exist_ok=True)

        ts = int(time.time())
        out = Path(FORENSIC_DIR) / f"forensic_pid_{pid}_{ts}.json"
        txt_out = Path(FORENSIC_DIR) / f"forensic_pid_{pid}_{ts}.txt"
        narrative = self._build_narrative_report(evidence, out)
        try:
            with open(out, 'w') as f:
                json.dump(evidence, f, indent=4)
            with open(txt_out, 'w') as f:
                f.write(narrative)
            logging.info(f"Forensic report: {out} ({txt_out})")
        except Exception as e:
            logging.error(f"Forensic write failed: {e}")

        with self._last_report_lock:
            self._last_report_text = narrative
            self._last_report_path = txt_out


# ============================================================
# RISK SCORER
# ============================================================
class RiskScorer:
    def __init__(self, config, forensic, pid_store, monitor_path):
        self.config = config
        self.forensic = forensic
        self.pid_store = pid_store
        self.monitor_path = monitor_path

        self.high_alert_event = threading.Event()
        self.baseline = {}
        self.ui_log_callback = None
        self.file_monitor = None

        self._scan_running = False
        self._scan_lock = threading.Lock()

        self._hw_alert_cooldown = {}
        self._hw_alert_cooldown_lock = threading.Lock()

        self.cpu_count = psutil.cpu_count() or 1

        psutil.cpu_percent(interval=None)

        for proc in psutil.process_iter(['pid']):
            try:
                proc.cpu_percent(interval=None)
            except Exception as e:
                logging.debug(f"cpu_percent warmup failed for pid {proc.pid}: {e}")

    def set_baseline(self, b):
        self.baseline = b

    def set_ui_log_callback(self, cb):
        self.ui_log_callback = cb

    def set_file_monitor(self, fm):
        self.file_monitor = fm

    def report_event(self, pid, proc_name, file_path, event_type, priority="normal"):
        if priority == "high" or event_type == "honeypot_triggered":
            self.high_alert_event.set()
            self.trigger_full_scan()

    def trigger_full_scan(self):
        if not self.baseline:
            logging.warning("Baseline not ready. Skipping full scan.")
            return
        
        with self._scan_lock:
            if self._scan_running:
                return
            self._scan_running = True

        def scan_worker():
            try:
                results = {}
                max_files = self.config.get("baseline_max_files", 100000)
                files_to_scan = list(Path(self.monitor_path).rglob("*"))[:max_files]

                for file in files_to_scan:
                    if not file.is_file():
                        continue

                    try:
                        f_abs = str(file.resolve())
                        curr_hash = compute_file_hash(f_abs)
                        curr_entropy = get_file_entropy_sampled(f_abs)

                        with baseline_lock:
                            base = self.baseline.get(f_abs)

                        orig_hash = base["hash"] if base else None
                        base_entropy = base["entropy"] if base else None

                        results[f_abs] = {
                            "changed": (orig_hash and curr_hash != orig_hash),
                            "entropy_delta": abs(curr_entropy - base_entropy)
                            if base_entropy is not None else None
                        }
                    except Exception:
                        continue
                
                Path(FORENSIC_DIR).mkdir(parents=True, exist_ok=True)

                rpt = Path(FORENSIC_DIR) / f"full_scan_{int(time.time())}.json"

                with open(rpt, 'w') as f:
                    json.dump(results, f, indent=4)

            except Exception as e:
                logging.error(f"Full scan failed: {e}")

            finally:
                with self._scan_lock:
                    self._scan_running = False

        threading.Thread(target=scan_worker, daemon=True).start()

    def process_hardware_event(self, sys_cpu, sys_mem):
        active_pids = self.pid_store.get_all_active_pids()
        if not active_pids:
            return

        best_score = -1.0
        best_pid = None
        best_name = "Unknown"
        best_norm_freq = 0.0
        best_norm_ent = 0.0
        best_norm_sig = 0.0

        min_files = self.config.get("signature_min_files_touched", 3)
        min_trend = self.config.get("signature_min_entropy_trend", 2)

        for pid in active_pids:
            try:
                proc = psutil.Process(pid)
                p_name = proc.name()

                cpu_perc = proc.cpu_percent(interval=None)
                norm_cpu = min(cpu_perc / (100 * self.cpu_count), 1.0)

                c_1s, c_1h, _, anomaly_cnt = self.pid_store.clean_and_get_counts(pid)

                norm_freq = min(
                    0.6 * (c_1s / self.config.get("threshold_1s", 5)) +
                    0.4 * (c_1h / self.config.get("threshold_1h", 50)), 1.0
                )

                norm_ent = min(anomaly_cnt / 3.0, 1.0)

                touched = self.pid_store.get_touched_file_count(pid)
                trend = self.pid_store.get_entropy_trend(pid)
                repetition_ok = touched >= min_files
                directionality_ok = len([d for d in trend if d > 0]) >= min_trend
                continuity_ok = c_1h > c_1s

                if repetition_ok and directionality_ok and continuity_ok:
                    norm_sig = 1.0
                elif repetition_ok and directionality_ok:
                    norm_sig = 0.5
                else:
                    norm_sig = 0.0

                score = (
                    norm_cpu * self.config.get("weight_cpu", 0.05) +
                    norm_freq * self.config.get("weight_freq", 0.25) +
                    norm_ent * self.config.get("weight_entropy", 0.25) +
                    norm_sig * self.config.get("weight_signature", 0.45)
                )

                if score > best_score:
                    best_score = score
                    best_pid = pid
                    best_name = p_name
                    best_norm_freq = norm_freq
                    best_norm_ent = norm_ent
                    best_norm_sig = norm_sig

            except Exception:
                continue

        if best_pid and best_score >= self.config.get("risk_alert_threshold", 0.4):
            if best_norm_freq <= 0 and best_norm_ent <= 0 and best_norm_sig <= 0:
                logging.debug(
                    f"Hardware spike on pid={best_pid} ({best_name}) ignored: "
                    f"no corroborating file-activity evidence (CPU-only)."
                )
                return

            now = time.time()

            with self._hw_alert_cooldown_lock:
                dead = [
                    pid for pid in self._hw_alert_cooldown
                    if pid not in active_pids
                ]
                for pid in dead:
                    del self._hw_alert_cooldown[pid]

                if now - self._hw_alert_cooldown.get(best_pid, 0) < 60:
                    return

                self._hw_alert_cooldown[best_pid] = now

            recent = (
                self.file_monitor.get_recent_files_for_pid(best_pid)
                if self.file_monitor else []
            )

            signature_note = (
                " + ransomware-pattern signature (repetition/directionality/continuity)"
                if best_norm_sig >= 1.0 else ""
            )
            reason = (
                f"Hardware anomaly CPU:{sys_cpu:.1f}% MEM:{sys_mem:.1f}% "
                f"Risk:{best_score:.2f}{signature_note}"
            )
            base_tier = "high" if best_norm_sig >= 1.0 else "low"
            tier = adjust_tier_for_whitelist(
                base_tier, best_name, self.config, _safe_get_exe_path(best_pid))
            if tier == "quiet":
                logging.info(f"[QUIET/whitelisted] {reason} (pid={best_pid}, proc={best_name})")
                return

            self.forensic.push_alert_to_ui({
                "pid": best_pid,
                "proc_name": best_name,
                "reason": reason,
                "recent_files": recent,
                "tier": tier
            })


# ============================================================
# HARDWARE MONITOR
# ============================================================
class HardwareAnomalyMonitor:
    def __init__(self, config, forensic, monitor_path, risk_scorer):
        self.config = config
        self.forensic = forensic
        self.monitor_path = monitor_path
        self.risk_scorer = risk_scorer
        self.running = False


    def start_polling(self):
        self.running = True

        cpu_thresh = self.config.get("hardware_cpu_threshold", 80.0)
        mem_thresh = self.config.get("hardware_mem_threshold", 85.0)
        interval = self.config.get("hardware_check_interval_sec", 1)
        snapshot_interval = self.config.get("hardware_snapshot_interval_sec", 5)
        confirm_window = self.config.get("hardware_confirm_window_sec", 10)

        last_snapshot_time = 0.0
        confirm_until = None

        while self.running:
            try:
                sys_cpu = psutil.cpu_percent(interval=None)
                sys_mem = psutil.virtual_memory().percent

                abnormal = (
                    sys_cpu >= cpu_thresh or
                    (sys_mem >= mem_thresh and sys_cpu >= 40)
                )

                now = time.time()

                if confirm_until is not None:
                    if abnormal:
                        self.risk_scorer.process_hardware_event(sys_cpu, sys_mem)
                        confirm_until = None
                    elif now > confirm_until:
                        confirm_until = None

                if now - last_snapshot_time >= snapshot_interval:
                    last_snapshot_time = now
                    if abnormal and confirm_until is None:
                        confirm_until = now + confirm_window

            except Exception as e:
                logging.error(f"HW monitor error: {e}")

            time.sleep(interval)


# ============================================================
# REGISTRY MONITOR
# ============================================================
class RegistryMonitor:
    """Polls Windows Registry keys used for persistence or disabling recovery; no-op on non-Windows."""

    RUN_KEY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"
    SHADOWCOPY_KEY_PATH = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ShadowCopy"

    def __init__(self, config, forensic, risk_scorer):
        self.config = config
        self.forensic = forensic
        self.risk_scorer = risk_scorer
        self.poll_interval = config.get("registry_poll_interval_sec", 5)
        self.running = False

        self._baseline_run = {}
        self._baseline_shadow_exists = True
        self._lock = threading.Lock()

        self._available = IS_WINDOWS
        self._winreg = None
        if self._available:
            try:
                import winreg
                self._winreg = winreg
            except ImportError:
                self._available = False
                logging.warning("winreg unavailable — Registry Monitor disabled.")
        else:
            logging.info("Registry Monitor disabled (non-Windows host).")

    @property
    def available(self):
        return self._available

    def _read_run_keys(self):
        values = {}
        if not self._available:
            return values
        try:
            with self._winreg.OpenKey(self._winreg.HKEY_CURRENT_USER, self.RUN_KEY_PATH) as key:
                i = 0
                while True:
                    try:
                        name, val, _ = self._winreg.EnumValue(key, i)
                        values[name] = str(val)
                        i += 1
                    except OSError:
                        break
        except FileNotFoundError:
            pass
        except Exception as e:
            logging.debug(f"Registry Run-key read failed: {e}")
        return values

    def _shadow_key_exists(self):
        if not self._available:
            return True
        try:
            with self._winreg.OpenKey(self._winreg.HKEY_LOCAL_MACHINE, self.SHADOWCOPY_KEY_PATH):
                return True
        except FileNotFoundError:
            return False
        except Exception as e:
            logging.debug(f"ShadowCopy key check failed: {e}")
            return True

    def build_baseline(self):
        if not self._available:
            return
        with self._lock:
            self._baseline_run = self._read_run_keys()
            self._baseline_shadow_exists = self._shadow_key_exists()
        logging.info(f"Registry baseline captured: {len(self._baseline_run)} Run-key entries.")

    def stop(self):
        self.running = False

    def start_polling(self):
        if not self._available:
            return
        self.running = True
        while self.running:
            try:
                self._check_run_keys()
                self._check_shadow_copy()
            except Exception as e:
                logging.error(f"Registry monitor error: {e}")
            time.sleep(self.poll_interval)

    def _check_run_keys(self):
        current = self._read_run_keys()
        with self._lock:
            added = {k: v for k, v in current.items() if k not in self._baseline_run}
            removed = {k: v for k, v in self._baseline_run.items() if k not in current}
            self._baseline_run = current

        for name, val in added.items():
            reason = f"Suspicious autorun entry added: '{name}' -> {val}"
            self.forensic.push_alert_to_ui({
                "pid": 0,
                "proc_name": "registry(unattributed)",
                "reason": reason,
                "recent_files": [],
                "tier": classify_alert_tier(reason)
            })
            self.risk_scorer.report_event(0, "registry", "", "registry_run_key_added", priority="high")

        if removed:
            logging.info(f"Run-key entries removed (informational): {list(removed.keys())}")

    def _check_shadow_copy(self):
        exists_now = self._shadow_key_exists()
        with self._lock:
            was_present = self._baseline_shadow_exists
            self._baseline_shadow_exists = exists_now

        if was_present and not exists_now:
            reason = "Volume Shadow Copy registry key removed — possible anti-recovery tampering"
            self.forensic.push_alert_to_ui({
                "pid": 0,
                "proc_name": "registry(unattributed)",
                "reason": reason,
                "recent_files": [],
                "tier": classify_alert_tier(reason)
            })
            self.risk_scorer.report_event(0, "registry", "", "shadowcopy_key_removed", priority="high")


# ============================================================
# FILE OPERATION MONITOR
# ============================================================
class FileOperationMonitor(FileSystemEventHandler):

    def __init__(self, monitor_path, config, forensic,
                 pid_store, baseline, risk_scorer):
        self.monitor_path = os.path.abspath(monitor_path)
        self.config = config
        self.forensic = forensic
        self.pid_store = pid_store
        self.baseline = baseline
        self.risk_scorer = risk_scorer

        self.pid_files_map = {}
        self.map_lock = threading.Lock()

        self._proc_cache = {}
        self._cache_ttl = 3.0
        self._cache_lock = threading.Lock()

        self._alert_cooldown = {}
        self._cooldown_lock = threading.Lock()

        self._prune_counter = 0
        self._prune_counter_lock = threading.Lock()

        self._honeypot_abs = set()
        for name in config.get("honeypot_filenames", []):
            self._honeypot_abs.add(
                str((Path(monitor_path) / name).resolve())
            )

        self._behavior_checked_pids = set()
        self._behavior_lock = threading.Lock()
        self._suspicious_parent_child = {
            k.lower(): {c.lower() for c in v}
            for k, v in config.get("suspicious_parent_child", {}).items()
        }
        self._tmp_dir_lower = tempfile.gettempdir().lower()

        self._event_queue = queue.Queue()
        self._worker_threads = []
        self._workers_running = False
        self._worker_count = 4

        self._folder_locked = False
        self._folder_lock_guard = threading.Lock()

        self._known_tampered_files = set()
        self._known_tampered_lock = threading.Lock()

    def _protect_now(self):
        with self._folder_lock_guard:
            if self._folder_locked:
                return
            self._folder_locked = True
        locked = ProcessTerminator.lock_monitor_folder(self.monitor_path)
        logging.critical(
            f"[FAST-PATH LOCK] Folder protected immediately on first "
            f"detection ({locked} files): {self.monitor_path}")

    def get_recent_files_for_pid(self, pid):
        with self.map_lock:
            return list(self.pid_files_map.get(pid, []))

    def _track(self, pid, path):
        with self.map_lock:
            if pid not in self.pid_files_map:
                self.pid_files_map[pid] = deque(maxlen=50)

            if path not in self.pid_files_map[pid]:
                self.pid_files_map[pid].append(path)

    def _get_calling_process(self, file_abs):
        curr_pid = os.getpid()
        now = time.time()

        with self._cache_lock:
            if len(self._proc_cache) > 500:
                sorted_pids = sorted(
                    self._proc_cache, key=lambda p: self._proc_cache[p]["time"]
                )
                for pid in sorted_pids[:len(sorted_pids) // 2]:
                    del self._proc_cache[pid]

            stale = [
                pid for pid, data in self._proc_cache.items()
                if now - data["time"] > self._cache_ttl
            ]
            for pid in stale:
                del self._proc_cache[pid]

            for pid, data in self._proc_cache.items():
                if file_abs in data["files"]:
                    return pid, data["name"]

        found_pid = None
        found_name = None
        fallback_pid = None
        fallback_name = None

        try:
            candidates = list(psutil.process_iter(['pid', 'name', 'create_time']))
            candidates.sort(key=lambda p: p.info.get("create_time") or 0, reverse=True)

            for idx, proc in enumerate(candidates):
                if idx > 500:
                    break

                if proc.info["pid"] in (curr_pid, 0):
                    continue

                try:
                    ofiles = proc.open_files()
                    if not ofiles:
                        ofiles = []

                    paths = {
                        os.path.abspath(f.path)
                        for f in ofiles if f.path
                    }

                    with self._cache_lock:
                        self._proc_cache[proc.info["pid"]] = {
                            "name": proc.info["name"],
                            "files": paths,
                            "time": now
                        }

                    if file_abs in paths:
                        found_pid = proc.info["pid"]
                        found_name = proc.info["name"]
                        break

                    if fallback_pid is None:
                        age = now - (proc.info.get("create_time") or 0)
                        if 0 <= age < 5:
                            try:
                                cwd_resolved = Path(proc.cwd()).resolve()
                                monitor_resolved = Path(self.monitor_path).resolve()
                                try:
                                    is_inside = (cwd_resolved == monitor_resolved or
                                                 cwd_resolved.is_relative_to(monitor_resolved))
                                except AttributeError:
                                    is_inside = str(cwd_resolved).startswith(str(monitor_resolved))
                                if is_inside:
                                    fallback_pid = proc.info["pid"]
                                    fallback_name = proc.info["name"]
                            except Exception:
                                pass

                    if fallback_pid is None:
                        age = now - (proc.info.get("create_time") or 0)
                        if 0 <= age < 30:
                            try:
                                cmdline = " ".join(proc.cmdline())
                                monitor_str = str(Path(self.monitor_path).resolve())
                                if monitor_str.lower() in cmdline.lower():
                                    fallback_pid = proc.info["pid"]
                                    fallback_name = proc.info["name"]
                            except Exception:
                                pass

                except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                    continue

        except Exception as e:
            logging.debug(f"process_iter scan failed in _get_calling_process: {e}")

        if found_pid is None and fallback_pid is not None:
            logging.debug(
                f"Attribution fallback: pid={fallback_pid} ({fallback_name}) "
                f"via cwd/cmdline+recency heuristic (no exact open-handle match)."
            )
            found_pid, found_name = fallback_pid, fallback_name

        do_prune = False
        with self._prune_counter_lock:
            self._prune_counter += 1
            do_prune = self._prune_counter >= 200

            if do_prune:
                self._prune_counter = 0

        if do_prune:
            threading.Thread(
                target=self.pid_store.prune_dead_pids,
                daemon=True
            ).start()

        return found_pid, found_name

    def _check_sequence_pattern(self, pid, name, f_abs):
        """Fires an alert if a pid's recent actions match a ransomware operation sequence."""
        min_pairs = self.config.get("enc_sequence_min_pairs", 3)
        if self.pid_store.detect_encryption_sequence(pid, min_pairs=min_pairs):
            self.risk_scorer.report_event(pid, name, f_abs, "encryption_sequence_pattern")
            self._fire_alert(
                pid, name,
                f"Encryption sequence pattern detected: repeated write/rename "
                f"loop by {name}",
                f_abs
            )
            return True
        return False

    def _check_process_behavior(self, pid, name):
        """Flags processes launched from temp directories or with suspicious parent-child lineage."""
        if not pid:
            return None

        with self._behavior_lock:
            if pid in self._behavior_checked_pids:
                return None
            if len(self._behavior_checked_pids) > 2000:
                self._behavior_checked_pids.clear()
            self._behavior_checked_pids.add(pid)

        try:
            proc = psutil.Process(pid)
        except Exception:
            return None

        try:
            exe = (proc.exe() or "").lower()
            if exe and (self._tmp_dir_lower in exe or "\\windows\\temp\\" in exe or "/tmp/" in exe):
                return f"Process launched from a temp directory: {exe}"
        except Exception as e:
            logging.debug(f"exe() check failed for pid {pid}: {e}")

        try:
            parent = proc.parent()
            if parent:
                pname = (parent.name() or "").lower()
                cname = (name or "").lower()
                bad_children = self._suspicious_parent_child.get(pname)
                if bad_children and cname in bad_children:
                    return f"Suspicious process lineage: {pname} spawned {cname}"
        except Exception as e:
            logging.debug(f"parent() check failed for pid {pid}: {e}")

        return None

    def _analyse(self, f_path, event_type):
        if not self.config.get("enabled", True):
            return

        f_abs = os.path.abspath(f_path)
        ext = os.path.splitext(f_abs)[1].lower()

        if f_abs in self._honeypot_abs:
            self._protect_now()
            pid, name = self._get_calling_process(f_abs)
            if pid is None:
                pid, name = 0, "unattributed(pid=0)"
            self.pid_store.record(pid, name, event_type, f_abs)
            self.risk_scorer.report_event(
                pid, name, f_abs, "honeypot_triggered", priority="high")
            self.forensic.push_alert_to_ui({
                "pid": pid,
                "proc_name": name,
                "reason": self._describe_honeypot_change(f_abs, event_type),
                "recent_files": [f_abs],
                "tier": "critical"
            })
            return

        try:
            abs_p = Path(f_abs).resolve()
            for wp in self.config.get("white_list_paths", []):
                try:
                    rel = abs_p.is_relative_to(Path(wp).resolve())
                except AttributeError:
                    rel = str(abs_p).startswith(str(Path(wp).resolve()))
                if rel:
                    return
        except Exception as e:
            logging.debug(f"Path whitelist check failed in _analyse: {e}")

        is_monitored = ext in self.config.get("monitored_exts", [])
        is_suspicious = ext in self.config.get("suspicious_exts", [])
        if is_suspicious:
            self._protect_now()

        with self._known_tampered_lock:
            already_known_bad = f_abs in self._known_tampered_files

        if already_known_bad and not is_suspicious:
            return

        pid, name = self._get_calling_process(f_abs)

        if pid is None:
            pid, name = 0, "unattributed(pid=0)"
        else:
            behavior_reason = self._check_process_behavior(pid, name)
            if behavior_reason:
                self.risk_scorer.report_event(pid, name, f_abs, "process_behavior_anomaly")
                self._fire_alert(pid, name, behavior_reason, f_abs)

        self.pid_store.record(pid, name, event_type, f_abs)
        self._track(pid, f_abs)
        freq_alerted = self._check_frequency(pid, name, f_abs)
        if not freq_alerted:
            self._check_sequence_pattern(pid, name, f_abs)


        if is_suspicious:
            self._fire_alert(
                pid, name,
                f"Suspicious extension deployed: {ext}",
                f_abs
            )
            return

        if event_type in ("modified", "moved") and os.path.exists(f_abs):
            header_reason = check_file_header(f_abs)
            if header_reason:
                with self._known_tampered_lock:
                    self._known_tampered_files.add(f_abs)
                self.pid_store.mark_entropy_anomaly(pid)
                self.risk_scorer.report_event(pid, name, f_abs, "file_header_mismatch", priority="high")
                self._fire_alert(pid, name, header_reason, f_abs)
                return

        is_entropy_anomaly = False
        delta = 0.0

        _HIGH_ENTROPY_NATURAL_EXTS = {
            ".zip", ".gz", ".bz2", ".xz", ".7z", ".rar", ".zst",
            ".iso", ".img", ".dmg",
            ".mp3", ".mp4", ".mkv", ".aac", ".ogg", ".flac",
            ".jpg", ".jpeg", ".png", ".webp", ".gif",
            ".sqlite", ".db3",
        }

        if (is_monitored and
                event_type in ("modified", "created", "moved") and os.path.exists(f_abs)):
            try:
                curr_entropy = get_file_entropy_sampled(f_abs)
                curr_hash = compute_file_hash(f_abs)

                with baseline_lock:
                    base = self.baseline.get(str(Path(f_abs).resolve()))

                base_hash = base["hash"] if base else None
                base_entropy = base["entropy"] if base else None

                if base_entropy is not None:
                    delta = curr_entropy - base_entropy
                    delta_anomaly = abs(delta) >= self.config.get("entropy_delta_threshold", 1.5)

                    baseline_already_high = base_entropy >= self.config.get(
                        "high_alert_entropy_threshold", 6.5)
                    absolute_anomaly = (
                        baseline_already_high and
                        curr_hash != base_hash and
                        curr_entropy >= self.config.get("entropy_threshold", 7.2)
                    )

                    is_entropy_anomaly = delta_anomaly or absolute_anomaly
                else:
                    if ext not in _HIGH_ENTROPY_NATURAL_EXTS:
                        is_entropy_anomaly = (
                            curr_entropy >= self.config.get("entropy_threshold", 7.2)
                        )

                if base_entropy is not None and curr_hash and curr_hash != base_hash and is_entropy_anomaly:
                    with self._known_tampered_lock:
                        self._known_tampered_files.add(f_abs)
                    self.pid_store.mark_entropy_anomaly(pid)
                    self.pid_store.mark_entropy_pending(pid, f_abs, delta)
                    self.risk_scorer.report_event(pid, name, f_abs, "entropy_anomaly")
                    logging.info(
                        f"[ASSIST] Entropy anomaly noted (pending): "
                        f"{Path(f_abs).name} (delta={delta:+.2f}) by {name}"
                    )
                    return

                if base is None and is_entropy_anomaly:
                    with self._known_tampered_lock:
                        self._known_tampered_files.add(f_abs)
                    self.pid_store.mark_entropy_anomaly(pid)
                    self.pid_store.mark_entropy_pending(pid, f_abs, curr_entropy)
                    self.risk_scorer.report_event(pid, name, f_abs, "entropy_anomaly")
                    logging.info(
                        f"[ASSIST] High entropy noted (pending) on new file: "
                        f"{Path(f_abs).name} (entropy={curr_entropy:.2f}) by {name}"
                    )
                    return

                if (base_entropy is not None and curr_hash and base_hash and
                        curr_hash != base_hash and not is_entropy_anomaly):
                    with self._known_tampered_lock:
                        self._known_tampered_files.add(f_abs)
                    self.pid_store.mark_entropy_pending(pid, f_abs, delta)
                    logging.info(
                        f"[ASSIST] Content changed (hash mismatch), entropy "
                        f"inconclusive (pending): {Path(f_abs).name} by {name}"
                    )
                    return

            except Exception as e:
                logging.debug(f"Entropy check failed: {e}")

    def _check_frequency(self, pid, name, f_abs) -> bool:
        c_1s, c_1h, c_24h, _ = self.pid_store.clean_and_get_counts(pid)

        if c_1s >= self.config.get("threshold_1s", 5):
            self._fire_alert(
                pid, name,
                f"1s burst detected: {c_1s} ops/sec by {name}",
                f_abs
            )
            return True

        if c_1h >= self.config.get("threshold_1h", 50):
            self._fire_alert(
                pid, name,
                f"1h accumulation detected: {c_1h} ops/hour by {name}",
                f_abs
            )
            return True

        if c_24h >= self.config.get("threshold_24h", 200):
            self._fire_alert(
                pid, name,
                f"24h slow attack detected: {c_24h} ops/day by {name}",
                f_abs
            )
            return True

        return False

    def _fire_alert(self, pid, name, reason, f_abs):
        now = time.time()

        reason_category = reason.split(":", 1)[0].strip() if reason else reason
        cooldown_key = pid if pid != 0 else f"unknown:{reason_category}"

        with self._cooldown_lock:
            stale = [
                p for p, ts in self._alert_cooldown.items()
                if now - ts > 300
            ]
            for p in stale:
                del self._alert_cooldown[p]

            if now - self._alert_cooldown.get(cooldown_key, 0) < 60:
                return

            self._alert_cooldown[cooldown_key] = now

        recent = self.get_recent_files_for_pid(pid)

        if not recent:
            recent = [f_abs]

        base_tier = classify_alert_tier(reason)
        tier = adjust_tier_for_whitelist(
            base_tier, name, self.config, _safe_get_exe_path(pid))
        if tier == "quiet":
            logging.info(f"[QUIET/whitelisted] {reason} (pid={pid}, proc={name})")
            return

        self._protect_now()

        self.forensic.push_alert_to_ui({
            "pid": pid,
            "proc_name": name,
            "reason": reason,
            "recent_files": recent,
            "tier": tier
        })

        self.risk_scorer.report_event(pid, name, f_abs, "file_trigger")

    def on_modified(self, event):
        if event.is_directory:
            return
        self._event_queue.put(("modified", event.src_path, None))

    def on_created(self, event):
        if event.is_directory:
            return
        self._event_queue.put(("created", event.src_path, None))

    def on_moved(self, event):
        if event.is_directory:
            return
        self._event_queue.put(("moved", event.src_path, event.dest_path))

    def on_deleted(self, event):
        if event.is_directory:
            return
        self._event_queue.put(("deleted", event.src_path, None))

    def start_workers(self):
        if self._workers_running:
            return
        self._workers_running = True
        for _ in range(self._worker_count):
            t = threading.Thread(target=self._event_worker_loop, daemon=True)
            t.start()
            self._worker_threads.append(t)

    def stop_workers(self):
        self._workers_running = False
        for t in self._worker_threads:
            t.join(timeout=2)
        self._worker_threads = []

    def _event_worker_loop(self):
        while self._workers_running:
            try:
                event_type, src_path, dest_path = self._event_queue.get(timeout=1)
            except queue.Empty:
                continue
            try:
                self._dispatch_event(event_type, src_path, dest_path)
            except Exception as e:
                logging.error(f"Event worker error ({event_type}): {e}")
            finally:
                self._event_queue.task_done()

    def _dispatch_event(self, event_type, src_path, dest_path):
        if event_type == "modified":
            self._analyse(src_path, "modified")
        elif event_type == "created":
            self._analyse(src_path, "created")
        elif event_type == "moved":
            self._handle_moved(src_path, dest_path)
        elif event_type == "deleted":
            self._handle_deleted(src_path)

    def _describe_honeypot_change(self, f_abs, event_type):
        """Describes what changed on a touched honeypot file (name, content, entropy)."""
        hp_name = Path(f_abs).name

        if event_type == "deleted":
            return f"HONEYPOT DELETED: {hp_name}"
        if event_type == "renamed_away":
            return f"HONEYPOT RENAMED/MOVED: {hp_name} (original path no longer exists)"
        if not os.path.exists(f_abs):
            return f"HONEYPOT TRIGGERED: {hp_name} (file no longer exists)"

        with baseline_lock:
            base = self.baseline.get(str(Path(f_abs).resolve()))
        if not base:
            return f"HONEYPOT TRIGGERED: {hp_name}"

        details = []
        curr_hash = compute_file_hash(f_abs)
        if base.get("hash") and curr_hash != base["hash"]:
            details.append("content/hash changed")

        base_entropy = base.get("entropy")
        if base_entropy is not None:
            curr_entropy = get_file_entropy_sampled(f_abs)
            edelta = curr_entropy - base_entropy
            if abs(edelta) >= 0.1:
                details.append(f"entropy {edelta:+.2f}")

        if details:
            return f"HONEYPOT TRIGGERED: {hp_name} ({', '.join(details)})"
        return f"HONEYPOT TRIGGERED: {hp_name} (touched, content unchanged so far)"

    def _handle_moved(self, src_path, dest_path):
        src_abs = os.path.abspath(src_path)

        if src_abs in self._honeypot_abs:
            self._protect_now()
            hp_pid, hp_name = self._get_calling_process(os.path.abspath(dest_path))
            if hp_pid is None:
                hp_pid, hp_name = 0, "unknown"
            self.forensic.push_alert_to_ui({
                "pid": hp_pid,
                "proc_name": hp_name,
                "reason": self._describe_honeypot_change(src_abs, "renamed_away"),
                "recent_files": [src_abs, os.path.abspath(dest_path)],
                "tier": "critical"
            })
            return

        dest_abs = os.path.abspath(dest_path)
        dest_ext = os.path.splitext(dest_abs)[1].lower()

        if dest_ext in self.config.get("suspicious_exts", []):
            self._protect_now()

            pid, name = self._get_calling_process(dest_abs)

            if pid is None:
                pid, name = 0, "unknown"

            self._fire_alert(
                pid, name,
                f"Rename to suspicious extension: "
                f"{Path(src_path).name} -> {Path(dest_path).name}",
                dest_abs
            )
        else:
            self._analyse(dest_path, "moved")

    def _handle_deleted(self, src_path):
        f_abs = os.path.abspath(src_path)

        if f_abs in self._honeypot_abs:
            self._protect_now()
            hp_pid, hp_name = self._get_calling_process(f_abs)
            if hp_pid is None:
                hp_pid, hp_name = 0, "unknown"
            self.forensic.push_alert_to_ui({
                "pid": hp_pid,
                "proc_name": hp_name,
                "reason": self._describe_honeypot_change(f_abs, "deleted"),
                "recent_files": [f_abs],
                "tier": "critical"
            })
            return

        del_pid, del_name = self._get_calling_process(f_abs)
        if del_pid is None:
            del_pid, del_name = 0, "unknown"

        self.pid_store.record(del_pid, del_name, "deleted", f_abs)

        pending = self.pid_store.get_entropy_pending_count(del_pid)
        if pending > 0:
            self.pid_store.resolve_entropy_pending(del_pid)
            self._fire_alert(
                del_pid, del_name,
                f"Operation sequence confirmed: encrypt+delete pattern "
                f"({pending} suspicious file(s) touched by {del_name})",
                f_abs
            )
            return

        _, c_1h, _, _ = self.pid_store.clean_and_get_counts(del_pid)

        if c_1h >= max(5, self.config.get("threshold_1h", 50) // 2):
            self._fire_alert(
                del_pid, del_name,
                f"Bulk deletion detected: {c_1h} files deleted/hour",
                f_abs
            )



# ============================================================
# UI CONTROL PANEL
# ============================================================
class ControlPanel:
    def __init__(self, root, config, monitor_path, forensic,
                 start_monitoring_callback, build_baseline_callback, alert_queue):
        self.root                     = root
        self.config                   = config
        self.monitor_path             = monitor_path
        self.forensic                 = forensic
        self.start_monitoring_callback = start_monitoring_callback
        self.build_baseline_callback   = build_baseline_callback
        self.alert_queue              = alert_queue
        self._processing_alert_lock   = threading.Lock()
        self.processing_alert         = False
        self.monitoring_started       = False
        self._closing                 = False

        self._last_threat_time        = 0.0
        self.risk_scorer              = None
        self.registry_monitor         = None

        self._folder_locked         = False
        self._last_dialog_time      = 0.0
        self._dialog_cooldown_sec   = 30

        self._incident_confirmed    = False

        self.root.title("Aegis Shield - Ransomware Detection & Forensics")
        self.root.geometry("720x800")
        self.root.configure(bg="#1e1e24")

        self.root.report_callback_exception = self._handle_tk_callback_exception

        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.style.configure("TProgressbar", thickness=10)
 
        self._create_widgets()
        self.root.bind("<<BaselineReady>>", self._on_baseline_ready)
        self.root.after(200, self._poll_alerts)
        self.root.after(1000, self._update_dashboard_stats)
        threading.Thread(target=self._initialization_pipeline,
                         daemon=True).start()

    def _ui(self, fn):
        """Schedule fn on the main Tk thread."""
        self.root.after(0, fn)

    def _create_widgets(self):
        banner_frame = tk.Frame(self.root, bg="#1e1e24")
        banner_frame.pack(fill=tk.X, pady=15)
        tk.Label(
            banner_frame,
            text=("==================================================\n"
                  "    AEGIS SHIELD: RANSOMWARE FORENSICS ENGINE     \n"
                  "        [ SECURE CORE V5.0 - PRIVILEGED ]         \n"
                  "=================================================="),
            font=("Consolas", 11, "bold"), fg="#00ff66",
            bg="#1e1e24", justify=tk.CENTER
        ).pack()

        self.load_frame = tk.LabelFrame(
            self.root, text=" MODULE ATTESTATION PIPELINE ",
            font=("Arial", 10, "bold"), fg="#ffffff",
            bg="#1e1e24", bd=1, relief=tk.SOLID)
        self.load_frame.pack(fill=tk.X, padx=20, pady=5)

        self.hw_label = tk.Label(
            self.load_frame,
            text="[-] Hardware Anomaly Monitor : Pending Verification...",
            font=("Consolas", 10), fg="#888888", bg="#1e1e24")
        self.hw_label.pack(anchor=tk.W, padx=15, pady=3)
        self.hw_progress = ttk.Progressbar(
            self.load_frame, mode='determinate', length=640)
        self.hw_progress.pack(padx=15, pady=2)

        self.file_label = tk.Label(
            self.load_frame,
            text="[-] File System Watchdog     : Pending Verification...",
            font=("Consolas", 10), fg="#888888", bg="#1e1e24")
        self.file_label.pack(anchor=tk.W, padx=15, pady=3)
        self.file_progress = ttk.Progressbar(
            self.load_frame, mode='determinate', length=640)
        self.file_progress.pack(padx=15, pady=2)

        self.status_frame = tk.Frame(self.root, bg="#1e1e24")
        self.status_frame.pack(pady=(0, 5))

        self.risk_level_label = tk.Label(
            self.status_frame, text="Risk Level: LOW",
            font=("Consolas", 11, "bold"), fg="#00ff66", bg="#1e1e24")
        self.risk_level_label.pack(side=tk.LEFT, padx=15)

        self.protected_count_label = tk.Label(
            self.status_frame, text="Protected Files: 0",
            font=("Consolas", 11, "bold"), fg="#ffffff", bg="#1e1e24")
        self.protected_count_label.pack(side=tk.LEFT, padx=15)

        self.btn_frame = tk.Frame(self.root, bg="#1e1e24")
        self.btn_frame.pack(pady=10)

        self.start_quit_frame = tk.Frame(self.btn_frame, bg="#1e1e24")
        self.start_quit_frame.pack()

        self.start_btn = tk.Button(
            self.start_quit_frame,
            text="SYSTEM LOCKED (AWAITING INTEGRITY BASELINE)",
            font=("Arial", 10, "bold"),
            bg="#3a3a45", fg="#888888",
            activebackground="#3a3a45", activeforeground="#888888",
            state=tk.DISABLED, width=40, height=2, bd=0, cursor="X_cursor")
        self.start_btn.pack(side=tk.LEFT, padx=(0, 6))

        self.quit_btn = tk.Button(
            self.start_quit_frame,
            text="QUIT",
            font=("Arial", 10, "bold"),
            bg="#3a3a45", fg="#ff6666",
            activebackground="#552222", activeforeground="#ff6666",
            width=10, height=2, bd=0, cursor="hand2",
            command=self._on_quit_clicked)
        self.quit_btn.pack(side=tk.LEFT)

        self.report_btn = tk.Button(
            self.btn_frame,
            text="View Latest Forensic Report",
            font=("Arial", 9, "bold"),
            bg="#2a2a35", fg="#00ccff",
            activebackground="#3a3a45", activeforeground="#00ccff",
            bd=0, cursor="hand2",
            command=self._open_latest_forensic_report)
        self.report_btn.pack(pady=(8, 0))

        self.unlock_btn = tk.Button(
            self.btn_frame,
            text="Unlock Monitored Folder",
            font=("Arial", 9, "bold"),
            bg="#2a2a35", fg="#ffcc00",
            activebackground="#3a3a45", activeforeground="#ffcc00",
            bd=0, cursor="hand2",
            command=self._on_unlock_folder)
        self.unlock_btn.pack(pady=(6, 0))

        self.log_frame = tk.LabelFrame(
            self.root, text=" SYSTEM INTERCEPT & AUDIT LOG ",
            font=("Arial", 9, "bold"), fg="#ffffff",
            bg="#1e1e24", bd=1)
        self.log_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        self.log_text = tk.Text(
            self.log_frame, bg="#111116", fg="#ffffff",
            insertbackground="white", font=("Consolas", 9), bd=0)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.log_text.tag_config("info",     foreground="#ffffff")
        self.log_text.tag_config("success",  foreground="#00ff66",
                                 font=("Consolas", 9, "bold"))
        self.log_text.tag_config("warning",  foreground="#ffcc00")
        self.log_text.tag_config("critical", foreground="#ff3333",
                                 font=("Consolas", 9, "bold"))

    def _initialization_pipeline(self):
        time.sleep(0.6)

        self._ui(lambda: self.hw_label.config(
            text="[>] Testing Hardware Anomaly Monitor APIs...", fg="#00ff66"))
        for i in range(1, 101):
            time.sleep(0.005)
            self._ui(lambda v=i: self.hw_progress.configure(value=v))
        self._ui(lambda: self.hw_label.config(
            text="[+] Hardware Anomaly Monitor : REGISTERED & ATTESTED",
            fg="#00ff66"))

        self._ui(lambda: self.file_label.config(
            text="[>] Testing File System Watchdog APIs...", fg="#00ff66"))
        for i in range(1, 101):
            time.sleep(0.005)
            self._ui(lambda v=i: self.file_progress.configure(value=v))
        self._ui(lambda: self.file_label.config(
            text="[+] File System Watchdog     : REGISTERED & ATTESTED",
            fg="#00ff66"))

        self._ui(lambda: self.do_log(
            "[SYSTEM] Core engine ready. Building cryptographic baseline...\n",
            "info"))

        def _baseline_then_signal():
            try:
                self.build_baseline_callback()
                if not self._closing:
                    self.root.after(0, lambda: self.root.event_generate("<<BaselineReady>>"))
            except Exception as e:
                logging.error(f"Baseline build failed: {e}")
        threading.Thread(target=_baseline_then_signal, daemon=True).start()

    def _on_baseline_ready(self, event):
        self.do_log(
            "[SYSTEM] Baseline hash and entropy values captured.\n", "success")
        self.do_log(
            "[SYSTEM] Engine unlocked. Ready to start.\n", "success")
        self.start_btn.config(
            text="ACTIVATE ACTIVE SHIELD INTELLIGENCE",
            bg="#00ff66", fg="#1e1e24",
            activebackground="#00cc55", activeforeground="#1e1e24",
            state=tk.NORMAL, cursor="hand2",
            command=self._on_start_activated)

    def _on_start_activated(self):
        if self.monitoring_started:
            return

        self.monitoring_started = True

        self.start_btn.config(
            text="SHIELD ACTIVE & DEFENDING",
            state=tk.DISABLED,
            bg="#004411",
            fg="#888888",
            cursor="X_cursor")

        self.do_log(
            "[ACTIVE] Shield online. Anti-ransomware interception live.\n",
            "warning" )

        try:
            self.start_monitoring_callback()
        except Exception as e:
            logging.error(f"Failed to start monitoring: {e}")

    def _do_log(self, msg, text_type):
        self.log_text.insert(tk.END, msg, text_type)
        line_count = int(self.log_text.index("end-1c").split(".")[0])
        if line_count > 2000:
            self.log_text.delete("1.0", f"{line_count - 2000}.0")
        self.log_text.see(tk.END)

    def _handle_tk_callback_exception(self, exc, val, tb):
        """Logs uncaught Tk callback exceptions instead of crashing the UI."""
        logging.error(
            "Unhandled exception in Tk callback:",
            exc_info=(exc, val, tb)
        )

    def do_log(self, msg, tag="info"):
        """Thread-safe public logger — safe to call from any thread."""
        self.root.after(0, lambda: self._do_log(msg, tag))

    def _open_latest_forensic_report(self):
        """Shows the most recently generated forensic report."""
        try:
            Path(FORENSIC_DIR).mkdir(parents=True, exist_ok=True)
            reports = sorted(
                Path(FORENSIC_DIR).glob("forensic_pid_*.txt"),
                key=lambda p: p.stat().st_mtime, reverse=True
            )
            if not reports:
                messagebox.showinfo(
                    "Aegis Shield - Forensic Report",
                    "No forensic report has been generated yet. A report "
                    "is created automatically once a threat is detected "
                    "and confirmed.")
                return

            latest = reports[0]
            report_text = latest.read_text()
            self._show_forensic_report_window(report_text, latest)

        except Exception as e:
            logging.error(f"Failed to open forensic report: {e}")
            messagebox.showerror("Aegis Shield - Error", f"Failed to open forensic report: {e}")

    def _show_forensic_report_window(self, report_text, report_path):
        """Displays a forensic report's text and file path in a popup window."""
        if not report_text:
            report_text = (
                "No forensic report content is available. Check the "
                f"forensic_evidence folder directly:\n{FORENSIC_DIR}")

        win = tk.Toplevel(self.root)
        win.title(f"Forensic Report - {Path(report_path).name if report_path else 'unavailable'}")
        win.geometry("720x640")
        win.configure(bg="#111116")

        path_label = tk.Label(
            win, text=f"Report file: {report_path}",
            font=("Consolas", 9, "bold"), fg="#00ccff", bg="#111116",
            anchor="w", justify=tk.LEFT, wraplength=700)
        path_label.pack(fill=tk.X, padx=8, pady=(8, 4))

        text = tk.Text(win, bg="#111116", fg="#00ff66",
                        insertbackground="white", font=("Consolas", 9), bd=0)
        text.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))
        text.insert(tk.END, report_text)
        text.config(state=tk.DISABLED)

    def _on_unlock_folder(self):
        """Manually restores folder permissions after an auto-lock."""
        self.unlock_btn.config(state=tk.DISABLED, text="Unlocking...")

        def _do_unlock():
            try:
                unlocked = ProcessTerminator.unlock_monitor_folder(self.monitor_path)
                self.root.after(0, lambda: self._on_unlock_finished(unlocked, None))
            except Exception as e:
                self.root.after(0, lambda: self._on_unlock_finished(None, e))

        threading.Thread(target=_do_unlock, daemon=True).start()

    def _on_unlock_finished(self, unlocked, error):
        self.unlock_btn.config(state=tk.NORMAL, text="Unlock Monitored Folder")
        if error is not None:
            logging.error(f"Failed to unlock monitor folder: {error}")
            messagebox.showerror("Aegis Shield - Error", f"Unlock failed: {error}")
            return

        self._folder_locked = False
        self._incident_confirmed = False
        if getattr(self, "file_monitor", None) is not None:
            self.file_monitor._folder_locked = False
            with self.file_monitor._known_tampered_lock:
                self.file_monitor._known_tampered_files.clear()
        self._do_log(
            f" [UNLOCKED] Monitored folder access restored "
            f"({unlocked} files): {self.monitor_path}\n", "success")
        messagebox.showinfo(
            "Aegis Shield - Folder Unlocked",
            f"Monitored folder access restored.\n\n{self.monitor_path}")

    def _update_dashboard_stats(self):
        """Refreshes the risk-level and protected-file-count dashboard labels."""
        try:
            if not self.root.winfo_exists():
                return
        except Exception:
            return

        try:
            protected = len(self.forensic.baseline) if self.forensic.baseline else 0
            self.protected_count_label.config(text=f"Protected Files: {protected}")

            elapsed = time.time() - self._last_threat_time
            if self._last_threat_time and elapsed < 60:
                self.risk_level_label.config(text="Risk Level: HIGH", fg="#ff3333")
            elif self._last_threat_time and elapsed < 300:
                self.risk_level_label.config(text="Risk Level: MEDIUM", fg="#ffcc00")
            else:
                self.risk_level_label.config(text="Risk Level: LOW", fg="#00ff66")
        except Exception as e:
            logging.debug(f"Dashboard stats update failed: {e}")

        self.root.after(3000, self._update_dashboard_stats)

    def _ask_trust_dialog(self, title, message):
        """Shows a Trust/Not-Trust confirmation dialog and returns the user's choice."""
        result = {"confirmed_threat": None}

        dlg = tk.Toplevel(self.root)
        dlg.title(title)
        dlg.transient(self.root)
        dlg.resizable(False, False)

        tk.Label(dlg, text=message, justify="left", padx=20, pady=15,
                 wraplength=480).pack()

        btn_frame = tk.Frame(dlg, pady=10)
        btn_frame.pack()

        def choose_not_trust():
            result["confirmed_threat"] = True
            dlg.destroy()

        def choose_trust():
            result["confirmed_threat"] = False
            dlg.destroy()

        tk.Button(btn_frame, text="⚠ NOT TRUST (Confirm Threat)",
                  command=choose_not_trust, bg="#c0392b", fg="white",
                  padx=12, pady=6).pack(side="left", padx=10)
        tk.Button(btn_frame, text="✓ TRUST (Dismiss & Unlock)",
                  command=choose_trust, bg="#27ae60", fg="white",
                  padx=12, pady=6).pack(side="left", padx=10)

        dlg.protocol("WM_DELETE_WINDOW", choose_not_trust)

        dlg.update_idletasks()
        try:
            px = self.root.winfo_rootx() + (self.root.winfo_width() - dlg.winfo_width()) // 2
            py = self.root.winfo_rooty() + (self.root.winfo_height() - dlg.winfo_height()) // 2
            dlg.geometry(f"+{max(px, 0)}+{max(py, 0)}")
        except Exception:
            pass

        dlg.grab_set()
        self.root.wait_window(dlg)
        return result["confirmed_threat"] if result["confirmed_threat"] is not None else True

    def _process_alert_safely(self, alert):
        try:
            pid          = alert["pid"]
            proc_name    = alert["proc_name"]
            reason       = alert["reason"]
            recent_files = alert["recent_files"]

            self._last_threat_time = time.time()

            if not self._folder_locked:
                locked = ProcessTerminator.lock_monitor_folder(self.monitor_path)
                self._folder_locked = True
                self._do_log(
                    f"🔒 [FOLDER PROTECTED] Monitored folder frozen read-only "
                    f"({locked} files) on first detection: {self.monitor_path}\n",
                    "critical")

            self._do_log(f"\n🚨 [DETECTED] {reason}\n", "critical")

            if self._incident_confirmed:
                self._do_log(
                    f"[LOGGED] {reason} (pid={pid}) — incident already "
                    f"confirmed and folder locked; no further prompts "
                    f"until manually unlocked.\n", "warning")
                with self._processing_alert_lock:
                    self.processing_alert = False
                return

            now = time.time()
            if now - self._last_dialog_time < self._dialog_cooldown_sec:
                self._do_log(
                    f"[LOGGED] {reason} (pid={pid}) — folder already "
                    f"protected; no further prompt within the cooldown "
                    f"window.\n", "warning")
                with self._processing_alert_lock:
                    self.processing_alert = False
                return
            self._last_dialog_time = now

            if pid != 0:
                ProcessTerminator.suspend_process(pid)
                self._do_log(
                    f"[SUSPENDED] {proc_name} (PID:{pid}). Capturing "
                    f"forensic evidence while process is frozen...\n",
                    "warning")

            forensic_thread = threading.Thread(
                target=self.forensic.generate_evidence_summary,
                args=(pid, proc_name, reason, recent_files),
                daemon=True)
            forensic_thread.start()

            proc_desc = f"{proc_name} (PID: {pid})" if pid != 0 else "Unknown (could not be identified)"

            if pid == 0:
                try:
                    user_choice = self._ask_trust_dialog(
                        "Aegis Shield - Threat Detected",
                        (f"Suspicious activity detected!\n\n"
                         f"Reason  : {reason}\n"
                         f"Process : {proc_desc}\n"
                         f"Files   : {len(recent_files)}\n\n"
                         f"The monitored folder has already been locked read-only "
                         f"as a precaution.\n\n"
                         f"The responsible process could not be identified, so "
                         f"it cannot be verified or safely resumed -- the "
                         f"folder will remain protected regardless of your "
                         f"choice below.\n\n"
                         f"Do you trust this activity?"))
                except Exception:
                    user_choice = True
                self._do_log(
                    f"[USER CHOICE] "
                    f"{'NOT TRUST' if user_choice else 'TRUST'} selected for "
                    f"an unattributed (pid=0) alert — folder stays "
                    f"protected either way since the process could not be "
                    f"verified.\n", "warning")
                self._incident_confirmed = True
                ans = True
            else:
                try:
                    ans = self._ask_trust_dialog(
                        "Aegis Shield - Threat Detected",
                        (f"Suspicious activity detected!\n\n"
                         f"Reason  : {reason}\n"
                         f"Process : {proc_desc}\n"
                         f"Files   : {len(recent_files)}\n\n"
                         f"The monitored folder has already been locked read-only "
                         f"as a precaution.\n\n"
                         f"Do you trust this activity?"))
                except Exception:
                    ans = True
                if ans:
                    self._incident_confirmed = True

            self._finish_alert(alert, ans, forensic_thread, time.time())

        except Exception as e:
            logging.error(f"Alert processing error: {e}")
            with self._processing_alert_lock:
                self.processing_alert = False

    def _finish_alert(self, alert, ans, forensic_thread, start_time):
        try:
            if forensic_thread.is_alive() and time.time() - start_time < 5.0:
                self.root.after(100, self._finish_alert, alert, ans, forensic_thread, start_time)
                return
            if forensic_thread.is_alive():
                logging.warning(
                    f"Forensic capture for PID {alert['pid']} still running "
                    f"after 5s — proceeding anyway (capture continues in "
                    f"background, may be incomplete)."
                )

            pid          = alert["pid"]
            proc_name    = alert["proc_name"]
            reason       = alert["reason"]
            recent_files = alert["recent_files"]

            if ans:
                if pid != 0:
                    ProcessTerminator.terminate_and_quarantine(
                        pid, ui_log_callback=self.do_log,
                        monitor_path=self.monitor_path)
                    self._do_log(
                        f" [TERMINATED] {proc_name} (PID:{pid}) — {reason}\n",
                        "critical")
                else:
                    self._do_log(
                        "[NO PROCESS TO TERMINATE] Responsible process could "
                        "not be identified; folder remains locked. Review "
                        "the forensic report below.\n", "critical")

                self.forensic.record_decision(
                    pid, proc_name, reason, recent_files, "confirmed_threat")
                report_text, report_path = self.forensic.get_last_report()
                self._show_forensic_report_window(report_text, report_path)
            else:
                if pid != 0:
                    ProcessTerminator.resume_process(pid)
                    self._do_log(
                        f" [TRUSTED] {proc_name} (PID:{pid}) released.\n",
                        "success")
                    if getattr(self, "file_monitor", None) is not None:
                        with self.file_monitor._cooldown_lock:
                            self.file_monitor._alert_cooldown.pop(pid, None)

                unlocked = ProcessTerminator.unlock_monitor_folder(self.monitor_path)
                self._folder_locked = False
                if getattr(self, "file_monitor", None) is not None:
                    self.file_monitor._folder_locked = False
                    with self.file_monitor._known_tampered_lock:
                        self.file_monitor._known_tampered_files.clear()
                self._do_log(
                    f" [UNLOCKED] Trusted by user — folder access restored "
                    f"({unlocked} files).\n", "success")

                self.forensic.record_decision(
                    pid, proc_name, reason, recent_files, "trusted")

        except Exception as e:
            logging.error(f"Alert finalization error: {e}")
        finally:
            with self._processing_alert_lock:
                self.processing_alert = False

    def _poll_alerts(self):
        if self._closing:
            return
        try:
            if not self.root.winfo_exists():
                return
        except Exception:
            return
        with self._processing_alert_lock:
            if not self.processing_alert:
                try:
                    _priority, _seq, alert = self.alert_queue.get_nowait()
                    self.processing_alert = True
                    self.root.after(0, self._process_alert_safely, alert)
                except queue.Empty:
                    pass
        self.root.after(200, self._poll_alerts)

    def set_monitor_refs(self, observer, hw_monitor, file_monitor,
                          risk_scorer=None, registry_monitor=None):
        self.observer    = observer
        self.hw_monitor  = hw_monitor
        self.file_monitor = file_monitor
        self.risk_scorer = risk_scorer
        self.registry_monitor = registry_monitor

    def _on_quit_clicked(self):
        """Confirms with the user before quitting or closing the window."""
        if self._closing:
            return
        try:
            ans = messagebox.askyesno(
                "Aegis Shield - Confirm Quit",
                "Are you sure you want to quit Aegis Shield?\n\n"
                "Ransomware monitoring will stop immediately and the "
                "monitored folder will no longer be protected.")
        except Exception:
            ans = False
        if ans:
            self.on_closing()

    def on_closing(self):
        if self._closing:
            return
        self._closing = True
        try:
            if hasattr(self, "hw_monitor"):
                self.hw_monitor.running = False
        except Exception as e:
            logging.debug(f"Failed to stop hw_monitor: {e}")
        try:
            if getattr(self, "registry_monitor", None):
                self.registry_monitor.stop()
        except Exception as e:
            logging.debug(f"Failed to stop registry_monitor: {e}")
        try:
            if hasattr(self, "observer"):
                self.observer.stop()
                self.observer.join(timeout=5)
                if self.observer.is_alive():
                    logging.warning("Observer thread did not exit within 5s — forcing ahead.")
        except Exception as e:
            logging.debug(f"Failed to stop observer: {e}")
        try:
            if hasattr(self, "file_monitor"):
                self.file_monitor.stop_workers()
        except Exception as e:
            logging.debug(f"Failed to stop file_monitor workers: {e}")
        try:
            if self.root.winfo_exists():
                self.root.destroy()
        except Exception as e:
            logging.debug(f"Failed to destroy root window: {e}")


# ============================================================
# MAIN
# ============================================================
def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(str(Path(__file__).parent / "ransomware_core.log")),
            logging.StreamHandler()
        ]
    )

    if os.name == "nt":
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                logging.warning(
                    "Not running as Administrator — process detection may be limited."
                )
                print(" Run as Administrator for full detection capability.")
        except Exception as e:
            logging.debug(f"Admin privilege check failed: {e}")

    MONITOR_PATH = sys.argv[1] if len(sys.argv) > 1 else "./test_monitor"

    for d in (MONITOR_PATH, QUARANTINE_DIR, FORENSIC_DIR):
        Path(d).mkdir(parents=True, exist_ok=True)

    decoys = {
        "!000_killme.txt":
            "Service Agreement\n\nConfidential Business Contract",

        "!000_killme.doc":
            "Q4 Financial Summary\nRevenue: 1240000",

        "!000_ransom_trap.txt":
            "Project Notes\nInternal planning document"
    }

    for fname, content in decoys.items():
        hp = Path(MONITOR_PATH) / fname

        if not hp.exists():
            try:
                hp.write_text(content)
            except Exception as e:
                logging.warning(f"Failed to create honeypot {fname}: {e}")

    config = load_config()
    baseline = {}
    pid_store = PerPidStore(config)
    forensic = ForensicEngine(config, baseline)
    risk_scorer = RiskScorer(config, forensic, pid_store, MONITOR_PATH)

    file_monitor = FileOperationMonitor(
        MONITOR_PATH,
        config,
        forensic,
        pid_store,
        baseline,
        risk_scorer
    )

    hw_monitor = HardwareAnomalyMonitor(
        config,
        forensic,
        MONITOR_PATH,
        risk_scorer
    )

    registry_monitor = RegistryMonitor(config, forensic, risk_scorer)

    risk_scorer.set_file_monitor(file_monitor)
    risk_scorer.set_baseline(baseline)

    observer = Observer()
    observer.schedule(file_monitor, MONITOR_PATH, recursive=True)

    monitoring_started = False
    monitoring_lock = threading.Lock()

    def do_build_baseline():
        try:
            shadow_path = create_shadow_copy(MONITOR_PATH, config)
            if shadow_path:
                logging.info(f"[SHADOW COPY] Protected snapshot available at: {shadow_path}")

            data = build_baseline(MONITOR_PATH, config.get("baseline_max_files", 100000))

            with baseline_lock:
                baseline.clear()
                baseline.update(data)

            risk_scorer.set_baseline(baseline)
            forensic.set_baseline(baseline)

            registry_monitor.build_baseline()

            logging.info(f"Baseline built: {len(data)} files")

        except Exception as e:
            logging.error(f"Baseline build failed: {e}")

    def do_start_monitoring():
        nonlocal monitoring_started

        with monitoring_lock:
            if monitoring_started:
                return

            monitoring_started = True

        try:
            file_monitor.start_workers()
            observer.start()

            threading.Thread(
                target=hw_monitor.start_polling,
                daemon=True
            ).start()

            if registry_monitor.available:
                threading.Thread(
                    target=registry_monitor.start_polling,
                    daemon=True
                ).start()

            logging.info(
                f"Monitoring started: {os.path.abspath(MONITOR_PATH)}"
            )

        except Exception as e:
            logging.error(f"Failed to start monitoring: {e}")

    try:
        root = tk.Tk()
    except Exception as e:
        logging.critical(f"Failed to initialize UI: {e}")
        return

    panel = ControlPanel(
        root,
        config,
        MONITOR_PATH,
        forensic,
        do_start_monitoring,
        do_build_baseline,
        forensic.alert_queue
    )

    panel.set_monitor_refs(observer, hw_monitor, file_monitor,
                            risk_scorer=risk_scorer, registry_monitor=registry_monitor)

    risk_scorer.set_ui_log_callback(panel.do_log)

    root.protocol("WM_DELETE_WINDOW", panel._on_quit_clicked)

    print("Aegis Shield Console Running...")

    try:
        root.mainloop()
    except KeyboardInterrupt:
        logging.info("Interrupted by user.")
    finally:
        try:
            panel.on_closing()
        except Exception as e:
            logging.debug(f"Error during shutdown cleanup: {e}")

if __name__ == "__main__":
    main()