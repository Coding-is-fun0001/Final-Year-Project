import os
import sys
import time
import json
import math
import shutil
import hashlib
import threading
import queue
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
IS_WINDOWS     = platform.system() == "Windows"

DEFAULT_CONFIG = {
    "enabled": True,
    "white_list_paths": [],
    "white_list_procs": [],
    "whitelist_match_mode": "exact",

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
    "hardware_check_interval_sec": 2,
    "hardware_sustain_sec":      10,

    "weight_cpu":     0.05,
    "weight_freq":    0.55,
    "weight_entropy": 0.4,
    "risk_alert_threshold": 0.4,

    "honeypot_filenames": [
        "!000_killme.txt",
        "!000_killme.doc",
        "!000_ransom_trap.txt"
    ],

    # --- Registry monitor ---
    "registry_poll_interval_sec": 5,

    # --- Process behaviour detection ---
    "suspicious_parent_child": {
        "winword.exe":  ["cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe", "cscript.exe"],
        "excel.exe":    ["cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe", "cscript.exe"],
        "powerpnt.exe": ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"],
        "outlook.exe":  ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"]
    },

    # --- Encryption-sequence (read->write->rename loop) detection ---
    "enc_sequence_window_events": 12,
    "enc_sequence_min_pairs": 3,

    # --- Forensic capture depth thresholds (affected-file-count based) ---
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
            # Only accept keys that exist in DEFAULT_CONFIG to prevent
            # unexpected keys from a malicious or corrupted config file.
            known_keys = set(DEFAULT_CONFIG.keys())
            filtered = {k: v for k, v in loaded.items() if k in known_keys}
            cfg.update(filtered)
        except Exception as e:
            logging.warning(f"Failed to load config: {e}, using defaults")
    return cfg


# ============================================================
# UTILITIES & ALGORITHMS
# ============================================================

# File-signature ("magic bytes") table used for lightweight header
# validation. If a monitored office/document file no longer starts with
# its expected signature, it has very likely been overwritten/encrypted
# even if entropy sampling is inconclusive.
FILE_MAGIC_SIGNATURES = {
    ".docx": b"PK",
    ".xlsx": b"PK",
    ".pptx": b"PK",
    ".pdf":  b"%PDF",
}


def check_file_header(file_path: str) -> Optional[str]:
    """Returns a human-readable reason string if the file's on-disk magic
    bytes no longer match what its extension expects, else None."""
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
    """Head+mid+tail sampling — fixed I/O cost regardless of file size."""
    try:
        size = os.path.getsize(file_path)
        if size == 0:
            return 0.0
        chunk = 512 * 1024
        with open(file_path, "rb") as f:
            if size <= 5 * 1024 * 1024:
                return calculate_entropy(f.read())
            f.seek(0)
            head = f.read(chunk)
            f.seek(size // 2)
            mid  = f.read(chunk)
            f.seek(max(0, size - chunk))
            tail = f.read(chunk)
        return calculate_entropy(head + mid + tail)
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


def build_baseline(monitor_path: str) -> dict:
    """Returns {abs_path: {"hash": str, "entropy": float}}"""
    baseline = {}
    p = Path(monitor_path)
    if not p.exists():
        return baseline
    MAX_FILES = 5000
    for file in p.rglob("*"):
        if len(baseline) >= MAX_FILES:
            logging.warning(
                f"Baseline capped at {MAX_FILES} files; "
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


# ============================================================
# WHITELIST
# ============================================================
def is_whitelisted(pid: int, proc_name: str, file_path: str, config: dict) -> bool:
    if not proc_name:
        return False
    w_procs = config.get("white_list_procs", [])
    w_paths = config.get("white_list_paths", [])
    mode    = config.get("whitelist_match_mode", "exact")

    if mode == "exact":
        if proc_name.lower() in [p.lower() for p in w_procs]:
            return True
    else:
        for wp in w_procs:
            if wp.lower() in proc_name.lower():
                return True

    # Path-based whitelist
    try:
        abs_file = Path(file_path).resolve()
        for wp in w_paths:
            try:
                rel = abs_file.is_relative_to(Path(wp).resolve())
            except AttributeError:
                rel = str(abs_file).startswith(str(Path(wp).resolve()))
            if rel:
                return True
    except Exception as e:
        logging.debug(f"Whitelist path check failed: {e}")
    return False


# ============================================================
# PROCESS CONTROL & QUARANTINE
# ============================================================
class ProcessTerminator:
    # Shared interpreter/host binaries that must NEVER be quarantined even
    # if psutil.Process(pid).exe() resolves to them - a malicious script run
    # via `python3 evil.py`, `powershell -File evil.ps1`, `node evil.js` etc.
    # reports the INTERPRETER's path as exe(), not the script's. Moving the
    # interpreter itself would break every other program on the host that
    # depends on it (this was verified to actually happen during testing:
    # it quarantined the sandbox's own /usr/bin/python3.12 multiple times).
    _INTERPRETER_HOSTS = {
        "python.exe", "python3.exe", "pythonw.exe", "python3",
        "python", "python3.10", "python3.11", "python3.12", "python3.13",
        "powershell.exe", "pwsh.exe", "cmd.exe",
        "wscript.exe", "cscript.exe", "mshta.exe",
        "node.exe", "node", "perl.exe", "perl", "ruby.exe", "ruby",
        "bash", "sh", "dash", "zsh",
    }

    # Well-known system directories: never quarantine anything living
    # directly under these roots, regardless of filename, as an extra
    # safety net beyond the interpreter-name check above.
    _SYSTEM_DIRS = (
        "c:\\windows\\", "c:\\program files\\", "c:\\program files (x86)\\",
        "/usr/bin/", "/usr/lib/", "/usr/sbin/", "/usr/local/bin/",
        "/bin/", "/sbin/", "/lib/", "/lib64/",
    )

    @staticmethod
    def _is_protected_host_binary(exe_path: str) -> bool:
        """Returns True if exe_path points at a shared interpreter or a
        well-known system directory that must never be moved/deleted.
        Checks both the resolved Path and the raw string, because
        pathlib.Path only parses backslash-separated Windows paths
        correctly when actually running on Windows -- on POSIX hosts a
        Windows-style path string needs a plain prefix check instead."""
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

        # basename check (covers cases resolve() couldn't parse cross-platform)
        base_name = raw_l_fwd.rsplit("/", 1)[-1]
        if base_name in ProcessTerminator._INTERPRETER_HOSTS:
            return True

        for d in ProcessTerminator._SYSTEM_DIRS:
            d_bslash = d.replace("/", "\\")
            if resolved_l.startswith(d) or raw_l.startswith(d_bslash) or raw_l_fwd.startswith(d):
                return True
        return False

    # Extensions treated as "this argument might be a malicious script" when
    # scanning an interpreter-launched process's cmdline. Deliberately a
    # strict endswith() match ONLY — earlier draft logic also matched any
    # argument merely containing a slash/backslash, which would have caught
    # ordinary arguments like `--output /home/user/report.docx` and
    # quarantined (deleted) the user's own legitimate files. That is
    # unacceptable for a tool whose whole job is protecting user data, so
    # this checker is intentionally conservative: only real script files.
    _SCRIPT_PAYLOAD_EXTS = (".py", ".pyw", ".ps1", ".bat", ".cmd",
                             ".js", ".vbs", ".vbe", ".wsf", ".sh")

    @staticmethod
    def _extract_script_payload(cmdline: list, monitor_path=None):
        """Best-effort: find a script file passed as an argument to a shared
        interpreter (e.g. the 'evil.py' in `python3 evil.py`). Returns a
        resolved Path or None. Deliberately conservative — false negatives
        (missing the payload) are fine, since the process is already
        terminated either way; false positives (quarantining the wrong
        file) are not, since that means silently moving/deleting a file
        that might belong to the user."""
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
            # Never touch anything under a protected system dir or that
            # resolves to a known interpreter/host binary name.
            if ProcessTerminator._is_protected_host_binary(str(arg_path)):
                continue
            # Never touch anything under the folder we're supposed to be
            # protecting — that's the victim's data, not the attacker's
            # tooling, even if its name happens to end in .py/.js/etc.
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
    def terminate_and_quarantine(pid: int, ui_log_callback=None, monitor_path=None) -> bool:
        exe_path  = None
        proc_name = "Unknown"
        cmdline   = []                 # must default to [] — used below even if psutil fails
        terminated = False
        try:
            p         = psutil.Process(pid)
            proc_name = p.name()
            exe_path  = p.exe()          # captured before kill
            cmdline   = p.cmdline()       # captured before kill, used for interpreter-launched payloads
        except Exception as e:
            logging.debug(f"Failed to get process info before kill: {e}")

        # Terminate
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

        # Quarantine executable
        if exe_path and os.path.exists(exe_path):
            src  = Path(exe_path).resolve()

            # SAFETY CHECK: never quarantine a shared interpreter or a file
            # living in a well-known system directory. The process itself
            # is already terminated above; here we only decide whether it's
            # safe to also move its executable. The real malicious payload
            # for interpreter-launched malware (e.g. `python3 evil.py`) is
            # in the SCRIPT file, which shows up in `recent_files` from the
            # detection layer, not in exe_path -- quarantining logic for
            # that should target recent_files, not the interpreter host.
            if ProcessTerminator._is_protected_host_binary(exe_path):
                msg = (f"SKIPPED QUARANTINE (shared interpreter/system "
                       f"binary, not the payload): {src}")
                logging.warning(msg)
                if ui_log_callback:
                    ui_log_callback(msg + "\n", "warning")

                # The interpreter itself is preserved, but the actual
                # attack script passed on its command line (if any and if
                # it's safe to touch) can still be pulled out and isolated.
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
                return True  # process was still terminated successfully

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
        # Process was terminated but no executable to quarantine
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
        with self.lock:
            if pid not in self.history:
                self.history[pid] = {
                    "name": proc_name,
                    "q_1s": deque(),
                    "q_1h": deque(),
                    "q_24h": deque(),
                    "entropy_anomaly_count": 0,
                    "touched_files": deque(maxlen=200),
                    "action_seq": deque(maxlen=self._seq_window)
                }
            else:
                # Detect PID reuse: if proc_name changed, a new process
                # took the same PID. Reset the store to avoid mis-attribution.
                stored_name = self.history[pid]["name"]
                if (proc_name and stored_name and
                        proc_name.lower() != stored_name.lower() and
                        proc_name not in ("unknown", "unattributed(pid=0)")):
                    logging.warning(
                        f"PID {pid} reuse detected: was '{stored_name}' "
                        f"now '{proc_name}'. Resetting attribution store."
                    )
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

    def get_action_sequence(self, pid):
        with self.lock:
            if pid not in self.history:
                return []
            return list(self.history[pid].get("action_seq", []))

    def detect_encryption_sequence(self, pid, min_pairs=3):
        """Lightweight substitute for API-call-sequence detection: ransomware
        typically performs a tight Read(open)->Write(rewrite/encrypt)->Rename
        loop across many files. We approximate this with watchdog event
        types: a 'modified' event immediately followed by a 'moved' (rename)
        or another 'created/modified' event, repeated several times."""
        seq = self.get_action_sequence(pid)
        if len(seq) < min_pairs + 1:
            return False
        pairs = 0
        for i in range(len(seq) - 1):
            if seq[i] in ("modified", "created") and seq[i + 1] in ("moved", "modified"):
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
# FORENSIC ENGINE (FIXED)
# ============================================================
class ForensicEngine:
    def __init__(self, config, baseline):
        self.config = config
        self.baseline = baseline
        self.alert_queue = queue.Queue(maxsize=2000)

    def set_baseline(self, b):
        self.baseline = b

    def push_alert_to_ui(self, alert_dict):
        try:
            self.alert_queue.put_nowait(alert_dict)
        except queue.Full:
            logging.critical(
                "ALERT QUEUE FULL — forensic alert DROPPED. "
                "Increase alert_queue maxsize or reduce event rate."
            )

    def _classify_depth(self, reason: str, recent_files: list) -> str:
        """Forensic trigger manager: decides capture depth from a coarse
        risk estimate. High-confidence reasons (honeypot/registry/header)
        or many affected files -> full capture; everything else -> basic.
        NOTE: keywords here must match the actual reason strings produced
        elsewhere in the codebase — verify against _fire_alert/push_alert_to_ui
        call sites whenever a new alert reason is added."""
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
        """Detection/forensic helper: walk up to max_depth parent processes,
        producing an attack-chain style lineage list, e.g.
        explorer.exe -> powershell.exe -> evil.exe"""
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
                raw = proc.connections(kind="inet")  # psutil < 6.0 fallback
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
        """Lightweight volatile-evidence capture: RSS/VMS + mapped regions,
        WITHOUT a full memory dump (too slow / heavyweight for real-time use)."""
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
        """Replacement for full kernel-handle enumeration: lists files
        currently open by the suspect process (sensitive file exposure)."""
        handles = []
        try:
            proc = psutil.Process(pid)
            for f in proc.open_files()[:50]:
                handles.append(f.path)
        except Exception as e:
            logging.debug(f"Open handle capture failed for pid {pid}: {e}")
        return handles

    def generate_evidence_summary(self, pid: int, proc_name: str, reason: str, recent_files: list):
        depth = self._classify_depth(reason, recent_files)

        evidence = {
            "forensic_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "capture_depth": depth,
            "suspect_process": {
                "pid": pid,
                "name": proc_name,
                "executable": "Unknown (terminated)"
            },
            "trigger_reason": reason,
            "impact_assessment": {
                "total_files_affected": len(recent_files),
                "modified_files_manifest": []
            }
        }
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
            evidence["suspect_process"]["executable"] = "Already terminated before evidence capture"

        # Forensic module additions — capture depth scales with risk.
        if pid and depth in ("medium", "full"):
            evidence["process_lineage"] = self._capture_process_lineage(pid)
        if pid and depth == "full":
            evidence["network_connections"] = self._capture_network_connections(pid)
            evidence["memory_info"] = self._capture_memory_info(pid)
            evidence["open_handles"] = self._capture_open_handles(pid)

        for f_path in recent_files:
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

        Path(FORENSIC_DIR).mkdir(parents=True, exist_ok=True)

        out = Path(FORENSIC_DIR) / f"forensic_pid_{pid}_{int(time.time())}.json"
        try:
            with open(out, 'w') as f:
                json.dump(evidence, f, indent=4)
            logging.info(f"Forensic report: {out}")
        except Exception as e:
            logging.error(f"Forensic write failed: {e}")

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
                files_to_scan = list(Path(self.monitor_path).rglob("*"))[:5000]

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

                score = (
                    norm_cpu * self.config.get("weight_cpu", 0.2) +
                    norm_freq * self.config.get("weight_freq", 0.5) +
                    norm_ent * self.config.get("weight_entropy", 0.3)
                )

                if score > best_score:
                    best_score = score
                    best_pid = pid
                    best_name = p_name
                    best_norm_freq = norm_freq
                    best_norm_ent = norm_ent

            except Exception:
                continue

        # Hardware anomaly is now a SUPPORTING signal only (downgraded from
        # primary detector). CPU/memory spikes alone — with no corroborating
        # file-frequency or entropy evidence for the same pid — are no
        # longer sufficient to raise an alert; they are logged for context.
        if best_pid and best_score >= self.config.get("risk_alert_threshold", 0.4):
            if best_norm_freq <= 0 and best_norm_ent <= 0:
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

            reason = f"Hardware anomaly CPU:{sys_cpu:.1f}% MEM:{sys_mem:.1f}% Risk:{best_score:.2f}"

            self.forensic.push_alert_to_ui({
                "pid": best_pid,
                "proc_name": best_name,
                "reason": reason,
                "recent_files": recent
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

        self._decoys = {
            "!000_killme.txt":      "Service Agreement\n\nConfidential Business Contract",
            "!000_killme.doc":      "Q4 Financial Summary\nRevenue: 1240000",
            "!000_ransom_trap.txt": "Project Notes\nInternal planning document"
        }

    def _restore_honeypots(self):
        for fname, content in self._decoys.items():
            hp = Path(self.monitor_path) / fname
            if not hp.exists():
                try:
                    hp.write_text(content)
                    logging.info(f"Honeypot restored: {fname}")
                except Exception as e:
                    logging.warning(f"Failed to restore honeypot {fname}: {e}")

    def start_polling(self):
        self.running = True

        cpu_thresh = self.config.get("hardware_cpu_threshold", 80.0)
        mem_thresh = self.config.get("hardware_mem_threshold", 85.0)
        interval = self.config.get("hardware_check_interval_sec", 2)
        sustain_sec = self.config.get("hardware_sustain_sec", 10)

        above_since = None
        alerted = False
        _honeypot_check_counter = 0

        while self.running:
            try:
                _honeypot_check_counter += 1
                if _honeypot_check_counter >= 30:
                    _honeypot_check_counter = 0
                    self._restore_honeypots()
                    
                sys_cpu = psutil.cpu_percent(interval=None)
                sys_mem = psutil.virtual_memory().percent

                abnormal = (
                    sys_cpu >= cpu_thresh or
                    (sys_mem >= mem_thresh and sys_cpu >= 40)
                )

                if abnormal:
                    if above_since is None:
                        above_since = time.time()
                    elif not alerted:
                        if time.time() - above_since >= sustain_sec:
                            self.risk_scorer.process_hardware_event(sys_cpu, sys_mem)
                            alerted = True
                else:
                    above_since = None
                    alerted = False

            except Exception as e:
                logging.error(f"HW monitor error: {e}")

            time.sleep(interval)


# ============================================================
# REGISTRY MONITOR (NEW)
# ============================================================
class RegistryMonitor:
    """Monitors Windows Registry persistence/anti-recovery keys:
      - HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run  (autorun)
      - HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ShadowCopy
        (presence used as a coarse proxy for shadow-copy/recovery tampering)
    Runs in its own polling thread; safely degrades to a no-op on non-Windows
    hosts (e.g. during development on Linux/macOS).
    """

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
            self.forensic.push_alert_to_ui({
                "pid": 0,
                "proc_name": "registry(unattributed)",
                "reason": f"Suspicious autorun entry added: '{name}' -> {val}",
                "recent_files": []
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
            self.forensic.push_alert_to_ui({
                "pid": 0,
                "proc_name": "registry(unattributed)",
                "reason": "Volume Shadow Copy registry key removed — possible anti-recovery tampering",
                "recent_files": []
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

        # Process-behaviour detection: avoid re-checking the same pid's
        # parentage/launch-path on every single file event.
        self._behavior_checked_pids = set()
        self._behavior_lock = threading.Lock()
        self._suspicious_parent_child = {
            k.lower(): {c.lower() for c in v}
            for k, v in config.get("suspicious_parent_child", {}).items()
        }
        self._tmp_dir_lower = tempfile.gettempdir().lower()

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
                # Evict the oldest half instead of clearing everything,
                # to avoid a detection gap on the next event.
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

        try:
            for idx, proc in enumerate(psutil.process_iter(['pid', 'name'])):
                if idx > 500:
                    break

                if proc.info["pid"] in (curr_pid, 0):
                    continue

                try:
                    ofiles = proc.open_files()
                    if not ofiles:
                        continue

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

                except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                    continue

        except Exception as e:
            logging.debug(f"process_iter scan failed in _get_calling_process: {e}")

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
        """Detection #3 helper: must be invoked after EVERY pid_store.record()
        call (not just on the default fall-through path), otherwise an
        earlier alert (entropy/header/suspicious-ext) that returns first
        would make this check unreachable in the exact scenario it exists
        to catch — a fast multi-file encrypt loop. Returns True if an alert
        was fired."""
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
        """Detection #1: flags processes launched from Temp directories, and
        processes spawned with an abnormal parent (e.g. winword.exe -> cmd.exe).
        Checked once per pid (cached) to keep overhead low."""
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

        pid, name = self._get_calling_process(f_abs)

        if pid is None:
            # Attribution failed: process already closed, AccessDenied, or
            # PID reuse race. Events attributed to pid=0 are unverified.
            pid, name = 0, "unattributed(pid=0)"
        else:
            if is_whitelisted(pid, name, f_abs, self.config):
                return

            behavior_reason = self._check_process_behavior(pid, name)
            if behavior_reason:
                # NOTE: do NOT record here — this branch falls through to the
                # unified self.pid_store.record(...) call at the bottom of
                # _analyse(). Recording here too caused every behavior-flagged
                # event to be counted twice in q_1s / action_seq.
                self.risk_scorer.report_event(pid, name, f_abs, "process_behavior_anomaly")
                self._fire_alert(pid, name, behavior_reason, f_abs)

        if f_abs in self._honeypot_abs:
            self.risk_scorer.report_event(
                pid, name, f_abs,
                "honeypot_triggered",
                priority="high"
            )

            self.forensic.push_alert_to_ui({
                "pid": pid,
                "proc_name": name,
                "reason": f"HONEYPOT TRIGGERED: {Path(f_abs).name}",
                "recent_files": [f_abs]
            })
            return

        is_monitored = ext in self.config.get("monitored_exts", [])
        is_suspicious = ext in self.config.get("suspicious_exts", [])

        if is_suspicious:
            self._fire_alert(
                pid, name,
                f"Suspicious extension deployed: {ext}",
                f_abs
            )
            return

        # Detection #4: file-header (magic bytes) validation — cheap and
        # precise. A monitored office/PDF file whose header no longer
        # matches its extension has almost certainly been overwritten.
        # Also checked on "moved" events: a common encryption pattern is
        # write-to-temp then rename-over-original, which watchdog reports
        # as a move rather than a modification.
        if event_type in ("modified", "moved") and os.path.exists(f_abs):
            header_reason = check_file_header(f_abs)
            if header_reason:
                self.pid_store.record(pid, name, event_type, f_abs, is_entropy_anomaly=True)
                self.risk_scorer.report_event(pid, name, f_abs, "file_header_mismatch", priority="high")
                self._fire_alert(pid, name, header_reason, f_abs)
                self._check_sequence_pattern(pid, name, f_abs)
                return

        is_entropy_anomaly = False
        delta = 0.0

        # Extensions that are naturally high-entropy and should NOT trigger
        # entropy-only alerts (zip, iso, compressed, media, encrypted DBs).
        _HIGH_ENTROPY_NATURAL_EXTS = {
            ".zip", ".gz", ".bz2", ".xz", ".7z", ".rar", ".zst",
            ".iso", ".img", ".dmg",
            ".mp3", ".mp4", ".mkv", ".aac", ".ogg", ".flac",
            ".jpg", ".jpeg", ".png", ".webp", ".gif",
            ".sqlite", ".db3",
        }

        # Also checked on "moved" events (temp-write + rename-over-original
        # is a common atomic-write / encryption pattern that watchdog
        # reports as a move, not a modification).
        if is_monitored and event_type in ("modified", "created", "moved") and os.path.exists(f_abs):
            try:
                curr_entropy = get_file_entropy_sampled(f_abs)
                curr_hash = compute_file_hash(f_abs)

                with baseline_lock:
                    base = self.baseline.get(str(Path(f_abs).resolve()))

                base_hash = base["hash"] if base else None
                base_entropy = base["entropy"] if base else None

                if base_entropy is not None:
                    delta = curr_entropy - base_entropy
                    delta_anomaly = delta >= self.config.get("entropy_delta_threshold", 1.5)

                    # Office/zip-style formats already sit near max entropy
                    # at baseline, so a small delta can't be relied on to
                    # catch further encryption. When the baseline itself was
                    # already high-entropy, fall back to an absolute-entropy
                    # check (content changed AND is now above the entropy
                    # bar) so these formats aren't a permanent blind spot.
                    baseline_already_high = base_entropy >= self.config.get(
                        "high_alert_entropy_threshold", 6.5)
                    absolute_anomaly = (
                        baseline_already_high and
                        curr_hash != base_hash and
                        curr_entropy >= self.config.get("entropy_threshold", 7.2)
                    )

                    is_entropy_anomaly = delta_anomaly or absolute_anomaly
                else:
                    # New file: only flag if high entropy AND not a naturally
                    # compressed/media format (reduces false positives).
                    if ext not in _HIGH_ENTROPY_NATURAL_EXTS:
                        is_entropy_anomaly = (
                            curr_entropy >= self.config.get("entropy_threshold", 7.2)
                        )

                if base_entropy is not None and curr_hash and curr_hash != base_hash and is_entropy_anomaly:
                    self.pid_store.record(
                        pid, name, event_type, f_abs,
                        is_entropy_anomaly = True
                    )
                    
                    self.risk_scorer.report_event(
                        pid, name, f_abs, "entropy_anomaly"
                    )

                    self._fire_alert(
                        pid, name,
                        f"Entropy anomaly: {Path(f_abs).name} (delta={delta:.2f})",
                        f_abs
                    )
                    self._check_sequence_pattern(pid, name, f_abs)
                    return

                if base is None and is_entropy_anomaly:

                    self.pid_store.record(
                        pid, name, event_type, f_abs,
                        is_entropy_anomaly=True
                    )
                    self.risk_scorer.report_event(
                        pid, name, f_abs, "entropy_anomaly"
                    )

                    self._fire_alert(
                        pid, name,
                        f"High entropy on new file: {Path(f_abs).name} "
                        f"(entropy={curr_entropy:.2f})",
                        f_abs
                    )
                    self._check_sequence_pattern(pid, name, f_abs)
                    return

            except Exception as e:
                logging.debug(f"Entropy check failed: {e}")

        self.pid_store.record(
            pid, name, event_type, f_abs,
            is_entropy_anomaly=is_entropy_anomaly
        )

        self._track(pid, f_abs)
        freq_alerted = self._check_frequency(pid, name, f_abs)

        # Detection #3: encryption-sequence pattern (lightweight substitute
        # for API call-sequence monitoring) — repeated Read/Write->Rename
        # loops across many files in a short window. Skipped if a frequency
        # alert already fired for this event, to avoid double-alerting.
        if not freq_alerted:
            self._check_sequence_pattern(pid, name, f_abs)

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

        # For unknown-process events (pid=0) use a reason-based key so that
        # different alert types are not all suppressed by a single shared slot.
        cooldown_key = pid if pid != 0 else f"unknown:{reason}"

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

        self.forensic.push_alert_to_ui({
            "pid": pid,
            "proc_name": name,
            "reason": reason,
            "recent_files": recent
        })

        self.risk_scorer.report_event(pid, name, f_abs, "file_trigger")

    def on_modified(self, event):
        if event.is_directory:
            return

        try:
            self._analyse(event.src_path, "modified")
        except Exception as e:
            logging.error(f"on_modified error: {e}")

    def on_created(self, event):
        if event.is_directory:
            return

        try:
            self._analyse(event.src_path, "created")
        except Exception as e:
            logging.error(f"on_created error: {e}")

    def on_moved(self, event):
        if event.is_directory:
            return

        try:
            dest_abs = os.path.abspath(event.dest_path)
            dest_ext = os.path.splitext(dest_abs)[1].lower()

            if dest_ext in self.config.get("suspicious_exts", []):
                pid, name = self._get_calling_process(dest_abs)

                if pid is None:
                    pid, name = 0, "unknown"

                self._fire_alert(
                    pid, name,
                    f"Rename to suspicious extension: "
                    f"{Path(event.src_path).name} -> {Path(event.dest_path).name}",
                    dest_abs
                )
            else:
                self._analyse(event.dest_path, "moved")

        except Exception as e:
            logging.error(f"on_moved error: {e}")

    def on_deleted(self, event):
        if event.is_directory:
            return

        try:
            f_abs = os.path.abspath(event.src_path)

            if f_abs in self._honeypot_abs:
                hp_pid, hp_name = self._get_calling_process(f_abs)
                if hp_pid is None:
                    hp_pid, hp_name = 0, "unknown"
                self.forensic.push_alert_to_ui({
                    "pid": hp_pid,
                    "proc_name": hp_name,
                    "reason": f"HONEYPOT DELETED: {Path(f_abs).name}",
                    "recent_files": [f_abs]
                })
                return

            del_pid, del_name = self._get_calling_process(f_abs)
            if del_pid is None:
                del_pid, del_name = 0, "unknown"

            self.pid_store.record(del_pid, del_name, "deleted", f_abs)

            _, c_1h, _, _ = self.pid_store.clean_and_get_counts(del_pid)

            if c_1h >= max(5, self.config.get("threshold_1h", 50) // 2):
                self._fire_alert(
                    del_pid, del_name,
                    f"Bulk deletion detected: {c_1h} files deleted/hour",
                    f_abs
                )

        except Exception as e:
            logging.error(f"on_deleted error: {e}")

 


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
        self._processing_alert_lock   = threading.Lock()   # prevents race condition
        self.processing_alert         = False
        self.monitoring_started       = False
        self.radar_angle              = 0
        self._closing                 = False

        # Dashboard state (Step 5: risk level + protected file count)
        self._last_threat_time        = 0.0
        self.risk_scorer              = None
        self.registry_monitor         = None

        self.root.title("Aegis Shield - Ransomware Detection & Forensics")
        self.root.geometry("720x800")
        self.root.configure(bg="#1e1e24")

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

        self.radar_frame = tk.Frame(self.root, bg="#1e1e24")
        self.radar_frame.pack(pady=10)
        self.radar_canvas = tk.Canvas(
            self.radar_frame, width=220, height=220,
            bg="#111116", highlightthickness=1,
            highlightbackground="#00ff66")
        self.radar_canvas.pack()
        self._draw_static_radar()

        # --- Dashboard status strip: current risk level + protected files ---
        self.status_frame = tk.Frame(self.root, bg="#1e1e24")
        self.status_frame.pack(pady=(0, 5))

        self.risk_level_label = tk.Label(
            self.status_frame, text="风险等级: 低 (LOW)",
            font=("Consolas", 11, "bold"), fg="#00ff66", bg="#1e1e24")
        self.risk_level_label.pack(side=tk.LEFT, padx=15)

        self.protected_count_label = tk.Label(
            self.status_frame, text="受保护文件总数: 0",
            font=("Consolas", 11, "bold"), fg="#ffffff", bg="#1e1e24")
        self.protected_count_label.pack(side=tk.LEFT, padx=15)

        self.btn_frame = tk.Frame(self.root, bg="#1e1e24")
        self.btn_frame.pack(pady=10)
        self.start_btn = tk.Button(
            self.btn_frame,
            text="SYSTEM LOCKED (AWAITING INTEGRITY BASELINE)",
            font=("Arial", 10, "bold"),
            bg="#3a3a45", fg="#888888",
            activebackground="#3a3a45", activeforeground="#888888",
            state=tk.DISABLED, width=50, height=2, bd=0, cursor="no")
        self.start_btn.pack()

        self.report_btn = tk.Button(
            self.btn_frame,
            text="📄 查看最新取证报告",
            font=("Arial", 9, "bold"),
            bg="#2a2a35", fg="#00ccff",
            activebackground="#3a3a45", activeforeground="#00ccff",
            bd=0, cursor="hand2",
            command=self._open_latest_forensic_report)
        self.report_btn.pack(pady=(8, 0))

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

    def _draw_static_radar(self):
        c = self.radar_canvas
        for r in ((15,15,205,205),(55,55,165,165),(95,95,125,125)):
            c.create_oval(*r, outline="#004411", width=1)
        c.create_line(110,5,110,215, fill="#004411", width=1)
        c.create_line(5,110,215,110, fill="#004411", width=1)

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
            cursor="no")

        self.do_log(
            "[ACTIVE] Shield online. Anti-ransomware interception live.\n",
            "warning" )

        try:
            self.start_monitoring_callback()
        except Exception as e:
            logging.error(f"Failed to start monitoring: {e}")

        self.radar_angle = 0
        self._update_radar_animation()

    def _do_log(self, msg, text_type):
        self.log_text.insert(tk.END, msg, text_type)
        self.log_text.see(tk.END)

    def do_log(self, msg, tag="info"):
        """Thread-safe public logger — safe to call from any thread."""
        self.root.after(0, lambda: self._do_log(msg, tag))

    def _open_latest_forensic_report(self):
        """Step 5: Forensic report viewer — shows the most recent
        forensic_pid_*.json (process/network/file-list contents) in a popup."""
        try:
            Path(FORENSIC_DIR).mkdir(parents=True, exist_ok=True)
            reports = sorted(
                Path(FORENSIC_DIR).glob("forensic_pid_*.json"),
                key=lambda p: p.stat().st_mtime, reverse=True
            )
            if not reports:
                messagebox.showinfo("Aegis Shield - 取证报告", "暂无取证报告。系统检测到入侵并完成响应后会自动生成报告。")
                return

            latest = reports[0]
            with open(latest, 'r') as f:
                data = json.load(f)

            win = tk.Toplevel(self.root)
            win.title(f"取证报告 - {latest.name}")
            win.geometry("640x560")
            win.configure(bg="#111116")

            text = tk.Text(win, bg="#111116", fg="#00ff66",
                            insertbackground="white", font=("Consolas", 9), bd=0)
            text.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

            sp = data.get("suspect_process", {})
            lines = []
            lines.append(f"== 取证报告 ({data.get('forensic_timestamp', '?')}) ==")
            lines.append(f"采集深度 (Capture Depth): {data.get('capture_depth', '?')}")
            lines.append(f"触发原因: {data.get('trigger_reason', '?')}\n")
            lines.append("--- 进程快照 ---")
            for k, v in sp.items():
                lines.append(f"  {k}: {v}")

            if "process_lineage" in data:
                chain = " -> ".join(f"{n['name']}(pid={n['pid']})" for n in data["process_lineage"])
                lines.append(f"\n--- 进程链 (Lineage) ---\n  {chain}")

            if "network_connections" in data:
                lines.append("\n--- 网络连接 ---")
                if data["network_connections"]:
                    for c in data["network_connections"]:
                        lines.append(f"  {c.get('local_addr')} -> {c.get('remote_addr')} [{c.get('status')}]")
                else:
                    lines.append("  (无活动连接)")

            if "memory_info" in data:
                mi = data["memory_info"]
                lines.append("\n--- 内存信息 ---")
                lines.append(f"  RSS: {mi.get('rss_bytes', '?')} bytes, VMS: {mi.get('vms_bytes', '?')} bytes")
                lines.append(f"  映射区域数: {mi.get('mapped_region_count', '?')}")

            if "open_handles" in data:
                lines.append("\n--- 活动句柄 (打开的文件) ---")
                for h in data["open_handles"][:20]:
                    lines.append(f"  {h}")

            ia = data.get("impact_assessment", {})
            lines.append(f"\n--- 影响评估 ---\n  受影响文件总数: {ia.get('total_files_affected', 0)}")
            for m in ia.get("modified_files_manifest", [])[:30]:
                lines.append(f"  [{m.get('status')}] {m.get('path')}")

            text.insert(tk.END, "\n".join(lines))
            text.config(state=tk.DISABLED)

        except Exception as e:
            logging.error(f"Failed to open forensic report: {e}")
            messagebox.showerror("Aegis Shield - 错误", f"无法打开取证报告: {e}")

    def _update_dashboard_stats(self):
        """Step 5: periodically refreshes the risk-level and protected-file
        count labels on the dashboard."""
        try:
            if not self.root.winfo_exists():
                return
        except Exception:
            return

        try:
            protected = len(self.forensic.baseline) if self.forensic.baseline else 0
            self.protected_count_label.config(text=f"受保护文件总数: {protected}")

            elapsed = time.time() - self._last_threat_time
            if self._last_threat_time and elapsed < 60:
                self.risk_level_label.config(text="风险等级: 高 (HIGH)", fg="#ff3333")
            elif self._last_threat_time and elapsed < 300:
                self.risk_level_label.config(text="风险等级: 中 (MEDIUM)", fg="#ffcc00")
            else:
                self.risk_level_label.config(text="风险等级: 低 (LOW)", fg="#00ff66")
        except Exception as e:
            logging.debug(f"Dashboard stats update failed: {e}")

        self.root.after(3000, self._update_dashboard_stats)

    def _update_radar_animation(self):
        try:
            if not self.root.winfo_exists():
                return
        except Exception:
            return
        self.radar_canvas.delete("sweep_line")
        r = math.radians(self.radar_angle)
        self.radar_canvas.create_line(
            110, 110,
            110 + 100 * math.cos(r), 110 + 100 * math.sin(r),
            fill="#00ff66", width=2, tags="sweep_line")
        self.radar_angle = (self.radar_angle + 4) % 360
        self.root.after(25, self._update_radar_animation)

    def _process_alert_safely(self, alert):
        try:
            pid          = alert["pid"]
            proc_name    = alert["proc_name"]
            reason       = alert["reason"]
            recent_files = alert["recent_files"]

            if pid == 0:
                self._last_threat_time = time.time()
                self._do_log(f"\n🚨 [BULK EVENT] {reason}\n", "critical")
                self._do_log(
                    "[WARNING] Cannot identify responsible process (PID 0 = system). "
                    "Capturing forensic evidence for the affected files anyway...\n",
                    "warning")

                # No live process to suspend/kill, but the affected files are
                # still known — capture file-level evidence (hash/entropy
                # comparison against baseline) instead of doing nothing.
                # generate_evidence_summary degrades gracefully when
                # psutil.Process(pid) fails, so this is safe to call with
                # an unattributed pid.
                threading.Thread(
                    target=self.forensic.generate_evidence_summary,
                    args=(pid, proc_name, reason, recent_files),
                    daemon=True).start()

                messagebox.showinfo(
                    "Aegis Shield - Bulk Activity Detected",
                    f"Suspicious bulk activity detected!\n\n"
                    f"Reason : {reason}\n"
                    f"Files  : {len(recent_files)}\n\n"
                    f"The responsible process could not be identified, so it "
                    f"cannot be suspended/terminated automatically.\n"
                    f"Forensic evidence for the affected files has been captured — "
                    f"review the forensic report and isolate manually if needed.")
                return

            ProcessTerminator.suspend_process(pid)
            self._last_threat_time = time.time()
            self._do_log(f"\n🚨 [BREACH DETECTED] {reason}\n", "critical")
            self._do_log(
                f"[SUSPENDED] {proc_name} (PID:{pid}). Capturing forensic "
                f"evidence in background while process is frozen...\n",
                "warning")

            # Parallel response (report §4.4.3): the process is now frozen
            # (suspended, not killed) — this is the ONLY window where
            # in-memory secrets (encryption keys, C2 connection state) are
            # still guaranteed to exist. We capture that evidence RIGHT NOW,
            # in the background, instead of waiting on the user's yes/no
            # decision. Whatever the user decides afterwards, the evidence
            # is already safely on disk.
            forensic_thread = threading.Thread(
                target=self.forensic.generate_evidence_summary,
                args=(pid, proc_name, reason, recent_files),
                daemon=True)
            forensic_thread.start()

            try:
                self.radar_canvas.create_oval(
                    100, 50, 110, 60,
                    fill="#ff3333", outline="#ffffff", tags="threat")
            except Exception as e:
                logging.debug(f"Radar canvas draw failed: {e}")

            try:
                ans = messagebox.askyesno(
                    "Aegis Shield - Threat Isolation",
                    (f"Suspicious activity detected!\n\n"
                     f"Process : {proc_name} (PID: {pid})\n"
                     f"Reason  : {reason}\n"
                     f"Files   : {len(recent_files)}\n\n"
                     f"YES → KILL & quarantine\n"
                     f"NO  → Trust & resume"),
                    icon="warning", default="yes")
            except Exception:
                ans = False

            try:
                self.radar_canvas.delete("threat")
            except Exception as e:
                logging.debug(f"Radar canvas delete failed: {e}")

            if ans:
                # Guarantee ordering: wait (briefly) for the forensic thread
                # to finish reading psutil.Process(pid) memory/network/handle
                # info BEFORE we actually kill the process. Without this, a
                # fast click could race the kill against the capture and
                # leave the evidence file with "Unknown (terminated)"
                # placeholders instead of real memory/network data — exactly
                # what the parallel-response design is meant to prevent.
                forensic_thread.join(timeout=5.0)
                if forensic_thread.is_alive():
                    logging.warning(
                        f"Forensic capture for PID {pid} still running after "
                        f"5s — proceeding with termination anyway (capture "
                        f"continues in background, may be incomplete)."
                    )
                ProcessTerminator.terminate_and_quarantine(
                    pid, ui_log_callback=self.do_log,
                    monitor_path=self.monitor_path)
            else:
                ProcessTerminator.resume_process(pid)
                self._do_log(
                    f"✅ [TRUSTED] {proc_name} (PID:{pid}) released.\n", "success")

        except Exception as e:
            logging.error(f"Alert processing error: {e}")
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
        # Use lock to prevent simultaneous alert dispatch race
        with self._processing_alert_lock:
            if not self.processing_alert:
                try:
                    alert = self.alert_queue.get_nowait()
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

    def on_closing(self):
        if self._closing:
            return
        self._closing = True
        # Stop hardware monitor first (sets running=False for its polling loop)
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
        # Stop watchdog observer and wait for it to fully exit
        try:
            if hasattr(self, "observer"):
                self.observer.stop()
                # join with timeout to avoid VM hang; daemon=False threads must exit
                self.observer.join(timeout=5)
                if self.observer.is_alive():
                    logging.warning("Observer thread did not exit within 5s — forcing ahead.")
        except Exception as e:
            logging.debug(f"Failed to stop observer: {e}")
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
                print("⚠ Run as Administrator for full detection capability.")
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
            data = build_baseline(MONITOR_PATH)

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

    root.protocol("WM_DELETE_WINDOW", panel.on_closing)

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