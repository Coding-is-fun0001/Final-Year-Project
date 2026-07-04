r"""
BENIGN Ransomware-Behavior Simulator - EXTENDED PAUSE VERSION
==============================================================
FOR AUTHORIZED TESTING OF FYP_near_proposal.py ONLY. Run only inside an
isolated VM, only against a throwaway test folder you create yourself.

This version has EXTENDED PAUSE TIME (5 minutes) to give your system
plenty of time to detect and respond to the attack, even with small file sets.

WHAT THIS SCRIPT DOES (and nothing else):
  1. Creates a folder of small dummy test files (txt/docx/jpg-like/db).
  2. "Encrypts" them in place with a trivial reversible XOR cipher
     (NOT real cryptography -- purely to spike file entropy and hash change,
     which is what your detector actually watches for).
  3. Renames each encrypted file with a suspicious extension
     (e.g. .locked) that matches FYP_near_proposal.py's suspicious_exts list.
  4. Touches many files quickly, to exceed the 1s/1h event-count thresholds.
  5. Drops a fake ransom note text file.
  6. Has a --restore mode to reverse everything (XOR is symmetric) and
     bring the test folder back to its original state.

CONFIGURATION:
  See lines 50-70 to adjust:
  - NUM_TEST_FILES: How many files to encrypt (default: 50, can be any number)
  - PAUSE_TIME: How long process stays alive after encryption (default: 300s/5min)
  - EVENT_BURST_SIZE: Files encrypted per rapid burst (default: 5)

USAGE:
  python Ransomware_ExtendedPause.py --target C:\path\to\test_folder --setup
  python Ransomware_ExtendedPause.py --target C:\path\to\test_folder --run
  python Ransomware_ExtendedPause.py --target C:\path\to\test_folder --restore
"""

import argparse
import json
import os
import random
import string
import sys
import time
from pathlib import Path

# ================================================================================
# ⚙️  CONFIGURATION - EASILY ADJUSTABLE FOR YOUR TEST
# ================================================================================

SUSPICIOUS_EXT = ".locked"          # in suspicious_exts list
RANSOM_NOTE_NAME = "READ_ME_TEST_NOTE.txt"

# === KEY PARAMETERS - ADJUST THESE FOR YOUR TEST ===

NUM_TEST_FILES = 50                 # Number of files to create and encrypt
                                    # - Smaller tests: 10-30 files
                                    # - Medium tests: 50-100 files
                                    # - Large tests: 100-500 files
                                    # Default (50) still exceeds threshold_1h (50)

EVENT_BURST_SIZE = 5                # Files encrypted per rapid burst
                                    # Must be > threshold_1s (5)
                                    # Ratio: NUM_TEST_FILES / EVENT_BURST_SIZE

PAUSE_TIME = 300                    # Seconds process stays alive after encryption
                                    # 300 = 5 minutes (EXTENDED for slow systems)
                                    # - Quick test: 120 seconds (2 minutes)
                                    # - Normal test: 180 seconds (3 minutes)  
                                    # - Extended: 300 seconds (5 minutes) ← DEFAULT
                                    # - Very slow: 600 seconds (10 minutes)

XOR_KEY = 0x5A                      # trivial, symmetric, reversible

# ================================================================================
# EXAMPLE CONFIGURATIONS - Copy and modify NUM_TEST_FILES + PAUSE_TIME:
# ================================================================================
#
# Small test (10 files, fast system):
#   NUM_TEST_FILES = 10
#   EVENT_BURST_SIZE = 5
#   PAUSE_TIME = 120          # 2 minutes
#
# Medium test (50 files, normal system):
#   NUM_TEST_FILES = 50
#   EVENT_BURST_SIZE = 5
#   PAUSE_TIME = 180          # 3 minutes
#
# Large test (100 files, slow system):
#   NUM_TEST_FILES = 100
#   EVENT_BURST_SIZE = 10
#   PAUSE_TIME = 300          # 5 minutes  ← Current setting
#
# Very slow system (50 files, need extra time):
#   NUM_TEST_FILES = 50
#   EVENT_BURST_SIZE = 5
#   PAUSE_TIME = 600          # 10 minutes
#
# ================================================================================

METADATA_FILE = ".simulator_metadata.json"

# Extensions the detector treats as "naturally high entropy" (won't trigger
# entropy alerts on their own) -- we deliberately AVOID these for our dummy
# files so the entropy signal actually fires as intended.
AVOID_EXTS = {".zip", ".gz", ".7z", ".mp3", ".mp4", ".jpg", ".jpeg",
              ".png", ".sqlite", ".db3"}

SAFE_TEST_EXTS = [".txt", ".docx", ".log", ".csv", ".ini"]


def safety_check(target: Path):
    """Refuse to run against anything that isn't an obvious throwaway folder."""
    resolved = target.resolve()

    # System/program directories: block the exact path AND anything nested
    # under them -- you never want a test file anywhere inside these.
    forbidden_system_roots = [
        Path(os.environ.get("WINDIR", "C:\\Windows")),
        Path(os.environ.get("SYSTEMROOT", "C:\\Windows")),
        Path("C:\\Program Files"),
        Path("C:\\Program Files (x86)"),
    ]
    for root in forbidden_system_roots:
        try:
            root_resolved = root.resolve()
            if resolved == root_resolved or root_resolved in resolved.parents:
                print(f"[SAFETY] Refusing to run against {resolved} "
                      f"(too close to a system directory).")
                sys.exit(1)
        except Exception:
            pass

    # Home directory: only block running DIRECTLY on the home folder itself.
    try:
        home_resolved = Path.home().resolve()
        if resolved == home_resolved:
            print(f"[SAFETY] Refusing to run directly against your home "
                  f"directory ({resolved}). Point --target at a dedicated "
                  f"subfolder instead, e.g. '{resolved}\\ransom_test'.")
            sys.exit(1)
    except Exception:
        pass

    if "test" not in resolved.name.lower() and "sandbox" not in resolved.name.lower():
        print(f"[SAFETY] Target folder name '{resolved.name}' doesn't contain "
              f"'test' or 'sandbox'. Rename it or pass a clearly-marked test "
              f"folder, e.g. 'C:\\ransom_test'.")
        sys.exit(1)


def xor_bytes(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)


def random_text_content(size: int) -> bytes:
    return "".join(random.choices(string.ascii_letters + string.digits + " \n",
                                   k=size)).encode("utf-8")


def cmd_setup(target: Path):
    target.mkdir(parents=True, exist_ok=True)
    print(f"[SETUP] Creating {NUM_TEST_FILES} dummy files in {target}")
    for i in range(NUM_TEST_FILES):
        ext = random.choice(SAFE_TEST_EXTS)
        fpath = target / f"testfile_{i:03d}{ext}"
        fpath.write_bytes(random_text_content(random.randint(200, 2000)))
    print(f"[SETUP] ✓ Done. {NUM_TEST_FILES} baseline files created (plain text, low entropy).\n")


def cmd_run(target: Path):
    if not target.exists():
        print(f"[RUN] Target {target} doesn't exist. Run --setup first.")
        sys.exit(1)

    files = [f for f in target.iterdir()
             if f.is_file() and f.suffix.lower() not in AVOID_EXTS
             and f.name not in (METADATA_FILE, RANSOM_NOTE_NAME)]

    if not files:
        print("[RUN] No eligible test files found. Run --setup first.")
        sys.exit(1)

    print(f"[RUN] Simulating encryption of {len(files)} files")
    print(f"[RUN] Burst size: {EVENT_BURST_SIZE} files per burst")
    print(f"[RUN] Starting encryption...\n")

    renamed_map = {}
    i = 0
    start_time = time.time()
    
    while i < len(files):
        burst = files[i:i + EVENT_BURST_SIZE]
        for f in burst:
            try:
                data = f.read_bytes()
                encrypted = xor_bytes(data, XOR_KEY)
                new_path = f.with_name(f.name + SUSPICIOUS_EXT)
                new_path.write_bytes(encrypted)
                f.unlink()
                renamed_map[str(new_path)] = str(f)
            except Exception as e:
                print(f"  [WARN] skipped {f}: {e}")
        i += EVENT_BURST_SIZE
        time.sleep(0.05)  # small gap so events still land inside 1s windows
    
    elapsed = time.time() - start_time
    print(f"[RUN] Encryption complete in {elapsed:.2f} seconds")

    # Drop a fake ransom note (plain text, clearly labeled as fake)
    note = target / RANSOM_NOTE_NAME
    note.write_text(
        "THIS IS A FAKE/TEST RANSOM NOTE.\n"
        "Generated by Ransomware_ExtendedPause.py (benign simulator) for detector testing.\n"
        "No files were actually harmed -- run --restore to reverse.\n"
    )

    # Save metadata so --restore can reverse everything
    meta_path = target / METADATA_FILE
    meta_path.write_text(json.dumps({
        "xor_key": XOR_KEY,
        "renamed_map": renamed_map,
        "note_file": str(note),
    }, indent=2))

    print(f"[RUN] ✓ {len(renamed_map)} files renamed to *{SUSPICIOUS_EXT}")
    print(f"[RUN] ✓ XOR-scrambled with key: 0x{XOR_KEY:02X}")
    print(f"[RUN] ✓ Ransom note dropped: {RANSOM_NOTE_NAME}")
    print(f"[RUN] ✓ Metadata saved: {METADATA_FILE}")
    print("\n" + "="*70)
    print("🚨 SIMULATION ACTIVE - EXTENDED PAUSE (5 MINUTES)")
    print("="*70)
    print(f"\n⏸️  This process will stay alive for {PAUSE_TIME} seconds ({PAUSE_TIME//60} minutes)")
    print("   to give your system PLENTY of time to detect and respond.")
    print("\n✓ Your detector should now see:")
    print("  - Rapid file modification events")
    print("  - Suspicious .locked extension change")
    print("  - Entropy spike (binary garbage)")
    print("  - Hash/timestamp mismatch")
    print("  - Honeypot triggered (if honeypot files exist)")
    print("  - Process suspension/kill dialog")
    print("\nWhat to do:")
    print(f"  • WAIT: Process auto-exits after {PAUSE_TIME} seconds")
    print("  • CTRL+C: Manually stop the process anytime")
    print("  • CLICK: Respond to YES/NO dialog in detector")
    print(f"\n⏱️  Timer: {PAUSE_TIME//60}:{(PAUSE_TIME%60):02d} minutes\n")
    
    # Keep the process alive so detector can suspend/kill it
    # Extended pause time for slow systems
    try:
        time.sleep(PAUSE_TIME)
    except KeyboardInterrupt:
        print("\n[RUN] Process terminated by user (Ctrl+C)")
        pass


def cmd_restore(target: Path):
    meta_path = target / METADATA_FILE
    if not meta_path.exists():
        print("[RESTORE] No metadata file found -- nothing to restore, "
              "or --run was never called.")
        return

    meta = json.loads(meta_path.read_text())
    key = meta["xor_key"]
    renamed_map = meta["renamed_map"]

    print(f"[RESTORE] Starting restoration of {len(renamed_map)} files...\n")
    
    restored_count = 0
    for enc_path_str, orig_path_str in renamed_map.items():
        enc_path = Path(enc_path_str)
        orig_path = Path(orig_path_str)
        if not enc_path.exists():
            print(f"  [WARN] missing {enc_path}, skipping")
            continue
        data = enc_path.read_bytes()
        plain = xor_bytes(data, key)
        orig_path.write_bytes(plain)
        enc_path.unlink()
        restored_count += 1

    note = Path(meta["note_file"])
    if note.exists():
        note.unlink()
    meta_path.unlink()
    
    print(f"\n[RESTORE] ✓ {restored_count} files restored to original names")
    print(f"[RESTORE] ✓ Ransom note deleted")
    print(f"[RESTORE] ✓ Metadata file deleted")
    print("[RESTORE] ✓ Folder restored to pre-attack state\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                      formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", required=True,
                         help="Path to a dedicated test folder (name must contain "
                              "'test' or 'sandbox'). Never point this at real data.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--setup", action="store_true", help="Create baseline dummy files")
    group.add_argument("--run", action="store_true", help="Simulate ransomware behavior")
    group.add_argument("--restore", action="store_true", help="Reverse the simulation")
    args = parser.parse_args()

    target = Path(args.target)
    safety_check(target)

    if args.setup:
        cmd_setup(target)
    elif args.run:
        cmd_run(target)
    elif args.restore:
        cmd_restore(target)


if __name__ == "__main__":
    main()
