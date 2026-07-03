r"""
BENIGN Ransomware-Behavior Simulator
=====================================
FOR AUTHORIZED TESTING OF FYP_near_proposal.py ONLY. Run only inside an
isolated VM, only against a throwaway test folder you create yourself.

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

WHAT THIS SCRIPT DOES NOT DO:
  - No network access, no C2, no persistence, no registry/service changes.
  - No key exfiltration -- the XOR key is stored locally in a metadata
    file inside the target folder so you can always reverse it yourself.
  - Never touches anything outside the folder you explicitly pass in.
  - Will refuse to run against system directories (see SAFETY CHECK below).

USAGE:
  python benign_ransomware_simulator.py --target C:\path\to\test_folder --setup
  python benign_ransomware_simulator.py --target C:\path\to\test_folder --run
  python benign_ransomware_simulator.py --target C:\path\to\test_folder --restore
"""

import argparse
import json
import os
import random
import string
import sys
import time
from pathlib import Path

# ---- Tunables matched to FYP_near_proposal.py's DEFAULT_CONFIG ----
SUSPICIOUS_EXT = ".locked"          # in suspicious_exts list
RANSOM_NOTE_NAME = "READ_ME_TEST_NOTE.txt"
NUM_TEST_FILES = 80                 # > threshold_1h (50) in one run
EVENT_BURST_SIZE = 8                # > threshold_1s (5) per burst
XOR_KEY = 0x5A                      # trivial, symmetric, reversible

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
    forbidden_roots = [
        Path(os.environ.get("WINDIR", "C:\\Windows")),
        Path(os.environ.get("SYSTEMROOT", "C:\\Windows")),
        Path("C:\\Program Files"),
        Path("C:\\Program Files (x86)"),
        Path.home(),  # don't let it run directly on the whole home dir
    ]
    for root in forbidden_roots:
        try:
            if resolved == root.resolve() or root.resolve() in resolved.parents:
                print(f"[SAFETY] Refusing to run against {resolved} "
                      f"(too close to a system/home directory).")
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
    print("[SETUP] Done. Baseline files created (plain text, low entropy).")


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

    print(f"[RUN] Simulating encryption of {len(files)} files "
          f"in bursts of {EVENT_BURST_SIZE} (rapid, to trip rate thresholds)...")

    renamed_map = {}
    i = 0
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

    # Drop a fake ransom note (plain text, clearly labeled as fake)
    note = target / RANSOM_NOTE_NAME
    note.write_text(
        "THIS IS A FAKE/TEST RANSOM NOTE.\n"
        "Generated by benign_ransomware_simulator.py for detector testing.\n"
        "No files were actually harmed -- run --restore to reverse.\n"
    )

    # Save metadata so --restore can reverse everything
    meta_path = target / METADATA_FILE
    meta_path.write_text(json.dumps({
        "xor_key": XOR_KEY,
        "renamed_map": renamed_map,
        "note_file": str(note),
    }, indent=2))

    print(f"[RUN] Done. {len(renamed_map)} files renamed to *{SUSPICIOUS_EXT} "
          f"and XOR-scrambled. Ransom note dropped.")
    print("[RUN] Your detector should now see: rapid file events, "
          "suspicious extension, entropy spike/hash mismatch.")


def cmd_restore(target: Path):
    meta_path = target / METADATA_FILE
    if not meta_path.exists():
        print("[RESTORE] No metadata file found -- nothing to restore, "
              "or --run was never called.")
        return

    meta = json.loads(meta_path.read_text())
    key = meta["xor_key"]
    renamed_map = meta["renamed_map"]

    print(f"[RESTORE] Reversing {len(renamed_map)} files...")
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

    note = Path(meta["note_file"])
    if note.exists():
        note.unlink()
    meta_path.unlink()
    print("[RESTORE] Done. Folder restored to pre-run state.")


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
