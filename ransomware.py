r"""
RANSOMWARE SIMULATOR - Complete Testing Tool
==============================================
Single file with setup, run, and restore functionality.
Designed for testing FYP_near_proposal.py detection system.

FOR AUTHORIZED TESTING ONLY - Use in isolated VM only!

Usage:
  python ransomware.py --target C:\ransom_test --setup
  python ransomware.py --target C:\ransom_test --run
  python ransomware.py --target C:\ransom_test --restore
"""

import argparse
import json
import os
import random
import string
import sys
import time
from pathlib import Path

# ====== CONFIGURATION ======
NUM_TEST_FILES = 50              # Number of files to create/encrypt
SUSPICIOUS_EXT = ".locked"       # Extension for encrypted files
RANSOM_NOTE_NAME = "READ_ME_TEST_NOTE.txt"
PAUSE_TIME = 300                 # 300 seconds (5 minutes) - gives detector time
XOR_KEY = 0x5A                   # Simple encryption key
METADATA_FILE = ".simulator_metadata.json"

AVOID_EXTS = {".zip", ".gz", ".7z", ".mp3", ".mp4", ".jpg", ".jpeg", ".png", ".sqlite", ".db3"}
SAFE_TEST_EXTS = [".txt", ".docx", ".log", ".csv", ".ini"]


def safety_check(target: Path):
    """Verify target folder is safe for testing."""
    resolved = target.resolve()

    # Block system directories
    forbidden = [
        Path(os.environ.get("WINDIR", "C:\\Windows")),
        Path(os.environ.get("SYSTEMROOT", "C:\\Windows")),
        Path("C:\\Program Files"),
        Path("C:\\Program Files (x86)"),
    ]
    
    for root in forbidden:
        try:
            root_resolved = root.resolve()
            if resolved == root_resolved or root_resolved in resolved.parents:
                print(f"[ERROR] Cannot run against {resolved} - too close to system directory")
                sys.exit(1)
        except Exception:
            pass

    # Block home directory itself (but allow subfolders)
    try:
        home_resolved = Path.home().resolve()
        if resolved == home_resolved:
            print(f"[ERROR] Cannot run against home directory - use a subfolder instead")
            sys.exit(1)
    except Exception:
        pass

    # Require 'test' or 'sandbox' in folder name
    if "test" not in resolved.name.lower() and "sandbox" not in resolved.name.lower():
        print(f"[ERROR] Folder name must contain 'test' or 'sandbox' - got '{resolved.name}'")
        sys.exit(1)


def xor_bytes(data: bytes, key: int) -> bytes:
    """Encrypt/decrypt data using XOR."""
    return bytes(b ^ key for b in data)


def random_text_content(size: int) -> bytes:
    """Generate random text content."""
    return "".join(random.choices(string.ascii_letters + string.digits + " \n", k=size)).encode("utf-8")


def cmd_setup(target: Path):
    """Create baseline test files."""
    try:
        target.mkdir(parents=True, exist_ok=True)
        print(f"\n[SETUP] Creating {NUM_TEST_FILES} test files...")
        
        for i in range(NUM_TEST_FILES):
            ext = random.choice(SAFE_TEST_EXTS)
            fpath = target / f"testfile_{i:03d}{ext}"
            fpath.write_bytes(random_text_content(random.randint(200, 2000)))
        
        print(f"[SETUP] ✓ Complete - {NUM_TEST_FILES} files created\n")
        
    except Exception as e:
        print(f"[ERROR] Setup failed: {e}")
        sys.exit(1)


def cmd_run(target: Path):
    """Encrypt files with slow execution to allow detection."""
    try:
        if not target.exists():
            print(f"[ERROR] Target folder doesn't exist. Run --setup first.")
            sys.exit(1)

        # Find eligible files
        files = [f for f in target.iterdir()
                 if f.is_file() and f.suffix.lower() not in AVOID_EXTS
                 and f.name not in (METADATA_FILE, RANSOM_NOTE_NAME)]

        if not files:
            print("[ERROR] No files found. Run --setup first.")
            sys.exit(1)

        print(f"\n[RUN] Starting encryption of {len(files)} files...")
        print(f"[RUN] Execution will be SLOW to allow detection\n")

        renamed_map = {}
        start_time = time.time()
        
        # Encrypt files with SLOW execution (0.2s delay between batches)
        for idx, f in enumerate(files, 1):
            try:
                data = f.read_bytes()
                encrypted = xor_bytes(data, XOR_KEY)
                new_path = f.with_name(f.name + SUSPICIOUS_EXT)
                new_path.write_bytes(encrypted)
                f.unlink()
                renamed_map[str(new_path)] = str(f)
                
                # Show progress every 10 files
                if idx % 10 == 0 or idx == len(files):
                    elapsed = time.time() - start_time
                    print(f"[RUN] Encrypted {idx}/{len(files)} files ({elapsed:.1f}s)")
                
                # SLOW execution - delay between files
                time.sleep(0.2)
                
            except Exception as e:
                print(f"[WARN] Failed to encrypt {f}: {e}")

        elapsed = time.time() - start_time
        print(f"[RUN] Encryption complete in {elapsed:.1f} seconds\n")

        # Create ransom note
        note = target / RANSOM_NOTE_NAME
        note.write_text(
            "THIS IS A FAKE/TEST RANSOM NOTE.\n"
            "Generated for detector testing.\n"
            "Run --restore to reverse.\n"
        )

        # Save metadata for restoration
        meta_path = target / METADATA_FILE
        meta_path.write_text(json.dumps({
            "xor_key": XOR_KEY,
            "renamed_map": renamed_map,
            "note_file": str(note),
        }, indent=2))

        print(f"[RUN] ✓ {len(renamed_map)} files encrypted and renamed to *.locked")
        print(f"[RUN] ✓ Metadata saved for restoration\n")
        print("="*70)
        print(f"⏸️  PROCESS PAUSING FOR {PAUSE_TIME} SECONDS ({PAUSE_TIME//60}m {PAUSE_TIME%60}s)")
        print("="*70)
        print(f"\nDetector has plenty of time to detect and respond.")
        print(f"Options:")
        print(f"  • Wait {PAUSE_TIME} seconds (auto-exit)")
        print(f"  • Press Ctrl+C to stop manually")
        print(f"  • Detector can suspend/kill this process\n")
        
        # Keep process alive for detector to interact
        try:
            time.sleep(PAUSE_TIME)
        except KeyboardInterrupt:
            print("\n[RUN] Stopped by user (Ctrl+C)")
            
    except Exception as e:
        print(f"[ERROR] Run failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


def cmd_restore(target: Path):
    """Restore encrypted files to original state."""
    try:
        meta_path = target / METADATA_FILE
        
        if not meta_path.exists():
            print(f"\n[ERROR] No metadata file found - nothing to restore")
            print(f"[ERROR] Expected: {meta_path}")
            sys.exit(1)

        print(f"\n[RESTORE] Loading metadata...")
        
        # Read and parse metadata
        try:
            with open(meta_path, 'r') as f:
                meta = json.load(f)
        except json.JSONDecodeError as e:
            print(f"[ERROR] Metadata file is corrupted: {e}")
            sys.exit(1)
        except Exception as e:
            print(f"[ERROR] Cannot read metadata: {e}")
            sys.exit(1)
        
        key = meta.get("xor_key", 0x5A)
        renamed_map = meta.get("renamed_map", {})

        if not renamed_map:
            print(f"[ERROR] No files in metadata")
            sys.exit(1)

        print(f"[RESTORE] Restoring {len(renamed_map)} files...\n")
        
        # Restore each file
        restored_count = 0
        failed_count = 0
        
        for enc_path_str, orig_path_str in renamed_map.items():
            try:
                enc_path = Path(enc_path_str)
                orig_path = Path(orig_path_str)
                
                if not enc_path.exists():
                    print(f"[WARN] File not found: {enc_path.name}")
                    failed_count += 1
                    continue
                
                # Decrypt and restore
                data = enc_path.read_bytes()
                plain = xor_bytes(data, key)
                orig_path.write_bytes(plain)
                enc_path.unlink()
                restored_count += 1
                
                # Show progress
                if restored_count % 10 == 0:
                    print(f"[RESTORE] Restored {restored_count}/{len(renamed_map)} files")
                
            except Exception as e:
                print(f"[WARN] Failed to restore {enc_path_str}: {e}")
                failed_count += 1
                continue

        # Clean up temporary files
        try:
            note_path = Path(meta.get("note_file", str(target / RANSOM_NOTE_NAME)))
            if note_path.exists():
                note_path.unlink()
        except Exception as e:
            print(f"[WARN] Could not delete ransom note: {e}")
        
        try:
            meta_path.unlink()
        except Exception as e:
            print(f"[WARN] Could not delete metadata: {e}")
        
        print(f"\n[RESTORE] ✓ {restored_count} files successfully restored")
        if failed_count > 0:
            print(f"[RESTORE] ⚠ {failed_count} files failed")
        print(f"[RESTORE] ✓ Temporary files cleaned up")
        print(f"[RESTORE] ✓ Folder restored to original state\n")
        
    except SystemExit:
        raise
    except Exception as e:
        print(f"[ERROR] Restore failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Ransomware Simulator - Test tool for FYP_near_proposal.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ransomware.py --target C:\\ransom_test --setup
  python ransomware.py --target C:\\ransom_test --run
  python ransomware.py --target C:\\ransom_test --restore
        """
    )
    
    parser.add_argument("--target", required=True,
                        help="Target test folder (must contain 'test' or 'sandbox' in name)")
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--setup", action="store_true", help="Create baseline test files")
    group.add_argument("--run", action="store_true", help="Simulate ransomware attack")
    group.add_argument("--restore", action="store_true", help="Restore encrypted files")
    
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
