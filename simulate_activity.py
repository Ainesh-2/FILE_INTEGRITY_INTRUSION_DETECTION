"""
simulate_activity.py
────────────────────
Simulates structured file-system behavior for testing the IDS AI layer.

Each scenario is aligned with the feature vector the model uses:
  [modified_count, deleted_count, new_count, exe_created,
   extension_changes, unique_dirs]

Workspace: ./simulation_workspace/  (created if absent, never touches system files)
"""

import os
import shutil
import time
import random
import string

# ---------------------------------------------------------------------------
# Workspace
# ---------------------------------------------------------------------------

WORKSPACE = "simulation_workspace"


def _setup_workspace() -> None:
    os.makedirs(WORKSPACE, exist_ok=True)


def _random_content(length: int = 64) -> str:
    return "".join(random.choices(string.ascii_letters + string.digits, k=length))


def _create_text_files(prefix: str, count: int) -> list[str]:
    """Create *count* plain .txt files and return their paths."""
    paths = []
    for i in range(count):
        path = os.path.join(WORKSPACE, f"{prefix}_{i}.txt")
        with open(path, "w") as fh:
            fh.write(f"File {prefix}_{i}\n{_random_content()}\n")
        paths.append(path)
    return paths


# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------

def simulate_normal_activity() -> None:
    """
    Normal: create 1-2 files, optionally modify one.
    Features: new≤2, modified≤1, deleted=0, exe=0
    Expected → normal
    """
    print("[normal] Creating a small number of routine files...")

    path = os.path.join(WORKSPACE, "report.txt")
    with open(path, "w") as fh:
        fh.write("Routine report\n" + _random_content() + "\n")
    print(f"  Created: {path}")
    time.sleep(0.3)

    cfg = os.path.join(WORKSPACE, "settings.txt")
    with open(cfg, "w") as fh:
        fh.write("log_level=INFO\nmax_size=100\n")
    print(f"  Created: {cfg}")

    print("[normal] Done. Expected → normal\n")


def simulate_burst_activity() -> None:
    """
    Burst: create 60 files quickly, no deletions.
    Features: new=60, modified=0, deleted=0, exe=0
    Expected → burst_activity
    """
    print("[burst] Creating a large number of files rapidly...")

    for i in range(60):
        path = os.path.join(WORKSPACE, f"burst_{i}_{_random_content(4)}.log")
        with open(path, "w") as fh:
            fh.write(f"Log entry {i}\n{_random_content()}\n")
        time.sleep(0.01)

    print("  Created 60 files.")
    print("[burst] Done. Expected → burst_activity\n")


def simulate_destructive_activity() -> None:
    """
    Destructive: seed 50 files, wait for IDS to see them, then wipe them all.
    Features: deleted=50, new=0, modified=0, exe=0
    Expected → destructive_activity
    """
    print("[destructive] Seeding 50 files before deletion...")

    seeded = _create_text_files("target", 50)
    print(f"  Seeded {len(seeded)} files.")
    print("  Waiting 3 s so the IDS captures the seeded state...")
    time.sleep(3)

    print("  Deleting all seeded files...")
    for path in seeded:
        try:
            os.remove(path)
        except FileNotFoundError:
            pass
        time.sleep(0.02)

    print(f"  Deleted {len(seeded)} files.")
    print("[destructive] Done. Expected → destructive_activity\n")


def simulate_malware_activity() -> None:
    """
    Malware: drop .exe, .bat, .ps1 files + a hidden config.
    Features: new≥10, exe≥8, ext_changes=3, deleted=0
    Expected → malware_like
    """
    print("[malware] Dropping executable and payload files...")

    executables = [".exe", ".bat", ".ps1", ".sh"]
    for i, ext in enumerate(executables * 3):       # 12 executable files
        name = f"svc_{_random_content(4)}{ext}"
        path = os.path.join(WORKSPACE, name)
        with open(path, "w") as fh:
            fh.write(f":: Fake binary\n{_random_content(128)}\n")
        print(f"  Dropped: {name}")
        time.sleep(0.05)

    # Hidden C2 config
    hidden = os.path.join(WORKSPACE, ".c2_config")
    with open(hidden, "w") as fh:
        fh.write(f"server=192.168.0.1\nkey={_random_content(32)}\n")
    print(f"  Dropped: .c2_config")

    print("[malware] Done. Expected → malware_like\n")


def simulate_ransomware_activity() -> None:
    """
    Ransomware: seed files, overwrite their content, then rename to .locked.
    Features: modified≥40, ext_changes≥2, deleted=0, exe=0
    Expected → ransomware_like
    """
    print("[ransomware] Seeding 40 victim files...")

    seeded = _create_text_files("doc", 40)
    print(f"  Seeded {len(seeded)} files.")
    print("  Waiting 3 s so the IDS captures original state...")
    time.sleep(3)

    print("  Overwriting file contents (simulating encryption)...")
    for path in seeded:
        with open(path, "w") as fh:
            fh.write(f"ENCRYPTED:{_random_content(128)}\n")
        time.sleep(0.02)

    print("  Renaming all files to .locked extension...")
    for path in seeded:
        try:
            os.rename(path, path + ".locked")
        except OSError:
            pass
        time.sleep(0.01)

    print(f"  Processed {len(seeded)} files.")
    print("[ransomware] Done. Expected → ransomware_like\n")


# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

def cleanup() -> None:
    """Remove all simulation files and recreate a clean workspace."""
    if os.path.exists(WORKSPACE):
        shutil.rmtree(WORKSPACE)
        print(f"  Removed: {WORKSPACE}/")
    _setup_workspace()
    print(f"  Recreated: {WORKSPACE}/")
    print("Workspace is clean.\n")


# ---------------------------------------------------------------------------
# Menu
# ---------------------------------------------------------------------------

_MENU = """
╔══════════════════════════════════════════╗
║         IDS Activity Simulator           ║
╠══════════════════════════════════════════╣
║  1. Normal        (create a few files)   ║
║  2. Burst         (create many rapidly)  ║
║  3. Destructive   (seed then delete all) ║
║  4. Malware       (drop executables)     ║
║  5. Ransomware    (overwrite + rename)   ║
║  6. Cleanup       (wipe workspace)       ║
║  0. Exit                                 ║
╚══════════════════════════════════════════╝
"""

_HANDLERS = {
    "1": simulate_normal_activity,
    "2": simulate_burst_activity,
    "3": simulate_destructive_activity,
    "4": simulate_malware_activity,
    "5": simulate_ransomware_activity,
    "6": cleanup,
}

if __name__ == "__main__":
    _setup_workspace()

    while True:
        print(_MENU)
        choice = input("Enter choice: ").strip()

        if choice == "0":
            print("Exiting simulator.")
            break

        handler = _HANDLERS.get(choice)
        if handler:
            handler()
        else:
            print("Invalid choice. Enter 0-6.\n")
