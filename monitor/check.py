import os
import json
import atexit
import hashlib
from datetime import date

from hashing.hasher import hash_file
from hashing.scanner import scan_directory
from logs.logger import write_log
from config.config_loader import load_config
from ai.predictor import predict_intrusion

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BASE_FILE = os.path.join("baseline", "base.json")
HASH_FILE = os.path.join("baseline", "base.hash")

# Executable extensions used for AI feature extraction.
_EXEC_EXTENSIONS = frozenset([".exe", ".bat", ".ps1", ".sh"])

# AI label → log severity mapping.
_AI_SEVERITY_MAP = {
    "normal":              "LOW",
    "burst_activity":      "MEDIUM",
    "malware_like":        "HIGH",
    "destructive_activity":"HIGH",
    "ransomware_like":     "CRITICAL",
}

# ---------------------------------------------------------------------------
# Module-level state
# ---------------------------------------------------------------------------

# --- Baseline layer (PERSISTENT) -------------------------------------------
# Key   : file path
# Value : hash that was present when the violation was first detected.
#         Sentinel value "DELETED" is used when the file was missing.
# An entry is removed only when the file fully recovers (hash == baseline hash,
# or file reappears after deletion).
# This dict is NEVER cleared between scans — that is the whole point.
_baseline_alerts: dict[str, str] = {}

# --- Snapshot layer ----------------------------------------------------------
# The last known-good scan result.  None until the first scan completes.
# Intentionally a simple dict; no sentinel magic needed.
_last_snapshot: dict | None = None

# --- AI layer (state-based) -------------------------------------------------
# Stores the last (label, features-tuple) pair that was logged.
# A new AI log is only emitted when either changes.
_last_ai_alert: tuple | None = None

# --- Daily summary counters --------------------------------------------------
_daily_counts = {"modified": 0, "deleted": 0, "new": 0}
_summary_date = date.today()


# ---------------------------------------------------------------------------
# Daily summary (registered with atexit so it fires on clean exit)
# ---------------------------------------------------------------------------

def _daily_summary() -> None:
    write_log(
        f"Daily Summary [{_summary_date}]: "
        f"Modified={_daily_counts['modified']}, "
        f"Deleted={_daily_counts['deleted']}, "
        f"New={_daily_counts['new']}",
        severity="INFO",
    )


atexit.register(_daily_summary)


# ---------------------------------------------------------------------------
# Helpers: feature extraction for AI layer
# ---------------------------------------------------------------------------

def _count_executables(files: list[str]) -> int:
    """Count files whose extension marks them as an executable."""
    return sum(
        1 for f in files
        if os.path.splitext(f)[1].lower() in _EXEC_EXTENSIONS
    )


def _count_unique_extensions(files: list[str]) -> int:
    """Count distinct file extensions across a list of files."""
    return len(set(os.path.splitext(f)[1].lower() for f in files))


def _count_unique_dirs(files: list[str]) -> int:
    """Count distinct parent directories across a list of files."""
    return len(set(os.path.dirname(f) for f in files))


# ---------------------------------------------------------------------------
# Layer 0: verify the baseline file has not been tampered with
# ---------------------------------------------------------------------------

def reset_baseline_state() -> None:
    """
    Clear all persistent baseline alert state.

    Call this immediately after creating a new baseline so that stale
    violation entries from the previous baseline do not produce spurious
    RESOLVED logs against the new one.
    """
    _baseline_alerts.clear()


def verify_baseline_integrity(config: dict | None = None) -> bool:
    """
    Return True if base.json matches its stored SHA-256 hash.
    Logs a CRITICAL alert and returns False on any failure.

    Parameters
    ----------
    config:
        Pre-loaded configuration dict.  If omitted, config is loaded from
        disk.  Pass the already-loaded config from check_integrity() to
        avoid reading config.json twice per scan cycle.
    """
    if config is None:
        config = load_config()
    severity = config["severity_levels"]["BASELINE_TAMPERED"]

    if not os.path.exists(HASH_FILE):
        write_log("Baseline hash file not found.", severity)
        return False

    with open(HASH_FILE, "r", encoding="utf-8") as fh:
        stored_hash = fh.read().strip()

    sha256 = hashlib.sha256()
    with open(BASE_FILE, "rb") as fh:
        for chunk in iter(lambda: fh.read(4096), b""):
            sha256.update(chunk)

    if sha256.hexdigest() != stored_hash:
        write_log("Baseline tampering detected!", severity)
        return False

    return True


# ---------------------------------------------------------------------------
# Layer 1: baseline integrity check
# ---------------------------------------------------------------------------

def _check_baseline_layer(
    baseline_data: dict,
    current_data: dict,
    severity_config: dict,
) -> None:
    """
    Compare every file in the trusted baseline against the current scan.

    Rules
    -----
    * Only files that EXIST in the baseline are checked here.
      New files (in current_data but NOT in baseline) are ignored — that
      is the snapshot layer's job.
    * An alert is logged ONCE per violation and suppressed on subsequent
      scans until the state changes.
    * If a file fully recovers (hash matches baseline again, or a deleted
      file reappears with the correct hash), a RESOLVED notice is logged
      and the entry is removed from _baseline_alerts.
    * If a previously-alerted file is modified AGAIN (different hash than
      when first detected), the alert is updated and re-logged.
    """
    for filepath, baseline_entry in baseline_data.items():
        baseline_hash = baseline_entry["hash"]
        previous_alert_hash = _baseline_alerts.get(filepath)  # None if clean

        if filepath not in current_data:
            # ── File is MISSING ──────────────────────────────────────────
            if previous_alert_hash != "DELETED":
                # First time we notice this, or it was modified before and
                # is now gone — either way, log it and record the sentinel.
                write_log(
                    f"[BASELINE] File deleted: {filepath}",
                    severity_config["DELETED"],
                )
                _baseline_alerts[filepath] = "DELETED"
            # else: already logged as deleted, do nothing.

        else:
            current_hash = current_data[filepath]["hash"]

            if current_hash == baseline_hash:
                # ── File matches baseline ─────────────────────────────────
                if previous_alert_hash is not None:
                    # It was previously in violation → now recovered.
                    write_log(
                        f"[BASELINE] File RESOLVED: {filepath}",
                        severity_config.get("RESOLVED", "INFO"),
                    )
                    del _baseline_alerts[filepath]
                # else: file was clean and still is — nothing to do.

            else:
                # ── File hash does NOT match baseline ─────────────────────
                if previous_alert_hash is None:
                    # First detection of this modification.
                    write_log(
                        f"[BASELINE] File modified: {filepath}",
                        severity_config["MODIFIED"],
                    )
                    _baseline_alerts[filepath] = current_hash

                elif previous_alert_hash == "DELETED":
                    # File was deleted before and is now back — but with
                    # a different hash than the baseline (not a clean restore).
                    write_log(
                        f"[BASELINE] File reappeared (content mismatch): {filepath}",
                        severity_config["MODIFIED"],
                    )
                    _baseline_alerts[filepath] = current_hash

                elif previous_alert_hash != current_hash:
                    # File was already alerted as modified, and has now been
                    # modified AGAIN (different hash from last detection).
                    write_log(
                        f"[BASELINE] File modified again: {filepath}",
                        severity_config["MODIFIED"],
                    )
                    _baseline_alerts[filepath] = current_hash

                # else: hash matches the hash we already alerted on — suppress.


# ---------------------------------------------------------------------------
# Layer 2: snapshot diff (event detection)
# ---------------------------------------------------------------------------

def _check_snapshot_layer(
    prev_data: dict,
    current_data: dict,
    severity_config: dict,
) -> tuple[list[str], list[str], list[str]]:
    """
    Diff the previous scan against the current scan.

    Returns (modified_files, deleted_files, new_files).

    Each file can appear in exactly ONE of the three lists per scan, so
    there is no intra-scan duplication to guard against.  There is also no
    cross-scan memory needed: snapshot compares prev→current, so a file that
    was modified in scan N is only re-reported in scan N+1 if it changes
    again between those two scans.

    Separation of concerns:
    * This function does NOT touch _baseline_alerts.
    * New files (present in current_data but absent from prev_data) are
      detected and logged here.  The baseline layer ignores new files
      entirely — it only checks files it already knows about.
    """
    modified_files: list[str] = []
    deleted_files:  list[str] = []
    new_files:      list[str] = []

    # One pass over prev_data → find deletions and modifications.
    for filepath, prev_entry in prev_data.items():
        if filepath not in current_data:
            deleted_files.append(filepath)
        elif prev_entry["hash"] != current_data[filepath]["hash"]:
            modified_files.append(filepath)

    # One pass over current_data → find new files.
    for filepath in current_data:
        if filepath not in prev_data:
            new_files.append(filepath)

    # Log every event.  Because these are diffs, each file appears at most
    # once per list, so no deduplication guard is needed here.
    for f in new_files:
        write_log(f"[SNAPSHOT] New file: {f}", severity_config["NEW"])

    for f in deleted_files:
        write_log(f"[SNAPSHOT] File deleted: {f}", severity_config["DELETED"])

    for f in modified_files:
        write_log(f"[SNAPSHOT] File modified: {f}", severity_config["MODIFIED"])

    return modified_files, deleted_files, new_files


# ---------------------------------------------------------------------------
# Layer 3: AI anomaly detection
# ---------------------------------------------------------------------------

def _run_ai_layer(
    modified_files: list[str],
    deleted_files:  list[str],
    new_files:      list[str],
    config: dict,
) -> None:
    """
    Compute behavioral features, run the ML model, apply rule overrides,
    and log an AI alert if the classification has changed since the last scan.
    """
    global _last_ai_alert

    thresholds = config.get("ai_thresholds", {})
    burst_threshold       = thresholds.get("burst_new_count",    40)
    destructive_threshold = thresholds.get("destructive_deleted", 40)
    quiet_threshold       = thresholds.get("quiet_total",          2)

    modified_count = len(modified_files)
    deleted_count  = len(deleted_files)
    new_count      = len(new_files)

    all_active = modified_files + new_files

    features = [
        modified_count,
        deleted_count,
        new_count,
        _count_executables(new_files),
        _count_unique_extensions(new_files),
        _count_unique_dirs(all_active),
    ]

    label, confidence = predict_intrusion(features)

    # Rule-based overrides applied AFTER the model prediction.
    # These handle edge cases the model may miss due to training data limits.
    if new_count > burst_threshold and deleted_count == 0:
        label = "burst_activity"
    elif deleted_count > destructive_threshold:
        label = "destructive_activity"
    elif (modified_count + deleted_count + new_count) <= quiet_threshold:
        label = "normal"

    ai_severity = _AI_SEVERITY_MAP.get(label, "MEDIUM")

    ai_msg = (
        f"AI DETECTION | type={label} "
        f"| confidence={confidence:.2f} "
        f"| features={features}"
    )

    current_alert = (label, tuple(features))

    if _last_ai_alert != current_alert:
        print(f"[{ai_severity}] {ai_msg}")
        write_log(ai_msg, ai_severity)
        _last_ai_alert = current_alert


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def check_integrity(directory: str) -> None:
    """
    Run a full integrity check cycle:
      1. Verify baseline has not been tampered with.
      2. Hash all current files in the monitored directory.
      3. Layer 1 — baseline integrity check (persistent dedup).
      4. Layer 2 — snapshot diff (per-scan event detection).
      5. Layer 3 — AI anomaly classification (state-based dedup).
      6. Print a console summary.
    """
    global _last_snapshot, _daily_counts, _summary_date

    config = load_config()
    severity_config = config["severity_levels"]

    # ── Daily rollover ───────────────────────────────────────────────────────
    today = date.today()
    if today != _summary_date:
        _daily_summary()
        _daily_counts = {"modified": 0, "deleted": 0, "new": 0}
        _summary_date = today

    # ── Baseline tamper check ────────────────────────────────────────────────
    # Pass the already-loaded config to avoid reading config.json twice.
    if not verify_baseline_integrity(config):
        write_log("Integrity check aborted due to baseline tampering.", "INFO")
        return

    print("Checking File Integrity...")

    if not os.path.exists(BASE_FILE):
        print("Baseline file not found. Please create a baseline first.")
        return

    # ── Load trusted baseline ────────────────────────────────────────────────
    with open(BASE_FILE, "r", encoding="utf-8") as fh:
        baseline_data: dict = json.load(fh)
    baseline_data.pop("log_data", None)  # strip internal metadata key

    # ── Scan current state of disk ───────────────────────────────────────────
    # NOTE: hash_file() and os.path.getsize/getmtime are separate syscalls.
    # A file can be deleted between them (TOCTOU window). We catch that here
    # so one volatile file cannot abort the entire scan.
    current_data: dict = {}
    for filepath in scan_directory(directory):
        file_hash = hash_file(filepath)
        if not file_hash:
            continue
        try:
            current_data[filepath] = {
                "hash":          file_hash,
                "size":          os.path.getsize(filepath),
                "last_modified": os.path.getmtime(filepath),
            }
        except OSError:
            # File vanished between hash and stat — treat as if it was
            # never seen this cycle (it will appear deleted in the diff).
            pass

    # ── Layer 1: baseline integrity (persistent dedup) ───────────────────────
    _check_baseline_layer(baseline_data, current_data, severity_config)

    # ── Snapshot bootstrap ───────────────────────────────────────────────────
    # On the very first call there is no previous scan to diff against.
    # Record the current state and return; no snapshot or AI events yet.
    if _last_snapshot is None:
        _last_snapshot = current_data
        print("Initial snapshot captured. Monitoring starts on next cycle.\n")
        return

    # ── Layer 2: snapshot diff (event detection) ─────────────────────────────
    modified_files, deleted_files, new_files = _check_snapshot_layer(
        _last_snapshot, current_data, severity_config
    )

    # Advance snapshot BEFORE AI so that if AI raises an exception we still
    # have a valid baseline for the next scan.
    _last_snapshot = current_data

    # ── Update daily counters ────────────────────────────────────────────────
    _daily_counts["modified"] += len(modified_files)
    _daily_counts["deleted"]  += len(deleted_files)
    _daily_counts["new"]      += len(new_files)

    # ── Layer 3: AI anomaly detection ────────────────────────────────────────
    _run_ai_layer(modified_files, deleted_files, new_files, config)

    # ── Console summary ──────────────────────────────────────────────────────
    print(
        f"\nSummary: Modified={len(modified_files)}  "
        f"Deleted={len(deleted_files)}  "
        f"New={len(new_files)}"
    )
    print("Integrity check completed.\n")
