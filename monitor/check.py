import os
import json
import atexit
import hashlib
from datetime import date, datetime

from hashing.hasher import hash_file
from hashing.scanner import scan_directory
from logs.logger import write_log
from config.config_loader import load_config
from ai.predictor import predict_intrusion

BASE_FILE = os.path.join("baseline", "base.json")
HASH_FILE = os.path.join("baseline", "base.hash")

_EXEC_EXTENSIONS = frozenset([".exe", ".bat", ".ps1", ".sh"])

_AI_SEVERITY_MAP = {
    "normal":              "LOW",
    "burst_activity":      "MEDIUM",
    "malware_like":        "HIGH",
    "destructive_activity": "HIGH",
    "ransomware_like":     "CRITICAL",
}

_baseline_alerts: dict[str, str] = {}
_last_snapshot: dict | None = None
_last_ai_alert: tuple | None = None
_daily_counts = {"modified": 0, "deleted": 0, "new": 0}
_summary_date = date.today()

DASHBOARD_STATE: dict = {
    "ai_label":        "normal",
    "ai_confidence":   0.0,
    "modified":        0,
    "deleted":         0,
    "new":             0,
    "last_event":      None,
    "last_event_type": None,
    "baseline_issues": {},
    "scan_time":       "--:--:--",
}


def _daily_summary() -> None:
    write_log(
        f"Daily Summary [{_summary_date}]: "
        f"Modified={_daily_counts['modified']}, "
        f"Deleted={_daily_counts['deleted']}, "
        f"New={_daily_counts['new']}",
        severity="INFO",
    )


atexit.register(_daily_summary)


def _count_executables(files: list[str]) -> int:
    return sum(
        1 for f in files
        if os.path.splitext(f)[1].lower() in _EXEC_EXTENSIONS
    )


def _count_unique_extensions(files: list[str]) -> int:
    return len(set(os.path.splitext(f)[1].lower() for f in files))


def _count_unique_dirs(files: list[str]) -> int:
    return len(set(os.path.dirname(f) for f in files))


def reset_baseline_state() -> None:
    _baseline_alerts.clear()


def verify_baseline_integrity(config: dict | None = None) -> bool:
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


def _check_baseline_layer(baseline_data: dict, current_data: dict, severity_config: dict,) -> None:
    for filepath, baseline_entry in baseline_data.items():
        baseline_hash = baseline_entry["hash"]
        previous_alert_hash = _baseline_alerts.get(filepath)  # None if clean

        if filepath not in current_data:
            if previous_alert_hash != "DELETED":
                write_log(
                    f"[BASELINE] File deleted: {filepath}",
                    severity_config["DELETED"],
                )
                _baseline_alerts[filepath] = "DELETED"
        else:
            current_hash = current_data[filepath]["hash"]
            if current_hash == baseline_hash:
                if previous_alert_hash is not None:
                    write_log(
                        f"[BASELINE] File RESOLVED: {filepath}",
                        severity_config.get("RESOLVED", "INFO"),
                    )
                    del _baseline_alerts[filepath]
            else:
                if previous_alert_hash is None:
                    write_log(
                        f"[BASELINE] File modified: {filepath}",
                        severity_config["MODIFIED"],
                    )
                    _baseline_alerts[filepath] = current_hash
                elif previous_alert_hash == "DELETED":
                    write_log(
                        f"[BASELINE] File reappeared (content mismatch): {filepath}",
                        severity_config["MODIFIED"],
                    )
                    _baseline_alerts[filepath] = current_hash

                elif previous_alert_hash != current_hash:
                    write_log(
                        f"[BASELINE] File modified again: {filepath}",
                        severity_config["MODIFIED"],
                    )
                    _baseline_alerts[filepath] = current_hash


def _check_snapshot_layer(prev_data: dict, current_data: dict, severity_config: dict,) -> tuple[list[str], list[str], list[str]]:
    modified_files: list[str] = []
    deleted_files:  list[str] = []
    new_files:      list[str] = []

    for filepath, prev_entry in prev_data.items():
        if filepath not in current_data:
            deleted_files.append(filepath)
        elif prev_entry["hash"] != current_data[filepath]["hash"]:
            modified_files.append(filepath)

    for filepath in current_data:
        if filepath not in prev_data:
            new_files.append(filepath)

    for f in new_files:
        write_log(f"[SNAPSHOT] New file: {f}", severity_config["NEW"])

    for f in deleted_files:
        write_log(f"[SNAPSHOT] File deleted: {f}", severity_config["DELETED"])

    for f in modified_files:
        write_log(
            f"[SNAPSHOT] File modified: {f}", severity_config["MODIFIED"])

    return modified_files, deleted_files, new_files


def _run_ai_layer(modified_files: list[str], deleted_files: list[str], new_files: list[str], config: dict,) -> tuple[str, float]:
    global _last_ai_alert
    thresholds = config.get("ai_thresholds", {})
    burst_threshold = thresholds.get("burst_new_count",    40)
    destructive_threshold = thresholds.get("destructive_deleted", 40)
    quiet_threshold = thresholds.get("quiet_total",          2)

    modified_count = len(modified_files)
    deleted_count = len(deleted_files)
    new_count = len(new_files)

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
        write_log(ai_msg, ai_severity)
        _last_ai_alert = current_alert

    return label, confidence


def check_integrity(directory: str) -> None:
    global _last_snapshot, _daily_counts, _summary_date

    config = load_config()
    severity_config = config["severity_levels"]

    today = date.today()
    if today != _summary_date:
        _daily_summary()
        _daily_counts = {"modified": 0, "deleted": 0, "new": 0}
        _summary_date = today

    if not verify_baseline_integrity(config):
        write_log("Integrity check aborted due to baseline tampering.", "INFO")
        return

    print("Checking File Integrity...")

    if not os.path.exists(BASE_FILE):
        print("Baseline file not found. Please create a baseline first.")
        return

    with open(BASE_FILE, "r", encoding="utf-8") as fh:
        baseline_data: dict = json.load(fh)
    baseline_data.pop("log_data", None)

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
            pass

    _check_baseline_layer(baseline_data, current_data, severity_config)
    if _last_snapshot is None:
        _last_snapshot = current_data
        print("Initial snapshot captured. Monitoring starts on next cycle.\n")
        return

    modified_files, deleted_files, new_files = _check_snapshot_layer(
        _last_snapshot, current_data, severity_config
    )

    _last_snapshot = current_data

    _daily_counts["modified"] += len(modified_files)
    _daily_counts["deleted"] += len(deleted_files)
    _daily_counts["new"] += len(new_files)

    ai_label, ai_confidence = _run_ai_layer(
        modified_files, deleted_files, new_files, config
    )

    last_event: str | None = None
    last_event_type: str | None = None
    if deleted_files:
        last_event = f"[DELETED] {os.path.basename(deleted_files[-1])}"
        last_event_type = "DELETED"
    elif modified_files:
        last_event = f"[MODIFIED] {os.path.basename(modified_files[-1])}"
        last_event_type = "MODIFIED"
    elif new_files:
        last_event = f"[NEW] {os.path.basename(new_files[-1])}"
        last_event_type = "NEW"

    DASHBOARD_STATE["ai_label"] = ai_label
    DASHBOARD_STATE["ai_confidence"] = ai_confidence
    DASHBOARD_STATE["modified"] = len(modified_files)
    DASHBOARD_STATE["deleted"] = len(deleted_files)
    DASHBOARD_STATE["new"] = len(new_files)
    DASHBOARD_STATE["last_event"] = last_event
    DASHBOARD_STATE["last_event_type"] = last_event_type
    DASHBOARD_STATE["baseline_issues"] = dict(
        _baseline_alerts)   # shallow copy
    DASHBOARD_STATE["scan_time"] = datetime.now().strftime("%H:%M:%S")
