import os
import json
import atexit
import hashlib
from datetime import date
from baseline.base import hash_baseline_file
from hashing.hasher import hash_file
from hashing.scanner import scan_directory
from logs.logger import write_log
from config.config_loader import load_config

BASE_FILE = os.path.join("baseline/base.json")
known_alerts = {}
daily_counts = {"modified": 0, "deleted": 0, "new": 0}
summary_date = date.today()


def daily_summary():
    write_log(
        f"Daily Summary [{summary_date}]: Modified={daily_counts['modified']}, "
        f"Deleted={daily_counts['deleted']}, New={daily_counts['new']}",
        severity="INFO"
    )


atexit.register(daily_summary)


def verify_baseline_integrity():
    config = load_config()
    severity_config = config["severity_levels"]

    hash_file_path = os.path.join("baseline", "base.hash")
    baseline_file = os.path.join("baseline", "base.json")
    if not os.path.exists(hash_file_path):
        severity = severity_config["BASELINE_TAMPERED"]
        msg = "Baseline hash file not found"
        print(f"[{severity}] Baseline hash not found!")
        write_log(msg, severity)
        return False

    with open(hash_file_path, "r", encoding="utf-8") as file:
        stored_hash = file.read().strip()

    sha256 = hashlib.sha256()
    with open(baseline_file, "rb") as f:
        chunk = f.read(4096)
        while chunk:
            sha256.update(chunk)
            chunk = f.read(4096)
    current_hash = sha256.hexdigest()

    if stored_hash != current_hash:
        severity = severity_config["BASELINE_TAMPERED"]
        msg = f"Baseline tampering detected! Stored hash: {stored_hash}, Current hash: {current_hash}"
        print(f"[{severity}] BASELINE IS TAMPERED!")
        write_log(msg, severity)
        return False
    return True


def check_integrity(directory):
    global daily_counts, summary_date
    config = load_config()
    severity_config = config["severity_levels"]

    today = date.today()
    if today != summary_date:
        daily_summary()
        daily_counts = {"modified": 0, "deleted": 0, "new": 0}
        summary_date = today

    if not verify_baseline_integrity():
        msg = "Integrity check aborted due to baseline tampering"
        print("Aborting Integrity Check...")
        write_log(msg, severity="INFO")
        return

    modified_count = 0
    deleted_count = 0
    new_count = 0

    print("Checking File Integrity...")
    if not os.path.exists(BASE_FILE):
        print("Baseline file not found. Please create a baseline first.")
        return

    with open(BASE_FILE, "r", encoding="utf-8") as file:
        baseline_data = json.load(file)

    log_info = baseline_data.get("log_data")
    if log_info:
        log_path = log_info.get("path")
        expected_size = log_info.get("size", 0)
        update_log_baseline = False

        if not os.path.exists(log_path):
            severity = severity_config["LOG_TAMPERED"]
            msg = f"Log file missing/deleted: {log_path}"
            print(f"[{severity}] {msg}")
            write_log(msg, severity)
            update_log_baseline = True
        else:
            current_size = os.path.getsize(log_path)
            if current_size < expected_size:
                severity = severity_config["LOG_TAMPERED"]
                msg = f"Log file truncated: {log_path} (baseline {expected_size} bytes, current {current_size} bytes)"
                print(f"[{severity}] {msg}")
                write_log(msg, severity)
                update_log_baseline = True

        if update_log_baseline:
            baseline_data["log_data"]["size"] = os.path.getsize(log_path)
            with open(BASE_FILE, "w", encoding="utf-8") as f:
                json.dump(baseline_data, f, indent=4)
            new_hash = hash_baseline_file(BASE_FILE)
            with open(os.path.join("baseline", "base.hash"), "w", encoding="utf-8") as f:
                f.write(new_hash)

    for ignore_path in config["ignore_files"]:
        ignore_norm = os.path.join(
            ".", os.path.normpath(ignore_path)).replace("/", "\\")
        ignore_alt = ignore_norm.replace("\\", "/")
        if ignore_norm in baseline_data:
            del baseline_data[ignore_norm]
        if ignore_alt in baseline_data:
            del baseline_data[ignore_alt]

    baseline_data.pop("log_data", None)

    current_files = scan_directory(directory)
    current_data = {}

    for file in current_files:
        file_hash = hash_file(file)
        if file_hash:
            current_data[file] = {
                "hash": file_hash,
                "size": os.path.getsize(file),
                "last_modified": os.path.getmtime(file)
            }

    resolved = [f for f in known_alerts if f not in baseline_data and f in current_data
                and baseline_data.get(f, {}).get("hash") == current_data[f]["hash"]]
    for file in resolved:
        del known_alerts[file]

    for file in baseline_data:
        if file not in current_data:
            if known_alerts.get(file) != "DELETED":
                severity = severity_config["DELETED"]
                msg = f"File deleted: {file}"
                print(f"[{severity}] {msg}")
                write_log(msg, severity)
                known_alerts[file] = "DELETED"
            deleted_count += 1

        elif baseline_data[file]["hash"] != current_data[file]["hash"]:
            current_hash = current_data[file]["hash"]
            if known_alerts.get(file) != current_hash:
                severity = severity_config["MODIFIED"]
                msg = f"File modified: {file}"
                print(f"[{severity}] {msg}")
                write_log(msg, severity)
                known_alerts[file] = current_hash
            modified_count += 1
        else:
            known_alerts.pop(file, None)

    for file in current_data:
        if file not in baseline_data:
            current_hash = current_data[file]["hash"]
            if known_alerts.get(file) != current_hash:
                severity = severity_config["NEW"]
                msg = f"New file: {file}" if file not in known_alerts else f"New file modified: {file}"
                print(f"[{severity}] {msg}")
                write_log(msg, severity)
                known_alerts[file] = current_hash
            new_count += 1

    daily_counts["modified"] += modified_count
    daily_counts["deleted"] += deleted_count
    daily_counts["new"] += new_count

    print("\nSummary:")
    print("Modified:", modified_count)
    print("Deleted:", deleted_count)
    print("New:", new_count)
    print("Integrity check completed.")
