import os
import json
import hashlib
from baseline.base import hash_baseline_file
from hashing.hasher import hash_file
from hashing.scanner import scan_directory
from logs.logger import write_log
from config.config_loader import load_config

BASE_FILE = os.path.join("baseline/base.json")


def verify_baseline_integrity():
    config = load_config()
    severity_config = config["severity_levels"]

    hash_file_path = os.path.join("baseline", "base.hash")
    baseline_file = os.path.join("baseline", "base.json")
    if not os.path.exists(hash_file_path):
        severity = severity_config["BASELINE_TAMPERED"]
        msg = f"Baseline hash file not found"
        print(f"[{severity}] Baseline hash not found!")
        write_log(msg, severity)
        return False

    with open(hash_file_path, "r") as file:
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
    config = load_config()
    severity_config = config["severity_levels"]

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

    with open(BASE_FILE, "r") as file:
        baseline_data = json.load(file)

    IGNORE_FILES = config["ignore_files"]
    for ignore_path in IGNORE_FILES:
        ignore_path = ignore_path.replace("/", "\\")
        full_ignore = os.path.join(".", ignore_path)
        if full_ignore in baseline_data:
            del baseline_data[full_ignore]
        alt_ignore = full_ignore.replace("\\", "/")
        if alt_ignore in baseline_data:
            del baseline_data[alt_ignore]

    SPECIAL_KEYS = ["log_data"]

    logs = baseline_data.get("log_data")
    if logs:
        log_path = logs["path"]
        log_issue = False
        if not os.path.exists(log_path):
            severity = severity_config["LOG_TAMPERED"]
            msg = f"Log file missing/deleted: {log_path}"
            print(f"[{severity}] {msg}")
            write_log(msg, severity)
            log_issue = True
        else:
            current_size = os.path.getsize(log_path)
            if current_size < logs["size"]:
                severity = severity_config["LOG_TAMPERED"]
                msg = f"Log file was truncated! Original size: {logs['size']} bytes, Current size: {current_size} bytes"
                print(f"[{severity}] {msg}")
                write_log(msg, severity)
                log_issue = True
        if log_issue and os.path.exists(log_path):
            baseline_data["log_data"]["size"] = os.path.getsize(log_path)
            with open(BASE_FILE, "w") as file:
                json.dump(baseline_data, file, indent=4)
            new_hash = hash_baseline_file(BASE_FILE)
            with open(os.path.join("baseline", "base.hash"), "w") as f:
                f.write(new_hash)

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

    for file in baseline_data:
        if file in SPECIAL_KEYS:
            continue
        if file not in current_data:
            severity = severity_config["DELETED"]
            msg = f"File deleted: {file}"
            print(f"[{severity}] {msg}")
            write_log(msg, severity)
            deleted_count += 1

        elif baseline_data[file]["hash"] != current_data[file]["hash"]:
            severity = severity_config["MODIFIED"]
            msg = f"File modified: {file}"
            print(f"[{severity}] {msg}")
            write_log(msg, severity)
            modified_count += 1

    for file in current_data:
        if file not in baseline_data:
            severity = severity_config["NEW"]
            msg = f"New file: {file}"
            print(f"[{severity}] {msg}")
            write_log(msg, severity)
            new_count += 1

    print("\nSummary:")
    print("Modified:", modified_count)
    print("Deleted:", deleted_count)
    print("New:", new_count)

    write_log(
        f"Summary: Modified={modified_count}, Deleted={deleted_count}, New={new_count}", severity="INFO")
    print("Integrity check completed.")

    if logs and os.path.exists(log_path):
        current_size = os.path.getsize(log_path)
        if current_size != logs["size"]:
            baseline_data["log_data"]["size"] = current_size
            with open(BASE_FILE, "w") as file:
                json.dump(baseline_data, file, indent=4)
            new_hash = hash_baseline_file(BASE_FILE)
            with open(os.path.join("baseline", "base.hash"), "w") as f:
                f.write(new_hash)
