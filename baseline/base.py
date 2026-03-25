import json
import hashlib
import os
from hashing.hasher import hash_file
from hashing.scanner import scan_directory

Base_File = os.path.join("baseline/base.json")


def hash_baseline_file(directory):
    sha256 = hashlib.sha256()
    with open(directory, "rb") as file:
        chunk = file.read(4096)
        while chunk:
            sha256.update(chunk)
            chunk = file.read(4096)
    return sha256.hexdigest()


def create_baseline(directory):
    print(f"Creating baseline for directory: {directory}")
    baseline_data = {}
    files = scan_directory(directory)
    for file in files:
        file_hash = hash_file(file)
        if file_hash:
            baseline_data[file] = {
                "hash": file_hash,
                "size": os.path.getsize(file),
                "last_modified": os.path.getmtime(file)
            }
    os.makedirs("baseline", exist_ok=True)

    log_file = os.path.join("logs", "alerts.log")
    if os.path.exists(log_file):
        baseline_data["log_data"] = {
            "path": log_file,
            "size": os.path.getsize(log_file)
        }

    with open(Base_File, "w") as file:
        json.dump(baseline_data, file, indent=4)

    baseline_hash = hash_baseline_file(Base_File)

    with open(os.path.join("baseline", "base.hash"), "w") as f:
        f.write(baseline_hash)

    print(f"Baseline created with {len(baseline_data)} files.")
