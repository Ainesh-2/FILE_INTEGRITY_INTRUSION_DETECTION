import json
import os
from hashing.hasher import hash_file
from hashing.scanner import scan_directory

Base_File = os.path.join("baseline/base.json")


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

    with open(Base_File, "w") as file:
        json.dump(baseline_data, file, indent=4)

    print(f"Baseline created with {len(baseline_data)} files.")
