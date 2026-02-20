import os
import json
from hashing.hasher import hash_file
from hashing.scanner import scan_directory

BASE_FILE = os.path.join("baseline/base.json")

def check_integrity(directory):
    print("Checking File Integrity...")
    if not os.path.exists(BASE_FILE):
        print("Baseline file not found. Please create a baseline first.")
        return

    with open(BASE_FILE, "r") as file:
        baseline_data = json.load(file)

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

    # Check for new, modified, and deleted files
    for file in baseline_data:
        if file not in current_data:
            print(f"Deleted: {file}")
        elif baseline_data[file]["hash"] != current_data[file]["hash"]:
            print(f"Modified: {file}")

    for file in current_data:
        if file not in baseline_data:
            print(f"New: {file}")