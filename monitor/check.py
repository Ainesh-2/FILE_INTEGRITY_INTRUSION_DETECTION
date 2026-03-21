import os
import json
import hashlib
from hashing.hasher import hash_file
from hashing.scanner import scan_directory
from logs.logger import write_log

BASE_FILE = os.path.join("baseline/base.json")

def verify_baseline_integrity():
    hash_file_path = os.path.join("baseline", "base.hash")
    baseline_file = os.path.join("baseline", "base.json")
    if not os.path.exists(hash_file_path):
        msg = "[CRITICAL] Baseline hash file not found"
        print("Baseline hash not found!")
        write_log(msg)
        return False
    
    with open(hash_file_path,"r") as file:
        stored_hash = file.read().strip()

    sha256 = hashlib.sha256()
    with open(baseline_file,"rb") as f:
        chunk = f.read(4096)
        while chunk:
            sha256.update(chunk)
            chunk = f.read(4096)
    current_hash = sha256.hexdigest()

    if stored_hash != current_hash:
        msg = "[CRITICAL] Baseline tampering detected"
        print("BASELINE IS TAMPERED!")
        write_log(msg)
        return False
    return True

def check_integrity(directory):
    if not verify_baseline_integrity():
        msg = "Integrity check aborted due to baseline tampering"
        print("Aborting Integrity Check...")
        write_log(msg)
        return
    
    modified_count=0
    deleted_count=0
    new_count=0

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

    for file in baseline_data:
        if file not in current_data:
            msg = f"[Deleted] {file}"
            print(msg)
            write_log(msg)
            deleted_count+=1
            
        elif baseline_data[file]["hash"] != current_data[file]["hash"]:
            msg = f"[Modified] {file}"
            print(msg)
            write_log(msg)
            modified_count+=1

    for file in current_data:
        if file not in baseline_data:
            msg = f"[New] {file}"
            print(msg)
            write_log(msg)
            new_count+=1

    print("\nSummary:")
    print("Modified:", modified_count)
    print("Deleted:", deleted_count)
    print("New:", new_count)

    write_log(f"Summary: Modified={modified_count}, Deleted={deleted_count}, New={new_count}")

    print("Integrity check completed.")
