from hashing.hasher import hash_file
from hashing.scanner import scan_directory

if __name__ == "__main__":
    files = scan_directory(".")
    print(f"Found {len(files)} files to hash.")
    for file in files:
        print(f"Hash of {file}: {hash_file(file)}")
