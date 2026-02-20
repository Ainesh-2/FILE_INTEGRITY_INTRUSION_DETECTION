import os

IGNORE_DIRS = {"__pycache__", ".git", "baseline", "logs"}


def scan_directory(directory):
    file_paths = []
    for root, dirs, files in os.walk(directory):
        for folder in IGNORE_DIRS:
            if folder in dirs:
                dirs.remove(folder)
        for file in files:
            file_paths.append(os.path.join(root, file))
    return file_paths
