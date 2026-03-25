import os
from config.config_loader import load_config


def scan_directory(directory):
    config = load_config()
    IGNORE_DIRS = config["directories_to_ignore"]
    file_paths = []

    for root, dirs, files in os.walk(directory):

        for folder in IGNORE_DIRS:
            if folder in dirs:
                dirs.remove(folder)
        for file in files:
            rel_path = os.path.relpath(os.path.join(root, file), directory)
            normalized_path = rel_path.replace("\\", "/")
            IGNORE_FILES = [os.path.normpath(p).replace(
                "\\", "/") for p in config["ignore_files"]]
            if normalized_path in IGNORE_FILES:
                continue
            full_path = os.path.join(".", rel_path)
            file_paths.append(full_path)
    return file_paths
