import os
from config.config_loader import load_config


def scan_directory(directory):
    config = load_config()
    IGNORE_DIRS = config["directories_to_ignore"]
    IGNORE_FILES = config["ignore_files"]
    file_paths = []

    for root, dirs, files in os.walk(directory):

        for folder in IGNORE_DIRS:
            if folder in dirs:
                dirs.remove(folder)
        for file in files:
            file_paths.append(os.path.join(root, file))
            normalized_path = (os.path.join(root, file)).replace("\\", "/")
            if normalized_path in IGNORE_FILES:
                continue
    return file_paths
