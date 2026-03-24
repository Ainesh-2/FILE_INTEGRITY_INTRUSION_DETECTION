import json
import os

CONFIG_FILE = os.path.join("config", "config.json")


def load_config():
    if not os.path.exists(CONFIG_FILE):
        print(f"Configuration file not found: {CONFIG_FILE}")
        return None

    with open(CONFIG_FILE, 'r') as f:
        return json.load(f)
