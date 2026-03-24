import os
from datetime import datetime

LOG_FILE = os.path.join("logs", "alerts.log")


def colour_severity(severity):
    if severity == "CRITICAL":
        return f"\033[91m[{severity}]\033[0m"
    elif severity == "HIGH":
        return f"\033[93m[  HIGH  ]\033[0m"
    elif severity == "LOW":
        return f"\033[92m[  LOW   ]\033[0m"
    elif severity == "INFO":
        return f"\033[94m[  INFO  ]\033[0m"
    else:
        return f"[{severity}]"


def write_log(msg, severity):
    os.makedirs("logs", exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d %H-%M-%S")
    coloured_msg = colour_severity(severity)
    log_entry = f"{timestamp} - {coloured_msg} {msg}"
    with open(LOG_FILE, 'a') as file:
        file.write(log_entry+"\n")
