import os
from datetime import datetime

LOG_FILE = os.path.join("logs","alerts.log")

def write_log(msg):
    os.makedirs("logs",exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d %H-%M-%S")
    log_entry = f"{timestamp} - {msg}"
    with open(LOG_FILE,'a') as file:
        file.write(log_entry+"\n")