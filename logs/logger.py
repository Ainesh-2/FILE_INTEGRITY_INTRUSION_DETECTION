import os

LOG_FILE = os.path.join("logs","alerts.log")

def write_log(msg):
    os.makedirs("logs",exist_ok=True)
    with open(LOG_FILE,'a') as file:
        file.write(msg+"\n")