import os
import logging
from datetime import datetime
from logging.handlers import TimedRotatingFileHandler

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


def _get_logger():
    logger = logging.getLogger("file_integrity")
    if not logger.handlers:
        os.makedirs("logs", exist_ok=True)
        handler = TimedRotatingFileHandler(
            LOG_FILE, when="midnight", backupCount=30, encoding="utf-8"
        )
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
    return logger


def write_log(msg, severity):
    logger = _get_logger()
    timestamp = datetime.now().strftime("%Y-%m-%d | %H:%M:%S")
    coloured_msg = colour_severity(severity)
    log_entry = f"{timestamp} - {coloured_msg} {msg}"
    logger.info(log_entry)
