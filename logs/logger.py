import os
import logging
import atexit
from datetime import datetime
from logging.handlers import TimedRotatingFileHandler

LOG_FILE = os.path.join("logs", "alerts.log")
ARCHIVE_DIR = os.path.join("logs", "archive")
_session_started = False


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
        os.makedirs(ARCHIVE_DIR, exist_ok=True)
        handler = TimedRotatingFileHandler(
            LOG_FILE, when="midnight", backupCount=30, encoding="utf-8"
        )
        handler.namer = lambda name: os.path.join(
            ARCHIVE_DIR, os.path.basename(name))
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
    return logger


def write_log(msg, severity):
    global _session_started
    logger = _get_logger()

    if not _session_started:
        _session_started = True
        ts = datetime.now().strftime("%Y-%m-%d | %H:%M:%S")
        logger.info(f"\033[92m{'=' * 60}\033[0m")
        logger.info(f"\033[92m  SESSION START  —  {ts}\033[0m")
        logger.info(f"\033[92m{'=' * 60}\033[0m")

        def _end_banner():
            ts_end = datetime.now().strftime("%Y-%m-%d | %H:%M:%S")
            logger.info(f"\033[91m{'=' * 60}\033[0m")
            logger.info(f"\033[91m  SESSION END    —  {ts_end}\033[0m")
            logger.info(f"\033[91m{'=' * 60}\033[0m")

        atexit.register(_end_banner)

    timestamp = datetime.now().strftime("%Y-%m-%d | %H:%M:%S")
    coloured_msg = colour_severity(severity)
    logger.info(f"{timestamp} - {coloured_msg} {msg}")
