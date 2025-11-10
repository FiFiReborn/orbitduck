"""
OrbitDuck Logger Manager – Phase 1.6
Adds separate error logging and traceback capture.
"""

import logging
import json
import os
import traceback
from datetime import datetime
from pathlib import Path

LOG_DIR = Path(__file__).resolve().parent.parent / "logs"
LOG_DIR.mkdir(exist_ok=True)

LOG_FILE = LOG_DIR / "orbitduck.log"
ERROR_FILE = LOG_DIR / "error.log"
AUDIT_FILE = LOG_DIR / "audit_trail.jsonl"

# -------------------------------
# Standard + Error Log Setup
# -------------------------------
def setup_logger():
    logger = logging.getLogger("OrbitDuck")
    logger.setLevel(logging.INFO)

    if not logger.handlers:
        # Main log
        file_handler = logging.FileHandler(LOG_FILE)
        console_handler = logging.StreamHandler()

        # Error log
        error_handler = logging.FileHandler(ERROR_FILE)
        error_handler.setLevel(logging.ERROR)

        formatter = logging.Formatter(
            "%(asctime)s | %(levelname)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        error_handler.setFormatter(formatter)

        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        logger.addHandler(error_handler)

    return logger


# -------------------------------
# Structured Audit Trail Writer
# -------------------------------
def log_audit_entry(event_type: str, data: dict):
    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "event_type": event_type,
        "data": data,
    }
    with open(AUDIT_FILE, "a") as f:
        json.dump(entry, f)
        f.write("\n")


# -------------------------------
# Error Handler with Traceback
# -------------------------------
def log_exception(logger, context: str, error: Exception):
    """Writes detailed error info and traceback to error.log."""
    tb = traceback.format_exc()
    logger.error(f"❌ {context}: {error}\n{tb}")

    # Also append to structured JSON error audit trail
    log_audit_entry("exception", {
        "context": context,
        "error": str(error),
        "traceback": tb.strip().splitlines()[-3:],  # only last 3 lines for compactness
    })
