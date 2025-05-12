# src/utils/logger.py

"""
Logging utility for Secure File Storage System (SFSS), supports event logging and rate-limited log rotation.
"""

import os
import hashlib
import logging
from pathlib import Path
from logging.handlers import TimedRotatingFileHandler

# Define log directory and file
LOG_DIR = Path.cwd() / "logs"
LOG_FILE = LOG_DIR / "app.log"

# Create log directory if it does not exist
LOG_DIR.mkdir(parents=True, exist_ok=True)

# Secure directory and file permissions
os.chmod(LOG_DIR, 0o700)
if LOG_FILE.exists():
    os.chmod(LOG_FILE, 0o600)

# Logger configuration
log_handler = TimedRotatingFileHandler(
    filename=str(LOG_FILE),
    when="D",
    interval=1,
    backupCount=7,
    encoding="utf-8",
    delay=False,
)

formatter = logging.Formatter(
    fmt="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log_handler.setFormatter(formatter)

logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.addHandler(log_handler)


def mask_sensitive_data(message):
    """ Mask sensitive information in log messages. """
    if "token" in message.lower():
        message = message.replace(message, "****MASKED TOKEN****")
    if "email" in message.lower():
        parts = message.split("@")
        if len(parts) == 2:
            domain_parts = parts[1].split(".")
            message = f"{parts[0][:3]}****@{domain_parts[0]}****"
    if "password" in message.lower():
        message = message.replace(message, "****MASKED PASSWORD****")
    if "secret" in message.lower():
        message = message.replace(message, "****MASKED SECRET****")
    if "private_key" in message.lower():
        message = message.replace(message, "****MASKED PRIVATE KEY****")
    return message


def hash_log_entry(message):
    """ Generate SHA-256 hash for log integrity. """
    return hashlib.sha256(message.encode()).hexdigest()


def log_event(level, message):
    """ Log an event with security best practices and hashing. """
    message = mask_sensitive_data(message)
    log_hash = hash_log_entry(message)
    formatted_message = f"{message} [Hash: {log_hash}]"

    if level == "INFO":
        logger.info(formatted_message)
    elif level == "WARNING":
        logger.warning(formatted_message)
    elif level == "ERROR":
        logger.error(formatted_message)
    elif level == "DEBUG":
        logger.debug(formatted_message)
    elif level == "CRITICAL":
        logger.critical(formatted_message)
    else:
        logger.info(formatted_message)

    # Force the handler to flush
    for handler in logger.handlers:
        handler.flush()

def mask_sensitive_data(message):
    if "token" in message.lower():
        message = message.replace(message, "****MASKED TOKEN****")
    if "email" in message.lower():
        parts = message.split("@")
        if len(parts) == 2:
            domain_parts = parts[1].split(".")
            message = f"{parts[0][:3]}****@{domain_parts[0]}****"
    if "password" in message.lower():
        message = message.replace(message, "****MASKED PASSWORD****")
    if "secret" in message.lower():
        message = message.replace(message, "****MASKED SECRET****")
    if "private_key" in message.lower():
        message = message.replace(message, "****MASKED PRIVATE KEY****")
    return message


def hash_log_entry(message):
    return hashlib.sha256(message.encode()).hexdigest()


def log_event(level, message):
    """Logs an event to the application log file with integrity hash."""
    message = mask_sensitive_data(message)
    log_hash = hash_log_entry(message)
    formatted_message = f"{message} [Hash: {log_hash}]"

    if level == "INFO":
        logger.info(formatted_message)
    elif level == "WARNING":
        logger.warning(formatted_message)
    elif level == "ERROR":
        logger.error(formatted_message)
    elif level == "DEBUG":
        logger.debug(formatted_message)
    elif level == "CRITICAL":
        logger.critical(formatted_message)
    else:
        logger.info(formatted_message)
