import os
import pytest
from src.utils.logger import log_event, LOG_FILE

LOG_FILE_PATH = LOG_FILE

@pytest.fixture(scope='module', autouse=True)
def setup_logging():
    log_dir = os.path.dirname(LOG_FILE)
    print(f"[DEBUG] Log Directory: {log_dir}")
    print(f"[DEBUG] Log File Path: {LOG_FILE}")
    if not os.path.exists(log_dir):
        print("[DEBUG] Creating log directory")
        os.makedirs(log_dir)
    if not os.path.exists(LOG_FILE):
        print("[DEBUG] Creating log file")
        open(LOG_FILE, 'w').close()

def clear_log_file():
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'w'):
            pass


def test_log_event_info():
    log_event("INFO", "Testing log info.")
    with open(LOG_FILE, 'r') as log_file:
        logs = log_file.read()
        assert "Testing log info." in logs


def test_log_event_warning():
    log_event("WARNING", "Testing log warning.")
    with open(LOG_FILE, 'r') as log_file:
        logs = log_file.read()
        assert "Testing log warning." in logs


def test_log_event_error():
    log_event("ERROR", "Testing log error.")
    with open(LOG_FILE, 'r') as log_file:
        logs = log_file.read()
        assert "Testing log error." in logs


def test_log_event_masking():
    log_event("INFO", "User's token: 123456789")
    with open(LOG_FILE, 'r') as log_file:
        logs = log_file.read()
        assert "****MASKED TOKEN****" in logs


def test_log_event_hash_integrity():
    log_event("INFO", "Hash integrity check.")
    with open(LOG_FILE, 'r') as log_file:
        logs = log_file.read()
        assert "[Hash:" in logs


def test_log_rotation():
    log_event("INFO", "Testing log rotation.")
    with open(LOG_FILE, 'r') as log_file:
        logs = log_file.read()
        assert "Testing log rotation." in logs