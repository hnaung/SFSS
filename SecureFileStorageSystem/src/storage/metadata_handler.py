# src/storage/metadata_handler.py

"""
Metadata management for Secure File Storage System (SFSS), including encryption keys, IVs, and HMAC storage.
"""

import os
import json
from src.utils.logger import log_event

# Paths for metadata
METADATA_PATH = os.path.expanduser("~/.sfss/keys/")
os.makedirs(METADATA_PATH, exist_ok=True)


def get_metadata_path(filename):
    """
    Constructs the metadata path for a given filename.
    """
    return os.path.join(METADATA_PATH, f"{filename}.json")


def save_encryption_metadata(filename, key, hmac_key, iv):
    """
    Securely saves the encryption key, HMAC key, and IV to local storage.
    """
    metadata_path = get_metadata_path(filename)
    data = {"key": key.hex(), "hmac_key": hmac_key.hex(), "iv": iv.hex()}
    with open(metadata_path, "w") as f:
        json.dump(data, f)
    os.chmod(metadata_path, 0o600)  # Owner read/write only
    log_event("INFO", f"Metadata saved for '{filename}' with secure permissions.")


def load_encryption_key(filename):
    metadata_path = get_metadata_path(filename)
    if os.path.exists(metadata_path):
        with open(metadata_path, "r") as f:
            data = json.load(f)
            log_event("INFO", f"Encryption key loaded for '{filename}'")
            return bytes.fromhex(data["key"])
    else:
        log_event("ERROR", f"Encryption key not found for '{filename}'")
        return None


def load_hmac_key(filename):
    metadata_path = get_metadata_path(filename)
    if os.path.exists(metadata_path):
        with open(metadata_path, "r") as f:
            data = json.load(f)
            log_event("INFO", f"HMAC key loaded for '{filename}'")
            return bytes.fromhex(data["hmac_key"])
    else:
        log_event("ERROR", f"HMAC key not found for '{filename}'")
        return None


def load_iv(filename):
    metadata_path = get_metadata_path(filename)
    if os.path.exists(metadata_path):
        with open(metadata_path, "r") as f:
            data = json.load(f)
            log_event("INFO", f"IV loaded for '{filename}'")
            return bytes.fromhex(data["iv"])
    else:
        log_event("ERROR", f"IV not found for '{filename}'")
        return None


def remove_encryption_metadata(filename):
    metadata_path = get_metadata_path(filename)
    encrypted_file = os.path.expanduser(f"~/.sfss/secure_storage/{filename}.enc")

    if not os.path.exists(encrypted_file):
        log_event(
            "WARNING", f"Encrypted file '{filename}' not found. Cleaning up orphaned metadata."
        )

    if os.path.exists(metadata_path):
        os.remove(metadata_path)
        log_event("INFO", f"Encryption metadata for '{filename}' removed.")
