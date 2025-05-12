# src/utils/session_handler.py

"""
Session management for Secure File Storage System (SFSS), including encryption, refresh, and expiry.
"""

import os
import json
import time
from cryptography.fernet import Fernet
from src.config import SECRET_KEY, SESSION_EXPIRY

# File path to store the encrypted session
SESSION_FILE = os.path.expanduser("~/.sfss/session_data.enc")

# Ensure the directory exists
os.makedirs(os.path.dirname(SESSION_FILE), exist_ok=True)


def generate_key():
    """
    Generates a Fernet instance using the provided SECRET_KEY from .env.
    """
    try:
        return Fernet(SECRET_KEY.encode())
    except Exception as e:
        print(f"[ERROR] Invalid SECRET_KEY format: {e}")
        return None


def save_session(session_data):
    """Encrypt and save session data to a local file with atomic write."""
    print("[INFO] Saving session securely...")
    fernet = generate_key()
    if not fernet:
        print("[ERROR] Encryption key is not properly initialized. Aborting session save.")
        return

    session_data["timestamp"] = int(time.time())

    try:
        encrypted_data = fernet.encrypt(json.dumps(session_data).encode())
        temp_file = SESSION_FILE + ".tmp"

        # Write to a temp file first for atomicity
        with open(temp_file, "wb") as file:
            file.write(encrypted_data)

        # Secure permission and atomically rename
        if os.name == "posix":
            os.chmod(temp_file, 0o600)

        os.rename(temp_file, SESSION_FILE)
        print("[INFO] Session saved successfully.")
    except Exception as e:
        print(f"[ERROR] Failed to save session: {e}")


def load_session():
    """
    Load and decrypt session data from a local file.
    """
    print("[INFO] Loading session...")
    if not os.path.exists(SESSION_FILE):
        print("[WARNING] No session found.")
        return None

    fernet = generate_key()
    if not fernet:
        print("[ERROR] Encryption key is not properly initialized. Aborting session load.")
        return None

    try:
        with open(SESSION_FILE, "rb") as file:
            encrypted_data = file.read()
            decrypted_data = fernet.decrypt(encrypted_data).decode()
            session_data = json.loads(decrypted_data)
            print("[INFO] Session loaded successfully.")

            if int(time.time()) - session_data["timestamp"] > SESSION_EXPIRY:
                print("[ERROR] Session expired. Please log in again.")
                clear_session()
                return None
            return session_data

    except Exception as e:
        if "Fernet" in str(e):
            print("[ERROR] Session decryption failed. Possible tampering or invalid key.")
        else:
            print(f"[ERROR] Failed to load session: {e}")
        return None


def refresh_session():
    """
    Refresh the session timestamp to extend its validity.
    """
    session_data = load_session()
    if not session_data:
        print("[ERROR] Cannot refresh. Session is not valid or expired.")
        return False

    session_data["timestamp"] = int(time.time())
    save_session(session_data)
    print("[INFO] Session refreshed successfully.")
    return True


def clear_session():
    """
    Clear the encrypted session from local storage.
    """
    if os.path.exists(SESSION_FILE):
        try:
            os.remove(SESSION_FILE)
            print("[INFO] Session cleared successfully.")
        except Exception as e:
            print(f"[ERROR] Failed to clear session: {e}")
    else:
        print("[WARNING] No session to clear.")
