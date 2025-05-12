# src/storage/file_manager.py

"""
File management for Secure File Storage System (SFSS), including secure upload, download, listing, and deletion.
"""

import os
import json
from datetime import datetime
from src.storage.encryptor import encrypt_file, decrypt_file, generate_key
from src.utils.session_handler import load_session
from src.utils.validators import is_valid_path, is_allowed_file_extension, sanitize_filename
from src.utils.logger import log_event
from src.storage.metadata_handler import (
    save_encryption_metadata,
    load_encryption_key,
    load_hmac_key,
    load_iv,
    remove_encryption_metadata,
)

# Secure storage paths
STORAGE_PATH = os.path.expanduser("~/.sfss/secure_storage/")
os.makedirs(STORAGE_PATH, exist_ok=True)


def upload_file(file_path):
    """
    Securely uploads and encrypts a file to the local secure storage.
    """
    session_data = load_session()
    if not session_data:
        log_event("ERROR", "No valid session found. Please log in.")
        return "No valid session found. Please log in."

    if not is_valid_path(file_path):
        log_event("WARNING", f"Path traversal attempt detected: {file_path}")
        return "Path traversal attempt detected."

    sanitized_filename = sanitize_filename(os.path.basename(file_path))

    if not is_allowed_file_extension(sanitized_filename):
        log_event("WARNING", f"File extension not allowed for '{sanitized_filename}'.")
        return "File extension not allowed."

    # Generate encryption keys
    key, hmac_key = generate_key()

    # Encrypt the file
    encrypted_path, iv = encrypt_file(file_path, key, hmac_key)

    if not encrypted_path:
        log_event("ERROR", f"Failed to encrypt the file: {file_path}")
        return "Encryption failed."

    # Store the encrypted file in secure storage
    final_path = os.path.join(STORAGE_PATH, sanitized_filename + ".enc")
    os.rename(encrypted_path, final_path)
    os.rename(f"{encrypted_path}.tag", f"{final_path}.tag")
    os.rename(f"{encrypted_path}.hmac", f"{final_path}.hmac")
    # Save metadata for decryption
    save_encryption_metadata(sanitized_filename, key, hmac_key, iv)

    log_event("INFO", f"File '{sanitized_filename}' uploaded and encrypted successfully.")
    return f"File '{sanitized_filename}' uploaded and encrypted successfully."


def download_file(filename, output_path):
    """
    Securely decrypts and downloads a file from the secure storage.
    """
    session_data = load_session()
    if not session_data:
        log_event("ERROR", "No valid session found. Please log in.")
        return "No valid session found. Please log in."

    sanitized_filename = sanitize_filename(filename)
    encrypted_file_path = os.path.join(STORAGE_PATH, sanitized_filename + ".enc")

    if not os.path.exists(encrypted_file_path):
        log_event("ERROR", f"File '{sanitized_filename}' not found.")
        return f"File '{sanitized_filename}' not found."

    # Ensure output path is absolute and exists
    output_path = os.path.abspath(output_path)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    # *Debug logs to check paths**
    log_event("DEBUG", f"Attempting to decrypt '{sanitized_filename}' to '{output_path}'")
    print(f"[DEBUG] Attempting to decrypt '{sanitized_filename}' to '{output_path}'")

    # Decrypt the file
    result = decrypt_file(
        encrypted_file_path,
        load_encryption_key(sanitized_filename),
        load_hmac_key(sanitized_filename),
        load_iv(sanitized_filename),
        output_path,
    )

    if result:
        log_event("INFO", f"File '{sanitized_filename}' downloaded successfully.")
        return f"File '{sanitized_filename}' downloaded successfully."
    else:
        log_event("ERROR", f"File '{sanitized_filename}' decryption failed.")
        return f"File '{sanitized_filename}' decryption failed."


def list_files():
    """
    Securely lists all encrypted files stored by the user.
    """
    session_data = load_session()
    if not session_data:
        log_event("ERROR", "No valid session found. Please log in.")
        return []

    files = [f for f in os.listdir(STORAGE_PATH) if f.endswith(".enc")]
    log_event("INFO", "Your Encrypted Files:")
    return [f.replace(".enc", "") for f in files] if files else []


def delete_file(filename):
    """
    Securely deletes an encrypted file from the storage.
    """
    session_data = load_session()
    if not session_data:
        log_event("ERROR", "No valid session found. Please log in.")
        return "No valid session found. Please log in."

    sanitized_filename = sanitize_filename(filename)
    encrypted_file_path = os.path.join(STORAGE_PATH, sanitized_filename + ".enc")

    if not os.path.exists(encrypted_file_path):
        log_event("ERROR", f"File '{sanitized_filename}' not found.")
        return f"File '{sanitized_filename}' not found."

    os.remove(encrypted_file_path)
    remove_encryption_metadata(sanitized_filename)
    log_event("INFO", f"File '{sanitized_filename}' deleted successfully.")
    return f"File '{sanitized_filename}' deleted successfully."
