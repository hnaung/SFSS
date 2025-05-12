# src/storage/encryptor.py

"""
Encryption and decryption services for Secure File Storage System (SFSS) using AES-256-GCM with HMAC validation.
"""

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hmac, hashes
from src.utils.logger import log_event
from src.utils.validators import is_valid_path

# AES Block size and key length
BLOCK_SIZE = 128
KEY_SIZE = 32
IV_SIZE = 16
HMAC_KEY_SIZE = 32


def generate_key():
    """
    Generate a secure AES-256 key and HMAC key.
    """
    return os.urandom(KEY_SIZE), os.urandom(HMAC_KEY_SIZE)


def secure_delete(file_path):
    """
    Overwrite and securely delete a file.
    """
    if os.path.exists(file_path):
        with open(file_path, "ba+", buffering=0) as delfile:
            length = delfile.tell()
            delfile.seek(0)
            delfile.write(os.urandom(length))
        os.remove(file_path)


def encrypt_file(file_path, key, hmac_key):
    """
    Encrypt the contents of a file using AES-256-GCM encryption.
    """
    if not os.path.exists(file_path):
        log_event("ERROR", f"File not found: {file_path}")
        return None, None

    if not is_valid_path(file_path):
        log_event("WARNING", f"Invalid file path detected during encryption: {file_path}")
        return None, None

    # Generate IV
    iv = os.urandom(IV_SIZE)

    # Create AES cipher in GCM mode
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Output path
    encrypted_file_path = f"{file_path}.enc"
    temp_file = encrypted_file_path + ".tmp"
    tag_temp_file = temp_file + ".tag"
    hmac_temp_file = temp_file + ".hmac"

    try:
        with open(file_path, "rb") as infile, open(temp_file, "wb") as outfile:
            while chunk := infile.read(4096):
                outfile.write(encryptor.update(chunk))
            outfile.write(encryptor.finalize())

        # Secure permission
        if os.name == "posix":
            os.chmod(temp_file, 0o600)

        # Write GCM tag and HMAC securely
        with open(tag_temp_file, "wb") as tagfile:
            tagfile.write(encryptor.tag)

        h = hmac.HMAC(hmac_key, hashes.SHA256())
        h.update(encryptor.tag)

        with open(hmac_temp_file, "wb") as hmacfile:
            hmacfile.write(h.finalize())

        # Atomic rename for main file and its tag and hmac
        os.rename(temp_file, encrypted_file_path)
        os.rename(tag_temp_file, f"{encrypted_file_path}.tag")
        os.rename(hmac_temp_file, f"{encrypted_file_path}.hmac")

        log_event("INFO", f"File encrypted: {encrypted_file_path}")
        return encrypted_file_path, iv

    except Exception as e:
        log_event("ERROR", f"Encryption failed: {str(e)}")
        return None, None


def decrypt_file(encrypted_path, key, hmac_key, iv, output_path=None):
    """
    Decrypt the contents of an encrypted file using AES-256-GCM decryption.
    """
    if not os.path.exists(encrypted_path):
        log_event("ERROR", f"Encrypted file not found: {encrypted_path}")
        print(f"[DEBUG] Encrypted path not found: {encrypted_path}")
        return None

    # If output path is not provided, generate it from encrypted path
    if not output_path:
        output_path = encrypted_path.replace(".enc", ".dec")

    print(f"[DEBUG] Decrypting to path: {output_path}")

    try:
        # Resolve tag and HMAC file paths
        tag_path = f"{encrypted_path}.tag"
        hmac_path = f"{encrypted_path}.hmac"

        # Check if the files exist
        if not os.path.exists(tag_path) or not os.path.exists(hmac_path):
            log_event("ERROR", f"Associated tag or HMAC file not found for: {encrypted_path}")
            print(f"[DEBUG] Tag or HMAC file not found for: {encrypted_path}")
            return None

        # Read tag and verify HMAC
        with open(tag_path, "rb") as tagfile, open(hmac_path, "rb") as hmacfile:
            tag = tagfile.read()
            h = hmac.HMAC(hmac_key, hashes.SHA256())
            h.update(tag)
            h.verify(hmacfile.read())

        # Create AES cipher for decryption
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()

        # ** Ensure the parent directory exists **
        parent_dir = os.path.dirname(output_path)
        if parent_dir and not os.path.exists(parent_dir):
            print(f"[DEBUG] Creating directory: {parent_dir}")
            os.makedirs(parent_dir, exist_ok=True)

        # ** Decrypt and write to the output path **
        with open(encrypted_path, "rb") as infile, open(output_path, "wb") as outfile:
            while chunk := infile.read(4096):
                outfile.write(decryptor.update(chunk))
            outfile.write(decryptor.finalize())

        log_event("INFO", f"File decrypted: {output_path}")

        # Verify that the file was written successfully
        if not os.path.exists(output_path):
            log_event(
                "ERROR", f"Decryption process completed but file not found at path: {output_path}"
            )
            print(f"[DEBUG] Decryption completed but file not found: {output_path}")
            return None

        print(f"[DEBUG] Decryption successful. File at: {output_path}")
        return output_path

    except Exception as e:
        log_event("ERROR", f"Decryption failed for '{encrypted_path}': {str(e)}")
        print(f"[DEBUG] Decryption failed: {e}")
        return None
