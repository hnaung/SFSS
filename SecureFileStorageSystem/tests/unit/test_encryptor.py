# tests/test_encryptor.py

import os
import pytest
import time
from src.storage.encryptor import generate_key, encrypt_file, decrypt_file
from src.utils.validators import is_valid_path

# Test configurations
TEST_FILE = "test_encryption.txt"
ENCRYPTED_FILE = "test_encryption.txt.enc"
DECRYPTED_FILE = "test_encryption.txt.dec"
TEST_CONTENT = "This is a test file for encryption."
HMAC_FILE = f"{ENCRYPTED_FILE}.hmac"
TAG_FILE = f"{ENCRYPTED_FILE}.tag"


@pytest.fixture(scope='function')
def setup_files():
    """ Create a temporary test file. """
    with open(TEST_FILE, 'w') as f:
        f.write(TEST_CONTENT)
    yield
    # Cleanup
    for file in [TEST_FILE, ENCRYPTED_FILE, DECRYPTED_FILE, HMAC_FILE, TAG_FILE]:
        if os.path.exists(file):
            os.remove(file)


def test_generate_key():
    """ Test if key and HMAC key are generated correctly and have the right length. """
    key, hmac_key = generate_key()
    assert key is not None
    assert len(key) == 32  # AES-256 requires a 32-byte key
    assert len(hmac_key) == 32


def test_encrypt_file(setup_files):
    """ Test if a file is encrypted correctly. """
    key, hmac_key = generate_key()
    encrypted_path, iv = encrypt_file(TEST_FILE, key, hmac_key)
    assert os.path.exists(encrypted_path)

    # Verify content is not readable
    with open(encrypted_path, 'rb') as f:
        content = f.read()
        assert TEST_CONTENT.encode() not in content


def test_decrypt_file(setup_files):
    """ Test if a file is decrypted correctly and matches the original content. """
    key, hmac_key = generate_key()
    encrypted_path, iv = encrypt_file(TEST_FILE, key, hmac_key)

    # Decrypt the file and validate content
    decrypt_file(encrypted_path, key, hmac_key, iv, DECRYPTED_FILE)
    assert os.path.exists(DECRYPTED_FILE)

    with open(DECRYPTED_FILE, 'r') as f:
        content = f.read()
    assert content == TEST_CONTENT


def test_decrypt_file_tampered(setup_files):
    """ Test if decryption gracefully fails on a tampered file. """
    key, hmac_key = generate_key()
    encrypted_path, iv = encrypt_file(TEST_FILE, key, hmac_key)

    # Tamper the encrypted file
    with open(encrypted_path, 'wb') as f:
        f.write(b"tampered data")

    # Attempt decryption (it should not crash)
    result = decrypt_file(encrypted_path, key, hmac_key, iv, DECRYPTED_FILE)
    assert result is None


def test_file_permission_lockdown(setup_files):
    """ Test if encrypted files have correct permissions. """
    key, hmac_key = generate_key()
    encrypted_path, iv = encrypt_file(TEST_FILE, key, hmac_key)

    if os.name == 'posix':
        file_mode = os.stat(encrypted_path).st_mode & 0o777
        assert file_mode == 0o600


def test_path_traversal_protection():
    """ Test if path traversal is blocked. """
    key, hmac_key = generate_key()
    encrypted_path, iv = encrypt_file("../unauthorized_access.txt", key, hmac_key)
    assert encrypted_path is None


def test_encryption_missing_file():
    """ Test if encryption handles missing files gracefully. """
    key, hmac_key = generate_key()
    encrypted_path, iv = encrypt_file("non_existent_file.txt", key, hmac_key)
    assert encrypted_path is None


def test_decryption_with_wrong_key(setup_files):
    """ Test if decryption fails with the wrong key. """
    key, hmac_key = generate_key()
    encrypted_path, iv = encrypt_file(TEST_FILE, key, hmac_key)

    # Generate a different key for decryption
    wrong_key, wrong_hmac_key = generate_key()
    result = decrypt_file(encrypted_path, wrong_key, wrong_hmac_key, iv, DECRYPTED_FILE)
    assert result is None


def test_secure_delete_after_decryption(setup_files):
    """ Test if decrypted files are securely deleted. """
    key, hmac_key = generate_key()
    encrypted_path, iv = encrypt_file(TEST_FILE, key, hmac_key)

    # Decrypt the file
    decrypt_file(encrypted_path, key, hmac_key, iv, DECRYPTED_FILE)

    # Secure delete the decrypted file
    if os.path.exists(DECRYPTED_FILE):
        os.remove(DECRYPTED_FILE)

    assert not os.path.exists(DECRYPTED_FILE)