# tests/test_metadata_handler.py

import os
import pytest
import json
from src.storage.metadata_handler import save_encryption_metadata, load_encryption_key, load_iv

# Temporary directory for testing
TEST_DIR = os.path.expanduser("~/.sfss/keys/")
TEST_FILE = "test_file.json"

@pytest.fixture(scope='function')
def setup_metadata():
    """
    Setup and teardown for metadata testing.
    """
    os.makedirs(TEST_DIR, exist_ok=True)
    yield
    # Cleanup
    test_path = os.path.join(TEST_DIR, TEST_FILE)
    if os.path.exists(test_path):
        os.remove(test_path)

def test_save_encryption_metadata(setup_metadata):
    """
    Test saving encryption metadata.
    """
    key = bytes.fromhex('00112233445566778899aabbccddeeff')
    hmac_key = bytes.fromhex('aabbccddeeff00112233445566778899')
    iv = bytes.fromhex('ffeeddccbbaa99887766554433221100')
    
    save_encryption_metadata("test_file", key, hmac_key, iv)

    # Assert the file was created
    metadata_path = os.path.expanduser("~/.sfss/keys/test_file.json")
    assert os.path.exists(metadata_path)

    # Assert the contents are correct
    with open(metadata_path, 'r') as f:
        data = json.load(f)
        assert data["key"] == key.hex()
        assert data["hmac_key"] == hmac_key.hex()
        assert data["iv"] == iv.hex()

def test_load_encryption_key(setup_metadata):
    """
    Test loading the encryption key from metadata.
    """
    key = bytes.fromhex('00112233445566778899aabbccddeeff')
    hmac_key = bytes.fromhex('aabbccddeeff00112233445566778899')
    iv = bytes.fromhex('ffeeddccbbaa99887766554433221100')
    
    save_encryption_metadata("test_file", key, hmac_key, iv)
    
    loaded_key = load_encryption_key("test_file")
    assert loaded_key == key

def test_load_iv(setup_metadata):
    """
    Test loading the IV from metadata.
    """
    key = bytes.fromhex('00112233445566778899aabbccddeeff')
    hmac_key = bytes.fromhex('aabbccddeeff00112233445566778899')
    iv = bytes.fromhex('ffeeddccbbaa99887766554433221100')
    
    save_encryption_metadata("test_file", key, hmac_key, iv)
    
    loaded_iv = load_iv("test_file")
    assert loaded_iv == iv


def test_missing_metadata():
    """
    Test loading from non-existent metadata file.
    """
    loaded_key = load_encryption_key("non_existent_file")
    loaded_iv = load_iv("non_existent_file")
    assert loaded_key is None
    assert loaded_iv is None
