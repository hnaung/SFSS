# tests/test_file_manager.py

import os
import pytest
from src.storage.file_manager import upload_file, download_file, delete_file, list_files
from src.utils.session_handler import save_session, clear_session

# Test configurations
TEST_STORAGE_PATH = os.path.expanduser("~/.sfss/secure_storage")
TEST_FILE = "test_upload.txt"
TEST_FILE_CONTENT = "This is a test file for upload."
TEST_DOWNLOAD_PATH = "downloaded_test_file.txt"


@pytest.fixture(scope='function')
def setup_session():
    """ Setup session for testing. """
    session_data = {"github_id": "123456", "username": "test_user"}
    save_session(session_data)
    yield
    clear_session()


@pytest.fixture(scope='function')
def setup_file():
    """ Create a temporary test file. """
    with open(TEST_FILE, 'w') as f:
        f.write(TEST_FILE_CONTENT)
    yield
    os.remove(TEST_FILE)
    if os.path.exists(TEST_DOWNLOAD_PATH):
        os.remove(TEST_DOWNLOAD_PATH)


# Test cases
def test_upload_file(setup_session, setup_file):
    """ Test uploading and encrypting a file. """
    result = upload_file(TEST_FILE)
    assert "uploaded and encrypted successfully" in result
    # Check for encrypted version
    encrypted_name = TEST_FILE + ".enc"
    assert os.path.exists(os.path.join(TEST_STORAGE_PATH, encrypted_name))


def test_download_file(setup_session):
    """ Test downloading and decrypting a file. """
    encrypted_name = TEST_FILE + ".enc"
    if not os.path.exists(os.path.join(TEST_STORAGE_PATH, encrypted_name)):
        upload_file(TEST_FILE)

    result = download_file(TEST_FILE, TEST_DOWNLOAD_PATH)
    assert os.path.exists(TEST_DOWNLOAD_PATH)

    # Verify content
    with open(TEST_DOWNLOAD_PATH, 'r') as f:
        content = f.read()
    assert content == TEST_FILE_CONTENT


def test_list_files(setup_session):
    """ Test listing all encrypted files. """
    encrypted_name = TEST_FILE + ".enc"
    if not os.path.exists(os.path.join(TEST_STORAGE_PATH, encrypted_name)):
        upload_file(TEST_FILE)
    
    result = list_files()
    assert TEST_FILE in result


def test_delete_file(setup_session):
    """ Test deleting an encrypted file. """
    encrypted_name = TEST_FILE + ".enc"
    if not os.path.exists(os.path.join(TEST_STORAGE_PATH, encrypted_name)):
        upload_file(TEST_FILE)

    result = delete_file(TEST_FILE)
    assert "deleted successfully" in result
    assert not os.path.exists(os.path.join(TEST_STORAGE_PATH, encrypted_name))
