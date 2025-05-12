# tests/test_session_handler.py

import os
import pytest
import time
from src.utils.session_handler import save_session, load_session, clear_session, SESSION_FILE

# Test Data
SESSION_DATA = {
    "github_id": "123456",
    "username": "test_user",
    "email": "test_user@example.com"
}


@pytest.fixture(scope='function')
def setup_session():
    """ Setup session for testing. """
    save_session(SESSION_DATA)
    yield
    clear_session()


def test_save_and_load_session(setup_session):
    """ Test if session is saved and loaded correctly. """
    session_data = load_session()
    assert session_data is not None
    assert session_data['github_id'] == "123456"
    assert session_data['username'] == "test_user"
    assert session_data['email'] == "test_user@example.com"


def test_clear_session():
    """ Test if session is cleared correctly. """
    save_session(SESSION_DATA)
    clear_session()
    session_data = load_session()
    assert session_data is None


def test_encrypted_file_exists(setup_session):
    """ Test if the encrypted session file exists on disk. """
    assert os.path.exists(SESSION_FILE)


def test_session_expiry(monkeypatch):
    """ Test if expired sessions are not loaded. """
    save_session(SESSION_DATA)

    # Override the SESSION_EXPIRY to 1 second for testing
    monkeypatch.setattr("src.utils.session_handler.SESSION_EXPIRY", 1)
    
    # Wait for expiry
    time.sleep(2)
    
    # Now it should be expired
    session_data = load_session()
    assert session_data is None
    assert session_data is None


def test_load_tampered_session():
    """ Test if tampered session file does not load. """
    save_session(SESSION_DATA)
    with open(SESSION_FILE, 'wb') as f:
        f.write(b'corrupted data')
    
    session_data = load_session()
    assert session_data is None