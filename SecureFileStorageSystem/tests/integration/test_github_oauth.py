# tests/test_github_oauth.py

import pytest
import requests
from unittest.mock import patch, MagicMock
from src.auth.github_oauth import github_login, logout, get_github_user
from src.utils.session_handler import load_session, clear_session

@pytest.fixture(scope='function')
def setup_session():
    """ Setup and teardown for session testing. """
    clear_session()
    yield
    clear_session()

@patch('builtins.print')
@patch('src.auth.github_oauth.time.sleep', return_value=None)
@patch('src.auth.github_oauth.requests.get')
@patch('src.auth.github_oauth.requests.post')
def test_github_login_redirect(mock_post, mock_get, mock_sleep, mock_print, setup_session):
    """ Test if GitHub login URL is generated correctly and user is authenticated. """
    # **Mock Device Authorization Call**
    mock_device_response = MagicMock()
    mock_device_response.status_code = 200
    mock_device_response.json.return_value = {
        "verification_uri": "https://github.com/login/device",
        "user_code": "ABCD-1234",
        "interval": 5,
        "device_code": "123456"
    }

    # **Mock Polling Call for Token Exchange**
    mock_token_response = MagicMock()
    mock_token_response.status_code = 200
    mock_token_response.json.return_value = {"access_token": "mock_access_token"}
    mock_post.side_effect = [mock_device_response, mock_token_response]

    # **Mock GitHub User Fetch Call**
    mock_get_response = MagicMock()
    mock_get_response.status_code = 200
    mock_get_response.json.return_value = {
        "login": "test_user",
        "email": "test@example.com",
        "id": 123456
    }
    mock_get.return_value = mock_get_response

    # **Run the login function**
    github_login()

    # ✅ **Verify the printed URL in the console**
    mock_print.assert_any_call(f"[INFO] Visit this URL in your browser to authenticate:")
    mock_print.assert_any_call("https://github.com/login/device")
    mock_print.assert_any_call(f"[INFO] Enter this code: ABCD-1234\n")

    # **Verify the user info was fetched**
    mock_get.assert_called_once_with(
        "https://api.github.com/user",
        headers={
            'Authorization': 'token mock_access_token',
            'Accept': 'application/vnd.github.v3+json'
        },
        timeout=10
    )

    # **Verify session was saved**
    session_data = load_session()
    assert session_data is not None
    assert session_data['username'] == "test_user"
    assert session_data['email'] == "test@example.com"
    print("[DEBUG] GitHub login redirect test completed.")

@patch('src.auth.github_oauth.requests.get')
def test_get_github_user(mock_get, setup_session):
    """ Test fetching user information from GitHub. """
    print("[DEBUG] Starting GitHub user fetch test...")
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"login": "test_user", "email": "test@example.com"}
    mock_get.return_value = mock_response

    user_info = get_github_user("mocked_token")
    print(f"[DEBUG] Received user info: {user_info}")
    assert user_info['login'] == "test_user"
    assert user_info['email'] == "test@example.com"
    print("[DEBUG] GitHub user fetch test completed.")

def test_logout(setup_session):
    """ Test if logout clears session data. """
    print("[DEBUG] Starting logout test...")
    # Mock session data
    session_data = {"username": "test_user", "email": "test@example.com"}
    clear_session()
    logout()
    assert load_session() is None
    print("[DEBUG] Logout test completed.")
