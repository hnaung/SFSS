# src/auth/github_oauth.py

"""
GitHub OAuth authentication for Secure File Storage System (SFSS), including device flow and token handling.
"""

import os
import requests
import time
from urllib.parse import parse_qs
from src.utils.session_handler import save_session, load_session, clear_session, refresh_session
from src.config import OAUTH_CLIENT_ID, OAUTH_CLIENT_SECRET, OAUTH_REDIRECT_URI
from src.utils.logger import log_event

print("[DEBUG] github_login called") 
log_event("INFO", "Starting GitHub Device Login...")

# OAuth URLs
GITHUB_DEVICE_URL = os.getenv("GITHUB_DEVICE_URL", "https://github.com/login/device/code")
GITHUB_TOKEN_URL = os.getenv("GITHUB_TOKEN_URL", "https://github.com/login/oauth/access_token")
GITHUB_API_URL = os.getenv("GITHUB_API_URL", "https://api.github.com/user")


# Configuration
MAX_RETRIES = 30
RETRY_INTERVAL = 5
MAX_POLL_RATE = 5


def github_login():
    """
    Initiates GitHub OAuth login using the Device Flow.
    If a valid session already exists, re-login is not required.
    """
    # Check for an existing valid session
    session_data = load_session()
    if session_data:
        print(f"[INFO] Already logged in as {session_data['username']}")
        return

    log_event("INFO", "Starting GitHub Device Login...")

    # Step 1: Request Device Code from GitHub
    try:
        response = requests.post(
            GITHUB_DEVICE_URL,
            data={"client_id": OAUTH_CLIENT_ID, "scope": "user:email read:user"},
            headers={"Accept": "application/json"},
            timeout=10,
        )

        log_event("DEBUG", f"Response Status: {response.status_code}")
        log_event("DEBUG", f"Response Content: {response.text}")
    except requests.RequestException as e:
        log_event("ERROR", f"Network error during OAuth request: {str(e)}")
        return

    if response.status_code != 200:
        log_event("ERROR", f"Failed to initiate device login. Status: {response.status_code}")
        log_event("ERROR", f"Response Content: {response.text}")
        return

    # Parse the response and validate required keys
    try:
        device_data = response.json()
        required_keys = ["verification_uri", "user_code", "interval", "device_code"]
        if not all(k in device_data for k in required_keys):
            log_event("ERROR", "Invalid OAuth response structure.")
            log_event("DEBUG", f"Device Data Content: {device_data}")
            return
    except ValueError as ve:
        log_event("ERROR", f"Failed to parse JSON response: {str(ve)}")
        log_event("ERROR", f"Response Content: {response.text}")
        return

    # Display URL and code to the user with a security tip
    interval = int(device_data["interval"])
    verification_uri = device_data["verification_uri"]
    user_code = device_data["user_code"]

    print(f"[SECURITY TIP] Make sure the domain is correct: {verification_uri}")
    print(f"[INFO] Visit this URL in your browser to authenticate:")
    print(f"{verification_uri}")
    print(f"[INFO] Enter this code: {user_code}\n")

    # Start polling for authorization
    log_event("INFO", "Waiting for authorization...")
    poll_for_token(device_data, interval)


def poll_for_token(device_data, interval):
    """
    Polls GitHub for the access token using the provided device code.
    Implements rate limiting and retries for better API management.
    """
    retries = 0

    while retries < MAX_RETRIES:
        time.sleep(interval)

        # Rate limit to prevent GitHub API abuse
        if retries % MAX_POLL_RATE == 0 and retries != 0:
            print("[WARNING] Too many attempts, slowing down to avoid rate limit.")
            # Cooldown for 1 minute
            time.sleep(60)

        try:
            token_response = requests.post(
                GITHUB_TOKEN_URL,
                data={
                    "client_id": OAUTH_CLIENT_ID,
                    "device_code": device_data["device_code"],
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                },
                headers={"Accept": "application/json"},
                timeout=10  # Add a timeout to prevent hanging requests
            )

            # Check if the request was successful
            token_response.raise_for_status()
            log_event("DEBUG", f"Token Response: {token_response.text}")

        except requests.Timeout:
            log_event("ERROR", "Request to GitHub API timed out. Retrying...")
            retries += 1
            continue

        except requests.RequestException as e:
            log_event("ERROR", f"Network error during token request: {str(e)}")
            retries += 1
            continue

        log_event("DEBUG", f"Token Response: {token_response.text}")

        if token_response.status_code == 200 and "access_token" in token_response.json():
            token_data = token_response.json()
            log_event("INFO", "GitHub Authentication Successful.")
            user_info = get_github_user(token_data["access_token"])
            if user_info:
                session_data = {
                    "username": user_info["login"],
                    "email": user_info.get("email", "N/A"),
                    "github_id": user_info["id"],
                    "token": token_data["access_token"],
                }
                save_session(session_data)
                # Refresh session after successful authentication
                refresh_session()
                log_event("INFO", f"Session created for user {user_info['login']}")
            return

        error = token_response.json().get("error")
        if error == "authorization_pending":
            log_event("INFO", "Waiting for you to authenticate...")
            retries += 1
        elif error == "slow_down":
            interval += 5
            log_event(
                "WARNING",
                f"GitHub asked to slow down polling. Increasing interval to {interval} seconds.",
            )
        else:
            log_event("ERROR", f"Token request failed: {token_response.json()}")
            return

    log_event("ERROR", "Authorization timed out. Please try again.")


def get_github_user(token):
    """
    Fetches user information from GitHub securely using the access token.
    """
    headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"}
    try:
        response = requests.get(GITHUB_API_URL, headers=headers, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        log_event("ERROR", f"Failed to fetch user info: {str(e)}")
        return None


def logout():
    """
    Clears the stored encrypted token and session.
    """
    try:
        clear_session()
        print("[INFO] Successfully logged out.")
        log_event("INFO", "User logged out successfully.")
    except Exception as e:
        log_event("ERROR", f"Error during logout: {str(e)}")
