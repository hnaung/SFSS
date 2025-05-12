# src/config.py

from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

# GitHub OAuth Configuration
OAUTH_CLIENT_ID = os.getenv("OAUTH_CLIENT_ID")
OAUTH_CLIENT_SECRET = os.getenv("OAUTH_CLIENT_SECRET")
OAUTH_REDIRECT_URI = os.getenv("OAUTH_REDIRECT_URI")

# Encryption Key (32 bytes for AES-256)
SECRET_KEY = os.getenv("SECRET_KEY")

# Session Expiry
SESSION_EXPIRY = int(os.getenv("SESSION_EXPIRY", 3600))

# Logging Configuration
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_ROTATION_DAYS = int(os.getenv("LOG_ROTATION_DAYS", 7))

# Required environment variables list
REQUIRED_VARS = [
    'OAUTH_CLIENT_ID',
    'OAUTH_CLIENT_SECRET',
    'OAUTH_REDIRECT_URI',
    'SECRET_KEY'
]

# Environment validation check
for var in REQUIRED_VARS:
    if not os.getenv(var):
        print(f"[ERROR] Environment variable '{var}' is not set. Please configure it in your .env file.")
        exit(1)
