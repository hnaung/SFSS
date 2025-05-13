# Secure File Storage System (SFSS)
[![SFSS](https://img.shields.io/badge/SFSS-Secure_File_Storage-black?logo=github)](https://github.com/hnaung/SFSS)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue)](https://docs.python.org/3/whatsnew/3.8.html)
[![Auth: GitHub OAuth Device Flow](https://img.shields.io/badge/Auth-GitHub_OAuth_Device_Flow-blue)](https://docs.github.com/en/developers/apps/building-oauth-apps/authorizing-oauth-apps#device-flow)
[![Security: AES-256-GCM](https://img.shields.io/badge/Security-AES--256--GCM-brightgreen)](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
[![Storage: Secure Metadata](https://img.shields.io/badge/Storage-Encrypted_Metadata_%26_Keys-important)](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
[![Sessions: Fernet Encrypted](https://img.shields.io/badge/Sessions-Fernet_Encrypted-yellowgreen)](https://cryptography.io/en/latest/fernet/)
---
## Current Features
- **Authentication**: GitHub OAuth Device Flow Authentication
- **Encryption**: AES-256 file encryption
- **File Operations**: Secure upload/download/list/delete
- **Audit Trail**: Comprehensive activity logging
- **Security**: Input validation, rate limiting, and sensitive data masking
- **CLI Interface**: Command-line management tool
---
## Authentication Setup

### **GitHub OAuth Device Flow Authentication Configuration**
To configure GitHub OAuth for the Secure File Storage System (SFSS):

1. Go to your GitHub account:
   - Navigate to **Settings → Developer settings → OAuth Apps → New OAuth App**.

2. Fill in the following details:
   - **Application Name:** SFSS
   - **Homepage URL:** `http://localhost:5000`
   - **Authorization callback URL:** `http://localhost:5000/callback`
   - **Enable Device Flow** in your **OAuth app settings**.
---
## Quick Start
```bash
# Clone the repository
git clone https://github.com/hnaung/SFSS
cd SecureFileStorageSystem

# Set up virtual environment
python3.8 -m venv venv
source venv/bin/activate

# Install dependencies
pip install e .

# Generate App SECRET_KEY
python3 -c 'import secrets; print(secrets.token_urlsafe(32))'
xxxxxxx

# Copy .env template and configure
cp .env.template .env

# Update a `.env` file in the root directory and add the following environment variables:
OAUTH_CLIENT_ID=your_client_id
OAUTH_CLIENT_SECRET=your_client_secret
SECRET_KEY=your_app_secret_key

# CLI Commands

# Login to GitHub
sfss --help

# Login to GitHub
sfss login

# Upload a file
sfss upload <file_path>

# List all encrypted files
sfss list

# Download a file
sfss download <file_name>

# Delete a file
sfss delete <file_name>
```
---
## Directory Structure
```plaintext
SecureFileStorageSystem/
├── src/
│   ├── auth/                 # GitHub OAuth logic
│   ├── storage/              # File encryption and management
│   ├── utils/                # Utility functions and logging
│   └── sfss_cli.py           # Main CLI application
│
├── tests/
│   ├── integration/          # Integration tests
│   └── unit/                 # Unit tests
│
├── logs/                     # Application logs
│   └── app.log
│
├── .env.template             # Environment variable template
├── README.md                 # Project documentation
├── setup.py                  # Installation script
├── requirements.txt          # Dependencies
└── pyproject.toml            # Build configuration
```
---
## Evaluation Criteria Alignment
| Requirement              | Implementation File           | Key Functions                   |
|---------------------------|--------------------------------|--------------------------------|
| Secure File Encryption   | src/storage/encryptor.py       | encrypt_file(), decrypt_file()  |
| GitHub OAuth             | src/auth/github_oauth.py       | get_oauth_token()               |
| Audit Logging            | src/utils/logger.py            | log_event()                     |
| Rate Limiting            | src/utils/rate_limiter.py      | check_rate_limit()              |
| Validation and Sanitization | src/utils/validators.py       | is_valid_path(), sanitize_filename() |
---
## Security Considerations
- AES-256 Encryption for secure file storage
- OAuth 2.0 for secure authentication with GitHub
- Input Validation to prevent path traversal and unauthorized access
- Rate Limiting to mitigate brute force attempts
- Sensitive Data Masking in logs for privacy protection
---
## Testing
```bash
# Run unit tests
pytest tests/unit -v

# Run integration tests
pytest tests/integration -v
```
---
## Architecture & Design Consideration Documentation
For a detailed explanation of the architecture, please refer to:
- [Architecture Documentation](SecureFileStorageSystem/docs/architecture.md)

The following diagrams are included:
- **OAuth Flow:** 
- **High-Level Design (HLD):** 
- **Low-Level Design (LLD):** 
- **Data Flow:** 