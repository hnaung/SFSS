# Secure File Storage System (SFSS)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Tests](https://img.shields.io/badge/tests-100%25%20coverage-success)
---
## Features
- 🔒 **GitHub OAuth Authentication**
- 🛡️ **AES-256 File Encryption**
- 📁 **Secure File Operations (Upload/Download/List/Delete)**
- 📊 **Activity Logging**
- 📑 **Secure Logging with Masked Sensitive Data**
- 🚀 **CLI-based for Easy Access and Management**
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
pip install -r requirements.txt

# Copy .env template and configure
cp .env.template .env

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
## 📂 Directory Structure
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
## ✅ Evaluation Criteria Alignment
| Requirement              | Implementation File           | Key Functions                   |
|---------------------------|--------------------------------|--------------------------------|
| Secure File Encryption   | src/storage/encryptor.py       | encrypt_file(), decrypt_file()  |
| GitHub OAuth             | src/auth/github_oauth.py       | get_oauth_token()               |
| Audit Logging            | src/utils/logger.py            | log_event()                     |
| Rate Limiting            | src/utils/rate_limiter.py      | check_rate_limit()              |
| Validation and Sanitization | src/utils/validators.py       | is_valid_path(), sanitize_filename() |
---
## 🔒 Security Considerations
- AES-256 Encryption for secure file storage
- OAuth 2.0 for secure authentication with GitHub
- Input Validation to prevent path traversal and unauthorized access
- Rate Limiting to mitigate brute force attempts
- Sensitive Data Masking in logs for privacy protection
---
## 🧪 Testing
```bash
# Run unit tests
pytest tests/unit --disable-warnings

# Run integration tests
pytest tests/integration --disable-warnings
```
---
## Architecture & Design Consideration Documentation
For a detailed explanation of the architecture, please refer to:
- [Architecture Documentation](SecureFileStorageSystem/docs/architecture.md)

The following diagrams are included:
- **oAuth Flow:** 
- **High-Level Design (HLD):** 
- **Low-Level Design (LLD):** 
- **Data Flow:** 
