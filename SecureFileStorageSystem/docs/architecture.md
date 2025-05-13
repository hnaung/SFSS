# **Secure File Storage System (SFSS) - Architecture Documentation**

## **Overview**

The **Secure File Storage System (SFSS)** is designed to provide a
highly secure and efficient mechanism for uploading, storing, and
retrieving files using AES-256 encryption and GitHub OAuth for
authentication. This document outlines the architectural design,
including:

-   **OAuth Flow** --- Overview of OAuth Github Authentication flow.

-   **High-Level Design (HLD)** --- Overview of core components.

-   **Low-Level Design (LLD)** --- Detailed breakdown of modules and interactions.

-   **Data Flow** --- Representation of data movement within the application.

## **OAuth Flow**
The OAuth Flow outlines how user authentication is handled via GitHub OAuth in the Secure File Storage System (SFSS). It ensures secure and seamless login while protecting sensitive data.

### **Flow Steps**
1.  **User Initiates Login**

    - The user triggers the sfss login command via the CLI.

    - The system redirects the user to the GitHub OAuth authorization page.

2.  **GitHub Authorization**

    - The user logs in with GitHub credentials.

    - GitHub prompts the user to grant permission to the SFSS application.

3.  **OAuth Token Exchange**

    - After successful authentication, GitHub redirects to the specified callback URL.

    - The authorization code is sent to the backend via a secure HTTPS request.

4. **Access Token Retrieval**

    - The system exchanges the authorization code for an access token.

    - The access token is stored securely in the user session.

5.  **Authenticated Session**

    - The system stores the token in a secure session.

    - Subsequent API requests are made using this token for authentication.

6. **Token Validation**

    - The token's validity is periodically checked.

    - If expired, the user is prompted to reauthenticate.

7. **Secure Logout**

    - The user logs out, and the session is invalidated.

    - The access token is securely wiped from the system.

**OAuthFlow**  
<img src="./OAuthFlow.png" alt="OAuth Flow" width="600"/>

## **High-Level Design (HLD)**

The High-Level Design represents the major components of the **Secure File Storage System (SFSS)** and their interactions. The primary components are:

---

### 1. **Auth Service (GitHub OAuth Device Flow)**
- Manages user authentication securely using **GitHub OAuth Device Flow**.
- Generates **access tokens** upon successful authorization.
- Tokens are securely stored and managed within the session handler.
**Location:** `src/auth/github_oauth.py`
---

### 2. **Encryption/Decryption Service**
- Manages **secure file encryption and decryption** using **AES-256-GCM** with HMAC validation.
- Ensures **confidentiality** and **integrity** of data through:
    - AES-256 encryption with a **random IV** (Initialization Vector).
    - HMAC-based integrity checks for tamper detection.
- Supports **secure deletion** of sensitive files by:
    - Overwriting the file with random data before removal.

**Core Functions:**
- **generate_key()** → Creates a secure AES key and HMAC key.
- **encrypt_file()** → Encrypts the contents of a file and stores the encrypted data.
- **decrypt_file()** → Decrypts an encrypted file and verifies its integrity using HMAC.
- **secure_delete()** → Overwrites and removes sensitive files securely.

**Location:** `src/storage/encryptor.py`

### 3. **File Manager Service**
- Manages **file operations** for the Secure File Storage System (SFSS), including:
    - **Upload:** Encrypts the file and stores it securely.
    - **Download:** Decrypts the file for user access.
    - **List:** Displays all securely stored files.
    - **Delete:** Removes files securely along with associated metadata.

**Workflow:**
1. **Upload Process:**
   - Validates file path and file extension.
   - Encrypts the file using **AES-256-GCM**.
   - Generates and stores metadata (keys, IV, HMAC) securely.
   - Saves the encrypted file in the **secure storage directory**.

2. **Download Process:**
   - Validates file existence.
   - Decrypts the file using the stored keys and IV.
   - Ensures integrity through HMAC verification.

3. **Listing Files:**
   - Lists all files stored in the secure directory.
   - Displays decrypted filenames only (no raw encrypted file names).

4. **Deletion Process:**
   - Deletes the encrypted file and associated metadata.
   - Uses **secure delete** to wipe file data before removal.

**Core Functions:**
- **upload_file()** → Securely uploads and encrypts a file.
- **download_file()** → Decrypts and retrieves a file from secure storage.
- **list_files()** → Lists all stored encrypted files.
- **delete_file()** → Securely deletes a file and its metadata.

**Location:** `src/storage/file_manager.py`

### 4. **Metadata Handler Service**
- Manages the **secure storage and retrieval of encryption keys, IVs, and HMAC values** for each encrypted file.
- Ensures that encryption metadata is stored securely and only accessible to authorized processes.

**Core Functions:**
- **save_encryption_metadata()** → Stores encryption keys and IV securely.
- **load_encryption_key()** → Retrieves the encryption key from local storage.
- **load_hmac_key()** → Retrieves the HMAC key for integrity checks.
- **load_iv()** → Loads the Initialization Vector (IV) for decryption.
- **remove_encryption_metadata()** → Deletes metadata associated with a file after successful deletion.

**Metadata Structure:**
- Stored as a JSON file in the `~/.sfss/keys/` directory.
- Each metadata file contains:
    - **key** → AES encryption key (hex-encoded).
    - **hmac_key** → HMAC key for integrity (hex-encoded).
    - **iv** → Initialization Vector for GCM mode (hex-encoded).

**Location:** `src/storage/metadata_handler.py`

### 5. **Session Management Service**
- Manages **session creation, storage, and expiration**.
- Uses **Fernet symmetric encryption** to encrypt and decrypt session data.
- Enforces **session expiry** based on predefined time in the `.env`.
- Prevents session tampering by verifying integrity during decryption.
- Handles:
    - **Session Save** → Encrypts session data and saves it to disk.
    - **Session Load** → Decrypts session data and validates it.
    - **Session Refresh** → Extends the session expiration time.
    - **Session Clear** → Securely wipes the session from storage.

**Location:** `src/utils/session_handler.py`

---

### 6. **Logger Service**
- Manages secure logging with:
    - **Sensitive Data Masking** (e.g., secrets, tokens).
    - **Rotating Logs** to avoid excessive log growth.
    - **Audit Trails** for all critical operations (upload, delete, authentication).
- Ensures logs are tamper-proof and readable only with appropriate permissions.

**Location:** `src/utils/logger.py`

---

### 7. **Rate Limiter Service**
- Protects the system from abuse by:
    - **Limiting CLI command executions** to prevent brute force attempts.
    - Tracking command counts and enforcing limits based on configured policies.
    - Ensuring fair usage for multi-session environments.

**Location:** `src/utils/rate_limiter.py`

---

### 8. **Validation Service**
- Ensures all file paths and filenames are validated securely before processing:
    - Prevents **Path Traversal Attacks**.
    - Only allows **approved file extensions** to be uploaded or downloaded.
    - Blocks access to sensitive system paths (e.g., `/etc`, `/bin`, `C:\Windows`).
    - Sanitizes filenames to remove forbidden characters and null bytes.
    - Validates maximum path length to avoid OS-level overflows.

**Location:** `src/utils/validators.py`

**Key Functions:**
- `is_valid_path()`: Securely validates the path to prevent directory traversal.
- `is_allowed_file_extension()`: Ensures only whitelisted file types are accepted.
- `sanitize_filename()`: Cleans and normalizes filenames to prevent injections.

**High Level Design**  
<img src="./HLD.png" alt="High-Level Design" width="600"/>

## **Low-Level Design (LLD)**

The Low-Level Design dives deeper into the implementation specifics of
each component:

### **Auth Service (src/auth/)**

-   github_oauth.py: Manages OAuth authentication.

-   token_manager.py: Generates and validates session tokens.

### **Storage Service (src/storage/)**

-   encryptor.py:

    -   encrypt_file(): Encrypts files using AES-256.

    -   decrypt_file(): Decrypts files for download.

-   file_manager.py:

    -   store_file(): Saves encrypted files.

    -   fetch_file(): Retrieves files for download.

### **File Manager (src/storage/file_manager.py)**

-   upload(): Encrypts and stores the file.

-   download(): Decrypts and retrieves the file.

-   list_files(): Lists all encrypted files.

-   delete_file(): Securely removes the file from storage.

### **Logger Service (src/utils/logger.py)**

-   log_event(): Records application events.

-   log_error(): Captures errors and exceptions.

### **Rate Limiter (src/utils/rate_limiter.py)**

-   check_rate_limit(): Validates API usage to prevent abuse.

**Low Level Design**  
![LLD](./LLD.png)

### **Data Flow Overview**
The **sfss_cli.py** serves as the **entry point** for all user commands. It handles:
- **Session Validation** → Verifies user authentication before any action.
- **Command Execution** → Triggers the appropriate service (`upload`, `download`, `list`, `delete`).
- **Error Handling and Logging** → Manages errors gracefully and logs every action.

---
### **CLI Command Flow**
1. **User Input →** The user executes a command like `sfss upload <file_path>`.
2. **Session Verification →** The CLI checks for a valid OAuth session.
3. **Command Routing →** 
   - If valid, it routes the request to the correct handler:
     - Upload → `upload_file()` in `file_manager.py`
     - Download → `download_file()` in `file_manager.py`
     - List → `list_files()` in `file_manager.py`
     - Delete → `delete_file()` in `file_manager.py`
4. **Action Logging →** All actions are logged for traceability and auditing.
5. **Output Display →** CLI provides real-time feedback to the user.

**Data Flow**  
<img src="./DataFlow.png" alt="Data Flow" width="600"/>

---
### 9. **Command Line Interface (CLI) - src/sfss_cli.py**
- The `sfss_cli.py` is the main interface for interacting with the **Secure File Storage System (SFSS)**.
- It provides a **command-driven interface** for performing secure file operations and session management.

**Core Commands:**
- **sfss login** → Initiates the GitHub OAuth Device Flow for authentication.
- **sfss logout** → Clears the current OAuth session and removes credentials.
- **sfss status** → Displays the current session status.
- **sfss upload <file_path>** → Encrypts and uploads the specified file.
- **sfss download <file_name> <output_path>** → Decrypts and downloads the specified file.
- **sfss list** → Lists all encrypted files currently in secure storage.
- **sfss delete <file_name>** → Securely deletes the specified file.

**Internal Interactions:**
- **OAuth Authentication** → Uses `github_oauth.py` for login and session management.
- **File Operations** → Interacts with `file_manager.py` for upload, download, list, and delete.
- **Session Handling** → Validates user session before any action.
- **Logging** → Logs every command execution with proper event tracking.

**Location:** `src/sfss_cli.py`
---
### **Interaction Overview**
| Component                 | Interacts With                 | Purpose                              |
|----------------------------|--------------------------------|--------------------------------------|
| **CLI Interface**         | File Manager, OAuth Service, Session Handler | Main entry point for user interactions |
| **Auth Service**          | GitHub OAuth API               | User Authentication                  |
| **Encryption Service**    | File Manager, Metadata Handler | Encrypts and decrypts file contents  |
| **File Manager**          | Encryption Service, Metadata Handler | Manages file operations and storage  |
| **Session Management**    | Auth Service, File Manager     | Secure session storage and refresh   |
| **Logger Service**        | All Components                 | Audit logging and error tracking     |
| **Rate Limiter**          | CLI Commands                   | Prevents abuse and brute force       |
| **Validation Service**    | File Manager, Storage Service  | Path and filename validation         |
| **Metadata Handler**      | Encryption Service, File Manager | Stores and retrieves encryption keys |
## **Security Considerations**

The **Secure File Storage System (SFSS)** enforces multiple layers of security to protect both data and operations:

### **1. OAuth 2.0 Device Flow Authentication**
   - Uses GitHub's **Device Flow** for secure, CLI-based authentication.
   - Prevents unauthorized access with secure token handling.

### **2. AES-256-GCM File Encryption**
   - Ensures that files are encrypted with **AES-256** before storage.
   - Galois/Counter Mode (GCM) provides both **encryption** and **integrity checks**.
   - Uses **HMAC (SHA-256)** to prevent tampering.

### **3. Session Management and Expiry**
   - Encrypted sessions are stored locally using **Fernet symmetric encryption**.
   - Sessions expire automatically based on environment settings to limit exposure.

### **4. Path and Filename Validation**
   - Prevents:
       - **Path traversal attacks**
       - **Access to restricted directories**
       - **Null byte and path injection vulnerabilities**
   - Sanitizes filenames to prevent unauthorized modifications.

### **5. Secure Metadata Storage**
   - Encryption keys, HMAC keys, and IVs are stored securely in:
       - `~/.sfss/keys/`
   - Protected with strict file permissions (`600`).

### **6. Rate Limiting**
   - Enforces rate limits on CLI commands to:
       - Prevent brute force attacks.
       - Limit abuse of the upload, download, and delete functionalities.

### **7. Secure Audit Logging**
   - All events are logged with:
       - **Masked sensitive data**
       - **Rotating logs** to prevent log overflow
       - Strict access control to log files

---