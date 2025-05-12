# src/utils/validators.py

"""
Input validation utilities for Secure File Storage System (SFSS), including path traversal prevention and filename sanitization.
"""

import os
import re
from pathlib import PureWindowsPath, Path
from src.utils.logger import log_event
from sys import platform


# Allowed file extensions
ALLOWED_EXTENSIONS = {
    ".txt",
    ".pdf",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".csv",
    ".json",
    ".xml",
    ".yaml",
    ".yml",
    ".md",
    ".log",
    ".zip",
}

# Forbidden paths based on OS detection
FORBIDDEN_PATHS = {"/etc/", "/bin/", "/usr/", "/boot/", "/lib/", "/sbin/", "/dev/"}

if platform == "win32":
    FORBIDDEN_PATHS.update(
        {
            "C:\\Windows\\",
            "C:\\Program Files\\",
            "C:\\Windows\\System32",
            "C:\\Program Files (x86)\\",
        }
    )

# Lock to project root
PROJECT_ROOT = Path.cwd()

# Path traversal and null byte patterns
FORBIDDEN_PATTERNS = [
    r"(\.\./|\.\.\\)",  # Prevent directory traversal
    r"[\x00]",  # Null byte injection
    r":",  # Path injection (Windows)
    r"\s",  # Whitespace
    r"\\\\\?\\UNC\\",  # UNC path
    r"^\.$",  # Current directory
    r"^\./$",  # Relative current directory
    r"^\././././$",  # Repetitive traversal
    r"\?|\*|\<|\>|\|",  # Forbidden characters
]

# Add Windows drive letter protection if not on Windows
if platform != "win32":
    FORBIDDEN_PATTERNS.append(r"^[A-Za-z]:\\")


def is_valid_path(file_path):
    """
    Validates if the file path is secure and prevents directory traversal.
    """
    # 1. Check for forbidden patterns
    for pattern in FORBIDDEN_PATTERNS:
        if re.search(pattern, file_path):
            log_event("WARNING", f"Path traversal or invalid character detected: {file_path}")
            return False

    # 2. Normalize path and get the real path
    try:
        abs_path = Path(file_path).resolve(strict=False)
        abs_real_path = abs_path.resolve()
    except Exception as e:
        log_event("ERROR", f"Path resolution failed for '{file_path}': {str(e)}")
        return False

    # 3. Prevent forbidden directories
    for forbidden in FORBIDDEN_PATHS:
        if str(abs_real_path).startswith(forbidden):
            log_event("WARNING", f"Access to forbidden path detected: {abs_real_path}")
            return False

    # 4. Allow only paths within the current working directory
    try:
        abs_real_path.relative_to(Path.cwd())
    except ValueError:
        log_event("WARNING", f"Path is outside the allowed directory: {abs_real_path}")
        return False

    # 5. Prevent access to system root but allow project root
    if abs_real_path == Path("/").resolve() or abs_real_path == Path("C:\\").resolve():
        log_event("WARNING", f"Access to system root directory is not allowed: {abs_real_path}")
        return False

    # 6. Prevent paths that are "." or empty string or just whitespace
    if abs_real_path.name.strip() == "" or abs_real_path.name == ".":
        log_event("WARNING", f"Empty or current directory path is not valid: {abs_real_path}")
        return False

    # 7. Path length validation (security hardening)
    try:
        max_length = os.pathconf(str(abs_real_path), "PC_PATH_MAX")
        if len(str(abs_real_path)) > max_length:
            log_event("WARNING", f"Path exceeds maximum length: {abs_real_path}")
            return False
    except Exception as e:
        log_event("ERROR", f"Path length check failed: {str(e)}")
        return False

    # 8. Final validation passed
    log_event("INFO", f"Path validated successfully: {abs_real_path}")
    return True


def is_allowed_file_extension(filename):
    """
    Validates if the file extension is allowed.
    """
    _, ext = os.path.splitext(filename)
    if ext.lower() in ALLOWED_EXTENSIONS:
        log_event("INFO", f"File extension validated: {ext}")
        return True
    else:
        log_event("WARNING", f"File extension '{ext}' is not allowed.")
        return False


# Invalid characters for file names
INVALID_CHARS = r'[<>:"/\\|?*]'
RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    "COM1",
    "COM2",
    "COM3",
    "COM4",
    "COM5",
    "COM6",
    "COM7",
    "COM8",
    "COM9",
    "LPT1",
    "LPT2",
    "LPT3",
    "LPT4",
    "LPT5",
    "LPT6",
    "LPT7",
    "LPT8",
    "LPT9",
}

def sanitize_filename(filename: str) -> str:
    """
    Sanitize the filename:
    - Remove path traversal components.
    - Remove invalid characters.
    - Handle reserved Windows names.
    - Ensure the filename is not empty or invalid.
    - Limit length to 251 characters.
    """
    # Normalize paths and remove backslashes or forward slashes
    filename = PureWindowsPath(filename).name if "\\" in filename else Path(filename).name

    # Remove invalid characters
    sanitized_name = re.sub(INVALID_CHARS, "", filename)

    # If it's a reserved name, add `_safe`
    if sanitized_name.upper() in RESERVED_NAMES:
        sanitized_name += "_safe"

    # Ensure it's not an empty string or just "."
    if not sanitized_name or sanitized_name == ".":
        sanitized_name = ""

    # Limit the filename to 251 characters
    MAX_FILENAME_LENGTH = 255

    # Ensure that the extension is considered in the max length calculation
    extension = Path(sanitized_name).suffix
    base_name = Path(sanitized_name).stem

    # Correctly truncate the base name to fit within the limit
    allowed_length = MAX_FILENAME_LENGTH - len(extension)
    if len(base_name) > allowed_length:
        base_name = base_name[:allowed_length]

    sanitized_name = base_name + extension

    return sanitized_name