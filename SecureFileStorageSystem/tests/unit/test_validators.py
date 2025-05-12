# tests/test_validators.py

import pytest
from unittest.mock import patch
from src.utils.validators import is_valid_path, is_allowed_file_extension, sanitize_filename
from pathlib import Path


# Test Cases for is_valid_path
@pytest.mark.parametrize("filename, sanitized", [
    ("../../secret/passwords.txt", "passwords.txt"),
    ("..\\..\\secret\\passwords.txt", "passwords.txt"),
    ("folder\\my_document.pdf", "my_document.pdf"),
    ("folder/file.txt", "file.txt"),
    ("normal_file.docx", "normal_file.docx"),
    ("<>:\"/\\|?*document.txt", "document.txt"),
    ("C:\\Windows\\System32\\cmd.exe", "cmd.exe"),
    ("some\\path\\to\\file<>.pdf", "file.pdf"),
    ("..\\..\\Windows\\System32\\drivers\\etc\\hosts", "hosts"),
    ("/etc/passwd", "passwd"),
    ("path\\to\\..\\another\\file.txt", "file.txt"),
    ("./folder//subfolder///file.txt", "file.txt"),
    ("CON", "CON_safe"),
    ("PRN", "PRN_safe"),
    ("LPT1", "LPT1_safe"),
    ("folder?name<>.txt", "foldername.txt"),
    ("\\\\?\\UNC\\server\\share\\file.txt", "file.txt"),
    ("./././././folder/file.txt", "file.txt"),
    ("", ""),    # Empty string should sanitize to empty, not "."
    ("<>:\"/\\|?*", ""),  # Completely illegal name should be empty
    ("a" * 300 + ".txt", "a" * 251 + ".txt"),  # Long filename fixed to max 251 chars
])
def test_sanitize_filename(filename, sanitized):
    """
    Test if filenames are sanitized correctly.
    """
    assert sanitize_filename(filename) == sanitized

# Test Cases for is_allowed_file_extension
@pytest.mark.parametrize("filename, expected", [
    ("document.pdf", True),
    ("image.png", True),
    ("archive.zip", True),
    ("malicious.exe", False),
    ("script.sh", False),
    ("file_with_no_extension", False),
    ("report.csv", True),
    ("backup.bat", False),
    ("unknown_file.bak", False),
    ("image.jpeg", True),
    ("config.yaml", True),
    ("sample.yml", True),
    ("example.tar.gz", False),
    ("example.TXT", True),  # Uppercase extension should pass
    ("example.PnG", True),   # Mixed case extension should pass
])
def test_is_allowed_file_extension(filename, expected):
    """
    Test if file extensions are correctly validated.
    """
    assert is_allowed_file_extension(filename) == expected


# Test Cases for sanitize_filename
@pytest.mark.parametrize("filename, sanitized", [
    ("../../secret/passwords.txt", "passwords.txt"),
    ("..\\..\\secret\\passwords.txt", "passwords.txt"),
    ("folder\\my_document.pdf", "my_document.pdf"),
    ("folder/file.txt", "file.txt"),
    ("normal_file.docx", "normal_file.docx"),
    ("<>:\"/\\|?*document.txt", "document.txt"),
    ("C:\\Windows\\System32\\cmd.exe", "cmd.exe"),
    ("some\\path\\to\\file<>.pdf", "file.pdf"),
    ("..\\..\\Windows\\System32\\drivers\\etc\\hosts", "hosts"),
    ("/etc/passwd", "passwd"),
    ("path\\to\\..\\another\\file.txt", "file.txt"),
    ("./folder//subfolder///file.txt", "file.txt"),
    ("CON", "CON_safe"),
    ("PRN", "PRN_safe"),
    ("LPT1", "LPT1_safe"),
    ("folder?name<>.txt", "foldername.txt"),
    ("\\\\?\\UNC\\server\\share\\file.txt", "file.txt"),
    ("./././././folder/file.txt", "file.txt"),
    ("", ""),  # Empty string should be empty, not "."
    ("<>:\"/\\|?*", ""),  # Completely illegal name should be empty
    ("a" * 300 + ".txt", "a" * 251 + ".txt"),  # Long filename fixed to max 251 chars
])
def test_sanitize_filename(filename, sanitized):
    """
    Test if filenames are sanitized correctly.
    """
    assert sanitize_filename(filename) == sanitized
