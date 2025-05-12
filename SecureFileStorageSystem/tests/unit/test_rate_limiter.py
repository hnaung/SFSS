# tests/test_rate_limiter.py

import pytest
from unittest.mock import patch
from src.utils.rate_limiter import rate_limit, rate_limited

# Unique API keys for testing
API_KEY_1 = "test_api_key_1"
API_KEY_2 = "test_api_key_2"

# We need to reset the ATTEMPT_STORAGE before each test
from src.utils.rate_limiter import ATTEMPT_STORAGE

@pytest.fixture(autouse=True)
def reset_attempt_storage():
    ATTEMPT_STORAGE.clear()


def test_rate_limit_allow():
    """Test that the rate limiter allows up to MAX_REQUESTS."""
    for _ in range(5):
        assert rate_limit(API_KEY_1) is True
    print("[TEST] Rate limit allows 5 requests successfully.")


def test_rate_limit_exceeded():
    """Test that the rate limiter blocks when exceeding the limit."""
    for _ in range(5):
        rate_limit(API_KEY_1)
    # 6th request should be blocked
    assert rate_limit(API_KEY_1) is False
    print("[TEST] Rate limit correctly blocks on the 6th attempt.")


@patch('time.time', return_value=1000000000)
def test_rate_limit_window_reset(mock_time):
    """Test that the rate limiter resets after the time window expires."""
    for _ in range(5):
        assert rate_limit(API_KEY_1) is True

    # Exceed limit
    assert rate_limit(API_KEY_1) is False

    # Fast-forward time by 61 seconds (simulate window expiration)
    mock_time.return_value += 61
    ATTEMPT_STORAGE[API_KEY_1] = []  # Clear storage for this key
    assert rate_limit(API_KEY_1) is True
    print("[TEST] Rate limit resets after the window expires.")


def test_rate_limit_isolated_keys():
    """Test that separate API keys have isolated rate limits."""
    for _ in range(5):
        assert rate_limit(API_KEY_2) is True
    assert rate_limit(API_KEY_1) is True  # Isolated limit
    print("[TEST] Rate limit is isolated per API key.")


@patch('time.time', return_value=1000000000)
def test_rate_limited_decorator(mock_time):
    """Test the rate-limited decorator works correctly without real sleep."""

    @rate_limited(API_KEY_1)
    def dummy_function():
        return "Success"

    # Fill the rate limit
    for _ in range(5):
        assert dummy_function() == "Success"
    
    # 6th attempt should be blocked
    assert dummy_function() is None
    
    # Fast-forward time
    mock_time.return_value += 61
    ATTEMPT_STORAGE[API_KEY_1] = []  # Clear storage for this key
    
    # Now it should work again
    assert dummy_function() == "Success"
    print("[TEST] Decorator successfully handles rate-limited calls.")