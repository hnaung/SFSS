import time
from functools import wraps
from src.utils.logger import log_event

# Rate Limiting Configuration
MAX_REQUESTS = 5
WINDOW_TIME = 5  # Time window in seconds
ATTEMPT_STORAGE = {}


def rate_limit(api_key):
    """
    Limits the number of requests to prevent brute-force attacks.

    Args:
        api_key (str): A unique identifier for the user or API.

    Returns:
        bool: True if the request is allowed, False otherwise.
    """
    current_time = int(time.time())

    # Initialize if not present
    if api_key not in ATTEMPT_STORAGE:
        ATTEMPT_STORAGE[api_key] = []

    # Remove old timestamps outside the window
    ATTEMPT_STORAGE[api_key] = [
        timestamp
        for timestamp in ATTEMPT_STORAGE[api_key]
        if timestamp > current_time - WINDOW_TIME
    ]

    # Check current count
    if len(ATTEMPT_STORAGE[api_key]) >= MAX_REQUESTS:
        log_event("WARNING", f"Rate limit exceeded for API Key: {api_key}")
        return False

    # Log the new attempt with timestamp
    ATTEMPT_STORAGE[api_key].append(current_time)
    log_event("INFO", f"Request allowed for API Key: {api_key} at {current_time}")
    return True


def rate_limited(api_key):
    """
    Decorator to automatically rate-limit a function.
    """

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not rate_limit(api_key):
                log_event("WARNING", f"Rate limit exceeded for API Key: {api_key}")
                print(f"[WARNING] Rate limit exceeded. Try again in {WINDOW_TIME} seconds.")
                return None
            return func(*args, **kwargs)

        return wrapper

    return decorator
