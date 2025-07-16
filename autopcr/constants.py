"""
Backward compatibility module for constants.

This module imports from the new config system to maintain backward compatibility
while reducing coupling and improving configuration management.
"""
from .config import (
    ROOT_DIR,
    CACHE_DIR,
    RESULT_DIR,
    DATA_DIR,
    CONFIG_PATH,
    OLD_CONFIG_PATH,
    AUTH_KEY,
    DEFAULT_HEADERS,
    IOS_HEADERS,
    refresh_headers
)
