"""
Shared utility functions for screenshot tools (gowitness_screenshot, brand_monitor_screenshot).
"""

import glob as _glob
import hashlib
import shutil
from typing import Optional


def find_chrome_path() -> Optional[str]:
    """Find a Chrome/Chromium binary path for GoWitness."""
    if shutil.which('google-chrome'):
        return None  # GoWitness will find it automatically
    candidates = _glob.glob('/root/.cache/ms-playwright/*/chrome-linux/chrome')
    if candidates:
        return candidates[0]
    return None


def compute_sha256(file_path: str) -> str:
    """Compute SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            sha256.update(chunk)
    return sha256.hexdigest()
