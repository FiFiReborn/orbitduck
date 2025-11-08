# src/orbitduck/utils/controls.py
import os
import time
import threading
from pathlib import Path
from typing import Set

# -----------------------------
#  Allowlist Handling
# -----------------------------
def load_allowlist() -> Set[str]:
    """
    Load allowlist entries from ORBIT_ALLOWLIST or an allowlist.txt file.
    """
    allowlist = set()

    # From environment variable (comma separated)
    env_allow = os.getenv("ORBIT_ALLOWLIST", "")
    if env_allow:
        allowlist.update([t.strip() for t in env_allow.split(",") if t.strip()])

    # From file (optional)
    file_path = os.getenv("ORBIT_ALLOWLIST_FILE", "config/allowlist.txt")
    path = Path(file_path)
    if path.exists():
        for line in path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                allowlist.add(line)

    return allowlist


def is_allowed(target: str, allowlist: Set[str]) -> bool:
    """
    Returns True if the target is in the allowlist (or allowlist is empty).
    """
    if not allowlist:
        return True  # no allowlist means allow everything
    return target in allowlist


# -----------------------------
#  Rate Limiter
# -----------------------------
class RateLimiter:
    """
    Basic token-bucket rate limiter.
    Example: limiter = RateLimiter(rate_per_min=30)
             limiter.wait_for_slot()
    """
    def __init__(self, rate_per_min: int = 30):
        self.rate_per_min = rate_per_min
        self.interval = 60.0 / rate_per_min
        self._lock = threading.Lock()
        self._last_request = 0.0

    def wait_for_slot(self):
        with self._lock:
            now = time.time()
            elapsed = now - self._last_request
            if elapsed < self.interval:
                time.sleep(self.interval - elapsed)
            self._last_request = time.time()