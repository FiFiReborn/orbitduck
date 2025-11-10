# src/orbitduck/modules/shodan_search.py
import os
import time
import httpx
import socket
import ipaddress
from typing import Dict
from threading import Lock
from pathlib import Path
from orbitduck.utils.io import write_report
import os
MOCK_MODE = os.getenv("ORBITDUCK_MOCK_MODE") == "1"


# -------------------------------
#  Allowlist + Rate-Limit Setup
# -------------------------------

_lock = Lock()

def _load_allowlist() -> set:
    """
    Load allowlist entries from ORBIT_ALLOWLIST (comma-separated) or a file
    specified by ORBIT_ALLOWLIST_FILE (default: config/allowlist.txt).
    If both are empty/not present, an empty set is returned (meaning "allow all").
    """
    allowlist = set()

    # From environment variable (comma-separated)
    env_allow = os.getenv("ORBIT_ALLOWLIST", "")
    if env_allow:
        for t in env_allow.split(","):
            t = t.strip()
            if t:
                allowlist.add(t)

    # From file (optional)
    file_path = os.getenv("ORBIT_ALLOWLIST_FILE", "config/allowlist.txt")
    path = Path(file_path)
    if path.exists():
        for line in path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                allowlist.add(line)

    return allowlist


# Rate limiter global state
_last_request_time = 0.0
_rate_per_min = int(os.getenv("SHODAN_RATE_PER_MIN", "30"))  # default 30 req/min
_min_interval = 60.0 / max(1, _rate_per_min)  # seconds between requests


def _wait_for_rate_limit():
    """
    Simple time-based rate limiter: ensures at least `_min_interval` seconds
    between successive requests. Uses a lock for thread-safety.
    """
    global _last_request_time
    with _lock:
        now = time.time()
        elapsed = now - _last_request_time
        if elapsed < _min_interval:
            time.sleep(_min_interval - elapsed)
        _last_request_time = time.time()


# -------------------------------
#  Helper: call Shodan endpoint
# -------------------------------
def _call_shodan_api(qtarget: str, api_key: str, save: bool = True) -> Dict:
    """
    Perform a single call to Shodan host endpoint for qtarget.
    On HTTP error, returns a dict with _http_error True and status/body for the caller to interpret.
    On success, returns the JSON data (and saves if requested).
    """
    url = f"https://api.shodan.io/shodan/host/{qtarget}?key={api_key}"
    try:
        resp = httpx.get(url, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        if save:
            out_path = f"reports/shodan_{qtarget}.json"
            write_report(data, out_path)
            data["_saved_to"] = out_path
        return data

    except httpx.HTTPStatusError as e:
        # Structured HTTP error for higher-level handling
        try:
            body = e.response.text
        except Exception:
            body = ""
        return {"_http_error": True, "status": e.response.status_code, "body": body}
    except Exception as e:
        return {"error": str(e)}


# -------------------------------
#  Shodan Lookup Function
# -------------------------------
def shodan_host_lookup(target: str, api_key: str | None = None, save: bool = True) -> Dict:
    """
    Query Shodan for information about a given IP or domain.
    Behaviors:
      - Uses allowlist and rate-limit.
      - On HTTP 403 (membership/permission), will attempt one retry resolving a hostname to its IP.
      - Returns either the Shodan JSON on success, or a structured error dict.
    """
    if api_key is None:
        api_key = os.getenv("SHODAN_API_KEY")

    if not api_key:
        return {"error": "Shodan API key missing. Set SHODAN_API_KEY in .env"}

    # --- Allowlist check ---
    allowlist = _load_allowlist()
    if allowlist and target not in allowlist:
        return {
            "error": f"Target '{target}' not allowed (not in allowlist)",
            "allowlist": sorted(list(allowlist)),
        }

    # --- Rate-limit enforcement ---
    _wait_for_rate_limit()

    # --- First attempt with the provided target ---
    res = _call_shodan_api(target, api_key, save=save)

    # If success, return data
    if isinstance(res, dict) and not res.get("_http_error") and "error" not in res:
        return res

    # If HTTP structured error, examine it
    if isinstance(res, dict) and res.get("_http_error"):
        status = res.get("status")
        body = res.get("body", "")

        # 401 = bad/invalid API key
        if status == 401:
            return {"error": "Shodan authentication failed (401). Check SHODAN_API_KEY", "detail": body}

        # 429 = rate-limited by Shodan
        if status == 429:
            return {"error": "Shodan rate limited (429). Slow your requests or adjust SHODAN_RATE_PER_MIN", "detail": body}

        # 403 = membership/permission required — try hostname->IP retry if reasonable
        if status == 403:
            # Determine if target is already an IP
            is_ip = False
            try:
                ipaddress.ip_address(target)
                is_ip = True
            except Exception:
                is_ip = False

            if not is_ip:
                # Attempt to resolve hostname -> IP and retry once
                try:
                    resolved_ip = socket.gethostbyname(target)
                    # rate-limit before retry as well
                    _wait_for_rate_limit()
                    retry_res = _call_shodan_api(resolved_ip, api_key, save=save)

                    # If retry succeeded, return it
                    if isinstance(retry_res, dict) and not retry_res.get("_http_error") and "error" not in retry_res:
                        retry_res["_resolved_from"] = target
                        return retry_res

                    # If retry also HTTP error, return informative message including both attempts
                    if isinstance(retry_res, dict) and retry_res.get("_http_error"):
                        return {
                            "error": "Shodan 403 — membership or permission required to access this resource",
                            "detail": body,
                            "retry_target": resolved_ip,
                            "retry_status": retry_res.get("status"),
                            "retry_body": retry_res.get("body"),
                        }

                    # If retry produced a non-HTTP error dict
                    return {"error": "Shodan 403 — membership or permission required", "detail": body, "retry_result": retry_res}

                except socket.gaierror:
                    return {
                        "error": "Shodan 403 — membership/permission required OR hostname could not be resolved to an IP",
                        "detail": body,
                    }
                except Exception as e:
                    return {"error": "Unhandled exception during 403 handling", "detail": str(e)}

            # If target already an IP, just return the 403 explanation
            return {"error": "Shodan 403 — membership or permission required to access this resource", "detail": body}

        # Other HTTP errors — pass through with details
        return {"error": f"HTTP error {status}", "detail": body}

    # Non-HTTP error (like network error) — pass through
    return res