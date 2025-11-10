# src/orbitduck/modules/spiderfoot.py
import os
import time
import requests
import os
MOCK_MODE = os.getenv("ORBITDUCK_MOCK_MODE") == "1"


BASE_URL = os.getenv("SPIDERFOOT_BASE_URL", "http://localhost:5001")
API_KEY = os.getenv("SPIDERFOOT_API_KEY", "")

def _mock_run(target):
    # create a fake scan id then pretend results are available
    scan_id = f"mock-{int(time.time())}-{target}"
    return scan_id

def _mock_results(scan_id):
    return {"mocked": True, "scan_id": scan_id, "findings": []}

def run_scan(target: str) -> str:
    """Start a SpiderFoot scan via API; return scan id, or mock id."""
    try:
        url = f"{BASE_URL}/api/scan/new"
        payload = {"target": target, "module-settings": {}}
        headers = {}
        if API_KEY:
            headers["Authorization"] = f"Bearer {API_KEY}"
        resp = requests.post(url, json=payload, headers=headers, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        return data.get("scan_id") or data.get("id") or _mock_run(target)
    except Exception:
        return _mock_run(target)

def get_results(scan_id: str):
    """Fetch results; if API not available, return mock."""
    try:
        url = f"{BASE_URL}/api/scan/{scan_id}/results"
        headers = {}
        if API_KEY:
            headers["Authorization"] = f"Bearer {API_KEY}"
        resp = requests.get(url, headers=headers, timeout=10)
        resp.raise_for_status()
        return {"mocked": False, "scan_id": scan_id, "data": resp.json()}
    except Exception:
        return _mock_results(scan_id)
