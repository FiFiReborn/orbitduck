# src/orbitduck/modules/spiderfoot.py
import os
import requests
import time

API_KEY = os.getenv("SPIDERFOOT_API_KEY", "")
BASE_URL = os.getenv("SPIDERFOOT_URL", "http://localhost:5001/api/")

def run_scan(target, modules="all"):
    """Run a SpiderFoot scan and return the scan ID."""
    payload = {
        "target": target,
        "modules": modules,
        "api_key": API_KEY
    }
    resp = requests.post(f"{BASE_URL}scan/new", json=payload)
    if resp.status_code != 200:
        raise RuntimeError(f"SpiderFoot error: {resp.text}")
    return resp.json().get("scan_id")

def get_results(scan_id):
    """Retrieve SpiderFoot scan results."""
    time.sleep(5)  # allow scan to start
    resp = requests.get(f"{BASE_URL}scan/results/{scan_id}?api_key={API_KEY}")
    if resp.status_code != 200:
        raise RuntimeError(f"SpiderFoot fetch error: {resp.text}")
    return resp.json()
