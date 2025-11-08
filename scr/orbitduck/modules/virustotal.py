from __future__ import annotations
from typing import Dict, Any, Optional
import os, time
import httpx
from urllib.parse import urlencode

VT_API = "https://www.virustotal.com/api/v3"

def _headers(key: str) -> dict:
    return {"x-apikey": key, "User-Agent": "orbitduck"}

def vt_url_scan(
    url: str,
    api_key: Optional[str] = None,
    wait_for_completion: bool = True,
    poll_sec: float = 2.5,
    max_wait: float = 60.0,
) -> Dict[str, Any]:
    key = api_key or os.getenv("VT_API_KEY")
    if not key:
        return {"url": url, "error": "VT_API_KEY missing"}

    try:
        data = urlencode({"url": url})
        r = httpx.post(f"{VT_API}/urls", data=data, headers=_headers(key), timeout=30)
        r.raise_for_status()
        analysis_id = (r.json().get("data") or {}).get("id")
    except httpx.HTTPError as e:
        return {"url": url, "error": f"submit failed: {e}"}

    if not wait_for_completion:
        return {"url": url, "analysis_id": analysis_id, "engines": {}}

    last = {}
    deadline = time.time() + max_wait
    while time.time() < deadline:
        try:
            a = httpx.get(f"{VT_API}/analyses/{analysis_id}", headers=_headers(key), timeout=30)
            a.raise_for_status()
            last = a.json()
            status = (last.get("data") or {}).get("attributes", {}).get("status")
            if status == "completed":
                break
        except Exception:
            pass
        time.sleep(poll_sec)

    attrs = (last.get("data") or {}).get("attributes", {})
    results = attrs.get("results") or {}
    engines = {eng: {"category": res.get("category")} for eng, res in results.items()}
    return {"url": url, "analysis_id": analysis_id, "engines": engines}