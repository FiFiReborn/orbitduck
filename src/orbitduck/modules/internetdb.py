# orbitduck/modules/internetdb.py
from __future__ import annotations
from typing import Dict, Any, List
import json
import time
import hashlib
import urllib.request

BASE = "https://internetdb.shodan.io"

def _stable_id(*parts: str) -> str:
    canon = "\u0001".join(p.strip().lower() for p in parts if p)
    return hashlib.sha1(canon.encode()).hexdigest()

def fetch_internetdb(ip: str, timeout: float = 30.0) -> Dict[str, Any]:
    """Call Shodan InternetDB for a single IP and return the JSON payload (or a structured error)."""
    url = f"{BASE}/{ip}"
    req = urllib.request.Request(url, headers={"User-Agent": "orbit-duck"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        return {"ip": ip, "error": str(e)}

def normalise_internetdb(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Turn the InternetDB payload into simple, report-friendly findings."""
    ip = payload.get("ip")
    ports: List[int] = payload.get("ports", []) or []
    tags: List[str] = payload.get("tags", []) or []
    vulns: List[str] = payload.get("vulns", []) or []
    now = int(time.time())
    findings: List[Dict[str, Any]] = []

    for port in ports:
        findings.append({
            "id": _stable_id("internetdb-open-port", ip or "", str(port)),
            "title": f"Open port {port} on {ip}",
            "severity": "LOW",
            "asset": {"kind": "ipv4", "value": ip},
            "exposure": {"port": int(port), "protocol": "tcp"},
            "cves": [],
            "tags": tags,
            "categories": ["exposure", "surface"],
            "source": "shodan_internetdb",
            "collected_at": now,
            "evidence": payload,
        })

    if vulns:
        findings.append({
            "id": _stable_id("internetdb-cves", ip or "", ",".join(sorted(vulns))),
            "title": f"CVE signals for {ip}",
            "severity": "MEDIUM",
            "asset": {"kind": "ipv4", "value": ip},
            "exposure": None,
            "cves": sorted(set(vulns)),
            "tags": tags + ["has_cves"],
            "categories": ["cve", "intel"],
            "source": "shodan_internetdb",
            "collected_at": now,
            "evidence": payload,
        })

    if not findings and payload.get("error") is not None:
        findings.append({
            "id": _stable_id("internetdb-error", ip or "", str(payload.get("error"))),
            "title": f"InternetDB error for {ip}",
            "severity": "INFO",
            "asset": {"kind": "ipv4", "value": ip},
            "exposure": None,
            "cves": [],
            "tags": tags,
            "categories": ["pipeline"],
            "source": "shodan_internetdb",
            "collected_at": now,
            "evidence": payload,
        })
    return findings