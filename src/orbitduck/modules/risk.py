"""
OrbitDuck Risk Assessment Module
Implements three safe rules:
1. Passive information gathering only
2. Respect target permissions (allowlist)
3. Limit frequency and scope (rate control)
"""

import os
import re
import time
import ipaddress
from datetime import datetime
from typing import Dict, Any
from threading import Lock
from orbitduck.utils.risk_merge import merge_module_scores
from orbitduck.modules.geoip_lookup import lookup_ip_location
from orbitduck.modules.whois_lookup import get_whois_data
import json



# -------------------------------
# Global Lock and Rate Limit
# -------------------------------
_lock = Lock()
_last_scan_time = 0.0
SCAN_INTERVAL = float(os.getenv("RISK_SAFE_INTERVAL", "5.0"))

# -------------------------------
# Safe Rule 1: Passive Command Check
# -------------------------------
def _is_safe_scan(cmd: str) -> bool:
    unsafe_flags = ["--script", "-A", "--traceroute", "-O"]
    return not any(flag in cmd for flag in unsafe_flags)

# -------------------------------
# Safe Rule 2: Allowlist
# -------------------------------
def _load_allowlist() -> set:
    allowlist = set()
    env_allow = os.getenv("ORBIT_ALLOWLIST", "")
    if env_allow:
        for t in env_allow.split(","):
            t = t.strip()
            if t:
                allowlist.add(t)

    allowlist_file = os.getenv("ORBIT_ALLOWLIST_FILE", "config/allowlist.txt")
    if os.path.exists(allowlist_file):
        with open(allowlist_file, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    allowlist.add(line)

    return allowlist

def _is_target_allowed(target: str, allowlist: set) -> bool:
    if target in allowlist:
        return True
    try:
        ip = ipaddress.ip_address(target)
        return ip.is_private
    except Exception:
        return False

# -------------------------------
# Safe Rule 3: Rate Control
# -------------------------------
def _safe_rate_limit():
    global _last_scan_time
    now = time.time()
    elapsed = now - _last_scan_time
    if elapsed < SCAN_INTERVAL:
        raise RuntimeError(f"Scan too frequent — wait {SCAN_INTERVAL - elapsed:.1f}s")
    _last_scan_time = now

def evaluate_module_risk(result: Dict[str, Any], weights: Dict[str, Any]) -> float:
    """Returns a numeric score for a single module result."""
    text = str(result).lower()
    score = 0

    if "cve" in text:
        score += weights.get("cve", 10)
    if "open" in text or "port" in text:
        score += weights.get("open_port", 5)
    if "exposed" in text:
        score += weights.get("exposed_service", 4)
    if "timeout" in text:
        score += weights.get("timeout", 2)
    if "error" in text:
        score += weights.get("error", 1)
    if "leak" in text or "breach" in text:
        score += weights.get("leak", 8)

    return score

# -------------------------------
# Risk Assessment
# -------------------------------
def assess_risk(result: Dict[str, Any]) -> Dict[str, Any]:
    cmd = result.get("cmd", "")
    target = result.get("target", "unknown")

    # Rule 1: Passive-only command
    if not _is_safe_scan(cmd):
        return {"risk": "BLOCKED", "reason": "Unsafe scan flags", "safe_rule": 1}

    # Rule 2: Allowlist enforcement
    allowlist = _load_allowlist()
    if not _is_target_allowed(target, allowlist):
        return {"risk": "BLOCKED", "reason": f"Target {target} not in allowlist", "safe_rule": 2}

    # Rule 3: Rate limit enforcement
    try:
        _safe_rate_limit()
    except RuntimeError as e:
        return {"risk": "BLOCKED", "reason": str(e), "safe_rule": 3}

    # Load configuration
    with open(os.getenv("ORBIT_RISK_CONFIG", "config/risk_weights.json")) as f:
        cfg = json.load(f)
    module_weights = cfg.get("modules", {})
    weights = cfg.get("weights", {})
    thresholds = cfg.get("thresholds", {})

    # Module-specific scoring (if results are structured)
    nmap_score = evaluate_module_risk(result.get("nmap", {}), weights)
    shodan_score = evaluate_module_risk(result.get("shodan", {}), weights)
    spider_score = evaluate_module_risk(result.get("spiderfoot", {}), weights)

    # Merge module scores using weighted average
    total_score = merge_module_scores(
        nmap_score=nmap_score,
        shodan_score=shodan_score,
        spiderfoot_score=spider_score,
        module_weights=module_weights
    )

    # Determine overall risk level
    if total_score >= thresholds.get("high", 30):
        level = "HIGH"
    elif total_score >= thresholds.get("medium", 15):
        level = "MEDIUM"
    else:
        level = "LOW"

    # GeoIP + WHOIS enrichment
    geo_info = lookup_ip_location(target)
    whois_info = get_whois_data(target)

    return {
        "target": target,
        "timestamp": datetime.utcnow().isoformat(),
        "score": total_score,
        "risk": level,
        "geo": geo_info,
        "whois": whois_info,
        "safe_rules_passed": True
    }

if __name__ == "__main__":
    example = {
        "target": "example.com",
        "cmd": "nmap -F -Pn example.com",
        "result": {"open_ports": [80, 443]}
    }
    print(assess_risk(example))
