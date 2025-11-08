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

    # Core scoring
    findings = str(result).lower()
    score = 0
    if "cve" in findings:
        score += 3
    if "open" in findings or "exposed" in findings:
        score += 2
    if "error" in findings or "timeout" in findings:
        score += 1

    if score >= 6:
        level = "HIGH"
    elif score >= 3:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "target": target,
        "timestamp": datetime.utcnow().isoformat(),
        "score": score,
        "risk": level,
        "safe_rules_passed": True
    }

if __name__ == "__main__":
    example = {
        "target": "example.com",
        "cmd": "nmap -F -Pn example.com",
        "result": {"open_ports": [80, 443]}
    }
    print(assess_risk(example))