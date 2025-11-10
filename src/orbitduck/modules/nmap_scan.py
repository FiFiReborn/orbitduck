# src/orbitduck/modules/nmap_scan.py
import shutil
import subprocess
import json
from typing import Dict, Any
import os
MOCK_MODE = os.getenv("ORBITDUCK_MOCK_MODE") == "1"


def _mock_nmap_result(target: str) -> Dict[str, Any]:
    # lightweight, safe mock so rest of pipeline continues
    return {
        "mocked": True,
        "target": target,
        "open_ports": [80, 443],
        "raw": "mock: no nmap installed"
    }

def _run_nmap(args):
    # run and capture output (expects nmap on PATH)
    out = subprocess.run(args, capture_output=True, text=True, check=True)
    return out.stdout

def nmap_quick_scan(target: str) -> Dict[str, Any]:
    """Quick nmap scan (-F) with fallback if nmap binary not present."""
    if not shutil.which("nmap"):
        return _mock_nmap_result(target)

    try:
        output = _run_nmap(["nmap", "-F", "-Pn", target])
        # You can parse output more thoroughly here if needed.
        return {"mocked": False, "target": target, "raw": output}
    except Exception as e:
        return {"mocked": True, "target": target, "error": str(e)}

def nmap_default_scan(target: str) -> Dict[str, Any]:
    """Longer scan (service/version) with fallback."""
    if not shutil.which("nmap"):
        return _mock_nmap_result(target)

    try:
        output = _run_nmap(["nmap", "-sV", "-Pn", target])
        return {"mocked": False, "target": target, "raw": output}
    except Exception as e:
        return {"mocked": True, "target": target, "error": str(e)}
