import json
import subprocess
from typing import Dict


def _run(cmd: list[str]) -> Dict:
    """Run a subprocess and capture JSON-like output when possible."""
    out = subprocess.run(cmd, capture_output=True, text=True, check=False)
    return {
        "cmd": " ".join(cmd),
        "returncode": out.returncode,
        "stdout": out.stdout,
        "stderr": out.stderr,
    }


def nmap_quick_scan(target: str) -> Dict:
    # -F = fast (top 100 ports), -Pn = skip host discovery (treat as up)
    cmd = ["nmap", "-F", "-Pn", target]
    return _run(cmd)



def nmap_default_scan(target: str) -> Dict:
    # Default TCP connect scan; add -sV for service detection
    cmd = ["nmap", "-sV", "-Pn", target]
    return _run(cmd)