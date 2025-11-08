from dataclasses import dataclass
from typing import List, Dict, Any
import os
import time
from datetime import datetime
import pandas as pd
from threading import Lock
from pathlib import Path
from orbitduck.modules.risk import assess_risk
from orbitduck.utils.risk_trend import generate_risk_trend

# -------------------------------
#  Allowlist + Rate Limit Helpers
# -------------------------------

_lock = Lock()


def _load_allowlist() -> set:
    """Load allowlist from .env or file.
    If no allowlist is defined, automatically allow all (developer mode)."""
    allowlist = set()


    # Load from environment variable
    env_allow = os.getenv("ORBIT_ALLOWLIST", "")
    if env_allow:
        for t in env_allow.split(","):
            t = t.strip()
            if t:
                allowlist.add(t)

    # Load from file
    file_path = os.getenv("ORBIT_ALLOWLIST_FILE", "config/allowlist.txt")
    path = Path(file_path)
    if path.exists():
        for line in path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                allowlist.add(line)

    # Developer-friendly mode: no allowlist defined
    if not allowlist:
        print("[!] No allowlist found — running in developer mode (all targets allowed).")
    else:
        print(f"[✓] Loaded allowlist with {len(allowlist)} entries.")

    return allowlist


_last_scan_time = 0.0
_rate_per_min = int(os.getenv("GLOBAL_RATE_PER_MIN", "30"))  # 30 actions per min by default
_min_interval = 60.0 / max(1, _rate_per_min)


def _wait_for_rate_limit():
    """Simple rate limiter for all scan tasks."""
    global _last_scan_time
    with _lock:
        now = time.time()
        elapsed = now - _last_scan_time
        if elapsed < _min_interval:
            time.sleep(_min_interval - elapsed)
        _last_scan_time = time.time()

@dataclass
class ScanTask:
    name: str
    target: str
    kind: str # e.g., "nmap:quick" | "nmap:default"

class CoreRunner:
    def __init__(self):
        self.tasks: List[ScanTask] = []
        self.allowlist = []
        
    def add_task(self, task: ScanTask):
        self.tasks.append(task)

    def run_all(self) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        for t in self.tasks:

            print("[DEBUG] Starting run_all()")
            print(f"[DEBUG] Found {len(self.tasks)} task(s) to execute")

            for t in self.tasks:
                print(f"[DEBUG] Running task: {t.name} ({t.kind}) for {t.target}")


            # --- Allowlist enforcement (only if allowlist exists) ---
            if self.allowlist and t.target not in self.allowlist:
                print(f"[!] Skipping {t.target} — not in allowlist.")
                results.append({"task": t.__dict__, "error": f"Target '{t.target}' not allowed"})
                continue

            _wait_for_rate_limit()

            risk_result = {"risk": "UNKNOWN", "score": 0}
            scan_result = {}

            if t.kind == "nmap:quick":
                from orbitduck.modules.nmap_scan import nmap_quick_scan
                results.append({"task": t.__dict__, "result": nmap_quick_scan(t.target)})

            elif t.kind == "nmap:default":
                from orbitduck.modules.nmap_scan import nmap_default_scan
                results.append({"task": t.__dict__, "result": nmap_default_scan(t.target)})

            elif t.kind == "shodan:lookup":
                from orbitduck.modules.shodan_search import shodan_host_lookup
                results.append({"task": t.__dict__, "result": shodan_host_lookup(t.target)})
            else:
                results.append({"task": t.__dict__, "error": f"Unknown kind: {t.kind}"})

            try:
                risk_result = assess_risk(scan_result)
            except Exception:
                risk_result = {"risk": "UNKNOWN", "score": 0}

            results.append({"task": t.__dict__, "result": scan_result, "risk": risk_result})

        print("[DEBUG] All tasks complete, updating risk metrics")
        self._update_risk_metrics(results)
        return results

    def _update_risk_metrics(self,results):
        print("[DEBUG] Entered _update_risk_metrics()")

        reports_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            "reports"
        )
        os.makedirs(reports_dir, exist_ok=True)
        csv_path = os.path.join(reports_dir, "risk_history.csv")
        print(f"[DEBUG] Writing risk data to: {csv_path}")
    
        rows = []

        for r in results:
            task = r.get("task", {})
            target = task.get("target", "unknown")
            risk_data = r.get("risk", {})
            score = risk_data.get("score", 0)
            risk_level = risk_data.get("risk", "UNKNOWN")

        print(f"[DEBUG] Recording {target}: {risk_level} ({score})")

        rows.append({
            "scan_id": datetime.now().strftime("%Y%m%d%H%M%S"),
            "date": datetime.now().strftime("%Y-%m-%d"),
            "target": target,
            "risk_level": risk_level,
            "risk_score": score
            })

        try:
            # Append new results safely
            if os.path.exists(csv_path):
                df = pd.read_csv(csv_path)
                df = pd.concat([df, pd.DataFrame(rows)], ignore_index=True)
            else:
                df = pd.DataFrame(rows)

            df.to_csv(csv_path, index=False)
            print("[DEBUG] risk_history.csv updated successfully")

            # Generate visual trend
            generate_risk_trend(data_file=csv_path, output_dir=reports_dir)
            print("[DEBUG] Risk trend visual updated successfully")

        except Exception as e:
            print(f"[!] Failed to write CSV: {e}")
