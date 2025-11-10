from dataclasses import dataclass
from typing import List, Dict, Any
import os
import time
from datetime import datetime
import pandas as pd
from threading import Lock
from pathlib import Path

# Module imports
from orbitduck.modules.risk import assess_risk
from orbitduck.utils.risk_trend import generate_risk_trend
from orbitduck.modules import spiderfoot  # 🕷️ Added for SpiderFoot integration

# Imports for discovery + reporting
from orbitduck.modules.subdomain_enum import enumerate_subdomains
from orbitduck.utils.report_manager import build_reports_dashboard
from orbitduck.utils.diff_manager import auto_generate_diffs
print("[DEBUG] orbitduck.core_runner loaded.")

_lock = Lock()

# -------------------------------
#  Allowlist + Rate Limit Helpers
# -------------------------------

def _load_allowlist() -> set:
    allowlist = set()

    file_path = os.getenv("ORBIT_ALLOWLIST_FILE", "config/allowlist.txt")
    path = Path(file_path)

    if path.exists():
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if " " in line or len(line) < 3:
                print(f"[!] Ignoring invalid allowlist entry: {line}")
                continue
            allowlist.add(line)
        print(f"[✓] Loaded {len(allowlist)} entries from {file_path}")
    else:
        print(f"[!] Allowlist file not found at {file_path}")

    env_allow = os.getenv("ORBIT_ALLOWLIST", "")
    if env_allow:
        added = 0
        for t in env_allow.split(","):
            t = t.strip()
            if t and t not in allowlist:
                allowlist.add(t)
                added += 1
        if added:
            print(f"[+] Added {added} extra entries from environment variable ORBIT_ALLOWLIST")

    if not allowlist:
        print("[!] No valid allowlist entries found — scanning disabled.")
    else:
        print(f"[✓] Final allowlist total: {len(allowlist)} targets.")

    return allowlist


_last_scan_time = 0.0
_rate_per_min = int(os.getenv("GLOBAL_RATE_PER_MIN", "30"))
_min_interval = 60.0 / max(1, _rate_per_min)


def _wait_for_rate_limit():
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
    kind: str  # e.g., "nmap:quick" | "shodan:lookup" | "spiderfoot"


class CoreRunner:
    def __init__(self):
        self.tasks: List[ScanTask] = []
        self.allowlist = _load_allowlist()

    def add_task(self, task: ScanTask):
        self.tasks.append(task)

    def run_all(self) -> List[Dict[str, Any]]:
        print("\n🚀 Starting Orbit scan run...")
        results: List[Dict[str, Any]] = []

        # Filter tasks early
        if self.allowlist:
            allowed = [t for t in self.tasks if t.target in self.allowlist]
            blocked = [t for t in self.tasks if t.target not in self.allowlist]
            if blocked:
                print(f"⚠️  Skipping {len(blocked)} disallowed task(s): " +
                      ", ".join(t.target for t in blocked))
            self.tasks = allowed

        # Subdomain discovery
        unique_targets = {t.target for t in self.tasks}
        all_targets = set()
        for target in unique_targets:
            if self.allowlist and target not in self.allowlist:
                print(f"⏭️  Skipping discovery for {target} (not in allowlist)")
                continue

            subs = enumerate_subdomains(target)
            print(f"🌐 Discovery: {target} → {len(subs)} subdomains found")
            all_targets.update(subs)

        if self.allowlist:
            all_targets.update({t for t in unique_targets if t in self.allowlist})
        else:
            all_targets.update(unique_targets)

        print(f"📋 Total targets to scan: {len(all_targets)}")

        # Run all tasks
        for t in self.tasks:
            print(f"🔍 {t.kind.replace(':', ' ')} → {t.target}")

            if self.allowlist and t.target not in self.allowlist:
                results.append({"task": t.__dict__, "error": f"Target '{t.target}' not allowed"})
                continue

            _wait_for_rate_limit()

            try:
                if t.kind == "nmap:quick":
                    from orbitduck.modules.nmap_scan import nmap_quick_scan
                    scan_result = nmap_quick_scan(t.target)

                elif t.kind == "nmap:default":
                    from orbitduck.modules.nmap_scan import nmap_default_scan
                    scan_result = nmap_default_scan(t.target)

                elif t.kind == "shodan:lookup":
                    from orbitduck.modules.shodan_search import shodan_host_lookup
                    scan_result = shodan_host_lookup(t.target)

                elif t.kind == "spiderfoot":
                    # 🕷️ SpiderFoot scan integration
                    from orbitduck.modules.spiderfoot import run_scan, get_results
                    scan_id = run_scan(t.target)
                    scan_result = get_results(scan_id)

                else:
                    scan_result = {"error": f"Unknown kind: {t.kind}"}
            except Exception as e:
                scan_result = {"error": str(e)}

            try:
                risk_result = assess_risk(scan_result)
            except Exception:
                risk_result = {"risk": "UNKNOWN", "score": 0}

            results.append({"task": t.__dict__, "result": scan_result, "risk": risk_result})

        print("✅ All tasks complete — updating risk metrics...")
        self._update_risk_metrics(results)

        # Auto-update dashboard + diffs
        print("🧭 Building updated dashboard...")
        build_reports_dashboard()
        print("🪄 Generating diffs...")
        auto_generate_diffs()
        print("🎉 Dashboard and diffs updated successfully.\n")

        # Summary
        print("📊 Scan Summary")
        total = len(results)
        scores = [r["risk"].get("score", 0) for r in results if "risk" in r]
        high = max(results, key=lambda r: r["risk"].get("score", 0), default=None)

        avg = sum(scores) / len(scores) if scores else 0
        print(f" • Total Targets: {total}")
        print(f" • Average Risk Score: {avg:.1f}")
        if high:
            h = high["risk"]
            print(f" • Highest Risk: {high['task']['target']} ({h.get('risk')}, {h.get('score')})")
        print("────────────────────────────\n")

        return results

    def _update_risk_metrics(self, results):
        reports_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "../reports")
        os.makedirs(reports_dir, exist_ok=True)
        csv_path = os.path.join(reports_dir, "risk_history.csv")

        rows = []
        for r in results:
            task = r.get("task", {})
            risk = r.get("risk", {})
            rows.append({
                "scan_id": datetime.now().strftime("%Y%m%d%H%M%S"),
                "date": datetime.now().strftime("%Y-%m-%d"),
                "target": task.get("target", "unknown"),
                "risk_level": risk.get("risk", "UNKNOWN"),
                "risk_score": risk.get("score", 0),
            })

        if os.path.exists(csv_path):
            df = pd.read_csv(csv_path)
            df = pd.concat([df, pd.DataFrame(rows)], ignore_index=True)
        else:
            df = pd.DataFrame(rows)
        df.to_csv(csv_path, index=False)

        generate_risk_trend(data_file=csv_path, output_dir=reports_dir)
        print("📈 Risk metrics updated.\n")


# -------------------------------
#  Main Execution Entry
# -------------------------------
if __name__ == "__main__":
    import sys

    print("[DEBUG] Main block running")
    runner = CoreRunner()

    if len(sys.argv) > 1:
        domains = sys.argv[1:]
    else:
        domains = list(runner.allowlist)

    if not domains:
        print("⚠️  No domains found in allowlist or arguments. Exiting.")
        exit(0)

    print(f"🚀 Starting Orbit scans for: {', '.join(domains)}")

    for d in domains:
        runner.add_task(ScanTask(name=f"{d} quick scan", target=d, kind="nmap:quick"))
        runner.add_task(ScanTask(name=f"{d} shodan lookup", target=d, kind="shodan:lookup"))
        # 🕷️ Added SpiderFoot task
        runner.add_task(ScanTask(name=f"{d} spiderfoot scan", target=d, kind="spiderfoot"))

    runner.run_all()
