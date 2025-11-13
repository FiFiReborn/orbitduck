# orbitduck/core_runner.py
from dataclasses import dataclass
from typing import List, Dict, Any
import os
import time
from datetime import datetime
import pandas as pd
from threading import Lock
from pathlib import Path
from colorama import init, Fore, Style

# project utils
from orbitduck.utils.logger_manager import setup_logger, log_audit_entry, log_exception
from orbitduck.modules.risk import assess_risk
from orbitduck.utils.risk_trend import generate_risk_trend
from orbitduck.modules import spiderfoot
from orbitduck.modules.subdomain_enum import enumerate_subdomains
from orbitduck.utils.report_manager import build_reports_dashboard
from orbitduck.utils.diff_manager import auto_generate_diffs

init(autoreset=True)

# debug notice (safe)
print("[DEBUG] orbitduck.core_runner loaded.")

_lock = Lock()
_last_scan_time = 0.0

# -------------------------------
# Helper: Startup banner (no emoji)
# -------------------------------
def show_startup_banner():
    conf_path = Path("orbitduck/config/orbitduck.conf")
    mock_mode = os.getenv("ORBITDUCK_MOCK_MODE") == "1"
    mode_label = "MOCK MODE" if mock_mode else "REAL MODE"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    box_width = 46
    def line(text="", color=Fore.YELLOW):
        padding = box_width - len(text) - 3
        if padding < 0:
            padding = 0
        return f"{color}║ {text}{' ' * padding}{Fore.MAGENTA}║"

    print(f"\n{Fore.MAGENTA}{Style.BRIGHT}╔{'═' * (box_width - 2)}╗")
    print(f"{Fore.MAGENTA}{Style.BRIGHT}║{'OrbitDuck Core v1.0'.center(box_width - 2)}║")
    print(f"{Fore.MAGENTA}{Style.BRIGHT}╠{'═' * (box_width - 2)}╣")
    print(line(f"[TIME] Started: {timestamp}"))
    print(line(f"[MODE] Mode:    {mode_label}"))
    if conf_path.exists():
        print(line(f"[CONFIG] File: {conf_path}"))
    else:
        print(line("[WARN] Config: Not found"))
    print(f"{Fore.MAGENTA}{Style.BRIGHT}╚{'═' * (box_width - 2)}╝{Style.RESET_ALL}\n")

# -------------------------------
# Allowlist loader + mock defaults
# -------------------------------
def _load_allowlist() -> set:
    allowlist = set()
    conf_path = Path("orbitduck/config/orbitduck.conf")
    mock_mode = False
    defaults: List[str] = []

    if conf_path.exists():
        for line in conf_path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.upper().startswith("MOCK_MODE"):
                mock_mode = "true" in line.lower()
            if line.upper().startswith("DEFAULT_ALLOWLIST"):
                defaults = [t.strip() for t in line.split("=", 1)[1].split(",") if t.strip()]

    file_path = os.getenv("ORBIT_ALLOWLIST_FILE", "config/allowlist.txt")
    path = Path(file_path)
    if path.exists():
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if " " in line or len(line) < 3:
                print(f"[WARN] Ignoring invalid allowlist entry: {line}")
                continue
            allowlist.add(line)
        print(f"[INFO] Loaded {len(allowlist)} entries from {file_path}")
    else:
        if defaults:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("\n".join(defaults))
            allowlist.update(defaults)
            print(f"[INFO] Created allowlist with defaults at {file_path}")
        else:
            print(f"[WARN] Allowlist file not found at {file_path}")

    env_allow = os.getenv("ORBIT_ALLOWLIST", "")
    if env_allow:
        added = 0
        for t in env_allow.split(","):
            t = t.strip()
            if t and t not in allowlist:
                allowlist.add(t)
                added += 1
        if added:
            print(f"[INFO] Added {added} entries from ORBIT_ALLOWLIST variable")

    if not allowlist:
        print("[WARN] No valid allowlist entries found — scanning disabled.")
    else:
        print(f"[INFO] Final allowlist total: {len(allowlist)} targets.")

    if mock_mode:
        print("[INFO] MOCK MODE ACTIVE — simulated scans enabled.")
        os.environ["ORBITDUCK_MOCK_MODE"] = "1"
    else:
        os.environ.pop("ORBITDUCK_MOCK_MODE", None)

    return allowlist

# -------------------------------
# Simple rate limiter
# -------------------------------
def _wait_for_rate_limit():
    global _last_scan_time
    interval = float(os.getenv("ORBITDUCK_SCAN_INTERVAL", "5"))
    now = time.time()
    if _last_scan_time == 0.0:
        _last_scan_time = now
        return
    elapsed = now - _last_scan_time
    if elapsed < interval:
        wait = interval - elapsed
        print(f"[WAIT] Waiting {wait:.1f}s before next task...")
        time.sleep(wait)
    _last_scan_time = time.time()

# -------------------------------
# Task dataclass + CoreRunner
# -------------------------------
@dataclass
class ScanTask:
    name: str
    target: str
    kind: str

class CoreRunner:
    def __init__(self):
        self.tasks: List[ScanTask] = []
        self.allowlist = _load_allowlist()
        self.logger = setup_logger()

    def add_task(self, task: ScanTask):
        self.tasks.append(task)

    def run_all(self) -> List[Dict[str, Any]]:
        show_startup_banner()
        self.logger.info("[START] Beginning Orbit scan run")
        log_audit_entry("scan_start", {"total_tasks": len(self.tasks)})
        results: List[Dict[str, Any]] = []

        # filter by allowlist
        if self.allowlist:
            allowed = [t for t in self.tasks if t.target in self.allowlist]
            blocked = [t for t in self.tasks if t.target not in self.allowlist]
            if blocked:
                self.logger.warning(f"[WARN] Skipping {len(blocked)} disallowed task(s): " +
                                    ", ".join(t.target for t in blocked))
                log_audit_entry("blocked_tasks", {"blocked": [t.target for t in blocked]})
            self.tasks = allowed

        # discovery
        unique_targets = {t.target for t in self.tasks}
        all_targets = set()
        for target in unique_targets:
            if self.allowlist and target not in self.allowlist:
                self.logger.info(f"[SKIP] Discovery for {target} (not in allowlist)")
                continue
            subs = enumerate_subdomains(target)
            self.logger.info(f"[DISCOVERY] {target} -> {len(subs)} subdomains found")
            log_audit_entry("subdomain_discovery", {"target": target, "subdomains_found": len(subs)})
            all_targets.update(subs)

        if self.allowlist:
            all_targets.update({t for t in unique_targets if t in self.allowlist})
        else:
            all_targets.update(unique_targets)

        self.logger.info(f"[SUMMARY] Total targets to scan: {len(all_targets)}")

        # run tasks
        for t in self.tasks:
            self.logger.info(f"[TASK] {t.kind.replace(':', ' ')} -> {t.target}")
            if self.allowlist and t.target not in self.allowlist:
                results.append({"task": t.__dict__, "error": f"Target '{t.target}' not allowed"})
                continue

            _wait_for_rate_limit()
            try:
                scan_result = {"target": t.target, "nmap": {}, "shodan": {}, "spiderfoot": {}}

                if t.kind == "nmap:quick":
                    from orbitduck.modules.nmap_scan import nmap_quick_scan
                    scan_result["nmap"] = nmap_quick_scan(t.target)
                elif t.kind == "nmap:default":
                    from orbitduck.modules.nmap_scan import nmap_default_scan
                    scan_result["nmap"] = nmap_default_scan(t.target)
                elif t.kind == "shodan:lookup":
                    from orbitduck.modules.shodan_search import shodan_host_lookup
                    scan_result["shodan"] = shodan_host_lookup(t.target)
                elif t.kind == "spiderfoot":
                    from orbitduck.modules.spiderfoot import run_scan, get_results
                    scan_id = run_scan(t.target)
                    scan_result["spiderfoot"] = get_results(scan_id)
                else:
                    scan_result["error"] = f"Unknown kind: {t.kind}"
                    self.logger.warning(f"[WARN] Unknown task type: {t.kind}")

            except Exception as e:
                scan_result = {"target": t.target, "error": str(e)}
                log_exception(self.logger, f"Error while scanning {t.target}", e)
                log_audit_entry("scan_error", {"target": t.target, "error": str(e)})

            # risk assessment (safe fallback if risk config missing)
            try:
                # assess_risk should itself be robust, but be defensive here
                risk_result = assess_risk(scan_result)
            except FileNotFoundError as fe:
                # config missing: log and return UNKNOWN risk so pipeline continues
                self.logger.warning(f"[WARN] Risk config missing: {fe}. Marking risk UNKNOWN for {t.target}")
                risk_result = {"risk": "UNKNOWN", "score": 0}
                log_exception(self.logger, f"Risk assessment failed for {t.target}", fe)
                log_audit_entry("risk_error", {"target": t.target, "error": str(fe)})
            except Exception as e:
                risk_result = {"risk": "UNKNOWN", "score": 0}
                log_exception(self.logger, f"Risk assessment failed for {t.target}", e)
                log_audit_entry("risk_error", {"target": t.target, "error": str(e)})

            results.append({"task": t.__dict__, "result": scan_result, "risk": risk_result})
            log_audit_entry("task_complete", {"target": t.target, "risk": risk_result})

        # finalize
        self.logger.info("[DONE] All tasks complete — updating risk metrics...")
        log_audit_entry("scan_complete", {"completed_tasks": len(results)})

        self.logger.info("[DASHBOARD] Building updated dashboard...")
        try:
            build_reports_dashboard()
        except Exception as e:
            self.logger.warning(f"[WARN] Failed to build dashboard: {e}")
            log_exception(self.logger, "Dashboard build failed", e)

        self.logger.info("[DIFF] Generating diffs...")
        try:
            auto_generate_diffs()
        except Exception as e:
            self.logger.warning(f"[WARN] Failed to generate diffs: {e}")
            log_exception(self.logger, "Diff generation failed", e)

        # summary & CSV update
        total = len(results)
        scores = [r["risk"].get("score", 0) for r in results if "risk" in r]
        high = max(results, key=lambda r: r["risk"].get("score", 0), default=None)
        avg = sum(scores) / len(scores) if scores else 0.0

        summary = {
            "total_targets": total,
            "average_score": avg,
            "highest_risk": high["task"]["target"] if high else "None",
            "highest_risk_level": high["risk"].get("risk") if high else "N/A"
        }

        self.logger.info(f" • Total Targets: {total}")
        self.logger.info(f" • Average Risk Score: {avg:.1f}")
        if high:
            h = high["risk"]
            self.logger.info(f" • Highest Risk: {high['task']['target']} ({h.get('risk')}, {h.get('score')})")
        self.logger.info("----------------------------------------")

        log_audit_entry("summary", summary)
        self.logger.info("[AUDIT] Scan summary logged and audit trail updated")

        # update risk_history.csv
        try:
            self._update_risk_metrics(results)
        except Exception as e:
            self.logger.warning(f"[WARN] Failed to update risk metrics CSV: {e}")
            log_exception(self.logger, "Risk metrics update failed", e)

        return results

    def _update_risk_metrics(self, results: List[Dict[str, Any]]):
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

        try:
            generate_risk_trend(data_file=csv_path, output_dir=reports_dir)
        except Exception as e:
            self.logger.warning(f"[WARN] Could not generate risk trend chart: {e}")
            log_exception(self.logger, "Risk trend generation failed", e)

# -------------------------------
# Main entry
# -------------------------------
if __name__ == "__main__":
    import sys
    logger = setup_logger()
    try:
        print("[DEBUG] Main block running")
        runner = CoreRunner()

        if len(sys.argv) > 1:
            # treat anything after module name as domains (skip optional flags parsing)
            domains = [a for a in sys.argv[1:] if not a.startswith("--")]
        else:
            domains = list(runner.allowlist)

        if not domains:
            logger.warning("[WARN] No domains found in allowlist or arguments. Exiting.")
            exit(0)

        logger.info(f"[INFO] Starting Orbit scans for: {', '.join(domains)}")

        for d in domains:
            runner.add_task(ScanTask(name=f"{d} quick scan", target=d, kind="nmap:quick"))
            runner.add_task(ScanTask(name=f"{d} shodan lookup", target=d, kind="shodan:lookup"))
            runner.add_task(ScanTask(name=f"{d} spiderfoot scan", target=d, kind="spiderfoot"))

        runner.run_all()

    except Exception as e:
        log_exception(logger, "CRITICAL - OrbitDuck crashed", e)
        logger.error("[ERROR] OrbitDuck encountered a fatal error. Check error.log for details.")
