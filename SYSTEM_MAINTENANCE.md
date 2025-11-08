# 🧰 ORBIT-DUCK — SYSTEM MAINTENANCE DOCUMENTATION
**Version:** 1.0  
**Maintainer:** Duck Orbit Development Team  
**Last Updated:** 2025-10-14  

---

## 📘 Overview
This document defines the **System Maintenance Procedures** for the Orbit-Duck Attack Surface Management tool.  
It provides baseline manual tasks to ensure the system operates smoothly, remains secure, and produces accurate reports.  
Maintenance activities include verification, cleanup, dependency management, and troubleshooting.

---

## 🗓️ Maintenance Schedule

| Frequency | Task | Description |
|------------|------|-------------|
| **After Each Scan** | Verify and Validate Reports | Confirm new entries appear in `risk_history.csv` and the `risk_trend.png` file is updated. |
| **Weekly** | Clean Logs and JSON Outputs | Remove unnecessary `.json` scan files from `/reports/`. |
| **Monthly** | Backup Reports | Archive the `/reports/` folder to `/backups/YYYY-MM/`. |
| **Monthly** | Update Dependencies | Review outdated packages and update as needed. |
| **Quarterly** | Review Risk Scoring Logic | Validate `_update_risk_metrics()` and `generate_risk_trend()` against the latest security policy. |
| **As Needed** | Purge Caches | Delete all `__pycache__` folders to prevent old code from running. |

---

## 🧩 SYSTEM MAINTENANCE PROCEDURES (BASELINE / MANUAL WORK)

### 1️⃣ Verify Scan Results
Run a basic scan test to confirm the system functions correctly:
```bash
python -B
>>> from orbitduck.core_runner import CoreRunner, ScanTask
>>> r = CoreRunner()
>>> r.add_task(ScanTask(name="Test", target="8.8.8.8", kind="nmap:quick"))
>>> r.run_all()
```
Expected output:
```
[✓] Risk metrics updated and Risk Delta Trend visual generated.
```

---

### 2️⃣ Validate Reports
After each scan, confirm the system generated the correct reports:
```
orbit-duck/reports/
```
Files to verify:
- ✅ `risk_history.csv` — risk log entries for each scan  
- ✅ `risk_trend.png` — visual trend chart  
- 🗃️ (optional) `scan_*.json`, `shodan_*.json` — raw scan data  

If the files are missing:
- Check `core_runner.py` for `_update_risk_metrics` execution.  
- Ensure `pandas` and `matplotlib` are installed.  

---

### 3️⃣ Backup Reports
Monthly, back up all generated reports to prevent data loss:
```powershell
New-Item -ItemType Directory -Force -Path "backups/$(Get-Date -Format yyyy-MM)"
Copy-Item reports/* backups/$(Get-Date -Format yyyy-MM)/ -Recurse -Force
```
> 💡 Tip: Automate this later with a PowerShell or Python cron job.

---

### 4️⃣ Maintain Dependencies
Keep the virtual environment healthy:
```bash
pip freeze > requirements.txt
pip list --outdated
pip install -U <package>
```
To remove unused libraries:
```bash
pip uninstall -y <package>
```

---

### 5️⃣ Clean Code Cache
Ensure Python is always running the latest version:
```powershell
Get-ChildItem -Recurse -Directory -Filter "__pycache__" | Remove-Item -Recurse -Force
```
Then restart your environment with:
```bash
python -B
```

---

### 6️⃣ Remove Old Reports and Logs
Free up space by deleting older scan data:
```powershell
Remove-Item reports\scan_*.json -Force
Remove-Item reports\shodan_*.json -Force
```
> 🔒 Always back up critical reports before removal.

---

## ⚙️ COMMON ISSUES & FIXES

| Symptom | Likely Cause | Solution |
|----------|---------------|-----------|
| `risk_history.csv` not updating | Cached module or missing library | Run with `python -B` and reinstall dependencies. |
| Reports appear in `/src/reports` | Old cache path in code | Delete `__pycache__` folders and restart. |
| PNG not generated | Missing `matplotlib` | Install: `pip install matplotlib`. |
| Scan fails | Missing `nmap` or invalid API key | Ensure `nmap` is installed and API key is configured. |
| Slow execution | Network latency | Use `nmap:quick` scan type instead. |

---

## 📦 FOLDER STRUCTURE

```
orbit-duck/
│
├── .pytest_cache/                 # Pytest cache files
├── .venv/                         # Virtual environment
│
├── reports/                       # Scan outputs and reports
│   ├── risk_history.csv
│   ├── risk_trend.png
│   ├── scan_8.8.8.8.json
│   ├── scan_google.com.json
│   ├── shodan_8.8.8.8.json
│
├── src/                           # Source code
│   └── orbitduck/
│       ├── __pycache__/           # Compiled Python cache
│       ├── modules/               # Functional modules for scanning & APIs
│       │   ├── __init__.py
│       │   ├── internetdb.py      # Shodan InternetDB integration
│       │   ├── nmap_scan.py       # Nmap scan module
│       │   ├── shodan_search.py   # Shodan host lookup module
│       │   └── virustotal.py      # VirusTotal integration module
│       │
│       ├── utils/                 # Utility and helper functions
│       │   ├── __init__.py
│       │   └── io.py              # File I/O and report writing
│       │
│       ├── cli.py                 # Command Line Interface
│       ├── core_runner.py         # Core execution and task management
│       ├── main.py                # Entry point (if directly executed)
│       ├── pipeline.py            # Combined scan workflow
│       ├── rules.json             # Rules or schema references
│       └── schema_merge.py        # Schema management or data merge logic
│
├── tests/                         # Automated testing
│   ├── __pycache__/
│   └── test_smoke.py              # Sanity test for CoreRunner & ScanTask   
│
├── .dockerignore
├── .env                           # Environment variables (API keys, configs)
├── .gitignore                     # Git ignore rules
├── docker-compose.yml              # Optional container orchestration
├── Dockerfile                     # Container build configuration
├── pyproject.toml                 # Project build metadata
├── requirements.txt               # Python dependencies
├── SYSTEM_MAINTENANCE.md          # System maintenance documentation (this file)
├── test_pipeline.py           # End-to-end pipeline test
└── test_shodan.py             # Tests for Shodan module



```

---

## 🧠 BEST PRACTICES
- Always run scans with `python -B` to avoid using stale code.  
- Confirm reports update after every scan.  
- Never manually edit `risk_history.csv`.  
- Regularly back up `/reports/`.  
- Document any major code or configuration changes in `SYSTEM_MAINTENANCE.md`.  

---

## 💬 OPTIONAL SYSTEM REMINDER (CODE INTEGRATION)
To remind operators of this documentation, you can add this snippet to the end of `run_all()` in `core_runner.py`:

```python
print("\n[INFO] Reports successfully updated.")
print("[INFO] Refer to SYSTEM_MAINTENANCE.md for backup and cleanup procedures.")
```

---

**End of Document**