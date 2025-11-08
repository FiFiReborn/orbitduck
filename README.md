# orbitduck
This was created as part of my Capstone class, as a group assessment, 3 of us created this program, with little knowledge of python or modules. 

# 🛰️ Orbit-Duck — Attack Surface Management Tool

**Version:** 1.0  
**Maintainer:** Duck Orbit Development Team  
**Last Updated:** 2025-10-27  

Orbit-Duck is a modular **Attack Surface Management (ASM)** and **Risk Assessment Framework** designed to automate network scanning, Shodan lookups, and risk tracking.  
It integrates **Nmap**, **Shodan**, and internal risk analysis modules to produce measurable insights and trend visuals over time.

---

## 📘 Table of Contents
- [Overview](#-overview)
- [Features](#-features)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Quick Start](#-quick-start)
- [CLI Usage](#-cli-usage)
- [Reports & Risk Tracking](#-reports--risk-tracking)
- [Allowlist Management](#-allowlist-management)
- [Maintenance](#-maintenance)
- [Folder Structure](#-folder-structure)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🌐 Overview

Orbit-Duck automates external reconnaissance and risk analytics for small networks and organizations.  
It supports Nmap scans, Shodan data collection, and risk scoring through its modular Python-based engine.

Each scan is logged in a persistent `risk_history.csv` file and visualized through a generated `risk_trend.png` chart.

---

## ⚙️ Features

| Feature | Description |
|----------|-------------|
| 🔍 **Nmap Scanning** | Supports quick (`-F`) and default (`-sV`) scan profiles |
| 🌐 **Shodan Integration** | Fetches asset data via the Shodan API |
| 📊 **Risk Scoring** | Calculates and logs risk levels for every scan target |
| 🧠 **Trend Visualization** | Generates ongoing risk trend charts in `/reports/` |
| 🔒 **Allowlist Enforcement** | Prevents unauthorized targets from being scanned |
| ⚡ **Rate Limiting** | Global scan throttling for responsible execution |
| 🧾 **Detailed Reports** | JSON reports and CSV summaries generated automatically |

---

## 💻 Installation

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/<your-username>/orbit-duck.git
cd orbit-duck
2️⃣ Create a Virtual Environment
bash
Copy code
python -m venv .venv
source .venv/bin/activate        # macOS/Linux
# or
.venv\Scripts\activate           # Windows
3️⃣ Install Dependencies
bash
Copy code
pip install -r requirements.txt
4️⃣ Verify Installation
bash
Copy code
python -B -m orbitduck.cli --help
You should see the CLI help message with available commands (run, scan, shodan).

⚙️ Configuration
Orbit-Duck uses an .env file for environment variables and API keys.

Example .env:

env
Copy code
# Shodan API Key
SHODAN_API_KEY=YOUR_API_KEY_HERE

# Rate Limits
GLOBAL_RATE_PER_MIN=20
SHODAN_RATE_PER_MIN=25

# Allowlist (comma-separated)
ORBIT_ALLOWLIST=example.com,8.8.8.8

# Optional: specify allowlist file
ORBIT_ALLOWLIST_FILE=config/allowlist.txt
🚀 Quick Start
Run a Quick Nmap Scan
bash
Copy code
python -m orbitduck.cli run --target example.com --quick
Run a Full Nmap Scan
bash
Copy code
python -m orbitduck.cli run --target example.com
Combined Nmap + Shodan Scan
bash
Copy code
python -m orbitduck.cli scan --target example.com
Shodan Lookup Only
bash
Copy code
python -m orbitduck.cli shodan --target example.com
🧾 Reports & Risk Tracking
After each scan, results are stored in the /reports/ folder.

File	Description
risk_history.csv	Appends a new record for every scan (date, target, score)
risk_trend.png	Auto-generated trend graph of cumulative risk scores
scan_*.json	Raw Nmap and combined scan results
shodan_*.json	Raw Shodan lookup data

Example record in risk_history.csv:

bash
Copy code
scan_id,date,target,risk_level,risk_score
20251027164532,2025-10-27,example.com,MEDIUM,65
🧩 Allowlist Management
To prevent unauthorized scanning, Orbit-Duck enforces an allowlist.

Option 1 — In .env
env
Copy code
ORBIT_ALLOWLIST=example.com,8.8.8.8
Option 2 — In config/allowlist.txt
bash
Copy code
# Allowed targets
example.com
8.8.8.8
If neither is defined, the system enters Developer Mode, allowing all scans.
This is safe for local testing but not recommended for production.

🧰 Maintenance
Refer to the SYSTEM_MAINTENANCE.md for detailed instructions on:

Backing up and validating reports

Cleaning old logs and caches

Managing dependencies

Troubleshooting common issues

To quickly verify system health:

bash
Copy code
python -B
>>> from orbitduck.core_runner import CoreRunner, ScanTask
>>> r = CoreRunner()
>>> r.add_task(ScanTask(name="Test", target="8.8.8.8", kind="nmap:quick"))
>>> r.run_all()
🗂️ Folder Structure
lua
Copy code
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
│       │   ├── risk.py
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
│       ├── schema_merge.py        # Schema management or data merge logic
│       └── diff_engine.py
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
├── README.md
├── requirements.txt               # Python dependencies
├── SYSTEM_MAINTENANCE.md          # System maintenance documentation (this file)
├── test_pipeline.py                # End-to-end pipeline test
└── test_shodan.py  

🧪 Testing
Run the included smoke test to verify core functions:

bash
Copy code
pytest tests/test_smoke.py -v
To perform a full pipeline test:

bash
Copy code
pytest tests/test_pipeline.py -v
🤝 Contributing
Fork the repository

Create a new feature branch

Commit your changes

Submit a pull request

All contributions must adhere to PEP8 standards and include basic test coverage.

🪪 License
This project is for educational and research purposes.
Unauthorized or unethical use of Orbit-Duck for scanning non-consensual targets is strictly prohibited.

© 2025 Duck Orbit Development Team. All rights reserved.