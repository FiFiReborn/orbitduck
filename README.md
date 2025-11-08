# 🛰️ OrbitDuck – Capstone Evolution Project

Originally developed as a **Capstone group project** by three team members (including myself), OrbitDuck began as an ambitious attempt to build a modular Attack Surface Management tool using Python — with minimal prior experience in networking automation or Python modules.

After our Capstone submission, I chose to continue developing OrbitDuck independently to **expand my skills in Python and cybersecurity automation**, refining existing systems and building new ones.  
This included improving modular architecture, implementing trend analysis, optimizing reporting, and enhancing overall usability.

This repository represents the evolution of our original Capstone work into an ongoing personal and professional project.

---

## 🧩 Project Overview

**Version:** 1.0  
**Maintainer:** Duck Orbit Development Team (Now maintained by [Your Name])  
**Last Updated:** 2025-11-08  

OrbitDuck is a modular **Attack Surface Management (ASM)** and **Risk Assessment Framework** that automates network scanning, Shodan lookups, and risk tracking.  
It integrates **Nmap**, **Shodan**, and internal risk analysis modules to produce measurable insights and long-term trend visuals.

---

## 📘 Table of Contents
- [Overview](#-project-overview)
- [Features](#-features)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Quick Start](#-quick-start)
- [Reports & Risk Tracking](#-reports--risk-tracking)
- [Allowlist Management](#-allowlist-management)
- [Maintenance](#-maintenance)
- [Folder Structure](#-folder-structure)
- [Testing](#-testing)
- [Contributing](#-contributing)
- [License](#-license)

---

## ⚙️ Features

| Feature | Description |
|----------|-------------|
| 🔍 **Nmap Scanning** | Supports quick (`-F`) and default (`-sV`) profiles |
| 🌐 **Shodan Integration** | Fetches asset intelligence via the Shodan API |
| 📊 **Risk Scoring** | Calculates and logs risk levels for each scan target |
| 🧠 **Trend Visualization** | Auto-generates ongoing risk trend charts in `/reports/` |
| 🔒 **Allowlist Enforcement** | Prevents unauthorized target scans |
| ⚡ **Rate Limiting** | Global throttling for responsible scanning |
| 🧾 **Detailed Reports** | Generates JSON, CSV, and HTML summaries automatically |

---

## 💻 Installation

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/<your-username>/orbitduck.git
cd orbitduck

2️⃣ Create a Virtual Environment

python -m venv .venv
source .venv/bin/activate        # macOS/Linux
# or
.venv\Scripts\activate           # Windows

3️⃣ Install Dependencies

pip install -r requirements.txt

4️⃣ Verify Installation

python -B -m orbitduck.cli --help
You should see the CLI help message listing available commands (run, scan, shodan).

⚙️ Configuration
OrbitDuck uses an .env file to manage API keys and configuration options.

Example .env:

# Shodan API Key
SHODAN_API_KEY=YOUR_API_KEY_HERE

# Rate Limits
GLOBAL_RATE_PER_MIN=20
SHODAN_RATE_PER_MIN=25

# Allowlist (comma-separated)
ORBIT_ALLOWLIST=example.com,8.8.8.8

# Optional allowlist file
ORBIT_ALLOWLIST_FILE=config/allowlist.txt


🚀 Quick Start
Run a quick Nmap scan:

python -m orbitduck.cli run --target example.com --quick
Run a full scan:

python -m orbitduck.cli run --target example.com
Combine Nmap + Shodan:

python -m orbitduck.cli scan --target example.com
Shodan lookup only:

python -m orbitduck.cli shodan --target example.com


🧾 Reports & Risk Tracking
All outputs are stored in the /reports/ directory.

File	Description
risk_history.csv	Historical record of all scans
risk_trend.png	Auto-generated visual of cumulative risk trends
scan_*.json	Raw Nmap and combined scan results
shodan_*.json	Shodan lookup data
index.html	Dashboard summary

Example risk_history.csv:

scan_id,date,target,risk_level,risk_score
20251027_164532,2025-10-27,example.com,MEDIUM,65


🧩 Allowlist Management
To prevent unauthorized scanning, OrbitDuck enforces an allowlist.

Option 1 — In .env

ORBIT_ALLOWLIST=example.com,8.8.8.8


Option 2 — In config/allowlist.txt

# Allowed targets
example.com
8.8.8.8
If neither exists, the system enters Developer Mode (for local testing only).

🧰 Maintenance
Detailed maintenance steps can be found in SYSTEM_MAINTENANCE.md.

Key topics:

Backing up reports

Cleaning old logs

Managing dependencies

Troubleshooting runtime issues

To verify system health manually:

python -B
>>> from orbitduck.core_runner import CoreRunner, ScanTask
>>> r = CoreRunner()
>>> r.add_task(ScanTask(name="Test", target="8.8.8.8", kind="nmap:quick"))
>>> r.run_all()
🗂️ Folder Structure

orbitduck/
│
├── config/                      # Allowlist + configs
│   └── allowlist.txt
│
├── reports/                     # Scan reports and visuals
│   ├── risk_history.csv
│   ├── risk_trend.png
│   ├── scan_*.json
│   └── index.html
│
├── src/orbitduck/
│   ├── modules/                 # Core scanning modules
│   │   ├── nmap_scan.py
│   │   ├── shodan_search.py
│   │   ├── subdomain_enum.py
│   │   └── risk.py
│   │
│   ├── utils/                   # Utilities and helpers
│   │   ├── diff_manager.py
│   │   ├── report_manager.py
│   │   ├── risk_trend.py
│   │   └── io.py
│   │
│   ├── cli.py
│   ├── core_runner.py
│   ├── main.py
│   └── pipeline.py
│
├── tests/
│   ├── test_smoke.py
│   ├── test_pipeline.py
│   └── test_shodan.py
│
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── pyproject.toml
├── SYSTEM_MAINTENANCE.md
└── README.md
🧪 Testing
Run a basic smoke test:

pytest tests/test_smoke.py -v
Run the full pipeline test:

pytest tests/test_pipeline.py -v
🤝 Contributing
Fork this repository

Create a new branch (feature/...)

Commit and push your changes

Submit a pull request

All contributions should follow PEP8 style and include basic testing.

🪪 License
This project is for educational and research purposes only.
Unauthorized or unethical use of OrbitDuck for scanning non-consensual targets is strictly prohibited.

© 2025 Duck Orbit Development Team. Maintained and expanded by Judith.

