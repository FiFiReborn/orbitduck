"""
OrbitDuck Environment Sanity Check
Checks that all dependencies, modules, and config files are properly set up.
"""

import importlib
import sys
import os
from pathlib import Path

# -------------------------------------------------
# MODULE IMPORT CHECK
# -------------------------------------------------
REQUIRED_MODULES = [
    "pandas",
    "matplotlib",
    "dns.resolver",
    "ipaddress",
    "json",
    "os",
    "time",
    "pathlib",
    "orbitduck.modules.risk",
    "orbitduck.modules.subdomain_enum",
    "orbitduck.modules.geoip_lookup",
    "orbitduck.modules.whois_lookup",
    "orbitduck.utils.risk_merge",
    "orbitduck.utils.risk_trend",
]


def check_imports(modules):
    print("\n🧩 Checking required modules...\n")
    failed = []

    for mod in modules:
        try:
            importlib.import_module(mod)
            print(f"✅ {mod} — OK")
        except Exception as e:
            print(f"❌ {mod} — FAILED ({e})")
            failed.append(mod)

    if failed:
        print("\n⚠️ Some imports failed:")
        for f in failed:
            print(f"  - {f}")
        print("\n💡 Try installing missing packages with:")
        print("   pip install pandas matplotlib dnspython\n")
        sys.exit(1)
    else:
        print("\n🎉 All modules imported successfully!\n")


# -------------------------------------------------
# CONFIG FILE CHECK
# -------------------------------------------------
def check_configs():
    print("🗂️ Checking configuration files...\n")

    base_dir = Path(__file__).resolve().parent
    project_root = base_dir.parent
    config_dir = project_root / "config"
    reports_dir = project_root / "reports"

    required_files = [
        config_dir / "risk_weights.json",
        config_dir / "allowlist.txt",
    ]

    for f in required_files:
        if f.exists():
            print(f"✅ Found: {f}")
        else:
            print(f"⚠️ Missing: {f}")
            if "allowlist" in str(f):
                print("   → Create one or disable allowlist mode to scan freely.")
            elif "risk_weights" in str(f):
                print("   → Copy from sample or regenerate using default weights.")

    # Ensure reports directory exists and is writable
    if not reports_dir.exists():
        try:
            reports_dir.mkdir(parents=True)
            print(f"📁 Created missing reports directory at {reports_dir}")
        except Exception as e:
            print(f"❌ Failed to create reports directory: {e}")
            sys.exit(1)
    else:
        print(f"✅ Reports directory found: {reports_dir}")

    # Test write permission
    test_file = reports_dir / "_write_test.tmp"
    try:
        with open(test_file, "w") as f:
            f.write("ok")
        test_file.unlink()
        print("✏️ Write test passed (reports/ directory writable)\n")
    except Exception as e:
        print(f"❌ Cannot write to reports directory: {e}\n")
        sys.exit(1)

# -------------------------------------------------
# AUTO-CREATE DEFAULT CONFIG FILES (Optional Upgrade)
# -------------------------------------------------
def create_default_configs():
    print("🧰 Verifying and auto-creating missing default config files...\n")

    base_dir = Path(__file__).resolve().parent
    project_root = base_dir.parent
    config_dir = project_root / "config"
    reports_dir = project_root / "reports"

    # Ensure config directory exists
    config_dir.mkdir(exist_ok=True)

    # Default allowlist
    allowlist_path = config_dir / "allowlist.txt"
    if not allowlist_path.exists():
        allowlist_path.write_text("# OrbitDuck Allowlist\nexample.com\nscanme.nmap.org\n")
        print(f"🪶 Created default allowlist.txt → {allowlist_path}")
    else:
        print(f"✅ allowlist.txt already exists → {allowlist_path}")

    # Default risk weights
    risk_weights_path = config_dir / "risk_weights.json"
    if not risk_weights_path.exists():
        default_risk_weights = {
            "weights": {
                "cve": 10,
                "open_port": 5,
                "exposed_service": 4,
                "timeout": 2,
                "error": 1,
                "leak": 8
            },
            "thresholds": {
                "high": 30,
                "medium": 15
            },
            "modules": {
                "nmap": 0.4,
                "shodan": 0.35,
                "spiderfoot": 0.25
            }
        }
        import json
        with open(risk_weights_path, "w") as f:
            json.dump(default_risk_weights, f, indent=4)
        print(f"🪶 Created default risk_weights.json → {risk_weights_path}")
    else:
        print(f"✅ risk_weights.json already exists → {risk_weights_path}")

    print("\n🔧 Default configuration verified.\n")


# -------------------------------------------------
# MAIN EXECUTION
# -------------------------------------------------
if __name__ == "__main__":
    print("🛰️ OrbitDuck Sanity Check - Phase 1\n")
    check_imports(REQUIRED_MODULES)
    create_default_configs()   # 🆕 Run before config checks
    check_configs()
    print("✅ Environment verification complete — ready for OrbitDuck core_runner.\n")

