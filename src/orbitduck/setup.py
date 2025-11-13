import os
from pathlib import Path
from colorama import Fore, Style, init
import json
init(autoreset=True)

def create_default_config():
    base_dir = Path("orbitduck/config")
    allow_dir = Path("config")

    base_dir.mkdir(parents=True, exist_ok=True)
    allow_dir.mkdir(parents=True, exist_ok=True)

    conf_file = base_dir / "orbitduck.conf"
    allow_file = allow_dir / "allowlist.txt"

    if not conf_file.exists():
        conf_file.write_text("""# OrbitDuck Configuration
MOCK_MODE=false
DEFAULT_ALLOWLIST=example.com, testsite.org
""")
        print(f"[+] Created default config at {conf_file}")
    else:
        print(f"[*] Config file already exists at {conf_file}")

    if not allow_file.exists():
        allow_file.write_text("example.com\n")
        print(f"[+] Created default allowlist at {allow_file}")
    else:
        print(f"[*] Allowlist already exists at {allow_file}")

    # Create risk_weights.json
    create_default_risk_weights()

    print("\nSetup complete! You can now run:")
    print("    python -m orbitduck.core_runner example.com\n")


def create_default_risk_weights():
    config_dir = Path("config")
    config_dir.mkdir(parents=True, exist_ok=True)
    risk_file = config_dir / "risk_weights.json"

    if not risk_file.exists():
        default_risks = {
            "open_ports": 2.0,
            "vulnerabilities": 3.5,
            "exposed_services": 2.5,
            "ssl_issues": 1.5,
            "subdomain_exposure": 1.0
        }
        risk_file.write_text(json.dumps(default_risks, indent=4))
        print(f"[+] Created default risk_weights.json at {risk_file}")
    else:
        print(f"[*] risk_weights.json already exists at {risk_file}")


if __name__ == "__main__":
    print(f"{Fore.YELLOW}OrbitDuck Setup Wizard\n{'=' * 28}")
    create_default_config()
