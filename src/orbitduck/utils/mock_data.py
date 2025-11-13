import random
import time

def fake_nmap_scan(target: str):
    """Simulate a quick nmap scan result."""
    time.sleep(0.5)
    open_ports = random.sample([22, 80, 443, 8080, 3306, 21, 25], random.randint(1, 4))
    return {
        "target": target,
        "open_ports": open_ports,
        "os_guess": random.choice(["Linux", "Windows", "Ubuntu", "CentOS"]),
        "scan_type": "mock_quick",
    }

def fake_shodan_lookup(target: str):
    """Simulate a Shodan-style lookup."""
    time.sleep(0.5)
    return {
        "target": target,
        "organization": random.choice(["MockISP", "OrbitDuckNet", "TestHosters"]),
        "ip": f"192.168.{random.randint(0,255)}.{random.randint(0,255)}",
        "vulns": random.sample(
            ["CVE-2023-1234", "CVE-2022-5678", "CVE-2021-9999", "None"], 2
        ),
        "open_ports": random.sample([22, 80, 443, 3389, 53], random.randint(1, 3)),
    }

def fake_spiderfoot_scan(target: str):
    """Simulate a SpiderFoot scan result."""
    time.sleep(0.5)
    return {
        "target": target,
        "emails_found": random.randint(0, 5),
        "leaked_credentials": random.randint(0, 2),
        "social_profiles": random.choice(["LinkedIn", "Twitter", "GitHub"]),
        "scan_status": "completed"
    }
