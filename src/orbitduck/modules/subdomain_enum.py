import requests
import dns.resolver
import concurrent.futures
import os
import json
from datetime import datetime

# --- Setup reports directory ---
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
REPORT_DIR = os.path.join(PROJECT_ROOT, "reports")
os.makedirs(REPORT_DIR, exist_ok=True)


def from_crtsh(domain):
    """Get subdomains from crt.sh"""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        r = requests.get(url, timeout=20)
        if r.status_code != 200:
            return []
        data = r.json()
        subs = set()
        for entry in data:
            name = entry.get("name_value", "")
            for sub in name.split("\n"):
                if sub.endswith(domain):
                    subs.add(sub.strip().lower())
        return sorted(subs)
    except Exception:
        return []


def dns_brute(domain):
    """Try resolving a few common subdomains"""
    words = ["www", "api", "mail", "dev", "test", "staging"]
    found = []
    resolver = dns.resolver.Resolver()
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(resolver.resolve, f"{w}.{domain}", "A"): w for w in words}
        for future in concurrent.futures.as_completed(futures):
            sub = futures[future]
            try:
                future.result()
                found.append(f"{sub}.{domain}")
            except Exception:
                pass
    return found


def enumerate_subdomains(domain):
    """Combine crt.sh and DNS brute results"""
    subs = set(from_crtsh(domain))
    for sub in dns_brute(domain):
        subs.add(sub)
    return sorted(subs)


def save_report(domain, results):
    """Save results as JSON and CSV in the reports directory"""
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    json_path = os.path.join(REPORT_DIR, f"discovery_{domain}.json")
    csv_path = os.path.join(REPORT_DIR, "discovery.csv")

    report = {
        "timestamp": timestamp,
        "target": domain,
        "total_subdomains": len(results),
        "subdomains": results,
    }

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)

    # Append to CSV summary
    header_needed = not os.path.exists(csv_path)
    with open(csv_path, "a", encoding="utf-8") as f:
        if header_needed:
            f.write("timestamp,domain,total_subdomains\n")
        f.write(f"{timestamp},{domain},{len(results)}\n")

    print(f"[+] Saved report: {json_path}")
    print(f"[+] Updated CSV summary: {csv_path}")


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m orbitduck.modules.subdomain_enum <domain>")
        sys.exit(1)

    domain = sys.argv[1]
    print(f"[*] Enumerating subdomains for {domain}...")
    results = enumerate_subdomains(domain)

    if results:
        print(f"[+] Found {len(results)} subdomains:")
        for sub in results:
            print(" -", sub)
    else:
        print("[-] No subdomains found or query blocked.")

    save_report(domain, results)
