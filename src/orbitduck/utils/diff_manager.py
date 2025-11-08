import os
import json
from datetime import datetime

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
REPORT_DIR = os.path.join(PROJECT_ROOT, "reports")
os.makedirs(REPORT_DIR, exist_ok=True)


def load_json(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def find_scan_reports(domain):
    """Return all scan reports for a specific domain, sorted by timestamp."""
    reports = []
    for fname in sorted(os.listdir(REPORT_DIR)):
        if fname.startswith(f"scan_{domain}") and fname.endswith(".json"):
            path = os.path.join(REPORT_DIR, fname)
            data = load_json(path)
            ts = data.get("timestamp") or datetime.fromtimestamp(
                os.path.getmtime(path)
            ).strftime("%Y-%m-%d %H:%M:%S")
            reports.append((ts, path))
    reports.sort(key=lambda x: x[0])
    return reports


def diff_assets(prev_data, curr_data):
    """Compare two scan reports and return the differences."""
    prev_assets = set(prev_data.get("assets", []))
    curr_assets = set(curr_data.get("assets", []))

    new_assets = curr_assets - prev_assets
    removed_assets = prev_assets - curr_assets

    prev_ports = {a: prev_data.get("ports", {}).get(a, []) for a in prev_assets}
    curr_ports = {a: curr_data.get("ports", {}).get(a, []) for a in curr_assets}

    changed_ports = []
    for asset in curr_assets & prev_assets:
        if prev_ports.get(asset) != curr_ports.get(asset):
            changed_ports.append(
                {
                    "asset": asset,
                    "previous_ports": prev_ports.get(asset, []),
                    "current_ports": curr_ports.get(asset, []),
                }
            )

    return {
        "new_assets": list(new_assets),
        "removed_assets": list(removed_assets),
        "changed_ports": changed_ports,
        "summary": {
            "new_count": len(new_assets),
            "removed_count": len(removed_assets),
            "changed_count": len(changed_ports),
        },
    }


def generate_diff(domain):
    """Create a diff_{domain}.json comparing the last two scans."""
    reports = find_scan_reports(domain)
    if len(reports) < 2:
        print(f"[!] Not enough scans to compare for {domain}")
        return

    # Pick the last two reports
    _, prev_path = reports[-2]
    _, curr_path = reports[-1]

    prev_data = load_json(prev_path)
    curr_data = load_json(curr_path)
    diff_data = diff_assets(prev_data, curr_data)

    diff_path = os.path.join(REPORT_DIR, f"diff_{domain}.json")
    with open(diff_path, "w", encoding="utf-8") as f:
        json.dump(diff_data, f, indent=4)

    print(f"[+] Diff created: {diff_path}")
    return diff_data


def auto_generate_diffs():
    """Auto-generate diffs for all domains that have multiple scans."""
    domains = set()
    for fname in os.listdir(REPORT_DIR):
        if fname.startswith("scan_") and fname.endswith(".json"):
            parts = fname.replace("scan_", "").replace(".json", "").split("_")
            domain = parts[0]
            domains.add(domain)

    for domain in domains:
        generate_diff(domain)


if __name__ == "__main__":
    auto_generate_diffs()

    from orbitduck.utils.diff_manager import auto_generate_diffs
    auto_generate_diffs()
