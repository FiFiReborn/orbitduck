import os
import json
import csv
from datetime import datetime
import matplotlib.pyplot as plt

# --- Path setup ---
# Get absolute path to project root (two levels above this file)
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))

# Define reports directory relative to project root
REPORT_DIR = os.path.join(PROJECT_ROOT, "reports")

# Make sure the directory exists
os.makedirs(REPORT_DIR, exist_ok=True)

RISK_HISTORY = os.path.join(REPORT_DIR, "risk_history.csv")
TREND_IMG = os.path.join(REPORT_DIR, "risk_trend.png")
INDEX_HTML = os.path.join(REPORT_DIR, "index.html")



def load_json(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def collect_reports():
    """Collects all JSON reports and returns summaries per domain."""
    summaries = []
    for fname in sorted(os.listdir(REPORT_DIR)):
        if not fname.endswith(".json") or fname.startswith("diff_"):
            continue

        path = os.path.join(REPORT_DIR, fname)
        data = load_json(path)
        timestamp = data.get("timestamp") or datetime.fromtimestamp(
            os.path.getmtime(path)
        ).strftime("%Y-%m-%d %H:%M:%S")

        domain = data.get("target") or fname.replace("scan_", "").replace(".json", "")
        risk_summary = data.get("risk_summary", {})
        total_assets = len(data.get("assets", [])) if "assets" in data else 0

        summaries.append(
            {
                "domain": domain,
                "timestamp": timestamp,
                "critical": risk_summary.get("critical", 0),
                "high": risk_summary.get("high", 0),
                "medium": risk_summary.get("medium", 0),
                "low": risk_summary.get("low", 0),
                "total_assets": total_assets,
            }
        )
    return summaries


def update_risk_history(summaries):
    """Append new scan results to risk_history.csv if missing."""
    existing = set()

    # Read existing rows if file already exists
    if os.path.exists(RISK_HISTORY):
        with open(RISK_HISTORY, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Handle older files with missing headers
                dom = row.get("domain") or row.get("target") or "unknown"
                ts = row.get("timestamp") or row.get("date") or "unknown"
                existing.add((dom, ts))

    # Write new data (append if not duplicate)
    with open(RISK_HISTORY, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["timestamp", "domain", "critical", "high", "medium", "low", "total_assets"],
        )
        if f.tell() == 0:  # write header if file is new
            writer.writeheader()

        for s in summaries:
            key = (s.get("domain", "unknown"), s.get("timestamp", "unknown"))
            if key not in existing:
                writer.writerow(s)



def generate_trend_chart():
    """Generate risk trend chart from risk_history.csv."""
    if not os.path.exists(RISK_HISTORY):
        print("[!] No risk_history.csv found, skipping trend chart.")
        return

    timestamps, highs, mediums, lows = [], [], [], []
    with open(RISK_HISTORY, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Handle missing or mismatched columns gracefully
            ts = row.get("timestamp") or row.get("date") or "unknown"
            timestamps.append(ts)
            highs.append(int(row.get("high", 0)))
            mediums.append(int(row.get("medium", 0)))
            lows.append(int(row.get("low", 0)))

    if not timestamps:
        print("[!] No data found in risk_history.csv, skipping chart.")
        return

    plt.figure(figsize=(8, 4))
    plt.plot(timestamps, highs, label="High", marker="o")
    plt.plot(timestamps, mediums, label="Medium", marker="o")
    plt.plot(timestamps, lows, label="Low", marker="o")
    plt.xticks(rotation=45, ha="right")
    plt.ylabel("Number of Findings")
    plt.title("Risk Trend Over Time")
    plt.legend()
    plt.tight_layout()
    plt.savefig(TREND_IMG)
    plt.close()
    print(f"[+] Risk trend chart updated: {TREND_IMG}")



def generate_index_html(summaries):
    """Create a basic HTML dashboard for all reports."""
    rows = ""
    for s in summaries:
        rows += f"""
        <tr>
            <td>{s['timestamp']}</td>
            <td>{s['domain']}</td>
            <td>{s['total_assets']}</td>
            <td>{s['critical']}</td>
            <td>{s['high']}</td>
            <td>{s['medium']}</td>
            <td>{s['low']}</td>
        </tr>
        """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Orbit Reports Summary</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 2rem; background: #f7f9fa; }}
        h1 {{ text-align: center; }}
        table {{ border-collapse: collapse; width: 100%; background: white; }}
        th, td {{ border: 1px solid #ccc; padding: 8px; text-align: center; }}
        th {{ background: #eee; }}
    </style>
</head>
<body>
    <h1>Orbit Reports Summary</h1>
    <img src="risk_trend.png" style="width:60%;display:block;margin:20px auto;">
    <table>
        <tr><th>Date</th><th>Domain</th><th>Assets</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th></tr>
        {rows}
    </table>
</body>
</html>
"""
    with open(INDEX_HTML, "w", encoding="utf-8") as f:
        f.write(html)


def build_reports_dashboard():
    """Full pipeline: collect, update CSV, generate chart + HTML."""
    summaries = collect_reports()
    update_risk_history(summaries)
    generate_trend_chart()
    generate_index_html(summaries)
    print(f"[+] Dashboard updated: {INDEX_HTML}")


if __name__ == "__main__":
    build_reports_dashboard()
