"""
Duck Orbit - Risk Delta Trend Visual
------------------------------------
Generates a trend chart showing how total risk changes across scans.
"""

import pandas as pd
import matplotlib.pyplot as plt
import os
from datetime import datetime

def generate_risk_trend(data_file="reports/risk_history.csv", output_dir="reports"):
    """
    Reads historical risk data and produces a Risk Delta Trend visual.
    Adjusted to work with risk_history.csv format (risk_score per target).
    """

    os.makedirs(output_dir, exist_ok=True)

    if not os.path.exists(data_file):
        print("[i] No risk history file found — skipping chart generation.")
        return

    # --- Step 1: Load dataset ---
    df = pd.read_csv(data_file, parse_dates=["date"])
    if df.empty:
        print("[i] Risk history is empty — no chart generated.")
        return

    # --- Step 2: Aggregate total risk per scan ---
    grouped = df.groupby("date", as_index=False)["risk_score"].sum()
    grouped.rename(columns={"risk_score": "total_risk_score"}, inplace=True)
    grouped.sort_values("date", inplace=True)
    grouped["risk_delta"] = grouped["total_risk_score"].diff()

    # --- Step 3: Generate chart ---
    plt.figure(figsize=(10, 6))
    plt.plot(grouped["date"], grouped["total_risk_score"], marker="o", color="steelblue", linewidth=2, label="Total Risk Score")

    bar_colors = ["green" if delta < 0 else "red" for delta in grouped["risk_delta"].fillna(0)]
    plt.bar(grouped["date"], grouped["risk_delta"].fillna(0), color=bar_colors, alpha=0.3, label="Risk Delta (change)")

    plt.title("Duck Orbit – Risk Delta Trend", fontsize=14, weight="bold")
    plt.xlabel("Scan Date")
    plt.ylabel("Total Risk Score")
    plt.grid(True, linestyle="--", alpha=0.6)
    plt.legend()
    plt.tight_layout()

    chart_path = os.path.join(output_dir, "risk_trend.png")
    plt.savefig(chart_path, dpi=200)
    plt.close()

    print(f"[✓] Risk Delta Trend visual generated: {chart_path}")

    # --- Step 4: Return summary info ---
    latest = grouped.iloc[-1]
    prev = grouped.iloc[-2] if len(grouped) > 1 else None
    summary = {
        "latest_date": str(latest["date"]),
        "total_risk": int(latest["total_risk_score"]),
        "risk_change": int(latest["risk_delta"]) if prev is not None else None,
        "chart_path": chart_path
    }
    return summary


if __name__ == "__main__":
    generate_risk_trend()
