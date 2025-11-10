# tests/test_reports.py
from orbitduck.utils import risk_trend, report_manager
import os

def test_risk_trend_generation(tmp_path):
    test_csv = tmp_path / "risk_history.csv"
    test_csv.write_text("date,risk_score\n2025-11-08,30\n2025-11-09,40\n")

    output_dir = tmp_path
    result = risk_trend.generate_risk_trend(str(test_csv), str(output_dir))

    assert result is not None
    assert os.path.exists(result["chart_path"])

def test_report_dashboard(tmp_path):
    report_path = tmp_path / "index.html"
    report_manager.build_reports_dashboard(output_dir=str(tmp_path))

    assert report_path.exists()
