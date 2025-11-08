from orbitduck.core_runner import CoreRunner, ScanTask
from orbitduck.utils.io import write_report


def main():
    runner = CoreRunner()
    runner.add_task(ScanTask(name="quick", target="example.com", kind="nmap:quick"))
    results = runner.run_all()
    write_report(results, "reports/scan.json")


if __name__ == "__main__":
    main()