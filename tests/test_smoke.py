from orbitduck.core_runner import CoreRunner, ScanTask


def test_add_task():
    r = CoreRunner()
    r.add_task(ScanTask(name="t1", target="example.com", kind="nmap:quick"))
    assert len(r.tasks) == 1