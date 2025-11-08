from pathlib import Path
import json


def write_report(obj, out_path: str | Path):
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, indent=2))
    return str(p)