from __future__ import annotations
import sqlite3, json
from pathlib import Path
from typing import Iterable, Dict, Any, Tuple, Set

def open_db(db_path: str | Path) -> sqlite3.Connection:
    p = Path(db_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(p))
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    _ensure_schema(conn)
    return conn

def _ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS runs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            domain      TEXT NOT NULL,
            started_at  INTEGER NOT NULL,
            finished_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS assets (
            run_id  INTEGER NOT NULL,
            domain  TEXT NOT NULL,
            host    TEXT NOT NULL,
            PRIMARY KEY (run_id, host),
            FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS services (
            run_id   INTEGER NOT NULL,
            domain   TEXT NOT NULL,
            host     TEXT NOT NULL,
            ip       TEXT NOT NULL,
            port     INTEGER NOT NULL,
            proto    TEXT NOT NULL,
            service  TEXT,
            product  TEXT,
            version  TEXT,
            sources  TEXT,
            PRIMARY KEY (run_id, host, ip, port, proto),
            FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE
        );
    """)
    conn.commit()

def start_run(conn: sqlite3.Connection, domain: str, started_at: int, finished_at: int) -> int:
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO runs(domain, started_at, finished_at) VALUES (?, ?, ?)",
        (domain, started_at, finished_at),
    )
    conn.commit()
    return int(cur.lastrowid)

def save_snapshot(conn: sqlite3.Connection, run_id: int, domain: str, rows: Iterable[Dict[str, Any]]) -> None:
    rows = list(rows) or []
    
    hosts = sorted({r.get("host") for r in rows if r.get("host")})
    conn.executemany(
        "INSERT OR IGNORE INTO assets(run_id, domain, host) VALUES (?, ?, ?)",
        [(run_id, domain, h) for h in hosts],
    )
    
    svc_rows = []
    for r in rows:
        host = r.get("host"); ip = r.get("ip"); port = int(r.get("port") or 0)
        proto = (r.get("proto") or "tcp").lower()
        if not host or not ip or port <= 0: 
            continue
        svc_rows.append((run_id, domain, host, ip, port, proto,
                        r.get("service"), r.get("product"), r.get("version"),
                        r.get("sources")))
    conn.executemany(
        """INSERT OR REPLACE INTO services
           (run_id, domain, host, ip, port, proto, service, product, version, sources)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        svc_rows,
    )
    conn.commit()

def previous_run_id(conn: sqlite3.Connection, domain: str, current_run_id: int) -> int | None:
    cur = conn.cursor()
    cur.execute("SELECT id FROM runs WHERE domain=? AND id < ? ORDER BY id DESC LIMIT 1",
            (domain, current_run_id))
    row = cur.fetchone()
    return int(row[0]) if row else None

def _fetch_set(conn: sqlite3.Connection, table: str, run_id: int) -> Set[Tuple]:
    cur = conn.cursor()
    if table == "assets":
        cur.execute("SELECT host FROM assets WHERE run_id=?", (run_id,))
        return {(h,) for (h,) in cur.fetchall()}
    if table == "services":
        cur.execute("SELECT host, ip, port, proto FROM services WHERE run_id=?", (run_id,))
        return set(cur.fetchall())
    raise ValueError("bad table")

def diff_runs(conn: sqlite3.Connection, prev_id: int, cur_id: int) -> Dict[str, Any]:
    prev_assets = _fetch_set(conn, "assets", prev_id)
    cur_assets  = _fetch_set(conn, "assets", cur_id)
    prev_svcs   = _fetch_set(conn, "services", prev_id)
    cur_svcs    = _fetch_set(conn, "services", cur_id)

    added_assets   = sorted(h for (h,) in (cur_assets - prev_assets))
    removed_assets = sorted(h for (h,) in (prev_assets - cur_assets))
    added_services   = sorted(list(cur_svcs - prev_svcs))
    removed_services = sorted(list(prev_svcs - cur_svcs))

    return {
        "prev_run_id": prev_id,
        "current_run_id": cur_id,
        "assets":  {"added": added_assets, "removed": removed_assets},
        "services":{"added": [{"host":a,"ip":b,"port":c,"proto":d} for (a,b,c,d) in added_services],
                    "removed":[{"host":a,"ip":b,"port":c,"proto":d} for (a,b,c,d) in removed_services]},
    }

def write_diff_report(report_dir: str | Path, domain: str, diff: Dict[str, Any]) -> str:
    report_dir = Path(report_dir); report_dir.mkdir(parents=True, exist_ok=True)
    out = report_dir / f"diff_{domain.replace('/', '_')}.json"
    out.write_text(json.dumps(diff, indent=2))
    return str(out)