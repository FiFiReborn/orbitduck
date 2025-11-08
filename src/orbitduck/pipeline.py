from __future__ import annotations
import argparse
import asyncio
import csv
import importlib
import json
import re
import socket
import ssl
import sys
import os
import time
from pathlib import Path
from ipaddress import ip_address
from typing import Any, Dict, List, Mapping, Optional
from orbitduck.modules.internetdb import fetch_internetdb, normalise_internetdb
from urllib import parse, request
from orbitduck.modules.virustotal import vt_url_scan
from orbitduck.diff_engine import (open_db, start_run, save_snapshot, previous_run_id, diff_runs, write_diff_report)


_REPO_ROOT = Path(__file__).resolve().parents[2]
_REPORTS = _REPO_ROOT / "reports"

print(f"[pipeline] running: {__file__}")

try:
    from orbitduck.modules.nmap_scan import nmap_quick_scan, nmap_default_scan
    _HAS_NMAP = True
except Exception:
    _HAS_NMAP = False

def _run(callable_obj, *args, **kwargs):
    if asyncio.iscoroutinefunction(callable_obj):
        return asyncio.run(callable_obj(*args, **kwargs))
    res = callable_obj(*args, **kwargs)
    if asyncio.iscoroutine(res):
        return asyncio.run(res)
    return res

def _normalise_http(x: Any) -> Dict[str, Any]:
    if not x:
        return {"status": None, "server": None, "title": None, "final_url": None, "error": None}
    if isinstance(x, Mapping):
        return {
            "status": x.get("status"),
            "server": x.get("server"),
            "title": x.get("title"),
            "final_url": x.get("final_url") or x.get("url"),
            "error": x.get("error"),
        }
    return {
        "status": getattr(x, "status", None),
        "server": getattr(x, "server", None),
        "title": getattr(x, "title", None),
        "final_url": getattr(x, "final_url", None) or getattr(x, "url", None),
        "error": getattr(x, "error", None),
    }

def _resolve_report_path(path: str) -> Path:
    p = Path(path)
    if not p.is_absolute():
        if p.parts and p.parts[0].lower() == "reports":
            p = _REPORTS / Path(*p.parts[1:])
        else:
            p = _REPORTS / p
    p.parent.mkdir(parents=True, exist_ok=True)
    return p

def _write_json(result: Dict[str, Any], path: str) -> None:
    p = _resolve_report_path(path)
    with p.open("w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
        print (f"[✓] JSON report written -> {p}")

def _write_csv(records: Mapping[str, Dict[str, Any]], path: str) -> None:
    p = _resolve_report_path(path)
    with p.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["host", "ips", "http_status", "server", "title", "final_url"])
        for host in sorted(records):
            rec = records[host]
            http = _normalise_http(rec.get("http"))
            w.writerow([
                host,
                ";".join(rec.get("ips", [])),
                http.get("status"),
                http.get("server"),
                (http.get("title") or "")[:200],
                http.get("final_url"),
            ])
    print (f"[✓] CSV report written -> {p}")

UA = "orbitduck/asm-pipeline/0.1"
TITLE_RX = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

def _http_get_text(url: str, timeout: float = 15.0, verbose: bool = False) -> Optional[str]:
    req = request.Request(url, headers={"User-Agent": UA})
    try:
        with request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", "ignore")
    except Exception as e:
        if verbose:
            print(f"[!] GET {url} failed: {e}")
        return None

def _http_get_json(url: str, timeout: float = 15.0, verbose: bool = False) -> Optional[dict]:
    req = request.Request(url, headers={"User-Agent": UA})
    try:
        with request.urlopen(req, timeout=timeout) as resp:
            data = resp.read()
            return json.loads(data.decode("utf-8", "ignore"))
    except Exception as e:
        if verbose:
            print(f"[!] GET {url} failed: {e}")
        return None

def _filter_for_domain(items: List[str], domain: str) -> List[str]:
    dom = domain.lower().strip(".")
    out: set[str] = set()
    for s in items:
        s = s.strip().lower().lstrip("*.").strip(".")
        if not s:
            continue
        if s == dom or s.endswith("." + dom):
            out.add(s)
    return sorted(out)

def enumerate_subdomains(domain: str, verbose: bool = False) -> List[str]:
    hosts: List[str] = []
    crt_url = f"https://crt.sh/?{parse.urlencode({'q': f'%.{domain}', 'output': 'json'})}"
    data = _http_get_json(crt_url, verbose=verbose) or []
    if isinstance(data, list) and data:
        for row in data:
            val = row.get("name_value", "") if isinstance(row, dict) else ""
            for h in re.split(r"[\s,]+", val):
                if h and "*" not in h:
                    hosts.append(h)
    else:
        html = _http_get_text(f"https://crt.sh/?q=%25.{domain}", verbose=verbose) or ""
        for h in re.findall(r"([a-zA-Z0-9_\-\.]+\." + re.escape(domain) + r")", html):
            if "*" not in h:
                hosts.append(h)
    
    bo_url = f"https://dns.bufferover.run/dns?{parse.urlencode({'q': domain})}"
    j = _http_get_json(bo_url, verbose=verbose) or {}
    for key in ("FDNS_A", "RDNS", "FDNS_CNAME"):
        for line in (j.get(key) or []):
            parts = line.split(",")
            host = parts[-1].strip().lower()
            if host:
                hosts.append(host)
    
    out = _filter_for_domain(hosts, domain)
    if verbose:
        print(f"[v] enum: {len(out)} unique hosts after filtering")
    return out

def _resolve_one(host: str) -> List[str]:
    ips: set[str] = set()
    try:
        for _fam, _typ, _proto, _canon, sockaddr in socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP):
            ip = sockaddr[0]
            try:
                ips.add(str(ip_address(ip)))
            except Exception:
                pass
    except Exception:
        pass
    return sorted(ips)

def resolve_many(hosts: List[str], max_workers: int = 50) -> Dict[str, List[str]]:
    from concurrent.futures import ThreadPoolExecutor, as_completed
    out: Dict[str, List[str]] = {}
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        fut = {ex.submit(_resolve_one, h): h for h in hosts}
        for f in as_completed(fut):
            out[fut[f]] = f.result()
    return out

def _fetch_url(url: str, timeout: float = 10.0) -> Dict[str, Any]:
    req = request.Request(url, headers={"User-Agent": UA})
    ctx = ssl.create_default_context()
    try:
        with request.urlopen(req, timeout=timeout, context=ctx) as resp:
            status = getattr(resp, "status", None)
            final_url = resp.geturl()
            server = resp.headers.get("Server")
            ctype = (resp.headers.get("Content-Type") or "").lower()
            title = None
            if "text/html" in ctype:
                data = resp.read(262144).decode("utf-8", "ignore")
                m = TITLE_RX.search(data or "")
                if m:
                    title = re.sub(r"\s+", " ", m.group(1)).strip()[:200]
            return {"status": status, "server": server, "title": title, "final_url": final_url, "error": None}
    except Exception as e:
        return {"status": None, "server": None, "title": None, "final_url": None, "error": str(e)}

def _http_probe_host(host: str, timeout: float = 10.0) -> Dict[str, Any]:
    https = _fetch_url(f"https://{host}", timeout=timeout)
    if https["status"] is not None or https["error"] is None:
        return https
    return _fetch_url(f"http://{host}", timeout=timeout)

def enrich_http_many(hosts: List[str], max_workers: int = 50, timeout: float = 10.0) -> Dict[str, Dict[str, Any]]:
    from concurrent.futures import ThreadPoolExecutor, as_completed
    out: Dict[str, Dict[str, Any]] = {}
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        fut = {ex.submit(_http_probe_host, h, timeout): h for h in hosts}
        for f in as_completed(fut):
            out[fut[f]] = f.result()
    return out

def _load_shodan_hosts(domain: str,
                       shodan_json_path: Optional[str],
                       shodan_callback: Optional[str]) -> List[dict]:
    hosts: List[dict] = []
    if shodan_callback:
        try:
            mod_name, func_name = shodan_callback.split(":")
            mod = importlib.import_module(mod_name)
            fn = getattr(mod, func_name)
            res = _run(fn, domain)
            if isinstance(res, list):
                hosts = res
            elif isinstance(res, dict):
                hosts = [res]
        except Exception as e:
            print(f"[!] shodan callback failed: {e}")
    
    if not hosts and shodan_json_path:
        try:
            with open(shodan_json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    hosts = data
                elif isinstance(data, dict):
                    hosts = [data]
        except Exception as e:
            print(f"[!] failed to read shodan JSON: {e}")
    
    return hosts

def _is_ip(target: str) -> bool:
    try:
        ip_address(target.strip())
        return True
    except Exception:
        return False

def run_pipeline(
    domain: str,
    out_json: str = "reports/discovery.json",
    out_csv: str = "reports/discovery.csv",
    with_nmap: bool = False,
    nmap_kind: str = "quick",
    http_timeout: float = 10.0,
    workers: int = 50,
    with_shodan: bool = False,
    shodan_json_path: Optional[str] = None,
    shodan_callback: Optional[str] = None,
    verbose: bool = False,
    db_path: str = "reports/orbitduck.db", 
) -> int:
    t0 = int(time.time())
    unique_ips: List[str] = []
    internetdb_payloads: List[dict] = []
    internetdb_findings: List[dict] = []
    
    if _is_ip(domain):
        print(f"[+] Target is an IP address: {domain}")
        discovered: List[str] = [domain.strip()]
        resolved_map: Dict[str, List[str]] = {domain: [domain]}
    else:
        print(f"[+] Enumerating subdomains for {domain}")
        discovered = sorted(set(_run(enumerate_subdomains, domain, verbose)))
        print(f"[+] Discovered {len(discovered)} host(s)")
        print("[+] Resolving hosts...")
        resolved_map = _run(resolve_many, discovered, max_workers=workers)
    
    print("[+] HTTP fingerprinting...")
    http_map: Dict[str, Any] = _run(enrich_http_many, discovered, max_workers=workers, timeout=http_timeout)
    
    if not discovered and not _is_ip(domain):
        discovered = [domain]
        resolved_map = _run(resolve_many, discovered, max_workers=workers)
        http_map = _run(enrich_http_many, discovered, max_workers=workers, timeout=http_timeout)
    
    records: Dict[str, Dict[str, Any]] = {}
    for h in discovered:
        records[h] = {
            "ips": resolved_map.get(h, []),
            "http": _normalise_http(http_map.get(h)),
        }

    unique_ips = sorted({
        ip
        for rec in (records or {}).values()
        for ip in (rec.get("ips") or [])
    })
    internetdb_payloads = [fetch_internetdb(ip) for ip in unique_ips]
    internetdb_findings = []
    for payload in internetdb_payloads:
        internetdb_findings.extend(normalise_internetdb(payload))

    (_REPORTS / "internetdb_raw.json").write_text(
        json.dumps(internetdb_payloads, indent=2, ensure_ascii=False))
    
    (_REPORTS / "internetdb_findings.json").write_text(
        json.dumps(internetdb_findings, indent=2, ensure_ascii=False))
    
    vt_url = f"http://{domain}/"
    vt_report = vt_url_scan(
        vt_url,
        api_key=os.getenv("VT_API_KEY"),
        wait_for_completion=True,
    )

    (_REPORTS / "virustotal_urlscan.json").write_text(
        json.dumps(vt_report, indent=2, ensure_ascii=False)
    )

    scanned: Dict[str, Any] = {}
    if with_nmap and _HAS_NMAP:
        print("[+] nmap scanning...")
        nmap_fn = nmap_quick_scan if nmap_kind == "quick" else nmap_default_scan
        for h in records.keys():
            try:
                scanned[h] = _run(nmap_fn, h)
            except Exception as e:
                scanned[h] = {"error": str(e)}
    elif with_nmap and not _HAS_NMAP:
        print("[!] nmap module couldn't be found — skipping active scan.")

    pipeline_result_data = {
        "domain": domain,
        "discovered_count": len(discovered),
        "records": records,
        "scanned": scanned if scanned else {},
        "started_at": t0,
        "finished_at": int(time.time()),
        "internetdb": {
            "ips": unique_ips,
            "payloads": internetdb_payloads,
            "findings": internetdb_findings,
        },
        "virustotal": {
            "url": vt_url,
            "urlscan": vt_report,
        },
    }

    _write_json(pipeline_result_data, out_json)
    _write_csv(records, out_csv)

    try:
        from orbitduck.schema_merge import merge_assets, write_assets_json, write_service_rows_csv
        shodan_hosts = _load_shodan_hosts(domain, shodan_json_path, shodan_callback) if with_shodan else None
        assets, rows = merge_assets(
            domain=domain,
            pipeline_result=pipeline_result_data,
            shodan_hosts=shodan_hosts
        )
        
        write_assets_json(assets, str(_REPORTS / "assets.json"))
        write_service_rows_csv(rows, str(_REPORTS / "asset_rows.csv"))
        print("[✓] assets.json and asset_rows.csv written")
        db_file = (_REPORTS / Path(db_path).name) if not Path(db_path).is_absolute() else Path(db_path)
        print(f"[i] using Database -> {db_file}")
        conn = open_db(db_file)
        run_id = start_run(conn, domain=domain, started_at=t0, finished_at=int(time.time()))
        save_snapshot(conn, run_id, domain, rows)

        prev_id = previous_run_id(conn, domain, run_id)
        if prev_id:
            diff = diff_runs(conn, prev_id, run_id)
            diff_out = write_diff_report(_REPORTS, domain, diff)
            print(f"[✓] diff report written -> {diff_out}")
        else:
            print("[i] no previous run for this domain — diff will be available from next run")
    except Exception as e:
            print(f"[!] diff engine skipped: {e}")
    except Exception as e:
        print(f"[!] schema merge skipped: {e}")

    print(f"[✓] Done: {out_json}, {out_csv}")
    return 0

def main():
    ap = argparse.ArgumentParser(description="ASM pipeline: orchestrate subdomain enum + enrichment (+ optional Shodan).")
    ap.add_argument("--domain", required=True, help="Base domain or IP (e.g., example.com or 203.0.113.10)")
    ap.add_argument("--out-json", default="reports/discovery.json", help="JSON output path")
    ap.add_argument("--out-csv", default="reports/discovery.csv", help="CSV output path")
    ap.add_argument("--with-nmap", action="store_true", help="Run optional nmap stage if available")
    ap.add_argument("--nmap-kind", choices=["quick", "default"], default="quick", help="nmap preset")
    ap.add_argument("--http-timeout", type=float, default=10.0, help="HTTP timeout seconds")
    ap.add_argument("--workers", type=int, default=50, help="Thread pool size")
    ap.add_argument("--with-shodan", action="store_true", help="Merge Shodan outputs into assets/services")
    ap.add_argument("--shodan-json", dest="shodan_json_path", help="Path to Shodan JSON (list or single host object)")
    ap.add_argument("--shodan-callback", dest="shodan_callback", help='module:function that returns list of Shodan "host" objects')
    ap.add_argument("--verbose", action="store_true", help="Print network errors and enum fallbacks")
    ap.add_argument("--db-path", default="reports/orbitduck.db", help="SQLite path for snapshots & diffs (default: reports/orbitduck.db)")
    args = ap.parse_args()
    
    sys.exit(run_pipeline(
        domain=args.domain,
        out_json=args.out_json,
        out_csv=args.out_csv,
        with_nmap=args.with_nmap,
        nmap_kind=args.nmap_kind,
        http_timeout=args.http_timeout,
        workers=args.workers,
        with_shodan=args.with_shodan,
        shodan_json_path=args.shodan_json_path,
        shodan_callback=args.shodan_callback,
        verbose=args.verbose,
        db_path=args.db_path,
    ))

if __name__ == "__main__":
    main()