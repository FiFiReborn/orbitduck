from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple, Iterable
import csv, json
from pathlib import Path

@dataclass
class Service:
    ip: str
    port: int
    proto: str = "tcp"
    service: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    cpe: List[str] = field(default_factory=list)
    http_status: Optional[int] = None
    http_server: Optional[str] = None
    http_title: Optional[str] = None
    url: Optional[str] = None
    tls_ja3: Optional[str] = None
    tls_issuer: Optional[str] = None
    tls_subject: Optional[str] = None
    sources: List[str] = field(default_factory=list)

@dataclass
class Asset:
    host: str
    domain: Optional[str] = None
    ips: List[str] = field(default_factory=list)
    asn: Optional[str] = None
    org: Optional[str] = None
    country: Optional[str] = None
    vt_reputation: Optional[int] = None
    vt_malicious: Optional[int] = None
    vt_suspicious: Optional[int] = None
    tags: List[str] = field(default_factory=list)
    services: List[Service] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)

def _append_service(asset: Asset, svc: Service) -> None:
    for existing in asset.services:
        if (existing.ip, existing.port, existing.proto) == (svc.ip, svc.port, svc.proto):
            existing.service = existing.service or svc.service
            existing.product = existing.product or svc.product
            existing.version = existing.version or svc.version
            existing.cpe = sorted(set((existing.cpe or []) + (svc.cpe or [])))
            existing.http_status = existing.http_status or svc.http_status
            existing.http_server = existing.http_server or svc.http_server
            existing.http_title = existing.http_title or svc.http_title
            existing.url = existing.url or svc.url
            existing.tls_ja3 = existing.tls_ja3 or svc.tls_ja3
            existing.tls_issuer = existing.tls_issuer or svc.tls_issuer
            existing.tls_subject = existing.tls_subject or svc.tls_subject
            existing.sources = sorted(set(existing.sources + svc.sources))
            return
    asset.services.append(svc)

def _asset_for_host(assets: Dict[str, Asset], host: str, domain: Optional[str]) -> Asset:
    if host not in assets:
        assets[host] = Asset(host=host, domain=domain, sources=["pipeline"])
    return assets[host]

def add_from_pipeline_result(assets: Dict[str, Asset], domain: str, pipeline_result: Dict[str, Any]) -> None:
    records = pipeline_result.get("records") or {}
    for host, rec in records.items():
        asset = _asset_for_host(assets, host, domain)
        for ip in rec.get("ips") or []:
            if ip not in asset.ips:
                asset.ips.append(ip)
        http = rec.get("http") or {}
        url = (http.get("final_url") or "") or None
        code = http.get("status")
        server = http.get("server")
        title = http.get("title")
        port = 443 if (url or "").startswith("https://") else 80
        if code is not None or server or title or url:
            target_ips = asset.ips or ["0.0.0.0"]
            for ip in target_ips:
                _append_service(asset, Service(
                    ip=ip, port=port, proto="tcp",
                    service="https" if port == 443 else "http",
                    http_status=code, http_server=server, http_title=title, url=url,
                    sources=["pipeline"]
                ))

def add_from_shodan_host(assets: Dict[str, Asset], domain: Optional[str], shodan_host_json: Dict[str, Any]) -> None:
    if not shodan_host_json:
        return
    ip_str = str(shodan_host_json.get("ip_str") or shodan_host_json.get("ip") or "").strip()
    if not ip_str:
        return
    hostnames = shodan_host_json.get("hostnames") or []
    chosen_host = hostnames[0] if hostnames else ip_str
    asset = _asset_for_host(assets, chosen_host, domain)
    if ip_str not in asset.ips:
        asset.ips.append(ip_str)
    asset.sources = sorted(set(asset.sources + ["shodan"]))
    asset.asn = asset.asn or (shodan_host_json.get("asn") or shodan_host_json.get("org"))
    asset.org = asset.org or shodan_host_json.get("org")
    cc = shodan_host_json.get("country_code") or shodan_host_json.get("country_name")
    asset.country = asset.country or (str(cc) if cc else None)
    tags = shodan_host_json.get("tags") or []
    asset.tags = sorted(set(asset.tags + [t for t in tags if isinstance(t, str)]))
    for entry in shodan_host_json.get("data") or []:
        port = int(entry.get("port") or 0) or 0
        if port <= 0: 
            continue
        product = entry.get("product")
        version = entry.get("version")
        cpe = entry.get("cpe") or entry.get("cpe23") or entry.get("cpe23Uri") or []
        if isinstance(cpe, str):
            cpe = [cpe]
        http = entry.get("http") or {}
        http_server = http.get("server")
        http_title = http.get("title")
        ssl = entry.get("ssl") or {}
        ja3 = (ssl.get("ja3") or {}).get("fingerprint") if isinstance(ssl.get("ja3"), dict) else ssl.get("ja3")
        cert = ssl.get("cert") or {}
        issuer = (cert.get("issuer") or {}).get("CN") if isinstance(cert.get("issuer"), dict) else None
        subject = (cert.get("subject") or {}).get("CN") if isinstance(cert.get("subject"), dict) else None
        _append_service(asset, Service(
            ip=ip_str, port=port, proto="tcp",
            service=entry.get("transport") or "tcp",
            product=product, version=version, cpe=[c for c in cpe if isinstance(c, str)],
            http_server=http_server, http_title=http_title,
            tls_ja3=ja3, tls_issuer=issuer, tls_subject=subject,
            sources=["shodan"]
        ))

def add_from_internetdb(assets: Dict[str, Asset], domain: Optional[str], internetdb_payloads: List[Dict[str, Any]]) -> None:
    for payload in internetdb_payloads or []:
        ip = str(payload.get("ip") or "").strip()
        if not ip:
            continue

        asset = _asset_for_host(assets, ip, domain)
        if ip not in asset.ips:
            asset.ips.append(ip)

        for t in (payload.get("tags") or []):
            if isinstance(t, str) and t not in asset.tags:
                asset.tags.append(t)
        asset.tags = sorted(set(asset.tags))
        if "internetdb" not in asset.sources:
            asset.sources.append("internetdb")
    
        for p in (payload.get("ports") or []):
            try:
                port = int(p)
            except Exception:
                continue
            _append_service(asset, Service(
                ip=ip,
                port=port,
                proto="tcp",
                service=None,
                sources=["internetdb"],
        ))

def merge_assets(
    domain: str,
    pipeline_result: Dict[str, Any],
    shodan_hosts: Optional[Iterable[Dict[str, Any]]] = None,
) -> Tuple[List[Asset], List[Dict[str, Any]]]:
    assets_by_host: Dict[str, Asset] = {}
    add_from_pipeline_result(assets_by_host, domain, pipeline_result)
    if shodan_hosts:
        for host_obj in shodan_hosts:
            try:
                add_from_shodan_host(assets_by_host, domain, host_obj)
            except Exception:
                continue
    internetdb = (pipeline_result or {}).get("internetdb") or {}
    add_from_internetdb(assets_by_host, domain, internetdb.get("payloads") or [])
    vt = (pipeline_result or {}).get("virustotal", {}).get("urlscan") or {}
    engines = vt.get("engines") or {}
    vt_flagged = any(
        (v or{}).get("category") not in (None, "harmless", "undetected")
        for v in engines.values()
    )
    if vt_flagged:
        for a in assets_by_host.values():
            a.tags = sorted(set((a.tags or []) + ["vt_flagged"]))
            a.sources = sorted(set((a.sources or []) + ["virustotal"]))
    assets: List[Asset] = list(assets_by_host.values())
    rows: List[Dict[str, Any]] = []
    for asset in assets:
        for svc in asset.services:
            rows.append({
                "domain": asset.domain,
                "host": asset.host,
                "ip": svc.ip,
                "asn": asset.asn,
                "org": asset.org,
                "country": asset.country,
                "port": svc.port,
                "proto": svc.proto,
                "service": svc.service,
                "product": svc.product,
                "version": svc.version,
                "cpe": ";".join(svc.cpe or []),
                "http_status": svc.http_status,
                "http_server": svc.http_server,
                "http_title": svc.http_title,
                "url": svc.url,
                "sources": ";".join(sorted(set((asset.sources or []) + (svc.sources or [])))),
                "vt_reputation": asset.vt_reputation,
                "vt_malicious": asset.vt_malicious,
                "vt_suspicious": asset.vt_suspicious,
            })
    return assets, rows

def write_assets_json(assets: List[Asset], out_path: str) -> str:
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps([asdict(a) for a in assets], indent=2, ensure_ascii=False))
    return str(p)

def write_service_rows_csv(rows: List[Dict[str, Any]], out_path: str) -> str:
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        p.write_text("")
        return str(p)
    with p.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        for r in rows:
            w.writerow(r)
    return str(p)           