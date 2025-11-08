# src/orbitduck/cli.py

from pathlib import Path
from dotenv import load_dotenv
load_dotenv()

import os
import click
from rich.console import Console
from rich.table import Table
from urllib.parse import urlparse
from orbitduck.core_runner import CoreRunner, ScanTask

console = Console()

def print_shodan_summary(data: dict):
    table = Table(title="Shodan Summary")
    table.add_column("Field")
    table.add_column("Value")

    ip = data.get("ip_str") or data.get("ip") or "n/a"
    org = data.get("org") or "n/a"
    osv = data.get("os") or "n/a"
    ports = ", ".join(map(str, data.get("ports", []))) if data.get("ports") else "n/a"

    table.add_row("IP", str(ip))
    table.add_row("Org", str(org))
    table.add_row("OS", str(osv))
    table.add_row("Open ports", ports)

    console.print(table)

def sanitize_target(raw: str) -> str:
    """
    Accept a URL or host/IP and return a hostname suitable for nmap and Shodan,
    and a safe filename base for saving reports.
    Examples:
      - https://www.example.com/ -> www.example.com
      - http://10.0.0.1:8080 -> 10.0.0.1
      - example.com -> example.com
    """
    if not raw:
        return raw

    # If it looks like a URL, parse it
    parsed = urlparse(raw)
    if parsed.scheme and parsed.netloc:
        host = parsed.netloc
    else:
        # maybe user passed host only or host:port
        host = raw

    # strip any trailing slashes
    host = host.rstrip("/")

    # If it contains a port, drop it for nmap/host lookup (Shodan accepts host without port)
    if ":" in host:
        host = host.split(":")[0]

    # Finally strip accidental whitespace
    host = host.strip()

    return host

def safe_filename_base(host: str) -> str:
    """
    Convert host into a Windows-safe filename fragment.
    Replace any character problematic in filenames.
    """
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._")
    return "".join(c if c in allowed else "_" for c in host)

@click.group()
def cli():
    """Orbit Duck CLI"""
    pass

@cli.command()
@click.option("--target", required=True, help="Domain or IP to scan")
@click.option("--quick", is_flag=True, help="Use a fast scan preset")
def run(target: str, quick: bool):
    """Run a simple nmap scan with risk tracking and a colored summary table."""
    console.rule("[bold green]Orbit Duck — nmap scan")
    t = sanitize_target(target)
    kind = "nmap:quick" if quick else "nmap:default"

    runner = CoreRunner()
    runner.add_task(ScanTask(name=f"Scan_{t}", target=t, kind=kind))

    results = runner.run_all()

    console.print()  # spacing
    console.rule("[bold cyan]Scan Results with Risk Summary")

    # Build Risk Summary Table
    table = Table(title="Risk Summary", show_lines=True)
    table.add_column("Target", style="bold white")
    table.add_column("Risk Level", justify="center")
    table.add_column("Score", justify="center", style="cyan")

    for r in results:
        task = r.get("task", {})
        risk = r.get("risk", {})
        target_name = task.get("target", "unknown")
        level = str(risk.get("risk", "UNKNOWN")).upper()
        score = str(risk.get("score", "?"))

        # Color and emoji formatting
        if level == "LOW":
            level_display = f"[green]🟢 {level}[/green]"
        elif level == "MEDIUM":
            level_display = f"[yellow]🟡 {level}[/yellow]"
        elif level == "HIGH":
            level_display = f"[red]🔴 {level}[/red]"
        else:
            level_display = f"[dim]{level}[/dim]"

        table.add_row(target_name, level_display, score)

    console.print(table)
    console.print(f"[dim]Trend chart saved: reports/risk_trend.png[/dim]\n")

    # Print detailed scan result for context
    for r in results:
        res = r.get("result", {})
        console.print(f"[bold]Full Nmap Output for {t}:[/bold]")
        console.print(res)

@cli.command()
@click.option("--target", required=True, help="Domain or IP or hostname to look up in Shodan")
@click.option("--save/--no-save", default=True, help="Save Shodan JSON to reports/ (default: save)")
@click.option("--api-key", "api_key", required=False, help="Optional Shodan API key (falls back to SHODAN_API_KEY env)")
def shodan(target: str, save: bool, api_key: str | None):
    """Run a Shodan host lookup and optionally save the report to /reports."""
    from orbitduck.modules.shodan_search import shodan_host_lookup

    # prefer CLI-provided api_key, otherwise use env var loaded by load_dotenv()
    key = api_key or os.getenv("SHODAN_API_KEY")
    if not key:
        console.print("[red]Error: No Shodan API key provided. Set SHODAN_API_KEY in .env or pass --api-key[/red]")
        return

    console.rule("[bold blue]Orbit Duck — Shodan lookup")
    t = sanitize_target(target)
    result = shodan_host_lookup(t, api_key=key, save=save)

    if isinstance(result, dict) and "error" in result:
        console.print("[red]Shodan error:[/red]")
        console.print(result)
    else:
        print_shodan_summary(result)
        if result.get("_saved_to"):
            console.print(f"[dim]Raw JSON saved to: {result.get('_saved_to')}[/dim]")

# -------------------- Combined scan command --------------------
@cli.command()
@click.option("--target", required=True, help="Domain, URL, or IP to scan (target for both nmap and Shodan)")
@click.option("--api-key", "api_key", required=False, help="Optional Shodan API key (falls back to SHODAN_API_KEY env)")
@click.option("--quick", is_flag=True, help="Use nmap quick scan")
@click.option("--save/--no-save", default=True, help="Save combined JSON report to reports/ (default: save)")
def scan(target: str, api_key: str | None, quick: bool, save: bool):
    """
    Run nmap (quick/default) and Shodan, print summaries, and optionally save a combined report.
    """
    from orbitduck.modules.nmap_scan import nmap_quick_scan, nmap_default_scan
    from orbitduck.modules.shodan_search import shodan_host_lookup
    from orbitduck.utils.io import write_report

    key = api_key or os.getenv("SHODAN_API_KEY")
    if not key:
        console.print("[yellow]Warning: No Shodan API key provided. Shodan lookup will be skipped unless you pass --api-key or set SHODAN_API_KEY in .env[/yellow]")

    console.rule("[bold magenta]Orbit Duck — Combined scan")

    # sanitize target (accept URLs like https://example.com)
    target_host = sanitize_target(target)
    safe_base = safe_filename_base(target_host)

    runner = CoreRunner()
    runner.add_task(ScanTask(name=f"Combined_{target}", target=target, kind="combined"))
    results = runner.run_all()

    # 1) run nmap
    console.print("[bold]Running Nmap...[/bold]")
    try:
        if quick:
            nmap_res = nmap_quick_scan(target_host)
        else:
            nmap_res = nmap_default_scan(target_host)
    except Exception as e:
        nmap_res = {"error": "nmap_exception", "detail": str(e)}

    # 2) run Shodan (if key present), but don't auto-save its own file here
    shodan_res = None
    if key:
        console.print("[bold]Querying Shodan...[/bold]")
        shodan_res = shodan_host_lookup(target_host, api_key=key, save=False)
    else:
        shodan_res = {"error": "no_api_key", "detail": "Shodan skipped (no API key provided)"}

    # 3) print short summaries
    console.rule("[bold cyan]Results Summary")
    console.print("[green]Nmap result:[/green]")
    console.print(nmap_res)

    if isinstance(shodan_res, dict) and "error" in shodan_res:
        console.print("[red]Shodan result/error:[/red]")
        console.print(shodan_res)
    else:
        print_shodan_summary(shodan_res)

    # 4) optionally save combined report
    combined = {
        "target_raw": target,
        "target_host": target_host,
        "nmap": nmap_res,
        "shodan": shodan_res,
    }

    if save:
        out_path = f"reports/scan_{safe_base}.json"
        try:
            saved = write_report(combined, out_path)
            console.print(f"[bold]Combined report written to:[/bold] {saved}")
        except Exception as e:
            console.print(f"[red]Failed to write combined report:[/red] {e}")
    else:
        console.print("[dim]Combined report not saved (run with --save to write to reports/)[/dim]")

if __name__ == "__main__":
    import sys

    runner = CoreRunner()

    # If user provides targets in CLI, use them; otherwise, use the allowlist
    if len(sys.argv) > 1:
        domains = sys.argv[1:]
    else:
        domains = list(runner.allowlist)

    print(f"[*] Starting Orbit scans for: {', '.join(domains)}")

    for d in domains:
        runner.add_task(ScanTask(name=f"{d} quick scan", target=d, kind="nmap:quick"))
        runner.add_task(ScanTask(name=f"{d} shodan lookup", target=d, kind="shodan:lookup"))

    runner.run_all()

