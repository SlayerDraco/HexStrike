"""
HexStrike v2 - Report Generation Module
CVSS scoring, prioritized findings, JSON + TXT output.
"""

from __future__ import annotations
import json
from datetime import datetime
from pathlib import Path
from typing import List

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.rule import Rule
from rich import box

from core.models import ScanGraph, Finding

console = Console()

RECOMMENDATIONS = {
    "sqli":        "Use parameterized queries/prepared statements. Apply WAF. Audit all DB queries.",
    "xss":         "Encode output. Implement Content-Security-Policy. Use HttpOnly cookies.",
    "idor":        "Implement server-side authorization checks. Use UUIDs instead of sequential IDs.",
    "bruteforce":  "Implement account lockout, rate limiting, CAPTCHA, and MFA.",
    "misconfig":   "Harden server config. Remove defaults. Apply principle of least privilege.",
    "rce":         "Patch immediately. Conduct full incident response. Isolate affected systems.",
    "biz_logic":   "Implement atomic transactions, locking, and input boundary validation.",
    "info":        "Review information disclosure. Remove debug/verbose output from production.",
    "api":         "Validate all API inputs. Apply auth to every endpoint. Use rate limiting.",
}

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


def _severity_color(severity: str) -> str:
    return {
        "Critical": "bold red", "High": "red",
        "Medium": "yellow", "Low": "green", "Info": "dim"
    }.get(severity, "white")


def print_report(graph: ScanGraph):
    """Print a rich terminal report."""
    console.print()
    console.print(Rule("[bold yellow]HEXSTRIKE VULNERABILITY REPORT[/bold yellow]"))

    sev = graph.findings_by_severity()
    counts = {k: len(v) for k, v in sev.items()}
    total = sum(counts.values())

    # Summary panel
    summary = graph.summary()
    console.print(Panel(
        f"[bold]Target:[/bold]      {graph.target}\n"
        f"[bold]Domain:[/bold]      {graph.domain}\n"
        f"[bold]Scan ID:[/bold]     {graph.scan_id}\n"
        f"[bold]Started:[/bold]     {graph.started_at}\n"
        f"[bold]Subdomains:[/bold]  {summary['subdomains_found']}\n"
        f"[bold]Endpoints:[/bold]   {summary['endpoints_found']}\n"
        f"[bold]Parameters:[/bold]  {summary['parameters_found']}\n"
        f"[bold]Technologies:[/bold] {', '.join(summary['technologies'][:6]) or 'none'}\n"
        f"[bold]API endpoints:[/bold] {summary['api_endpoints']}",
        title="[bold cyan]SCAN SUMMARY[/bold cyan]",
        border_style="cyan"
    ))

    # Risk count table
    risk_table = Table(box=box.ROUNDED, border_style="cyan", title="Risk Summary")
    risk_table.add_column("Severity")
    risk_table.add_column("Count", justify="center", width=8)
    risk_table.add_column("CVSS Range")
    for label, rng in [("Critical","9.0–10.0"),("High","7.0–8.9"),("Medium","4.0–6.9"),("Low","0.1–3.9"),("Info","0.0")]:
        c = counts.get(label, 0)
        color = _severity_color(label)
        risk_table.add_row(f"[{color}]{label}[/{color}]", str(c), rng)
    console.print(risk_table)

    if not total:
        console.print("[bold green]✔ No vulnerabilities found.[/bold green]")
        return

    # Findings table — sorted by priority_score
    all_findings = sorted(graph.findings, key=lambda f: f.priority_score, reverse=True)
    ft = Table(box=box.ROUNDED, border_style="red", title=f"Findings ({total})")
    ft.add_column("#", width=3)
    ft.add_column("Sev", width=10)
    ft.add_column("CVSS", width=6, justify="center")
    ft.add_column("Pri", width=5, justify="center")
    ft.add_column("Title", max_width=55)
    ft.add_column("Endpoint", max_width=35, style="dim")

    for i, f in enumerate(all_findings, 1):
        color = _severity_color(f.severity)
        ft.add_row(
            str(i),
            f"[{color}]{f.severity}[/{color}]",
            f"[{color}]{f.cvss_score}[/{color}]",
            f"{f.priority_score:.1f}",
            f.title,
            (f.endpoint or "")[:35],
        )
    console.print(ft)


def write_json_report(graph: ScanGraph, output_dir: str, timestamp: str) -> str:
    path = Path(output_dir) / f"hexstrike_report_{timestamp}.json"
    with open(path, "w") as f:
        json.dump(graph.to_dict(), f, indent=2, default=str)
    console.print(f"[green]✔ JSON:[/green] {path}")
    return str(path)


def write_txt_report(graph: ScanGraph, output_dir: str, timestamp: str) -> str:
    path = Path(output_dir) / f"hexstrike_report_{timestamp}.txt"
    sev = graph.findings_by_severity()
    lines = []
    sep = "=" * 70

    lines += [
        sep,
        "  HexStrike v2 — Penetration Test Report",
        f"  Target:    {graph.target}",
        f"  Domain:    {graph.domain}",
        f"  Scan ID:   {graph.scan_id}",
        f"  Generated: {datetime.now().isoformat()}",
        sep, "",
        "EXECUTIVE SUMMARY",
        "-" * 40,
    ]

    counts = {k: len(v) for k, v in sev.items()}
    for label in ["Critical", "High", "Medium", "Low", "Info"]:
        lines.append(f"  {label:<12}: {counts.get(label, 0)}")
    lines.append(f"  {'TOTAL':<12}: {len(graph.findings)}")
    lines += ["", "ATTACK SURFACE", "-" * 40]
    s = graph.summary()
    lines += [
        f"  Subdomains : {s['subdomains_found']}",
        f"  Endpoints  : {s['endpoints_found']}",
        f"  Parameters : {s['parameters_found']}",
        f"  API paths  : {s['api_endpoints']}",
        f"  Tech stack : {', '.join(s['technologies'][:8]) or 'none'}",
        "",
    ]

    all_findings = sorted(graph.findings, key=lambda f: f.priority_score, reverse=True)
    lines += ["FINDINGS (sorted by priority)", "-" * 70]
    for i, f in enumerate(all_findings, 1):
        rec = RECOMMENDATIONS.get(f.finding_type, "Apply security best practices.")
        lines += [
            "",
            f"[{i}] {f.title}",
            f"    Severity   : {f.severity} (CVSS {f.cvss_score} | Priority {f.priority_score:.1f})",
            f"    Vector     : {f.cvss_vector}",
            f"    Type       : {f.finding_type}",
            f"    Target     : {f.target}",
            f"    Endpoint   : {f.endpoint or 'N/A'}",
            f"    Parameter  : {f.parameter or 'N/A'}",
            f"    Detail     : {f.detail}",
            f"    Evidence   : {f.evidence or 'N/A'}",
            f"    Fix        : {rec}",
            f"    Timestamp  : {f.timestamp}",
        ]

    lines += ["", sep, "SUBDOMAIN MAP", "-" * 40]
    for sub in graph.subdomains:
        lines.append(f"  {sub.fqdn}  [{sub.ip or 'unresolved'}]")
        for ep in sub.endpoints[:5]:
            lines.append(f"    → {ep.url} ({ep.status_code})")

    if graph.whois:
        lines += ["", "WHOIS SUMMARY", "-" * 40,
                  f"  Registrar  : {graph.whois.get('registrar','N/A')}",
                  f"  Created    : {graph.whois.get('created','N/A')}",
                  f"  Expires    : {graph.whois.get('expires','N/A')}",
                  f"  Nameservers: {', '.join(graph.whois.get('nameservers',[])[:3])}"]

    if graph.shodan.get("vulns"):
        lines += ["", "SHODAN CVEs", "-" * 40]
        for cve in graph.shodan["vulns"]:
            lines.append(f"  {cve}")

    intel = graph.metadata.get("intelligence", [])
    if intel:
        lines += ["", "SCAN INTELLIGENCE", "-" * 40]
        for msg in intel:
            lines.append(f"  [!] {msg}")

    lines += ["", sep, "  END OF REPORT — HexStrike v2", sep]

    with open(path, "w") as f:
        f.write("\n".join(lines))

    console.print(f"[green]✔ TXT: [/green]{path}")
    return str(path)


def generate_report(graph: ScanGraph, config: dict) -> dict:
    console.print()
    console.print(Panel(
        "[bold white]Generating HexStrike Report...[/bold white]",
        title="[bold yellow]REPORT[/bold yellow]",
        border_style="yellow"
    ))

    output_dir = config["output_dir"]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    print_report(graph)
    json_path = write_json_report(graph, output_dir, timestamp)
    txt_path  = write_txt_report(graph, output_dir, timestamp)

    # Also save raw graph
    graph_path = str(Path(output_dir) / f"hexstrike_graph_{timestamp}.json")
    graph.save(graph_path)

    sev = graph.findings_by_severity()
    counts = {k: len(v) for k, v in sev.items()}
    console.print(Panel(
        f"[bold green]✔ Reports saved![/bold green]\n\n"
        f"  JSON  : {json_path}\n"
        f"  TXT   : {txt_path}\n"
        f"  Graph : {graph_path}\n\n"
        f"  [bold red]Critical:[/bold red] {counts.get('Critical',0)}  "
        f"[red]High:[/red] {counts.get('High',0)}  "
        f"[yellow]Medium:[/yellow] {counts.get('Medium',0)}  "
        f"[green]Low:[/green] {counts.get('Low',0)}",
        title="[bold green]DONE[/bold green]",
        border_style="green"
    ))
    return {"json": json_path, "txt": txt_path, "graph": graph_path}
