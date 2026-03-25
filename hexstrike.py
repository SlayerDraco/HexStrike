#!/usr/bin/env python3
"""
HexStrike - Web Penetration Testing Automation Tool
Author: HexStrike Team
License: For authorized penetration testing only.
"""

import os
import sys
import json
import time
import signal
import argparse
from pathlib import Path
from datetime import datetime

# Ensure running as root
if os.geteuid() != 0:
    print("\n[!] HexStrike must be run as root (sudo). Exiting.\n")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.prompt import Prompt, Confirm
    from rich.text import Text
    from rich.align import Align
    from rich import box
    from rich.columns import Columns
    from rich.rule import Rule
    from rich.style import Style
except ImportError:
    os.system("pip3 install rich --break-system-packages -q")
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.prompt import Prompt, Confirm
    from rich.text import Text
    from rich.align import Align
    from rich import box
    from rich.columns import Columns
    from rich.rule import Rule
    from rich.style import Style

console = Console()

SESSION_FILE = Path.home() / ".hexstrike_session.json"

BANNER = r"""
 ██╗  ██╗███████╗██╗  ██╗███████╗████████╗██████╗ ██╗██╗  ██╗███████╗
 ██║  ██║██╔════╝╚██╗██╔╝██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝
 ███████║█████╗   ╚███╔╝ ███████╗   ██║   ██████╔╝██║█████╔╝ █████╗  
 ██╔══██║██╔══╝   ██╔██╗ ╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝  
 ██║  ██║███████╗██╔╝ ██╗███████║   ██║   ██║  ██║██║██║  ██╗███████╗
 ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝
"""

def print_banner():
    console.print(Text(BANNER, style="bold red"))
    console.print(Align.center(Text("[ Web Penetration Testing Automation Framework ]", style="bold yellow")))
    console.print(Align.center(Text("v1.0.0  |  For Authorized Testing Only  |  Parrot OS", style="dim white")))
    console.print()

def print_legal_warning():
    warning = Panel(
        "[bold red]⚠  LEGAL WARNING  ⚠[/bold red]\n\n"
        "[white]HexStrike is intended ONLY for authorized penetration testing.\n"
        "Unauthorized use against systems you do not own or have explicit\n"
        "written permission to test is [bold red]ILLEGAL[/bold red] and may result in\n"
        "criminal prosecution under the Computer Fraud and Abuse Act (CFAA)\n"
        "and equivalent laws worldwide.\n\n"
        "[bold yellow]By continuing, you confirm that:[/bold yellow]\n"
        "  [green]✔[/green]  You have explicit written authorization to test the target.\n"
        "  [green]✔[/green]  You understand and accept full legal responsibility.\n"
        "  [green]✔[/green]  This tool will not be used for malicious purposes.[/white]",
        title="[bold red]DISCLAIMER[/bold red]",
        border_style="red",
        padding=(1, 4),
    )
    console.print(warning)
    console.print()

def get_consent():
    confirmed = Confirm.ask(
        "[bold yellow]Do you have explicit authorization to test the target? Continue?[/bold yellow]",
        default=False
    )
    if not confirmed:
        console.print("\n[bold red]Authorization not confirmed. Exiting HexStrike.[/bold red]\n")
        sys.exit(0)
    console.print("\n[bold green]✔ Authorization confirmed. Proceeding...[/bold green]\n")

def load_session():
    if SESSION_FILE.exists():
        try:
            with open(SESSION_FILE, "r") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_session(session_data):
    with open(SESSION_FILE, "w") as f:
        json.dump(session_data, f, indent=2)

def clear_session():
    if SESSION_FILE.exists():
        SESSION_FILE.unlink()

def get_targets():
    console.print(Rule("[bold cyan]Target Configuration[/bold cyan]"))
    console.print()

    target_type = Prompt.ask(
        "[bold yellow]Target mode[/bold yellow]",
        choices=["single", "file"],
        default="single"
    )

    targets = []
    if target_type == "single":
        url = Prompt.ask("[bold cyan]Enter target URL or IP[/bold cyan]")
        targets.append(url.strip())
    else:
        file_path = Prompt.ask("[bold cyan]Enter path to targets file (.txt)[/bold cyan]")
        try:
            with open(file_path.strip(), "r") as f:
                targets = [line.strip() for line in f if line.strip()]
            console.print(f"[green]✔ Loaded {len(targets)} targets from file.[/green]")
        except FileNotFoundError:
            console.print(f"[red]✘ File not found: {file_path}[/red]")
            sys.exit(1)

    return targets

def get_scan_intensity():
    console.print()
    intensity = Prompt.ask(
        "[bold yellow]Scan intensity[/bold yellow]",
        choices=["stealth", "normal", "aggressive"],
        default="normal"
    )
    intensity_map = {
        "stealth": "[dim]Slow, low-noise scans. Harder to detect.[/dim]",
        "normal": "[dim]Balanced speed and noise level.[/dim]",
        "aggressive": "[dim]Fast, loud scans. Higher detection risk.[/dim]",
    }
    console.print(intensity_map[intensity])
    return intensity

def get_output_dir():
    console.print()
    default_dir = str(Path.home() / "hexstrike_reports")
    out_dir = Prompt.ask(
        f"[bold yellow]Output directory[/bold yellow] (press Enter for default: {default_dir})",
        default=default_dir
    )
    out_path = Path(out_dir.strip())
    out_path.mkdir(parents=True, exist_ok=True)
    console.print(f"[green]✔ Reports will be saved to: {out_path}[/green]")
    return str(out_path)

def get_wordlist():
    console.print()
    bundled = str(Path(__file__).parent / "wordlists" / "subdomains.txt")
    wl = Prompt.ask(
        f"[bold yellow]Subdomain wordlist[/bold yellow] (press Enter for bundled default)",
        default=bundled
    )
    if not Path(wl).exists():
        console.print(f"[red]✘ Wordlist not found: {wl}. Using bundled default.[/red]")
        return bundled
    return wl

def get_bruteforce_wordlist():
    console.print()
    default_wl = "/usr/share/wordlists/rockyou.txt"
    wl = Prompt.ask(
        f"[bold yellow]Brute-force wordlist[/bold yellow] (press Enter for rockyou.txt)",
        default=default_wl
    )
    if not Path(wl).exists():
        console.print(f"[yellow]⚠ Wordlist not found at {wl}. Hydra/John may fail unless you provide a valid path.[/yellow]")
    return wl

def get_sqli_xss_scope():
    console.print()
    scope = Prompt.ask(
        "[bold yellow]SQLMap/XSS scanning scope[/bold yellow]",
        choices=["all", "mainonly"],
        default="all"
    )
    if scope == "all":
        console.print("[dim]Will scan all discovered forms and URLs.[/dim]")
    else:
        console.print("[dim]Will scan only the main target URL.[/dim]")
    return scope

def print_menu():
    console.print()
    console.print(Rule("[bold cyan]HexStrike — Main Menu[/bold cyan]"))
    console.print()

    table = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
    table.add_column("Key", style="bold yellow", width=6)
    table.add_column("Module", style="bold white")
    table.add_column("Description", style="dim")

    table.add_row("1", "Tool Check", "Verify & auto-install all required tools")
    table.add_row("2", "Reconnaissance", "WHOIS, Google Dorking, Nmap, Shodan, Subdomains, Source")
    table.add_row("3", "Exploitation", "SQLi, XSS, Auth Bypass, Misconfig, Metasploit")
    table.add_row("4", "Full Auto Scan", "Run all modules sequentially")
    table.add_row("5", "Generate Report", "Generate JSON + TXT report from session data")
    table.add_row("6", "Clear Session", "Wipe saved session/resume state")
    table.add_row("0", "Exit", "Quit HexStrike")

    console.print(table)
    console.print()

def run_module(choice, config, session):
    from modules.toolcheck import run_toolcheck
    from modules.recon import run_recon
    from modules.exploit import run_exploit
    from modules.report import generate_report

    if choice == "1":
        console.print(Rule("[bold green]Tool Check[/bold green]"))
        run_toolcheck()

    elif choice == "2":
        if session.get("recon_done"):
            resume = Confirm.ask("[yellow]⟳ Recon was previously completed. Re-run?[/yellow]", default=False)
            if not resume:
                console.print("[dim]Skipping recon.[/dim]")
                return
        console.print(Rule("[bold green]Reconnaissance[/bold green]"))
        recon_results = run_recon(config)
        session["recon_done"] = True
        session["recon_results"] = recon_results
        save_session(session)

    elif choice == "3":
        if session.get("exploit_done"):
            resume = Confirm.ask("[yellow]⟳ Exploitation was previously completed. Re-run?[/yellow]", default=False)
            if not resume:
                console.print("[dim]Skipping exploitation.[/dim]")
                return
        console.print(Rule("[bold green]Exploitation[/bold green]"))
        exploit_results = run_exploit(config, session.get("recon_results", {}))
        session["exploit_done"] = True
        session["exploit_results"] = exploit_results
        save_session(session)

    elif choice == "4":
        console.print(Rule("[bold green]Full Auto Scan[/bold green]"))
        if not session.get("toolcheck_done"):
            run_toolcheck()
            session["toolcheck_done"] = True
            save_session(session)

        if not session.get("recon_done"):
            recon_results = run_recon(config)
            session["recon_done"] = True
            session["recon_results"] = recon_results
            save_session(session)
        else:
            console.print("[dim]⟳ Recon already completed. Skipping.[/dim]")
            recon_results = session.get("recon_results", {})

        if not session.get("exploit_done"):
            exploit_results = run_exploit(config, recon_results)
            session["exploit_done"] = True
            session["exploit_results"] = exploit_results
            save_session(session)
        else:
            console.print("[dim]⟳ Exploitation already completed. Skipping.[/dim]")

        generate_report(config, session)
        session["report_done"] = True
        save_session(session)

    elif choice == "5":
        console.print(Rule("[bold green]Report Generation[/bold green]"))
        generate_report(config, session)
        session["report_done"] = True
        save_session(session)

    elif choice == "6":
        clear_session()
        console.print("[green]✔ Session cleared.[/green]")
        return {}

    return session

def main():
    print_banner()
    print_legal_warning()
    get_consent()

    # Load or start session
    session = load_session()
    if session:
        resume = Confirm.ask(
            f"[yellow]⟳ Previous session found (started {session.get('started_at', 'unknown')}). Resume?[/yellow]",
            default=True
        )
        if not resume:
            clear_session()
            session = {}

    # Build config
    if not session.get("config"):
        targets = get_targets()
        intensity = get_scan_intensity()
        output_dir = get_output_dir()
        wordlist = get_wordlist()
        bf_wordlist = get_bruteforce_wordlist()
        sqli_scope = get_sqli_xss_scope()

        config = {
            "targets": targets,
            "intensity": intensity,
            "output_dir": output_dir,
            "wordlist": wordlist,
            "bf_wordlist": bf_wordlist,
            "sqli_scope": sqli_scope,
            "started_at": datetime.now().isoformat(),
        }
        session["config"] = config
        session["started_at"] = config["started_at"]
        save_session(session)
    else:
        config = session["config"]
        console.print(f"[green]✔ Loaded config for targets: {', '.join(config['targets'])}[/green]")

    # Menu loop
    while True:
        print_menu()
        choice = Prompt.ask("[bold yellow]Select option[/bold yellow]", choices=["0","1","2","3","4","5","6"])
        if choice == "0":
            console.print("\n[bold red]Exiting HexStrike. Stay legal.[/bold red]\n")
            sys.exit(0)
        session = run_module(choice, config, session) or session

if __name__ == "__main__":
    main()
