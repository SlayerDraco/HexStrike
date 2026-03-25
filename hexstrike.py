#!/usr/bin/env python3
"""
HexStrike v2 - Main Entry Point
CLI menu + command-based execution (hexstrike scan target --profile full --cookie "...")
"""

import os
import sys
import json
import uuid
import argparse
import signal
from pathlib import Path
from datetime import datetime

# Root check
if os.geteuid() != 0:
    print("\n[!] HexStrike must be run as root (sudo). Exiting.\n")
    sys.exit(1)

# Auto-install rich if missing
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.prompt import Prompt, Confirm
    from rich.text import Text
    from rich.align import Align
    from rich.rule import Rule
    from rich import box
except ImportError:
    os.system("pip3 install rich --break-system-packages -q")
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.prompt import Prompt, Confirm
    from rich.text import Text
    from rich.align import Align
    from rich.rule import Rule
    from rich import box

console = Console()

# ── Paths ──────────────────────────────────────────────────────────────────────
BASE_DIR     = Path(__file__).parent
SESSION_FILE = Path.home() / ".hexstrike_v2_session.json"

# ── Banner ─────────────────────────────────────────────────────────────────────
BANNER = r"""
 ██╗  ██╗███████╗██╗  ██╗███████╗████████╗██████╗ ██╗██╗  ██╗███████╗
 ██║  ██║██╔════╝╚██╗██╔╝██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝
 ███████║█████╗   ╚███╔╝ ███████╗   ██║   ██████╔╝██║█████╔╝ █████╗
 ██╔══██║██╔══╝   ██╔██╗ ╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝
 ██║  ██║███████╗██╔╝ ██╗███████║   ██║   ██║  ██║██║██║  ██╗███████╗
 ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝
"""

TAGLINE = "[ Web Penetration Testing Automation Framework v2.0 ]"
SUBTITLE = "Parrot OS  |  For Authorized Testing Only  |  Plugin-Ready"


def print_banner():
    console.print(Text(BANNER, style="bold red"))
    console.print(Align.center(Text(TAGLINE, style="bold yellow")))
    console.print(Align.center(Text(SUBTITLE, style="dim white")))
    console.print()


def print_legal():
    console.print(Panel(
        "[bold red]⚠  LEGAL WARNING  ⚠[/bold red]\n\n"
        "[white]HexStrike is intended ONLY for authorized penetration testing.\n"
        "Unauthorized use is [bold red]ILLEGAL[/bold red] under CFAA and equivalent laws.\n\n"
        "[bold yellow]By continuing you confirm:[/bold yellow]\n"
        "  [green]✔[/green]  Explicit written authorization to test the target\n"
        "  [green]✔[/green]  Full legal responsibility accepted\n"
        "  [green]✔[/green]  No malicious intent[/white]",
        title="[bold red]DISCLAIMER[/bold red]",
        border_style="red", padding=(1, 4),
    ))
    console.print()


def get_consent() -> bool:
    ok = Confirm.ask(
        "[bold yellow]Do you have explicit authorization to test the target?[/bold yellow]",
        default=False
    )
    if not ok:
        console.print("\n[bold red]Authorization not confirmed. Exiting.[/bold red]\n")
        sys.exit(0)
    console.print("[bold green]✔ Authorization confirmed.[/bold green]\n")
    return True


# ── Session persistence ────────────────────────────────────────────────────────

def load_session() -> dict:
    if SESSION_FILE.exists():
        try:
            return json.loads(SESSION_FILE.read_text())
        except Exception:
            return {}
    return {}


def save_session(data: dict):
    SESSION_FILE.write_text(json.dumps(data, indent=2, default=str))


def clear_session():
    if SESSION_FILE.exists():
        SESSION_FILE.unlink()
    console.print("[green]✔ Session cleared.[/green]")


# ── Config collection (interactive) ───────────────────────────────────────────

def collect_config(args=None) -> dict:
    """
    Build the runtime config dict.
    If `args` is provided (CLI mode), use those values.
    Otherwise prompt interactively.
    """
    from core.profiles import get_profile, list_profiles, PROFILES

    console.print(Rule("[bold cyan]Scan Configuration[/bold cyan]"))
    console.print()

    # Targets
    if args and getattr(args, "target", None):
        targets = [args.target]
    elif args and getattr(args, "targets_file", None):
        targets = [l.strip() for l in Path(args.targets_file).read_text().splitlines() if l.strip()]
    else:
        mode = Prompt.ask("[bold yellow]Target mode[/bold yellow]",
                          choices=["single", "file"], default="single")
        if mode == "single":
            targets = [Prompt.ask("[bold cyan]Target URL / IP[/bold cyan]")]
        else:
            fp = Prompt.ask("[bold cyan]Targets file (.txt)[/bold cyan]")
            targets = [l.strip() for l in Path(fp).read_text().splitlines() if l.strip()]
            console.print(f"[green]✔ {len(targets)} targets loaded.[/green]")

    # Profile
    profile_name = getattr(args, "profile", None) if args else None
    if not profile_name:
        pt = Table(show_header=True, box=box.SIMPLE)
        pt.add_column("Name", style="bold yellow")
        pt.add_column("Description")
        pt.add_column("Intensity", style="dim")
        for p in list_profiles():
            pt.add_row(p["name"], p["description"], p["intensity"])
        console.print(pt)
        profile_name = Prompt.ask(
            "[bold yellow]Scan profile[/bold yellow]",
            choices=list(PROFILES.keys()), default="normal"
        )

    try:
        profile = get_profile(profile_name)
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(1)

    console.print(f"[green]✔ Profile: {profile.name} ({profile.intensity})[/green]")

    # Auth
    cookie = getattr(args, "cookie", None) if args else None
    header = getattr(args, "header", None) if args else None
    login_url = getattr(args, "login_url", None) if args else None
    login_user = getattr(args, "login_user", None) if args else None
    login_pass = getattr(args, "login_pass", None) if args else None

    if not any([cookie, header, login_url]) and not args:
        use_auth = Confirm.ask("[bold yellow]Configure authentication?[/bold yellow]", default=False)
        if use_auth:
            auth_type = Prompt.ask("Auth type", choices=["cookie", "header", "login"], default="cookie")
            if auth_type == "cookie":
                cookie = Prompt.ask("Cookie string (e.g. PHPSESSID=abc123)")
            elif auth_type == "header":
                header = [Prompt.ask("Header (e.g. Authorization: Bearer token)")]
            else:
                login_url  = Prompt.ask("Login URL")
                login_user = Prompt.ask("Username")
                login_pass = Prompt.ask("Password", password=True)

    # Output dir
    default_out = str(Path.home() / "hexstrike_reports")
    output_dir = getattr(args, "output", None) if args else None
    if not output_dir:
        output_dir = Prompt.ask(
            f"[bold yellow]Output directory[/bold yellow]",
            default=default_out
        )
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    console.print(f"[green]✔ Output: {output_dir}[/green]")

    # Wordlists
    bundled_wl = str(BASE_DIR / "wordlists" / "subdomains.txt")
    wordlist = getattr(args, "wordlist", bundled_wl) if args else bundled_wl
    if not args:
        custom = Prompt.ask("Subdomain wordlist (Enter for bundled)", default=bundled_wl)
        wordlist = custom

    default_bf = "/usr/share/wordlists/rockyou.txt"
    bf_wordlist = getattr(args, "bf_wordlist", default_bf) if args else default_bf
    if not args:
        custom_bf = Prompt.ask("Brute-force wordlist (Enter for rockyou.txt)", default=default_bf)
        bf_wordlist = custom_bf

    # SQLi/XSS scope
    sqli_scope = getattr(args, "scope", "all") if args else None
    if not sqli_scope:
        sqli_scope = Prompt.ask(
            "SQLi/XSS scope",
            choices=["all", "mainonly"], default="all"
        )

    # Proxy
    proxy = getattr(args, "proxy", None) if args else None

    return {
        "targets":     targets,
        "profile":     profile,
        "output_dir":  output_dir,
        "wordlist":    wordlist,
        "bf_wordlist": bf_wordlist,
        "sqli_scope":  sqli_scope,
        "cookie":      cookie,
        "header":      header,
        "login_url":   login_url,
        "login_user":  login_user,
        "login_pass":  login_pass,
        "proxy":       proxy,
        "scan_id":     str(uuid.uuid4())[:8],
        "started_at":  datetime.now().isoformat(),
    }


# ── Core scan orchestration ────────────────────────────────────────────────────

def build_graph_and_session(config: dict):
    """Build a fresh ScanGraph + HexSession from config."""
    from core.models import ScanGraph
    from core.session import session_from_args
    from urllib.parse import urlparse

    target = config["targets"][0]
    domain = urlparse(target if target.startswith("http") else "http://" + target).hostname or target

    graph = ScanGraph(
        target=target,
        domain=domain,
        scan_id=config["scan_id"],
        started_at=config["started_at"],
    )

    session = session_from_args(
        cookie=config.get("cookie"),
        header=config.get("header"),
        login_url=config.get("login_url"),
        login_user=config.get("login_user"),
        login_pass=config.get("login_pass"),
        proxy=config.get("proxy"),
    )

    return graph, session


def run_scan(config: dict, steps: list = None):
    """
    Run the full scan pipeline or specific steps.
    steps: list of step names to run, or None = all based on profile.
    """
    from core.plugins import PluginRegistry
    from core.decisions import AutoDecisionEngine
    from modules.toolcheck import run_toolcheck
    from modules.recon import run_recon
    from modules.exploit import run_exploit
    from modules.report import generate_report

    profile = config["profile"]
    graph, session = build_graph_and_session(config)

    # Load plugins
    registry = PluginRegistry()
    console.print("[dim]Loading plugins...[/dim]")
    registry.discover()

    all_steps = steps or ["toolcheck", "recon", "exploit", "report"]

    # ── Tool check ──────────────────────────────────────────────────────
    if "toolcheck" in all_steps:
        run_toolcheck()

    # ── Recon ────────────────────────────────────────────────────────────
    if "recon" in all_steps:
        graph = run_recon(graph, session, config, profile)
        # Run recon-phase plugins
        registry.run_phase("recon", graph, session, profile, console)

    # ── Auto Decision Engine ─────────────────────────────────────────────
    if "exploit" in all_steps:
        ade = AutoDecisionEngine()
        decisions = ade.analyze(graph)
        ade.print_decisions(decisions)

        # Run exploitation
        graph = run_exploit(graph, session, config, profile)
        # Run exploit-phase plugins (including auto-triggered)
        registry.run_phase("exploit", graph, session, profile, console)

    # ── Report ────────────────────────────────────────────────────────────
    if "report" in all_steps:
        generate_report(graph, config)
        registry.run_phase("report", graph, session, profile, console)

    session.close()
    return graph


# ── Menu ──────────────────────────────────────────────────────────────────────

def print_menu():
    console.print()
    console.print(Rule("[bold cyan]HexStrike v2 — Main Menu[/bold cyan]"))
    t = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
    t.add_column("Key", style="bold yellow", width=4)
    t.add_column("Module", style="bold white", width=26)
    t.add_column("Description", style="dim")

    rows = [
        ("1",  "Tool Check",              "Verify & auto-install all required tools"),
        ("2",  "Reconnaissance",          "WHOIS, Dorking, Nmap, Shodan, Subdomains, Source, Crawl"),
        ("3",  "Exploitation",            "SQLi, XSS, IDOR, Brute Force, Misconfig, Metasploit"),
        ("4",  "API Testing",             "REST discovery, Swagger fuzzing, GraphQL"),
        ("5",  "Business Logic",          "Race conditions, replay, negative values"),
        ("6",  "Param Fuzzing",           "Hidden parameter discovery"),
        ("7",  "Full Auto Scan",          "Recon → ADE → All exploit modules → Report"),
        ("8",  "Request Console",         "Interactive request/response manipulation (Burp-lite)"),
        ("9",  "Generate Report",         "JSON + TXT report from current session"),
        ("10", "Show Scan Graph",         "Print correlated recon data (endpoints/params/tech)"),
        ("11", "List Plugins",            "Show loaded plugins"),
        ("12", "Clear Session",           "Wipe saved session state"),
        ("0",  "Exit",                    "Quit HexStrike"),
    ]
    for key, mod, desc in rows:
        t.add_row(key, mod, desc)
    console.print(t)
    console.print()


def show_graph(graph):
    """Print the correlated scan graph summary."""
    from rich.tree import Tree

    console.print(Rule("[bold cyan]Scan Graph[/bold cyan]"))
    tree = Tree(f"[bold cyan]{graph.target}[/bold cyan]")

    # Technologies
    if graph.technologies:
        tech_branch = tree.add("[yellow]Technologies[/yellow]")
        for t in graph.technologies:
            tech_branch.add(f"[white]{t.name}[/white] [dim]{t.version or ''}[/dim]")

    # Subdomains → Endpoints → Parameters
    subs_branch = tree.add(f"[yellow]Subdomains ({len(graph.subdomains)})[/yellow]")
    for sub in graph.subdomains[:15]:
        sb = subs_branch.add(f"[green]{sub.fqdn}[/green] [dim]{sub.ip or ''}[/dim]")
        for ep in sub.endpoints[:5]:
            eb = sb.add(f"[white]{ep.method} {ep.url[:60]}[/white]")
            for p in ep.parameters[:4]:
                eb.add(f"[dim]{p.param_type}:{p.name}={p.value[:20]}[/dim]")

    # Root endpoints
    ep_branch = tree.add(f"[yellow]Root Endpoints ({len(graph.root_endpoints)})[/yellow]")
    for ep in graph.root_endpoints[:20]:
        eb = ep_branch.add(
            f"[{'red' if ep.is_admin else 'cyan' if ep.is_api else 'white'}]"
            f"{ep.method} {ep.url[:65]}[/] [{ep.status_code or '?'}]"
        )
        for p in ep.parameters[:3]:
            eb.add(f"[dim]{p.param_type}:{p.name}={p.value[:20]}[/dim]")

    # Findings
    if graph.findings:
        f_branch = tree.add(f"[yellow]Findings ({len(graph.findings)})[/yellow]")
        for f in sorted(graph.findings, key=lambda x: x.priority_score, reverse=True)[:10]:
            color = {"Critical":"bold red","High":"red","Medium":"yellow","Low":"green"}.get(f.severity,"white")
            f_branch.add(f"[{color}][{f.severity}][/{color}] {f.title[:60]}")

    console.print(tree)


def run_menu(config: dict, session, graph, registry):
    """Interactive menu loop."""
    from modules.toolcheck import run_toolcheck
    from modules.recon import run_recon
    from modules.exploit import run_exploit
    from modules.api_testing import run_api_testing
    from modules.biz_logic import run_biz_logic
    from modules.param_fuzzer import run_param_fuzzing
    from modules.req_console import run_request_console
    from modules.report import generate_report
    from core.decisions import AutoDecisionEngine

    profile = config["profile"]

    while True:
        print_menu()
        choice = Prompt.ask(
            "[bold yellow]Select[/bold yellow]",
            choices=[str(i) for i in range(13)]
        )

        if choice == "0":
            console.print("\n[bold red]Exiting HexStrike. Stay legal.[/bold red]\n")
            session.close()
            sys.exit(0)

        elif choice == "1":
            run_toolcheck()

        elif choice == "2":
            graph = run_recon(graph, session, config, profile)
            registry.run_phase("recon", graph, session, profile, console)
            _save_graph(graph, config)

        elif choice == "3":
            if not graph.all_endpoints() and not graph.subdomains:
                console.print("[yellow]⚠ Run Recon first to build the attack surface.[/yellow]")
                continue
            ade = AutoDecisionEngine()
            decisions = ade.analyze(graph)
            ade.print_decisions(decisions)
            graph = run_exploit(graph, session, config, profile)
            registry.run_phase("exploit", graph, session, profile, console)
            _save_graph(graph, config)

        elif choice == "4":
            if not graph.all_endpoints():
                console.print("[yellow]⚠ Run Recon first.[/yellow]")
                continue
            run_api_testing(graph, session, profile)
            _save_graph(graph, config)

        elif choice == "5":
            if not graph.all_endpoints():
                console.print("[yellow]⚠ Run Recon first.[/yellow]")
                continue
            run_biz_logic(graph, session, profile)
            _save_graph(graph, config)

        elif choice == "6":
            if not graph.all_endpoints():
                console.print("[yellow]⚠ Run Recon first.[/yellow]")
                continue
            run_param_fuzzing(graph, session, profile)
            _save_graph(graph, config)

        elif choice == "7":
            # Full auto
            run_toolcheck()
            graph = run_recon(graph, session, config, profile)
            registry.run_phase("recon", graph, session, profile, console)
            ade = AutoDecisionEngine()
            decisions = ade.analyze(graph)
            ade.print_decisions(decisions)
            graph = run_exploit(graph, session, config, profile)
            registry.run_phase("exploit", graph, session, profile, console)
            generate_report(graph, config)
            registry.run_phase("report", graph, session, profile, console)
            _save_graph(graph, config)

        elif choice == "8":
            run_request_console(graph, session)

        elif choice == "9":
            generate_report(graph, config)

        elif choice == "10":
            show_graph(graph)

        elif choice == "11":
            plugins = registry.list_plugins()
            if not plugins:
                console.print("[dim]No plugins loaded.[/dim]")
            else:
                t = Table(box=box.SIMPLE)
                t.add_column("Name", style="bold cyan")
                t.add_column("Phase", style="yellow")
                t.add_column("Auto", width=6)
                t.add_column("Description")
                for p in plugins:
                    t.add_row(
                        p["name"], p["phase"],
                        "✔" if p["auto_trigger"] else "",
                        p["description"]
                    )
                console.print(t)

        elif choice == "12":
            clear_session()
            graph, session = build_graph_and_session(config)


def _save_graph(graph, config):
    """Save intermediate graph to session file."""
    try:
        session_data = load_session()
        session_data["graph_summary"] = graph.summary()
        session_data["findings_count"] = len(graph.findings)
        session_data["last_updated"] = datetime.now().isoformat()
        save_session(session_data)
    except Exception:
        pass


# ── CLI argument parser ────────────────────────────────────────────────────────

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hexstrike",
        description="HexStrike v2 — Web Penetration Testing Automation Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Interactive menu:
    sudo python3 hexstrike.py

  Full scan:
    sudo python3 hexstrike.py scan target.com --profile full

  Recon only:
    sudo python3 hexstrike.py scan target.com --profile recon

  Authenticated scan:
    sudo python3 hexstrike.py scan target.com --cookie "PHPSESSID=abc123" --profile normal

  Header injection:
    sudo python3 hexstrike.py scan target.com --header "Authorization: Bearer TOKEN"

  Login automation:
    sudo python3 hexstrike.py scan target.com --login-url http://target.com/login \\
        --login-user admin --login-pass secret

  Bulk targets:
    sudo python3 hexstrike.py scan --targets-file targets.txt --profile stealth

  With proxy:
    sudo python3 hexstrike.py scan target.com --proxy http://127.0.0.1:8080

  Specific modules only:
    sudo python3 hexstrike.py scan target.com --steps recon exploit

  API scan only:
    sudo python3 hexstrike.py scan target.com --profile api --steps recon api report

  Custom output directory:
    sudo python3 hexstrike.py scan target.com --output /tmp/pentest_results
        """
    )

    subparsers = parser.add_subparsers(dest="command")

    # ── scan subcommand ────────────────────────────────────────────────
    scan_p = subparsers.add_parser("scan", help="Run a scan")
    scan_p.add_argument("target", nargs="?", help="Target URL or IP")
    scan_p.add_argument("--targets-file", dest="targets_file", help="File with targets (one per line)")
    scan_p.add_argument("--profile", default="normal",
                        choices=["recon","stealth","normal","full","api","custom"],
                        help="Scan profile (default: normal)")
    scan_p.add_argument("--steps", nargs="+",
                        choices=["toolcheck","recon","exploit","api","biz_logic","report"],
                        help="Run specific steps only")
    scan_p.add_argument("--cookie", help='Cookie string: "NAME=val; NAME2=val2"')
    scan_p.add_argument("--header", action="append", dest="header",
                        help='Custom header: "Authorization: Bearer token" (repeatable)')
    scan_p.add_argument("--login-url", dest="login_url", help="URL to POST login credentials to")
    scan_p.add_argument("--login-user", dest="login_user", help="Login username")
    scan_p.add_argument("--login-pass", dest="login_pass", help="Login password")
    scan_p.add_argument("--output", "-o", help="Output directory (default: ~/hexstrike_reports)")
    scan_p.add_argument("--wordlist", "-w", help="Subdomain wordlist path")
    scan_p.add_argument("--bf-wordlist", dest="bf_wordlist",
                        default="/usr/share/wordlists/rockyou.txt",
                        help="Brute-force wordlist (default: rockyou.txt)")
    scan_p.add_argument("--scope", choices=["all","mainonly"], default="all",
                        help="SQLi/XSS scope (default: all)")
    scan_p.add_argument("--proxy", help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    scan_p.add_argument("--no-consent", dest="no_consent", action="store_true",
                        help="Skip consent prompt (for scripted/CI use)")

    # ── plugins subcommand ─────────────────────────────────────────────
    plugins_p = subparsers.add_parser("plugins", help="List available plugins")

    # ── profiles subcommand ────────────────────────────────────────────
    profiles_p = subparsers.add_parser("profiles", help="List scan profiles")

    # ── console subcommand ─────────────────────────────────────────────
    console_p = subparsers.add_parser("console", help="Open request console")
    console_p.add_argument("target", nargs="?", help="Target URL")
    console_p.add_argument("--cookie", help="Cookie string")
    console_p.add_argument("--header", action="append", dest="header")
    console_p.add_argument("--proxy", help="Proxy")

    return parser


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    print_banner()

    parser = build_arg_parser()
    args = parser.parse_args()

    # ── No subcommand → interactive menu ──────────────────────────────
    if not args.command:
        print_legal()
        get_consent()

        session_data = load_session()
        config = None

        if session_data.get("config"):
            resume = Confirm.ask(
                f"[yellow]⟳ Previous session found "
                f"({session_data.get('started_at','?')}). Resume?[/yellow]",
                default=True
            )
            if resume:
                config = session_data["config"]
                console.print(f"[green]✔ Resumed: {config['targets']}[/green]")
            else:
                clear_session()

        if not config:
            config = collect_config()
            save_session({"config": config, "started_at": config["started_at"]})

        from core.plugins import PluginRegistry
        registry = PluginRegistry()
        console.print("[dim]Loading plugins...[/dim]")
        registry.discover()

        graph, session = build_graph_and_session(config)
        run_menu(config, session, graph, registry)
        return

    # ── profiles command ───────────────────────────────────────────────
    if args.command == "profiles":
        from core.profiles import list_profiles
        t = Table(box=box.ROUNDED, title="HexStrike Scan Profiles")
        t.add_column("Name", style="bold yellow")
        t.add_column("Description")
        t.add_column("Intensity")
        t.add_column("MSF", width=5)
        t.add_column("IDOR", width=5)
        t.add_column("API", width=5)
        from core.profiles import PROFILES
        for p in PROFILES.values():
            t.add_row(
                p.name, p.description, p.intensity,
                "✔" if p.run_msf else "", "✔" if p.run_idor else "",
                "✔" if p.run_api else "",
            )
        console.print(t)
        return

    # ── plugins command ────────────────────────────────────────────────
    if args.command == "plugins":
        from core.plugins import PluginRegistry
        r = PluginRegistry()
        r.discover()
        plugins = r.list_plugins()
        if not plugins:
            console.print("[dim]No plugins found in /plugins directory.[/dim]")
            return
        t = Table(box=box.ROUNDED, title="Loaded Plugins")
        t.add_column("Name", style="bold cyan")
        t.add_column("Phase", style="yellow")
        t.add_column("Version", width=8)
        t.add_column("Author", width=12)
        t.add_column("Auto-trigger", width=12)
        t.add_column("Description")
        for p in plugins:
            t.add_row(
                p["name"], p["phase"], p["version"], p["author"],
                p["trigger_condition"] if p["auto_trigger"] else "—",
                p["description"]
            )
        console.print(t)
        return

    # ── console command ────────────────────────────────────────────────
    if args.command == "console":
        from core.session import session_from_args
        from modules.req_console import run_request_console
        target = getattr(args, "target", None) or "http://example.com"
        session = session_from_args(
            cookie=getattr(args, "cookie", None),
            header=getattr(args, "header", None),
            proxy=getattr(args, "proxy", None),
        )
        run_request_console(None, session)
        session.close()
        return

    # ── scan command ───────────────────────────────────────────────────
    if args.command == "scan":
        if not getattr(args, "no_consent", False):
            print_legal()
            get_consent()
        else:
            console.print("[dim]Consent prompt skipped (--no-consent).[/dim]")

        if not args.target and not getattr(args, "targets_file", None):
            console.print("[red]✘ Provide a target: hexstrike scan <target> or --targets-file file.txt[/red]")
            sys.exit(1)

        config = collect_config(args)
        save_session({"config": config, "started_at": config["started_at"]})

        steps = getattr(args, "steps", None) or ["toolcheck", "recon", "exploit", "report"]
        console.print(f"[dim]Steps: {' → '.join(steps)}[/dim]")

        graph = run_scan(config, steps)
        console.print(f"\n[bold green]✔ Scan complete. {len(graph.findings)} finding(s).[/bold green]")
        return


if __name__ == "__main__":
    # Graceful Ctrl+C
    def _sigint(sig, frame):
        console.print("\n\n[bold yellow]⚠ Interrupted. Saving session...[/bold yellow]")
        sys.exit(0)
    signal.signal(signal.SIGINT, _sigint)
    main()
