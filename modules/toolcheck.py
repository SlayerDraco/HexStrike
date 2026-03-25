"""
HexStrike v2 - Tool Check Module
Verifies and auto-installs all required system tools.
"""

import subprocess
import shutil
import os
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()

REQUIRED_TOOLS = [
    # (display_name, apt_package, pip_package, binary_to_check)
    ("nmap",             "nmap",                 None,                  "nmap"),
    ("sqlmap",           "sqlmap",               None,                  "sqlmap"),
    ("hydra",            "hydra",                None,                  "hydra"),
    ("john",             "john",                 None,                  "john"),
    ("wfuzz",            "wfuzz",                None,                  "wfuzz"),
    ("metasploit",       "metasploit-framework", None,                  "msfconsole"),
    ("whois",            "whois",                None,                  "whois"),
    ("curl",             "curl",                 None,                  "curl"),
    ("sublist3r",        None,                   "sublist3r",           "sublist3r"),
    ("httpx (py)",       None,                   "httpx",               None),
    ("requests",         None,                   "requests",            None),
    ("beautifulsoup4",   None,                   "beautifulsoup4",      None),
    ("dnspython",        None,                   "dnspython",           None),
    ("python-whois",     None,                   "python-whois",        None),
    ("shodan (py)",      None,                   "shodan",              None),
    ("rich",             None,                   "rich",                None),
    ("python-dotenv",    None,                   "python-dotenv",       None),
]


def _check(entry) -> bool:
    name, apt, pip, binary = entry
    if binary:
        return shutil.which(binary) is not None
    pkg = pip or name
    r = subprocess.run(["pip3", "show", pkg], capture_output=True, text=True)
    return r.returncode == 0


def _install(entry) -> bool:
    name, apt, pip, binary = entry
    try:
        if pip:
            subprocess.run(
                ["pip3", "install", pip, "--break-system-packages", "-q"],
                check=True, capture_output=True
            )
            return True
        if apt:
            subprocess.run(
                ["apt-get", "install", "-y", "-q", apt],
                check=True, capture_output=True
            )
            return True
    except subprocess.CalledProcessError:
        pass
    return False


def run_toolcheck() -> dict:
    console.print()
    console.print(Panel(
        "[bold yellow]Verifying required tools...[/bold yellow]",
        border_style="yellow", padding=(0, 2)
    ))

    present, missing = [], []
    for entry in REQUIRED_TOOLS:
        (present if _check(entry) else missing).append(entry)

    table = Table(box=box.SIMPLE_HEAVY, border_style="cyan", show_header=True)
    table.add_column("Tool", style="bold white", width=18)
    table.add_column("Status", width=14, justify="center")
    table.add_column("Method", style="dim")

    for entry in REQUIRED_TOOLS:
        name, apt, pip, _ = entry
        ok = entry in present
        method = f"pip:{pip}" if pip else (f"apt:{apt}" if apt else "system")
        status = "[bold green]✔  found[/bold green]" if ok else "[bold red]✘  missing[/bold red]"
        table.add_row(name, status, method)

    console.print(table)

    if not missing:
        console.print("[bold green]✔ All tools available.[/bold green]\n")
        return {"status": "ok", "missing": []}

    console.print(f"[yellow]Installing {len(missing)} missing tool(s)...[/yellow]")
    subprocess.run(["apt-get", "update", "-q"], capture_output=True)

    failed = []
    for entry in missing:
        name = entry[0]
        if _install(entry):
            console.print(f"  [green]✔ {name}[/green]")
        else:
            console.print(f"  [red]✘ {name} — install manually[/red]")
            failed.append(name)

    return {"status": "partial" if failed else "ok", "missing": failed}
