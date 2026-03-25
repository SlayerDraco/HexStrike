"""
HexStrike - Tool Availability Checker & Auto-Installer
Checks for all required tools and installs missing ones automatically.
"""

import subprocess
import shutil
import os
import sys

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

# Tools: (name, apt_package, pip_package or None, check_command)
REQUIRED_TOOLS = [
    ("nmap",        "nmap",               None,              ["nmap", "--version"]),
    ("sqlmap",      "sqlmap",             None,              ["sqlmap", "--version"]),
    ("hydra",       "hydra",              None,              ["hydra", "-h"]),
    ("john",        "john",               None,              ["john", "--version"]),
    ("wfuzz",       "wfuzz",              None,              ["wfuzz", "--version"]),
    ("w3af",        None,                 None,              None),           # manual install note
    ("metasploit",  "metasploit-framework", None,            ["msfconsole", "--version"]),
    ("whois",       "whois",              None,              ["whois", "--version"]),
    ("curl",        "curl",               None,              ["curl", "--version"]),
    ("wget",        "wget",               None,              ["wget", "--version"]),
    ("sublist3r",   None,                 "sublist3r",       ["sublist3r", "--help"]),
    ("shodan",      None,                 "shodan",          ["shodan", "--version"]),
    ("python-nmap", None,                 "python-nmap",     None),
    ("requests",    None,                 "requests",        None),
    ("bs4",         None,                 "beautifulsoup4",  None),
    ("dnspython",   None,                 "dnspython",       None),
    ("python-whois",None,                 "python-whois",    None),
]

def check_tool(tool_entry):
    name, apt_pkg, pip_pkg, check_cmd = tool_entry
    if check_cmd is None:
        # Pure Python package — check via import or pip show
        pkg = pip_pkg or name
        result = subprocess.run(
            ["pip3", "show", pkg],
            capture_output=True, text=True
        )
        return result.returncode == 0
    # Check if binary exists in PATH
    return shutil.which(check_cmd[0]) is not None

def install_tool(tool_entry):
    name, apt_pkg, pip_pkg, check_cmd = tool_entry
    try:
        if pip_pkg:
            console.print(f"  [cyan]→ pip3 install {pip_pkg}[/cyan]")
            subprocess.run(
                ["pip3", "install", pip_pkg, "--break-system-packages", "-q"],
                check=True
            )
            return True
        elif apt_pkg:
            console.print(f"  [cyan]→ apt-get install -y {apt_pkg}[/cyan]")
            subprocess.run(
                ["apt-get", "install", "-y", "-q", apt_pkg],
                check=True
            )
            return True
        else:
            return False
    except subprocess.CalledProcessError:
        return False

def run_toolcheck():
    console.print()
    console.print(Panel(
        "[bold yellow]Checking all required tools for HexStrike...[/bold yellow]",
        border_style="yellow"
    ))
    console.print()

    results = []
    missing = []

    for tool_entry in REQUIRED_TOOLS:
        name = tool_entry[0]
        present = check_tool(tool_entry)
        results.append((name, present, tool_entry))
        if not present:
            missing.append(tool_entry)

    # Print status table
    table = Table(title="Tool Status", box=box.ROUNDED, border_style="cyan")
    table.add_column("Tool", style="bold white")
    table.add_column("Status", justify="center")
    table.add_column("Install Method", style="dim")

    for name, present, entry in results:
        _, apt_pkg, pip_pkg, _ = entry
        method = f"pip: {pip_pkg}" if pip_pkg else (f"apt: {apt_pkg}" if apt_pkg else "manual")
        status = "[bold green]✔ Found[/bold green]" if present else "[bold red]✘ Missing[/bold red]"
        table.add_row(name, status, method)

    console.print(table)
    console.print()

    if not missing:
        console.print("[bold green]✔ All tools are available. Ready to proceed.[/bold green]")
        return

    console.print(f"[bold yellow]⚠ {len(missing)} tool(s) missing. Auto-installing...[/bold yellow]\n")

    # Update apt cache first
    console.print("[dim]Running apt-get update...[/dim]")
    subprocess.run(["apt-get", "update", "-q"], capture_output=True)

    failed = []
    for tool_entry in missing:
        name = tool_entry[0]
        console.print(f"[yellow]Installing: [bold]{name}[/bold][/yellow]")
        success = install_tool(tool_entry)
        if success:
            console.print(f"  [green]✔ {name} installed successfully.[/green]")
        else:
            if name == "w3af":
                console.print(f"  [yellow]⚠ w3af requires manual installation: https://w3af.org/[/yellow]")
            else:
                console.print(f"  [red]✘ Failed to install {name}. Please install manually.[/red]")
                failed.append(name)

    console.print()
    if failed:
        console.print(f"[bold red]✘ Could not auto-install: {', '.join(failed)}[/bold red]")
        console.print("[dim]Please install these manually before running affected modules.[/dim]")
    else:
        console.print("[bold green]✔ All available tools installed successfully.[/bold green]")
