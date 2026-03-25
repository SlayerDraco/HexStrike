"""
HexStrike v2 - Request/Response Manipulation Console
Minimal CLI version of Burp Suite repeater.
Allows viewing, editing, and resending HTTP requests interactively.
"""

from __future__ import annotations
import json
import re
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt
from rich.syntax import Syntax
from rich.columns import Columns
from rich.rule import Rule
from rich import box

from core.models import ScanGraph
from core.session import HexSession

console = Console()


class RequestRecord:
    """Represents an editable HTTP request."""

    def __init__(self, url: str, method: str = "GET",
                 headers: Optional[Dict[str, str]] = None,
                 body: str = "", params: Optional[Dict[str, str]] = None):
        self.url      = url
        self.method   = method.upper()
        self.headers  = headers or {"User-Agent": "HexStrike/2.0", "Accept": "*/*"}
        self.body     = body
        self.params   = params or {}
        self.history: List[dict] = []

    def display(self):
        """Print the current request in a formatted view."""
        lines = [f"[bold cyan]{self.method}[/bold cyan] [white]{self.url}[/white]"]
        if self.params:
            lines.append(f"[dim]Params: {self.params}[/dim]")
        lines.append("")
        for k, v in self.headers.items():
            lines.append(f"[yellow]{k}:[/yellow] {v}")
        if self.body:
            lines.append("")
            lines.append(f"[white]{self.body}[/white]")

        console.print(Panel("\n".join(lines), title="[bold]Current Request[/bold]", border_style="cyan"))

    def send(self, session: HexSession) -> dict:
        """Send the request and return response details."""
        t0 = time.monotonic()
        try:
            resp = session.request(
                self.method, self.url,
                headers=self.headers,
                params=self.params if self.method == "GET" else {},
                content=self.body.encode() if self.body else None,
            )
            elapsed = time.monotonic() - t0
            result = {
                "status": resp.status_code,
                "headers": dict(resp.headers),
                "body": resp.text,
                "length": len(resp.text),
                "elapsed": round(elapsed * 1000, 1),
            }
            self.history.append({
                "request": {"url": self.url, "method": self.method,
                             "params": self.params, "body": self.body},
                "response": result,
            })
            return result
        except Exception as e:
            return {"error": str(e)}

    def display_response(self, result: dict):
        """Pretty-print a response."""
        if "error" in result:
            console.print(f"[red]✘ {result['error']}[/red]")
            return

        status = result["status"]
        color = "green" if status < 300 else ("yellow" if status < 400 else "red")
        console.print(f"\n[bold {color}]HTTP {status}[/bold {color}]  "
                      f"[dim]{result['length']} bytes  {result['elapsed']}ms[/dim]")

        # Response headers
        h_lines = "\n".join(f"[yellow]{k}:[/yellow] {v}"
                            for k, v in list(result["headers"].items())[:12])
        console.print(Panel(h_lines, title="Response Headers", border_style="dim"))

        # Response body
        body = result["body"]
        ct = result["headers"].get("content-type", "")
        if "json" in ct:
            try:
                pretty = json.dumps(json.loads(body), indent=2)
                console.print(Syntax(pretty[:3000], "json", theme="monokai", line_numbers=False))
            except Exception:
                console.print(body[:2000])
        elif "html" in ct:
            console.print(Syntax(body[:3000], "html", theme="monokai", line_numbers=False))
        else:
            console.print(body[:2000])


def _print_help():
    table = Table(box=box.SIMPLE, show_header=False)
    table.add_column("Cmd", style="bold yellow", width=12)
    table.add_column("Description", style="white")
    table.add_row("send",        "Send the current request")
    table.add_row("view",        "View the current request")
    table.add_row("set url",     "Set a new URL")
    table.add_row("set method",  "Change HTTP method (GET/POST/PUT/DELETE/PATCH)")
    table.add_row("set param",   "Set a query/body parameter: set param key value")
    table.add_row("del param",   "Remove a parameter: del param key")
    table.add_row("set header",  "Set a header: set header Name Value")
    table.add_row("set body",    "Set raw request body")
    table.add_row("history",     "Show request/response history")
    table.add_row("load",        "Load an endpoint from scan: load <number>")
    table.add_row("list",        "List discovered endpoints")
    table.add_row("repeat N",    "Send request N times (race condition test)")
    table.add_row("compare",     "Compare last two responses")
    table.add_row("clear",       "Reset current request")
    table.add_row("exit / quit", "Exit console")
    console.print(Panel(table, title="[bold cyan]HexStrike Request Console — Commands[/bold cyan]", border_style="cyan"))


def _load_endpoint(graph: ScanGraph, index: int) -> Optional[RequestRecord]:
    eps = graph.all_endpoints()
    if 0 <= index < len(eps):
        ep = eps[index]
        params = {p.name: p.value for p in ep.parameters if p.param_type == "query"}
        return RequestRecord(
            url=ep.url, method=ep.method,
            headers=dict(ep.headers) if ep.headers else {},
            params=params,
        )
    return None


def run_request_console(graph: Optional[ScanGraph], session: HexSession):
    """
    Interactive request manipulation console.
    Can be invoked standalone or within the main menu.
    """
    console.print()
    console.print(Panel(
        "[bold white]HexStrike Request Console[/bold white]\n"
        "[dim]Inspect, modify, and replay HTTP requests interactively.\n"
        "Type [bold yellow]help[/bold yellow] for commands.[/dim]",
        title="[bold cyan]◈ REQUEST CONSOLE[/bold cyan]",
        border_style="cyan"
    ))

    # Default request
    default_url = graph.target if graph else "http://example.com"
    if not default_url.startswith("http"):
        default_url = "http://" + default_url

    req = RequestRecord(url=default_url)
    if session.is_authenticated:
        req.headers["Cookie"] = session.cookie_header

    while True:
        try:
            cmd_raw = Prompt.ask("\n[bold cyan]req>[/bold cyan]").strip()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim]Exiting console.[/dim]")
            break

        if not cmd_raw:
            continue

        parts = cmd_raw.split(None, 3)
        cmd = parts[0].lower()

        if cmd in ("exit", "quit", "q"):
            console.print("[dim]Exiting request console.[/dim]")
            break

        elif cmd == "help":
            _print_help()

        elif cmd == "view":
            req.display()

        elif cmd == "send":
            req.display()
            console.print("[dim]Sending...[/dim]")
            result = req.send(session)
            req.display_response(result)

        elif cmd == "repeat" and len(parts) >= 2:
            try:
                n = int(parts[1])
            except ValueError:
                n = 5
            console.print(f"[cyan]Sending {n} requests...[/cyan]")
            responses = []
            for i in range(n):
                r = req.send(session)
                status = r.get("status", "?")
                length = r.get("length", 0)
                console.print(f"  [{i+1}] [{'green' if status==200 else 'yellow'}]{status}[/] {length}b")
                responses.append(r)
            # Quick diff
            hashes = set(
                r.get("body", "")[:500] for r in responses if "body" in r
            )
            if len(hashes) > 1:
                console.print(f"[bold yellow]⚠ {len(hashes)} unique responses — possible race condition![/bold yellow]")

        elif cmd == "compare":
            if len(req.history) >= 2:
                r1 = req.history[-2]["response"]
                r2 = req.history[-1]["response"]
                console.print(
                    Panel(
                        f"Request -2:  HTTP {r1['status']}  {r1['length']}b  {r1['elapsed']}ms\n"
                        f"Request -1:  HTTP {r2['status']}  {r2['length']}b  {r2['elapsed']}ms\n\n"
                        f"Status same: {'[green]yes' if r1['status']==r2['status'] else '[red]NO'}\n"
                        f"Body same:   {'[green]yes' if r1['body']==r2['body'] else '[red]NO — different content'}",
                        title="Response Diff",
                        border_style="yellow",
                    )
                )
            else:
                console.print("[yellow]Need at least 2 requests in history.[/yellow]")

        elif cmd == "history":
            for i, h in enumerate(req.history[-10:]):
                rq = h["request"]
                rs = h["response"]
                console.print(
                    f"  [{i+1}] {rq['method']} {rq['url']} → "
                    f"HTTP {rs.get('status','?')} {rs.get('length','?')}b"
                )

        elif cmd == "set" and len(parts) >= 3:
            sub = parts[1].lower()
            if sub == "url":
                req.url = parts[2]
                console.print(f"[green]URL set: {req.url}[/green]")
            elif sub == "method":
                req.method = parts[2].upper()
                console.print(f"[green]Method: {req.method}[/green]")
            elif sub == "param" and len(parts) >= 4:
                req.params[parts[2]] = parts[3]
                console.print(f"[green]Param {parts[2]}={parts[3]}[/green]")
            elif sub == "header" and len(parts) >= 4:
                req.headers[parts[2]] = parts[3]
                console.print(f"[green]Header {parts[2]}: {parts[3]}[/green]")
            elif sub == "body":
                body_val = " ".join(parts[2:])
                req.body = body_val
                console.print(f"[green]Body set ({len(body_val)} chars)[/green]")
            else:
                console.print("[yellow]Usage: set url|method|param|header|body ...[/yellow]")

        elif cmd == "del" and len(parts) >= 3:
            sub = parts[1].lower()
            if sub == "param" and parts[2] in req.params:
                del req.params[parts[2]]
                console.print(f"[green]Removed param: {parts[2]}[/green]")
            elif sub == "header" and parts[2] in req.headers:
                del req.headers[parts[2]]
                console.print(f"[green]Removed header: {parts[2]}[/green]")

        elif cmd == "list" and graph:
            eps = graph.all_endpoints()
            t = Table(box=box.SIMPLE)
            t.add_column("#", width=4)
            t.add_column("Method", width=8)
            t.add_column("URL", style="cyan")
            t.add_column("Status", width=7)
            t.add_column("Params", width=6)
            for i, ep in enumerate(eps[:30]):
                t.add_row(
                    str(i), ep.method, ep.url[:70],
                    str(ep.status_code or ""), str(len(ep.parameters))
                )
            console.print(t)

        elif cmd == "load" and graph and len(parts) >= 2:
            try:
                idx = int(parts[1])
                loaded = _load_endpoint(graph, idx)
                if loaded:
                    req = loaded
                    if session.is_authenticated:
                        req.headers["Cookie"] = session.cookie_header
                    console.print(f"[green]✔ Loaded: {req.method} {req.url}[/green]")
                    req.display()
                else:
                    console.print(f"[red]No endpoint at index {idx}[/red]")
            except ValueError:
                console.print("[yellow]Usage: load <number>[/yellow]")

        elif cmd == "clear":
            req = RequestRecord(url=default_url)
            if session.is_authenticated:
                req.headers["Cookie"] = session.cookie_header
            console.print("[green]Request reset.[/green]")

        else:
            console.print(f"[yellow]Unknown command: {cmd_raw}. Type 'help' for commands.[/yellow]")
