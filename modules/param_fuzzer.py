"""
HexStrike v2 - Parameter Discovery & Fuzzing Engine
Discovers hidden parameters via wordlist + response comparison.
"""

from __future__ import annotations
import asyncio
import hashlib
from pathlib import Path
from typing import List, Dict, Optional
from urllib.parse import urlparse, urlencode, urlunparse, parse_qs

import httpx
from rich.console import Console
from rich.rule import Rule
from rich.progress import Progress, BarColumn, TextColumn, TaskID

from core.models import ScanGraph, Endpoint, Parameter, Finding
from core.session import HexSession, AsyncHexSession

console = Console()

# Common hidden parameters to fuzz
COMMON_PARAMS = [
    "id", "uid", "user_id", "userId", "user", "username", "email",
    "debug", "test", "admin", "mode", "format", "output", "type",
    "action", "cmd", "command", "exec", "redirect", "url", "next",
    "return", "returnUrl", "callback", "file", "path", "dir", "page",
    "lang", "locale", "token", "key", "api_key", "secret", "auth",
    "access", "role", "level", "privilege", "include", "require",
    "load", "template", "view", "layout", "render", "style", "theme",
    "search", "query", "q", "s", "keyword", "filter", "sort", "order",
    "limit", "offset", "page", "per_page", "size", "count", "num",
    "ref", "source", "from", "to", "start", "end", "date",
    "version", "v", "ver", "revision", "release",
    "config", "cfg", "conf", "setting", "option",
    "backup", "export", "import", "upload", "download",
    "log", "logs", "error", "trace", "stack",
    "proxy", "forward", "host", "domain", "port",
    "xml", "json", "data", "payload", "body",
    "category", "tag", "label", "group", "class",
    "status", "state", "flag", "enabled", "active",
]


def _baseline_hash(text: str) -> str:
    return hashlib.md5(text.encode()).hexdigest()


async def _fuzz_param(
    url: str, param: str, baseline_hash: str, baseline_len: int,
    client: httpx.AsyncClient, sem: asyncio.Semaphore
) -> Optional[dict]:
    """Test if adding a parameter changes the response (indicates it's processed)."""
    async with sem:
        try:
            # Add param with a canary value
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            qs[param] = ["HEXSTRIKEFUZZ1337"]
            new_query = urlencode({k: v[0] for k, v in qs.items()})
            test_url = urlunparse(parsed._replace(query=new_query))

            resp = await client.get(test_url)
            h = _baseline_hash(resp.text)
            diff_len = abs(len(resp.text) - baseline_len)

            # Significant response change → parameter is processed
            if h != baseline_hash and diff_len > 30:
                return {
                    "url": url, "param": param,
                    "status": resp.status_code,
                    "len_diff": diff_len,
                    "test_url": test_url,
                }
        except Exception:
            pass
    return None


async def _discover_params_for_endpoint(
    ep: Endpoint, params_to_test: List[str],
    session: HexSession, concurrency: int
) -> List[dict]:
    """Discover hidden params for one endpoint."""
    url = ep.url

    async_sess = AsyncHexSession(session)
    async with async_sess.build() as client:
        # Baseline request
        try:
            base_resp = await client.get(url)
            baseline_h = _baseline_hash(base_resp.text)
            baseline_len = len(base_resp.text)
        except Exception:
            return []

        # Skip already known params
        known = {p.name for p in ep.parameters}
        candidates = [p for p in params_to_test if p not in known]

        sem = asyncio.Semaphore(concurrency)
        tasks = [
            _fuzz_param(url, param, baseline_h, baseline_len, client, sem)
            for param in candidates
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if r and not isinstance(r, Exception)]


def run_param_fuzzing(
    graph: ScanGraph, session: HexSession, profile,
    custom_wordlist: Optional[str] = None
) -> List[Finding]:
    console.print(Rule("[bold red]Parameter Discovery & Fuzzing[/bold red]"))

    # Load wordlist
    params_to_test = list(COMMON_PARAMS)
    if custom_wordlist and Path(custom_wordlist).exists():
        extra = [l.strip() for l in Path(custom_wordlist).read_text().splitlines() if l.strip()]
        params_to_test = list(set(params_to_test + extra))
        console.print(f"  [cyan]Loaded {len(extra)} custom params. Total: {len(params_to_test)}[/cyan]")

    # Only test endpoints that are reachable (200 status) and have a URL
    testable = [
        ep for ep in graph.all_endpoints()
        if ep.status_code and ep.status_code < 400
    ][:profile.max_urls]

    if not testable:
        console.print("[yellow]  No reachable endpoints for fuzzing.[/yellow]")
        return []

    console.print(f"  [cyan]Fuzzing {len(testable)} endpoint(s) × {len(params_to_test)} params...[/cyan]")

    findings: List[Finding] = []
    loop = asyncio.new_event_loop()

    for ep in testable:
        raw = loop.run_until_complete(
            _discover_params_for_endpoint(ep, params_to_test, session, profile.concurrency)
        )
        for r in raw:
            console.print(
                f"  [green]✔ Hidden param:[/green] [cyan]{r['param']}[/cyan] "
                f"on [white]{r['url']}[/white]  (Δlen={r['len_diff']})"
            )
            # Add to graph
            p = Parameter(
                name=r["param"], value="HEXSTRIKEFUZZ1337",
                param_type="query", endpoint=r["url"]
            )
            ep.add_parameter(p)

            # If debug/admin params → finding
            if r["param"].lower() in ["debug", "admin", "test", "trace", "cmd", "exec", "command"]:
                f = Finding(
                    title=f"Dangerous Hidden Parameter: ?{r['param']}",
                    finding_type="misconfig",
                    severity="High",
                    cvss_score=7.2,
                    cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
                    target=graph.target,
                    endpoint=r["url"],
                    parameter=r["param"],
                    detail=(
                        f"Hidden parameter '{r['param']}' is processed by the server. "
                        f"Debug/admin parameters can expose sensitive functionality."
                    ),
                    evidence=f"Test URL: {r['test_url']} produced different response (Δlen={r['len_diff']})",
                    recommendation=(
                        "Remove debug/admin parameters from production. "
                        "Implement strict input validation and allowlisting."
                    ),
                )
                findings.append(f)
                graph.add_finding(f)

    loop.close()
    console.print(f"\n[green]✔ Param fuzzing complete. {len(findings)} finding(s).[/green]")
    return findings
