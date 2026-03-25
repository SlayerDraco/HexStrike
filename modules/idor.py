"""
HexStrike v2 - IDOR Detection Engine
Tests parameter-based access control issues by mutating numeric IDs
and detecting response differences.
"""

from __future__ import annotations
import asyncio
import hashlib
import re
from typing import List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx
from rich.console import Console
from rich.rule import Rule
from rich.table import Table
from rich import box

from core.models import ScanGraph, Endpoint, Parameter, Finding
from core.session import HexSession, AsyncHexSession

console = Console()

# Parameters likely to be user-controlled IDs
ID_PARAM_PATTERNS = re.compile(
    r"^(id|user_?id|account_?id|profile_?id|order_?id|invoice_?id|"
    r"doc_?id|file_?id|record_?id|item_?id|post_?id|uid|pid|cid|"
    r"ticket_?id|customer_?id|emp_?id|product_?id|ref|uuid|key|token_id)$",
    re.I
)


def _is_numeric_id(value: str) -> bool:
    """Check if param value looks like a numeric ID."""
    try:
        n = int(value)
        return 0 < n < 10_000_000
    except (ValueError, TypeError):
        return False


def _mutate_url(url: str, param: str, new_val: str) -> str:
    """Replace a specific param value in the URL."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [new_val]
    new_query = urlencode({k: v[0] for k, v in qs.items()})
    return urlunparse(parsed._replace(query=new_query))


def _response_signature(resp: httpx.Response) -> dict:
    """Extract meaningful response features for comparison."""
    text = resp.text
    return {
        "status": resp.status_code,
        "length": len(text),
        "hash": hashlib.md5(text.encode()).hexdigest(),
        "contains_error": any(k in text.lower() for k in
                               ["error", "denied", "forbidden", "unauthorized", "not found"]),
        "has_data": len(text) > 200,
    }


def _is_idor(base_sig: dict, test_sig: dict) -> Tuple[bool, str]:
    """
    Determine if a response difference indicates IDOR.
    Returns (is_vulnerable, reason).
    """
    # Same status, different content → potential IDOR
    if (base_sig["status"] == test_sig["status"] == 200
            and base_sig["hash"] != test_sig["hash"]
            and test_sig["has_data"]
            and not test_sig["contains_error"]):
        length_diff = abs(base_sig["length"] - test_sig["length"])
        if length_diff > 50:
            return True, f"Status 200, different content (Δlen={length_diff})"

    # Base was 403/401, test is 200 → clear IDOR
    if base_sig["status"] in [401, 403] and test_sig["status"] == 200:
        return True, f"Access control bypass: {base_sig['status']} → 200"

    return False, ""


async def _test_idor_param(
    url: str, param_name: str, base_val: str,
    client: httpx.AsyncClient, sem: asyncio.Semaphore
) -> Optional[dict]:
    """Test a single parameter for IDOR by trying adjacent IDs."""
    base_id = int(base_val)
    test_ids = [base_id + 1, base_id + 2, base_id - 1,
                base_id + 100, base_id + 1000, 1, 2, 3]
    test_ids = [str(i) for i in test_ids if i > 0 and str(i) != base_val]

    async with sem:
        try:
            base_resp = await client.get(url)
            base_sig = _response_signature(base_resp)
        except Exception:
            return None

        for test_val in test_ids[:4]:  # Limit to 4 tests per param
            test_url = _mutate_url(url, param_name, test_val)
            try:
                test_resp = await client.get(test_url)
                test_sig = _response_signature(test_resp)
                vuln, reason = _is_idor(base_sig, test_sig)
                if vuln:
                    return {
                        "url": url, "param": param_name,
                        "base_value": base_val, "test_value": test_val,
                        "base_status": base_sig["status"],
                        "test_status": test_sig["status"],
                        "reason": reason,
                        "test_url": test_url,
                    }
            except Exception:
                pass
    return None


async def _run_idor_async(
    endpoints: List[Endpoint], session: HexSession, concurrency: int
) -> List[dict]:
    """Run IDOR tests in parallel across all endpoints."""
    tasks = []
    sem = asyncio.Semaphore(concurrency)
    async_sess = AsyncHexSession(session)

    async with async_sess.build() as client:
        for ep in endpoints:
            for param in ep.parameters:
                if param.param_type != "query":
                    continue
                if not (ID_PARAM_PATTERNS.match(param.name) or _is_numeric_id(param.value)):
                    continue
                if not _is_numeric_id(param.value):
                    continue
                tasks.append(
                    _test_idor_param(ep.url, param.name, param.value, client, sem)
                )

        if not tasks:
            return []
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if r and not isinstance(r, Exception)]


def run_idor(graph: ScanGraph, session: HexSession, profile) -> List[Finding]:
    console.print(Rule("[bold red]IDOR Detection Engine[/bold red]"))

    candidates = [
        ep for ep in graph.all_endpoints()
        if any(
            ID_PARAM_PATTERNS.match(p.name) or _is_numeric_id(p.value)
            for p in ep.parameters
            if p.param_type == "query"
        )
    ]

    if not candidates:
        console.print("[yellow]  No numeric ID parameters found for IDOR testing.[/yellow]")
        return []

    console.print(f"  [cyan]{len(candidates)} endpoint(s) with testable parameters.[/cyan]")

    loop = asyncio.new_event_loop()
    raw_results = loop.run_until_complete(
        _run_idor_async(candidates, session, profile.concurrency)
    )
    loop.close()

    findings: List[Finding] = []
    for r in raw_results:
        console.print(
            f"  [bold red]🔥 IDOR:[/bold red] [white]{r['url']}[/white]\n"
            f"     param=[cyan]{r['param']}[/cyan]  "
            f"{r['base_value']}→{r['test_value']}  [{r['reason']}]"
        )

        # Mark param in graph
        for ep in graph.all_endpoints():
            if ep.url == r["url"]:
                for p in ep.parameters:
                    if p.name == r["param"]:
                        p.idor_tested = True
                        p.findings.append("IDOR")

        # Severity: if it's an API or admin endpoint → Critical, else High
        ep_url = r["url"]
        is_sensitive = any(k in ep_url.lower() for k in
                           ["api", "admin", "user", "account", "payment", "order"])
        severity = "Critical" if is_sensitive else "High"
        score = 9.1 if is_sensitive else 7.5
        vector = "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"

        f = Finding(
            title=f"IDOR on {ep_url}",
            finding_type="idor",
            severity=severity,
            cvss_score=score,
            cvss_vector=vector,
            target=graph.target,
            endpoint=ep_url,
            parameter=r["param"],
            detail=(
                f"Parameter '{r['param']}' with value '{r['base_value']}' "
                f"can be replaced with '{r['test_value']}' to access other users' data. "
                f"Reason: {r['reason']}"
            ),
            evidence=f"Test URL: {r['test_url']} | {r['reason']}",
            recommendation=(
                "Implement server-side access control validation. "
                "Never rely on client-supplied IDs without authorization checks. "
                "Use indirect object references (UUIDs) where possible."
            ),
        )
        findings.append(f)
        graph.add_finding(f)

    console.print(f"\n[green]✔ IDOR scan complete. {len(findings)} finding(s).[/green]")

    if findings:
        t = Table(box=box.SIMPLE, title="IDOR Findings")
        t.add_column("URL", style="cyan", max_width=60)
        t.add_column("Param", style="yellow")
        t.add_column("Severity", style="bold red")
        for f in findings:
            t.add_row(f.endpoint or "", f.parameter or "", f.severity)
        console.print(t)

    return findings
