"""
HexStrike v2 - Business Logic Testing Module
Race conditions, request replay, multi-step workflow testing.
"""

from __future__ import annotations
import asyncio
import time
import hashlib
from typing import List, Dict, Optional, Tuple
from urllib.parse import urlparse

import httpx
from rich.console import Console
from rich.rule import Rule
from rich.panel import Panel
from rich.table import Table
from rich import box

from core.models import ScanGraph, Endpoint, Finding
from core.session import HexSession, AsyncHexSession

console = Console()


# ─── Race Condition ───────────────────────────────────────────────────────────

async def _fire_parallel(
    url: str, method: str, data: dict,
    count: int, client: httpx.AsyncClient
) -> List[dict]:
    """Send `count` identical requests simultaneously."""

    async def _single(i: int):
        t0 = time.monotonic()
        try:
            if method == "POST":
                resp = await client.post(url, data=data)
            else:
                resp = await client.get(url, params=data)
            elapsed = time.monotonic() - t0
            return {
                "index": i, "status": resp.status_code,
                "length": len(resp.text),
                "hash": hashlib.md5(resp.text.encode()).hexdigest(),
                "elapsed": round(elapsed, 3),
                "snippet": resp.text[:200],
            }
        except Exception as e:
            return {"index": i, "error": str(e)}

    tasks = [_single(i) for i in range(count)]
    return await asyncio.gather(*tasks)


def _analyze_race_responses(responses: List[dict], url: str) -> Optional[Finding]:
    """
    Detect race condition indicators:
    - All requests succeed (200) when only one should
    - Different response bodies for identical requests (state change mid-flight)
    """
    ok = [r for r in responses if r.get("status") == 200]
    if len(ok) < 2:
        return None

    hashes = set(r["hash"] for r in ok if "hash" in r)
    lengths = [r["length"] for r in ok]
    unique_lengths = len(set(lengths))

    # Multiple 200s with different response bodies → race condition
    if len(hashes) > 1 and unique_lengths > 1:
        console.print(
            f"  [bold red]🔥 RACE CONDITION:[/bold red] {url}\n"
            f"     {len(ok)}/{len(responses)} requests succeeded with {len(hashes)} distinct responses"
        )
        return Finding(
            title=f"Race Condition on {url}",
            finding_type="biz_logic",
            severity="High",
            cvss_score=7.5,
            cvss_vector="AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N",
            target=url,
            endpoint=url,
            detail=(
                f"{len(ok)} parallel requests all returned HTTP 200 with {len(hashes)} "
                f"different response bodies. This indicates a race condition — "
                f"concurrent requests may bypass single-use logic (coupons, transfers, votes)."
            ),
            evidence=f"Response lengths: {lengths[:10]}",
            recommendation=(
                "Implement database-level locking, atomic transactions, "
                "or idempotency keys to prevent concurrent exploitation."
            ),
        )
    return None


# ─── Request Replay ───────────────────────────────────────────────────────────

def _replay_request(
    url: str, method: str, data: dict,
    session: HexSession, count: int = 5
) -> List[dict]:
    """Replay a request N times and compare responses."""
    results = []
    for i in range(count):
        try:
            if method == "POST":
                resp = session.post(url, data=data)
            else:
                resp = session.get(url, params=data)
            results.append({
                "index": i, "status": resp.status_code,
                "length": len(resp.text),
                "hash": hashlib.md5(resp.text.encode()).hexdigest(),
            })
        except Exception as e:
            results.append({"index": i, "error": str(e)})
    return results


# ─── Coupon / Token Reuse ─────────────────────────────────────────────────────

def _test_token_reuse(
    url: str, token_param: str, token_value: str,
    session: HexSession
) -> Optional[Finding]:
    """Test if a one-time token/coupon can be reused."""
    results = []
    for i in range(3):
        try:
            resp = session.post(url, data={token_param: token_value, "action": "redeem"})
            results.append(resp.status_code)
        except Exception:
            results.append(0)

    # If all 3 uses returned 200 → reuse vulnerability
    ok_count = results.count(200)
    if ok_count >= 2:
        return Finding(
            title=f"One-Time Token Reuse: {url}",
            finding_type="biz_logic",
            severity="High",
            cvss_score=8.1,
            cvss_vector="AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
            target=url,
            endpoint=url,
            parameter=token_param,
            detail=f"Token '{token_value}' was accepted {ok_count}/3 times. Should be single-use.",
            recommendation=(
                "Mark tokens as used immediately on first redemption. "
                "Use database transactions to prevent concurrent reuse."
            ),
        )
    return None


# ─── Negative Value / Limit Bypass ───────────────────────────────────────────

NEGATIVE_PAYLOADS = ["-1", "-100", "0", "99999", "-0.01", "1e10", "NaN", "null"]

def _test_negative_values(
    url: str, endpoints: List[Endpoint], session: HexSession
) -> List[Finding]:
    """Test numeric fields for negative/boundary value abuse."""
    findings = []
    for ep in endpoints:
        for param in ep.parameters:
            if param.param_type not in ["query", "body"]:
                continue
            if not any(k in param.name.lower() for k in
                       ["amount", "quantity", "price", "count", "qty", "total", "balance"]):
                continue

            for payload in NEGATIVE_PAYLOADS:
                try:
                    if param.param_type == "query":
                        resp = session.get(f"{ep.url}?{param.name}={payload}")
                    else:
                        resp = session.post(ep.url, data={param.name: payload})

                    if resp.status_code == 200:
                        body = resp.text.lower()
                        if any(k in body for k in ["success", "accepted", "confirmed", "ok"]):
                            f = Finding(
                                title=f"Negative Value Accepted: {param.name}={payload}",
                                finding_type="biz_logic",
                                severity="High",
                                cvss_score=7.8,
                                cvss_vector="AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                                target=url,
                                endpoint=ep.url,
                                parameter=param.name,
                                detail=(
                                    f"Parameter '{param.name}' accepted value '{payload}'. "
                                    f"Negative/boundary values in financial fields may allow "
                                    f"balance manipulation or free transactions."
                                ),
                                recommendation=(
                                    "Validate all numeric inputs server-side. "
                                    "Reject negative, zero, or out-of-range values for financial fields."
                                ),
                            )
                            findings.append(f)
                            console.print(
                                f"  [bold red]🔥 Negative value accepted:[/bold red] "
                                f"{param.name}={payload} @ {ep.url}"
                            )
                            break
                except Exception:
                    pass
    return findings


# ─── Main Runner ──────────────────────────────────────────────────────────────

def run_biz_logic(graph: ScanGraph, session: HexSession, profile) -> List[Finding]:
    console.print(Rule("[bold red]Business Logic Testing[/bold red]"))
    all_findings: List[Finding] = []

    base_url = graph.target if graph.target.startswith("http") else "http://" + graph.target
    endpoints = graph.all_endpoints()

    # 1. Race condition testing on forms/actions
    console.print("[cyan]Testing race conditions on endpoints...[/cyan]")
    form_endpoints = [ep for ep in endpoints if ep.forms and ep.status_code == 200][:5]

    loop = asyncio.new_event_loop()
    async_sess = AsyncHexSession(session)

    for ep in form_endpoints:
        for form in ep.forms[:1]:
            action = form.get("action", ep.url)
            method = form.get("method", "POST")
            data = {i["name"]: i.get("value", "test") for i in form.get("inputs", []) if i.get("name")}

            if not data:
                continue

            console.print(f"  [dim]Race test: {method} {action} ({profile.concurrency} parallel)[/dim]")

            async def _race():
                async with async_sess.build() as client:
                    return await _fire_parallel(action, method, data, profile.concurrency, client)

            responses = loop.run_until_complete(_race())
            finding = _analyze_race_responses(responses, action)
            if finding:
                finding.target = graph.target
                all_findings.append(finding)
                graph.add_finding(finding)

    loop.close()

    # 2. Request replay
    console.print("\n[cyan]Request replay testing...[/cyan]")
    for ep in form_endpoints[:3]:
        for form in ep.forms[:1]:
            action = form.get("action", ep.url)
            data = {i["name"]: i.get("value", "test") for i in form.get("inputs", []) if i.get("name")}
            results = _replay_request(action, form.get("method", "POST"), data, session, count=5)
            hashes = set(r.get("hash", "") for r in results if "hash" in r)
            if len(hashes) > 1:
                console.print(f"  [yellow]⚠ Non-idempotent endpoint: {action}[/yellow]")

    # 3. Negative values
    console.print("\n[cyan]Testing negative/boundary values...[/cyan]")
    neg_findings = _test_negative_values(graph.target, endpoints, session)
    for f in neg_findings:
        all_findings.append(f)
        graph.add_finding(f)

    console.print(f"\n[green]✔ Business logic testing complete. {len(all_findings)} finding(s).[/green]")
    return all_findings
