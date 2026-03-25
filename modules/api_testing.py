"""
HexStrike v2 - API Testing Module
REST endpoint detection, Swagger/OpenAPI fuzzing, GraphQL introspection + attacks.
"""

from __future__ import annotations
import asyncio
import json
import re
from typing import List, Dict, Optional, Any
from urllib.parse import urljoin

import httpx
from rich.console import Console
from rich.rule import Rule
from rich.table import Table
from rich import box

from core.models import ScanGraph, Endpoint, Parameter, Finding
from core.session import HexSession, AsyncHexSession

console = Console()

# Common REST paths to discover
REST_DISCOVERY_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/rest", "/rest/v1",
    "/v1", "/v2", "/v3",
    "/api/users", "/api/user", "/api/accounts", "/api/profile",
    "/api/admin", "/api/config", "/api/settings",
    "/api/login", "/api/auth", "/api/token",
    "/api/search", "/api/data", "/api/export",
    "/api/files", "/api/upload", "/api/download",
    "/api/health", "/api/status", "/api/version", "/api/info",
    "/api/docs", "/api/swagger", "/api/openapi",
    "/graphql", "/gql",
    "/.well-known/openapi.yaml",
    "/swagger.json", "/openapi.json",
]

# GraphQL attack payloads
GQL_INTROSPECTION = '{"query":"{__schema{types{name fields{name}}}}"}'
GQL_DOS_DEEP = '{"query":"{user{friends{friends{friends{friends{id}}}}}}}"}'
GQL_FIELD_SUGGEST = '{"query":"{user{invalidFieldXYZ}}"}'

# REST common HTTP methods to test
REST_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]


async def _probe_rest(
    url: str, client: httpx.AsyncClient, sem: asyncio.Semaphore
) -> Optional[dict]:
    async with sem:
        for method in ["GET", "POST"]:
            try:
                req = client.build_request(method, url)
                resp = await client.send(req)
                if resp.status_code not in [404, 405]:
                    ct = resp.headers.get("content-type", "")
                    is_json = "application/json" in ct or resp.text.strip().startswith("{")
                    return {
                        "url": url, "method": method,
                        "status": resp.status_code,
                        "content_type": ct,
                        "is_json": is_json,
                        "length": len(resp.text),
                        "snippet": resp.text[:300],
                    }
            except Exception:
                pass
    return None


async def _test_rest_methods(
    url: str, client: httpx.AsyncClient, sem: asyncio.Semaphore
) -> List[dict]:
    """Test all HTTP methods on an endpoint for unexpected 2xx responses."""
    findings = []
    async with sem:
        for method in REST_METHODS:
            try:
                req = client.build_request(method, url, content=b"{}")
                resp = await client.send(req)
                if resp.status_code < 300 and method not in ["GET", "HEAD", "OPTIONS"]:
                    findings.append({
                        "url": url, "method": method,
                        "status": resp.status_code,
                        "issue": f"Unexpected {method} allowed"
                    })
            except Exception:
                pass
    return findings


async def _fuzz_rest_param(
    url: str, param: str, payloads: List[str],
    client: httpx.AsyncClient, sem: asyncio.Semaphore
) -> List[dict]:
    """Fuzz a REST API parameter with injection payloads."""
    results = []
    async with sem:
        for payload in payloads[:5]:
            try:
                test_url = f"{url}?{param}={payload}"
                resp = await client.get(test_url)
                body = resp.text.lower()
                # SQL error patterns
                if any(e in body for e in ["sql syntax", "mysql_fetch", "ora-0", "pg_query",
                                            "unclosed quotation", "syntax error", "sqlite_"]):
                    results.append({
                        "url": test_url, "param": param, "payload": payload,
                        "status": resp.status_code, "issue": "SQL error in API response"
                    })
                # Debug info
                if any(e in body for e in ["traceback", "stack trace", "exception", "debug"]):
                    results.append({
                        "url": test_url, "param": param, "payload": payload,
                        "status": resp.status_code, "issue": "Debug info exposed"
                    })
            except Exception:
                pass
    return results


def _test_graphql(base_url: str, session: HexSession, graph: ScanGraph) -> List[Finding]:
    """Test GraphQL endpoint for introspection, IDOR, injection."""
    findings = []
    gql_url = base_url.rstrip("/") + "/graphql"

    # Find actual GraphQL endpoint
    for ep in graph.all_endpoints():
        if ep.is_api and "graphql" in ep.url.lower():
            gql_url = ep.url
            break

    console.print(f"  [cyan]Testing GraphQL: {gql_url}[/cyan]")

    # Introspection (should be disabled in production)
    try:
        resp = session.post(gql_url, json={"query": "{__schema{types{name}}}"})
        if resp.status_code == 200 and "__schema" in resp.text:
            console.print("  [bold red]🔥 GraphQL introspection ENABLED[/bold red]")
            f = Finding(
                title="GraphQL Introspection Enabled",
                finding_type="misconfig",
                severity="Medium",
                cvss_score=5.3,
                cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                target=graph.target,
                endpoint=gql_url,
                detail="GraphQL introspection exposes full schema to attackers.",
                evidence=resp.text[:300],
                recommendation="Disable introspection in production environments.",
            )
            findings.append(f)
            graph.add_finding(f)
    except Exception:
        pass

    # Batching DoS potential
    try:
        batch = [{"query": "{__typename}"}] * 10
        resp = session.post(gql_url, json=batch)
        if resp.status_code == 200 and isinstance(resp.json(), list):
            console.print("  [yellow]⚠ GraphQL batching enabled — DoS potential[/yellow]")
            f = Finding(
                title="GraphQL Batching Enabled — DoS Risk",
                finding_type="misconfig",
                severity="Low",
                cvss_score=3.7,
                cvss_vector="AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L",
                target=graph.target,
                endpoint=gql_url,
                detail="Query batching with no rate limiting can enable DoS attacks.",
                recommendation="Implement query depth limiting and rate limiting.",
            )
            findings.append(f)
            graph.add_finding(f)
    except Exception:
        pass

    return findings


def _parse_swagger_and_fuzz(graph: ScanGraph, session: HexSession) -> List[Finding]:
    """Parse OpenAPI spec and fuzz discovered endpoints."""
    if not graph.api_spec:
        return []

    findings = []
    spec = graph.api_spec
    base_url = graph.target if graph.target.startswith("http") else "http://" + graph.target

    sqli_payloads = ["'", "' OR '1'='1", "1; DROP TABLE users--", "1 UNION SELECT null--"]
    xss_payloads  = ["<script>alert(1)</script>", "'\"><img src=x onerror=alert(1)>"]

    paths = spec.get("paths", {})
    console.print(f"  [cyan]Fuzzing {len(paths)} Swagger path(s)...[/cyan]")

    for api_path, methods in paths.items():
        url = base_url.rstrip("/") + api_path
        for method_name, method_data in methods.items():
            method = method_name.upper()
            params = method_data.get("parameters", [])

            for param in params:
                param_name = param.get("name", "")
                param_in   = param.get("in", "query")

                payloads = sqli_payloads + xss_payloads
                for payload in payloads:
                    try:
                        if param_in == "query":
                            resp = session.request(method, f"{url}?{param_name}={payload}")
                        elif param_in == "body":
                            resp = session.request(method, url, json={param_name: payload})
                        else:
                            continue

                        body = resp.text.lower()
                        if any(e in body for e in ["sql syntax", "mysql_fetch", "syntax error",
                                                    "ora-0", "pg_query", "sqlite"]):
                            console.print(f"  [bold red]🔥 SQLi in API:[/bold red] {url} ?{param_name}")
                            f = Finding(
                                title=f"SQL Injection in API: {api_path}",
                                finding_type="sqli",
                                severity="Critical",
                                cvss_score=9.8,
                                cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                target=graph.target,
                                endpoint=url,
                                parameter=param_name,
                                detail=f"SQLi via API parameter '{param_name}'",
                                evidence=f"Payload: {payload}",
                                recommendation="Use parameterized queries. Validate all API inputs.",
                            )
                            findings.append(f)
                            graph.add_finding(f)
                            break
                    except Exception:
                        pass

    return findings


def run_api_testing(graph: ScanGraph, session: HexSession, profile) -> List[Finding]:
    console.print(Rule("[bold red]API-Specific Testing[/bold red]"))

    base_url = graph.target if graph.target.startswith("http") else "http://" + graph.target
    all_findings: List[Finding] = []

    # 1. Discover REST endpoints
    console.print("[cyan]Discovering REST endpoints...[/cyan]")
    loop = asyncio.new_event_loop()
    sem = asyncio.Semaphore(profile.concurrency)
    async_sess = AsyncHexSession(session)

    async def _discover_all():
        async with async_sess.build() as client:
            tasks = [
                _probe_rest(base_url.rstrip("/") + path, client, sem)
                for path in REST_DISCOVERY_PATHS
            ]
            return await asyncio.gather(*tasks, return_exceptions=True)

    raw = loop.run_until_complete(_discover_all())
    discovered = [r for r in raw if r and not isinstance(r, Exception)]

    for r in discovered:
        ep = Endpoint(
            url=r["url"], method=r["method"],
            status_code=r["status"], content_type=r["content_type"],
            is_api=True
        )
        graph.add_root_endpoint(ep)
        console.print(
            f"  [green]✔[/green] [{r['status']}] {r['url']} "
            f"({'JSON' if r['is_json'] else 'HTML'}) {r['method']}"
        )

    # 2. Test for unexpected HTTP methods
    console.print("\n[cyan]Testing HTTP method abuse...[/cyan]")

    async def _method_test_all():
        async with async_sess.build() as client:
            tasks = [
                _test_rest_methods(ep.url, client, sem)
                for ep in graph.api_endpoints()[:20]
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            return [item for sublist in results if isinstance(sublist, list) for item in sublist]

    method_issues = loop.run_until_complete(_method_test_all())
    for issue in method_issues:
        console.print(f"  [yellow]⚠ {issue['method']} allowed: {issue['url']}[/yellow]")
        f = Finding(
            title=f"HTTP Method Abuse: {issue['method']} on {issue['url']}",
            finding_type="misconfig",
            severity="Medium",
            cvss_score=5.3,
            cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
            target=graph.target,
            endpoint=issue["url"],
            detail=f"{issue['method']} is unexpectedly allowed on this endpoint.",
            recommendation="Restrict HTTP methods using allowlisting.",
        )
        all_findings.append(f)
        graph.add_finding(f)

    loop.close()

    # 3. Swagger/OpenAPI fuzzing
    if graph.api_spec:
        console.print("\n[cyan]Fuzzing OpenAPI/Swagger spec endpoints...[/cyan]")
        swagger_findings = _parse_swagger_and_fuzz(graph, session)
        all_findings.extend(swagger_findings)

    # 4. GraphQL
    if graph.graphql_detected:
        console.print("\n[cyan]Testing GraphQL...[/cyan]")
        gql_findings = _test_graphql(base_url, session, graph)
        all_findings.extend(gql_findings)

    console.print(f"\n[green]✔ API testing complete. {len(all_findings)} finding(s).[/green]")
    return all_findings
