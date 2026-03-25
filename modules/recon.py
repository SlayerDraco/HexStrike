"""
HexStrike v2 - Reconnaissance Module
Builds the ScanGraph: subdomains → endpoints → parameters → technologies.
All results are correlated, not dumped.
"""

from __future__ import annotations
import asyncio
import hashlib
import re
import socket
import subprocess
import time
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlparse, urljoin, parse_qs, urlunparse

import httpx
import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskID
from rich.table import Table
from rich import box

from core.models import (
    ScanGraph, Subdomain, Endpoint, Parameter, Technology, Finding
)
from core.session import HexSession, AsyncHexSession

console = Console()

# ─── Helpers ──────────────────────────────────────────────────────────────────

def _base_url(target: str) -> str:
    if not target.startswith("http"):
        return "http://" + target
    return target

def _domain(target: str) -> str:
    return urlparse(_base_url(target)).hostname or target

def _run_live(cmd: List[str], label: str = "") -> str:
    console.print(f"\n[bold cyan]▶ {label or ' '.join(cmd[:2])}[/bold cyan]")
    console.print(f"[dim]$ {' '.join(str(c) for c in cmd)}[/dim]")
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1
        )
        lines = []
        for line in proc.stdout:
            line = line.rstrip()
            if line:
                console.print(f"  [white]{line}[/white]")
                lines.append(line)
        proc.wait()
        return "\n".join(lines)
    except FileNotFoundError:
        console.print(f"[red]✘ Not found: {cmd[0]}[/red]")
        return ""


# ─── WHOIS ────────────────────────────────────────────────────────────────────

def _whois(domain: str) -> dict:
    console.print(Rule("[bold green]WHOIS[/bold green]"))
    raw = _run_live(["whois", domain], f"WHOIS {domain}")
    result: dict = {"raw": raw, "domain": domain, "nameservers": []}
    for line in raw.splitlines():
        ll = line.lower()
        if "registrar:" in ll:
            result["registrar"] = line.split(":", 1)[-1].strip()
        elif any(x in ll for x in ["creation date:", "created:"]):
            result.setdefault("created", line.split(":", 1)[-1].strip())
        elif any(x in ll for x in ["expiry date:", "expiration date:"]):
            result.setdefault("expires", line.split(":", 1)[-1].strip())
        elif any(x in ll for x in ["name server:", "nserver:"]):
            result["nameservers"].append(line.split(":", 1)[-1].strip())
        elif "org:" in ll or "organisation:" in ll:
            result.setdefault("org", line.split(":", 1)[-1].strip())
    return result


# ─── Google Dorking ───────────────────────────────────────────────────────────

DORKS = [
    "site:{d}", "site:{d} filetype:pdf",
    "site:{d} inurl:admin OR inurl:login", "site:{d} intitle:\"index of\"",
    "site:{d} intext:\"sql syntax\" OR intext:\"mysql error\"",
    "site:{d} ext:env OR ext:log OR ext:bak",
    "\"{d}\" password OR apikey OR secret",
    "site:{d} inurl:upload OR inurl:shell",
    "site:{d} inurl:config OR inurl:backup",
]

def _google_dork(domain: str, api_key: str, cx: str) -> dict:
    console.print(Rule("[bold green]Google Dorking[/bold green]"))
    if not api_key or not cx:
        dorks = [d.replace("{d}", domain) for d in DORKS]
        console.print("[yellow]⚠ No Google API keys. Manual dorks:[/yellow]")
        for dork in dorks:
            console.print(f"  [dim]{dork}[/dim]")
        return {"skipped": True, "manual_dorks": dorks}
    results = {}
    for tmpl in DORKS:
        q = tmpl.replace("{d}", domain)
        try:
            r = requests.get(
                "https://www.googleapis.com/customsearch/v1",
                params={"key": api_key, "cx": cx, "q": q, "num": 5},
                timeout=10
            )
            items = r.json().get("items", [])
            results[q] = [{"title": i.get("title"), "link": i.get("link")} for i in items]
            for item in items:
                console.print(f"  [white]→ {item.get('link')}[/white]")
            time.sleep(0.5)
        except Exception as e:
            results[q] = {"error": str(e)}
    return results


# ─── Nmap ─────────────────────────────────────────────────────────────────────

def _nmap(target: str, flags: List[str], output_dir: str, graph: ScanGraph) -> dict:
    console.print(Rule("[bold green]Nmap Fingerprinting[/bold green]"))
    domain = _domain(target)
    out_xml = str(Path(output_dir) / f"nmap_{domain.replace('.','_')}.xml")
    cmd = ["nmap"] + flags + ["-oX", out_xml, domain]
    raw = _run_live(cmd, f"Nmap → {domain}")
    graph.raw_nmap = raw

    result = {"target": domain, "open_ports": [], "services": [], "os_guess": None}
    for line in raw.splitlines():
        m = re.search(r"(\d+)/tcp\s+open\s+(\S+)\s*(.*)", line)
        if m:
            port, svc, detail = m.group(1), m.group(2), m.group(3).strip()
            result["open_ports"].append(port)
            result["services"].append({"port": port, "service": svc, "detail": detail})

            # Add tech to graph
            tech_str = f"{svc} {detail}".lower()
            ver_match = re.search(r"(\d+\.\d+[\.\d]*)", detail)
            version = ver_match.group(1) if ver_match else None
            graph.add_technology(Technology(name=svc, version=version, category="service"))

            # Update root subdomain
            sub = graph.get_subdomain(domain)
            if sub:
                sub.open_ports.append(int(port))
                sub.services.append({"port": port, "service": svc, "detail": detail})
        if "OS details:" in line or "Running:" in line:
            result["os_guess"] = line.strip()
    return result


# ─── Shodan ───────────────────────────────────────────────────────────────────

def _shodan(domain: str, key: str) -> dict:
    console.print(Rule("[bold green]Shodan[/bold green]"))
    if not key:
        console.print("[yellow]⚠ SHODAN_API_KEY not set. Skipping.[/yellow]")
        return {"skipped": True}
    try:
        import shodan as shodan_lib
        api = shodan_lib.Shodan(key)
        try:
            ip = socket.gethostbyname(domain)
        except Exception:
            ip = domain
        host = api.host(ip)
        result = {
            "ip": ip, "org": host.get("org"),
            "country": host.get("country_name"), "isp": host.get("isp"),
            "os": host.get("os"), "ports": host.get("ports", []),
            "vulns": list(host.get("vulns", [])), "services": [],
        }
        for item in host.get("data", []):
            svc = {"port": item.get("port"), "product": item.get("product"),
                   "version": item.get("version"), "banner": item.get("data", "")[:200]}
            result["services"].append(svc)
            console.print(f"  [white]Port {svc['port']} — {svc['product']} {svc['version']}[/white]")
        if result["vulns"]:
            console.print(f"  [bold red]CVEs: {', '.join(result['vulns'])}[/bold red]")
        return result
    except Exception as e:
        console.print(f"[red]✘ Shodan: {e}[/red]")
        return {"error": str(e)}


# ─── Tech Detection ───────────────────────────────────────────────────────────

TECH_SIGNATURES = {
    "WordPress":   [r"wp-content", r"wp-includes", r"/wp-json/"],
    "Drupal":      [r"Drupal", r"/sites/default/", r'data-drupal'],
    "Joomla":      [r"/components/com_", r"Joomla!"],
    "Laravel":     [r"laravel_session", r"XSRF-TOKEN"],
    "Django":      [r"csrfmiddlewaretoken", r"djdt"],
    "React":       [r"__NEXT_DATA__", r"react-root", r'data-reactroot'],
    "Angular":     [r"ng-version", r"ng-app"],
    "Vue.js":      [r"__vue__", r"data-v-"],
    "jQuery":      [r"jquery", r"jQuery"],
    "Bootstrap":   [r"bootstrap.min.css", r"bootstrap.min.js"],
    "PHP":         [r"\.php", r"PHPSESSID"],
    "ASP.NET":     [r"__VIEWSTATE", r"\.aspx", r"ASP\.NET"],
    "Express.js":  [r"X-Powered-By: Express"],
    "Nginx":       [r"Server: nginx"],
    "Apache":      [r"Server: Apache"],
    "IIS":         [r"Server: Microsoft-IIS"],
    "Cloudflare":  [r"CF-RAY", r"__cfduid"],
    "GraphQL":     [r"/graphql", r'"__typename"', r"graphql"],
    "Swagger":     [r"swagger-ui", r"/api-docs", r"openapi"],
}

def _detect_technologies(text: str, headers: dict) -> List[Technology]:
    combined = text + " " + " ".join(f"{k}: {v}" for k, v in headers.items())
    found = []
    for name, patterns in TECH_SIGNATURES.items():
        for pat in patterns:
            if re.search(pat, combined, re.I):
                # Try to extract version
                ver_match = re.search(rf"{re.escape(name)}[/\s]+([\d.]+)", combined, re.I)
                version = ver_match.group(1) if ver_match else None
                found.append(Technology(name=name, version=version, category="web"))
                break
    return found


# ─── Source Code Analysis ─────────────────────────────────────────────────────

SECRET_PATTERNS = [
    (r'(?i)(api[_\-]?key|apikey)\s*[:=]\s*[\'"]?([A-Za-z0-9\-_]{16,})', "API Key"),
    (r'(?i)(password|passwd|pwd)\s*[:=]\s*[\'"]?([^\s\'"]{4,})',         "Password"),
    (r'(?i)(secret[_\-]?key|secret)\s*[:=]\s*[\'"]?([A-Za-z0-9\-_]{8,})','Secret Key'),
    (r'(?i)(access[_\-]?token|auth[_\-]?token)\s*[:=]\s*[\'"]?([A-Za-z0-9\-_.]{16,})', "Token"),
    (r'AKIA[0-9A-Z]{16}',                                                 "AWS Key"),
    (r'(?i)(db[_\-]?password)\s*[:=]\s*[\'"]?([^\s\'"]{4,})',            "DB Password"),
    (r'<!--.*?-->',                                                        "HTML Comment"),
]

def _analyze_source(url: str, session: HexSession, graph: ScanGraph) -> Endpoint:
    ep = Endpoint(url=url, method="GET")
    try:
        resp = session.get(url)
        ep.status_code = resp.status_code
        ep.content_type = resp.headers.get("content-type", "")
        ep.headers = dict(resp.headers)
        ep.authenticated = session.is_authenticated

        html = resp.text
        ep.response_hash = hashlib.md5(html.encode()).hexdigest()

        # Detect technologies
        techs = _detect_technologies(html, dict(resp.headers))
        ep.technologies = techs
        for t in techs:
            graph.add_technology(t)
            if t.name == "GraphQL":
                graph.graphql_detected = True

        soup = BeautifulSoup(html, "html.parser")

        # Parse forms
        for form in soup.find_all("form"):
            action = form.get("action") or url
            if not action.startswith("http"):
                action = urljoin(url, action)
            method = form.get("method", "GET").upper()
            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name", "")
                val  = inp.get("value", "")
                if name:
                    inputs.append({"name": name, "value": val, "type": inp.get("type", "text")})
                    p = Parameter(name=name, value=val, param_type="body", endpoint=action)
                    ep.add_parameter(p)
            ep.forms.append({"action": action, "method": method, "inputs": inputs})
            if any(k in str(inputs).lower() for k in ["password", "passwd", "pass"]):
                ep.is_admin = False  # login, not admin
                console.print(f"  [cyan]Login form:[/cyan] {method} → {action}")

        # Parse URL parameters
        parsed = urlparse(url)
        for k, vals in parse_qs(parsed.query).items():
            p = Parameter(name=k, value=vals[0] if vals else "", param_type="query", endpoint=url)
            ep.add_parameter(p)

        # Links
        links = []
        for tag in soup.find_all("a", href=True):
            href = tag["href"]
            if href.startswith("http"):
                links.append(href)
            elif href.startswith("/"):
                base = f"{parsed.scheme}://{parsed.netloc}"
                links.append(base + href)

        # Secrets
        for pat, label in SECRET_PATTERNS:
            for m in re.finditer(pat, html, re.DOTALL):
                snippet = m.group(0)[:120]
                ep.notes.append(f"SECRET:{label}:{snippet}")
                console.print(f"  [bold red]🔑 {label}:[/bold red] {snippet[:80]}")

        # Admin detection
        if any(k in url.lower() for k in ["admin", "dashboard", "cpanel", "wp-admin"]):
            ep.is_admin = True

        # API detection
        if any(k in url.lower() for k in ["/api/", "/v1/", "/v2/", "/graphql", "/rest/"]):
            ep.is_api = True

        console.print(
            f"  [green]✔[/green] {url} — "
            f"[white]{ep.status_code}[/white]  "
            f"forms:{len(ep.forms)}  params:{len(ep.parameters)}  "
            f"techs:{','.join(t.name for t in ep.technologies) or 'none'}"
        )

    except Exception as e:
        console.print(f"  [red]✘ {url}: {e}[/red]")

    return ep


# ─── Subdomain Enumeration ────────────────────────────────────────────────────

async def _resolve_sub(sub: str, sem: asyncio.Semaphore) -> tuple[str, Optional[str]]:
    async with sem:
        try:
            loop = asyncio.get_event_loop()
            ip = await loop.run_in_executor(None, socket.gethostbyname, sub)
            return sub, ip
        except Exception:
            return sub, None

async def _enum_subs_async(domain: str, wordlist: str, concurrency: int) -> List[tuple]:
    """Brute-force subdomains asynchronously."""
    try:
        with open(wordlist) as f:
            words = [l.strip() for l in f if l.strip()][:3000]
    except FileNotFoundError:
        return []
    subs = [f"{w}.{domain}" for w in words]
    sem = asyncio.Semaphore(concurrency)
    tasks = [_resolve_sub(s, sem) for s in subs]
    results = await asyncio.gather(*tasks)
    return [(sub, ip) for sub, ip in results if ip]

def _subdomain_enum(domain: str, wordlist: str, output_dir: str, profile) -> List[Subdomain]:
    console.print(Rule("[bold green]Subdomain Enumeration[/bold green]"))
    found: dict[str, str] = {}

    # Sublist3r
    out_file = str(Path(output_dir) / f"subs_{domain.replace('.','_')}.txt")
    _run_live(["sublist3r", "-d", domain, "-o", out_file, "-t", "10"],
              f"Sublist3r → {domain}")
    if Path(out_file).exists():
        for line in Path(out_file).read_text().splitlines():
            sub = line.strip()
            if sub:
                try:
                    ip = socket.gethostbyname(sub)
                    found[sub] = ip
                    console.print(f"  [green]✔[/green] {sub} → {ip}")
                except Exception:
                    pass

    # Async brute-force
    console.print(f"\n[cyan]Async brute-force ({wordlist})...[/cyan]")
    loop = asyncio.new_event_loop()
    new_subs = loop.run_until_complete(
        _enum_subs_async(domain, wordlist, profile.concurrency)
    )
    loop.close()
    for sub, ip in new_subs:
        if sub not in found:
            found[sub] = ip
            console.print(f"  [green]✔[/green] {sub} → {ip}")

    result = []
    for fqdn, ip in found.items():
        s = Subdomain(fqdn=fqdn, ip=ip, alive=True)
        result.append(s)

    console.print(f"\n[green]✔ Found {len(result)} subdomain(s).[/green]")
    return result


# ─── Crawler ──────────────────────────────────────────────────────────────────

async def _crawl_async(
    start_url: str, session: HexSession, graph: ScanGraph,
    depth: int, max_urls: int
):
    """Async BFS crawler. Builds endpoint list for the graph."""
    visited = set()
    queue = [(start_url, 0)]
    parsed_base = urlparse(start_url)
    base_domain = parsed_base.netloc

    async_sess = AsyncHexSession(session)

    async with async_sess.build() as client:
        while queue and len(visited) < max_urls:
            url, lvl = queue.pop(0)
            if url in visited or lvl > depth:
                continue
            visited.add(url)

            try:
                resp = await client.get(url)
                ep = Endpoint(
                    url=url, method="GET",
                    status_code=resp.status_code,
                    content_type=resp.headers.get("content-type", ""),
                    headers=dict(resp.headers),
                    authenticated=session.is_authenticated,
                )
                ep.response_hash = hashlib.md5(resp.text.encode()).hexdigest()

                # Parse params from URL
                for k, vals in parse_qs(urlparse(url).query).items():
                    ep.add_parameter(Parameter(
                        name=k, value=vals[0] if vals else "",
                        param_type="query", endpoint=url
                    ))

                # Admin/API flags
                ep.is_admin = any(k in url.lower() for k in ["admin","dashboard","cpanel","wp-admin"])
                ep.is_api   = any(k in url.lower() for k in ["/api/","/v1/","/v2/","/graphql","/rest/"])

                if resp.status_code < 400:
                    graph.add_root_endpoint(ep)
                    if lvl < depth:
                        soup = BeautifulSoup(resp.text, "html.parser")
                        for tag in soup.find_all("a", href=True):
                            href = tag["href"]
                            if href.startswith("/"):
                                href = f"{parsed_base.scheme}://{base_domain}{href}"
                            if href.startswith("http") and base_domain in href:
                                if href not in visited:
                                    queue.append((href, lvl + 1))
            except Exception:
                pass

    console.print(f"  [green]✔ Crawled {len(visited)} URL(s).[/green]")


# ─── API / Swagger / GraphQL ──────────────────────────────────────────────────

SWAGGER_PATHS = [
    "/swagger-ui.html", "/api-docs", "/swagger.json", "/openapi.json",
    "/v2/api-docs", "/v3/api-docs", "/api/swagger", "/docs",
    "/api/docs", "/.well-known/openapi.yaml",
]
GRAPHQL_PATHS = ["/graphql", "/gql", "/graphql/v1", "/api/graphql"]

def _check_api_spec(base_url: str, session: HexSession, graph: ScanGraph):
    console.print(Rule("[bold green]API / Swagger / GraphQL Detection[/bold green]"))

    for path in SWAGGER_PATHS:
        url = base_url.rstrip("/") + path
        try:
            resp = session.get(url)
            if resp.status_code == 200 and len(resp.text) > 100:
                console.print(f"  [bold green]✔ Swagger/OpenAPI found:[/bold green] {url}")
                try:
                    import json
                    spec = resp.json()
                    graph.api_spec = spec
                    # Extract paths from spec
                    paths = spec.get("paths", {})
                    for api_path, methods in paths.items():
                        for method in methods.keys():
                            ep_url = base_url.rstrip("/") + api_path
                            ep = Endpoint(url=ep_url, method=method.upper(), is_api=True)
                            # Extract parameters
                            params = methods[method].get("parameters", [])
                            for param in params:
                                p = Parameter(
                                    name=param.get("name", ""),
                                    param_type=param.get("in", "query"),
                                    endpoint=ep_url
                                )
                                ep.add_parameter(p)
                            graph.add_root_endpoint(ep)
                    console.print(f"  [cyan]  Extracted {len(paths)} API path(s) from spec.[/cyan]")
                except Exception:
                    graph.api_spec = {"raw_url": url, "content": resp.text[:500]}
                break
        except Exception:
            pass

    for path in GRAPHQL_PATHS:
        url = base_url.rstrip("/") + path
        try:
            # Introspection query
            resp = session.post(url, json={"query": "{__schema{types{name}}}"})
            if resp.status_code == 200 and "__schema" in resp.text:
                console.print(f"  [bold green]✔ GraphQL endpoint found:[/bold green] {url}")
                graph.graphql_detected = True
                ep = Endpoint(url=url, method="POST", is_api=True)
                graph.add_root_endpoint(ep)
                break
        except Exception:
            pass

    if not graph.api_spec and not graph.graphql_detected:
        console.print("  [dim]No Swagger/OpenAPI/GraphQL spec detected.[/dim]")


# ─── Real-Time Intelligence ───────────────────────────────────────────────────

INTELLIGENCE_RULES = [
    (r"apache[/ ]2\.[0-2]",    "Outdated Apache — check CVE-2017-7679, CVE-2017-9798"),
    (r"php/[45]\.",             "Outdated PHP — multiple known RCE CVEs"),
    (r"openssl/1\.0",           "Outdated OpenSSL — POODLE/Heartbleed potential"),
    (r"nginx/1\.[0-9]\.",       "Check nginx version for known vulns"),
    (r"microsoft-iis/[67]\.",   "Old IIS — check CVE-2017-7269"),
    (r"wp-login\.php",          "WordPress login — XML-RPC brute force applicable"),
    (r"drupal",                 "Drupal detected — check Drupalgeddon2"),
    (r"joomla",                 "Joomla detected — check CVE-2015-8562"),
    (r"struts",                 "Apache Struts — check CVE-2017-5638 (Equifax)"),
]

def _print_intelligence(graph: ScanGraph):
    console.print(Rule("[bold yellow]⚡ Real-Time Scan Intelligence[/bold yellow]"))
    flagged = []
    full_text = graph.raw_nmap.lower()
    for sub in graph.subdomains:
        for svc in sub.services:
            full_text += f" {svc.get('service','')} {svc.get('detail','')}".lower()
    for tech in graph.technologies:
        full_text += f" {tech.name}/{tech.version or ''}".lower()

    for pattern, message in INTELLIGENCE_RULES:
        if re.search(pattern, full_text, re.I):
            console.print(f"  [bold yellow][!][/bold yellow] {message}")
            flagged.append(message)

    if not flagged:
        console.print("  [dim]No obvious outdated tech detected.[/dim]")
    return flagged


# ─── Main Recon Runner ────────────────────────────────────────────────────────

def run_recon(graph: ScanGraph, session: HexSession, config: dict, profile) -> ScanGraph:
    import config as cfg

    target = config["targets"][0]  # Primary target
    domain = _domain(target)
    base_url = _base_url(target)
    output_dir = config["output_dir"]

    console.print()
    console.print(Panel(
        f"[bold white]Target:[/bold white] [bold cyan]{target}[/bold cyan]\n"
        f"[bold white]Profile:[/bold white] [bold yellow]{profile.name}[/bold yellow]  "
        f"[bold white]Intensity:[/bold white] {profile.intensity}",
        title="[bold yellow]RECONNAISSANCE[/bold yellow]",
        border_style="yellow"
    ))

    # 1. Create root subdomain node
    root_sub = Subdomain(fqdn=domain, alive=True)
    try:
        root_sub.ip = socket.gethostbyname(domain)
    except Exception:
        pass
    graph.add_subdomain(root_sub)

    # 2. WHOIS
    graph.whois = _whois(domain)

    # 3. Google Dorking
    graph.dork_results = _google_dork(domain, cfg.GOOGLE_API_KEY, cfg.GOOGLE_CX)

    # 4. Nmap
    nmap_result = _nmap(target, profile.nmap_flags, output_dir, graph)

    # 5. Shodan
    graph.shodan = _shodan(domain, cfg.SHODAN_API_KEY)

    # 6. Subdomain enumeration
    subs = _subdomain_enum(domain, config["wordlist"], output_dir, profile)
    for sub in subs:
        graph.add_subdomain(sub)

    # 7. Source analysis on root
    console.print(Rule("[bold green]Source Code Analysis[/bold green]"))
    root_ep = _analyze_source(base_url, session, graph)
    graph.add_root_endpoint(root_ep)

    # 8. Async crawl
    console.print(Rule("[bold green]Crawling[/bold green]"))
    loop = asyncio.new_event_loop()
    loop.run_until_complete(
        _crawl_async(base_url, session, graph, profile.crawl_depth, profile.max_urls)
    )
    loop.close()

    # 9. API / Swagger / GraphQL detection
    _check_api_spec(base_url, session, graph)

    # 10. Scan each alive subdomain's root
    if subs:
        console.print(Rule("[bold green]Subdomain Surface Analysis[/bold green]"))
        for sub in subs[:10]:  # Cap to 10 to avoid excessive scanning
            sub_url = f"http://{sub.fqdn}"
            ep = _analyze_source(sub_url, session, graph)
            sub.add_endpoint(ep)

    # 11. Real-time intelligence
    intelligence = _print_intelligence(graph)
    graph.metadata["intelligence"] = intelligence

    # 12. Surface summary
    summary = graph.summary()
    console.print()
    console.print(Panel(
        f"[bold]Subdomains:[/bold]  {summary['subdomains_found']}\n"
        f"[bold]Endpoints:[/bold]   {summary['endpoints_found']}\n"
        f"[bold]Parameters:[/bold]  {summary['parameters_found']}\n"
        f"[bold]API endpoints:[/bold] {summary['api_endpoints']}\n"
        f"[bold]Technologies:[/bold] {', '.join(summary['technologies']) or 'none'}",
        title="[bold green]RECON COMPLETE[/bold green]",
        border_style="green"
    ))

    if summary["endpoints_found"] == 0 and not nmap_result["open_ports"]:
        console.print(Panel(
            "[bold yellow]⚠ No significant attack surface found on this target.[/bold yellow]\n"
            "No open ports, no reachable endpoints, no parameters discovered.",
            title="[yellow]LOW ATTACK SURFACE[/yellow]",
            border_style="yellow"
        ))

    return graph
