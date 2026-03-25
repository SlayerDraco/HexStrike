"""
HexStrike - Reconnaissance Module
Step 1: Passive & Active Reconnaissance
- WHOIS Lookup
- Google Dorking (Google Custom Search API)
- Nmap Fingerprinting
- Shodan Scanning
- Source Code Analysis
- Subdomain Enumeration
"""

import os
import sys
import json
import subprocess
import socket
import re
import time
import threading
from pathlib import Path
from urllib.parse import urlparse
from datetime import datetime

import requests
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.rule import Rule
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich import box

console = Console()

# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def extract_domain(target):
    """Extract clean domain/IP from URL or raw input."""
    if not target.startswith("http"):
        target = "http://" + target
    parsed = urlparse(target)
    return parsed.hostname or target

def extract_base_url(target):
    if not target.startswith("http"):
        return "http://" + target
    return target

def run_live(cmd, label="Running"):
    """Run a subprocess and stream output live to the terminal."""
    console.print(f"\n[bold cyan]▶ {label}[/bold cyan]")
    console.print(f"[dim]$ {' '.join(cmd)}[/dim]\n")
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1
        )
        output_lines = []
        for line in proc.stdout:
            line = line.rstrip()
            if line:
                console.print(f"  [white]{line}[/white]")
                output_lines.append(line)
        proc.wait()
        return "\n".join(output_lines)
    except FileNotFoundError:
        console.print(f"[red]✘ Command not found: {cmd[0]}[/red]")
        return ""
    except Exception as e:
        console.print(f"[red]✘ Error: {e}[/red]")
        return ""

# ─────────────────────────────────────────────
# WHOIS
# ─────────────────────────────────────────────

def run_whois(domain):
    console.print(Rule("[bold green]WHOIS Lookup[/bold green]"))
    output = run_live(["whois", domain], label=f"WHOIS {domain}")
    result = {"raw": output, "domain": domain}

    # Extract key fields
    for line in output.splitlines():
        ll = line.lower()
        if "registrar:" in ll:
            result["registrar"] = line.split(":", 1)[-1].strip()
        elif "creation date:" in ll or "created:" in ll:
            result["created"] = line.split(":", 1)[-1].strip()
        elif "expiry date:" in ll or "expiration date:" in ll:
            result["expires"] = line.split(":", 1)[-1].strip()
        elif "name server:" in ll or "nserver:" in ll:
            result.setdefault("nameservers", []).append(line.split(":", 1)[-1].strip())
        elif "registrant" in ll and "email" in ll:
            result["registrant_email"] = line.split(":", 1)[-1].strip()
        elif "org:" in ll or "organisation:" in ll:
            result["org"] = line.split(":", 1)[-1].strip()

    console.print(f"\n[green]✔ WHOIS complete.[/green]")
    return result

# ─────────────────────────────────────────────
# Google Dorking
# ─────────────────────────────────────────────

DORK_QUERIES = [
    "site:{domain}",
    "site:{domain} filetype:pdf",
    "site:{domain} filetype:xml OR filetype:json OR filetype:sql",
    "site:{domain} inurl:admin OR inurl:login OR inurl:dashboard",
    "site:{domain} intitle:\"index of\"",
    "site:{domain} intext:\"sql syntax\" OR intext:\"mysql error\"",
    "site:{domain} inurl:config OR inurl:backup OR inurl:db",
    "site:{domain} ext:env OR ext:log OR ext:bak",
    "\"{domain}\" password OR credentials OR apikey",
    "site:{domain} inurl:upload OR inurl:shell",
]

def run_google_dorking(domain, google_api_key, google_cx):
    console.print(Rule("[bold green]Google Dorking[/bold green]"))

    if not google_api_key or not google_cx:
        console.print("[yellow]⚠ Google API keys not configured. Skipping dorking.[/yellow]")
        dork_list = [q.replace("{domain}", domain) for q in DORK_QUERIES]
        console.print("[dim]Generated dork queries (run manually):[/dim]")
        for d in dork_list:
            console.print(f"  [cyan]{d}[/cyan]")
        return {"skipped": True, "manual_dorks": dork_list}

    results = {}
    for query_template in DORK_QUERIES:
        query = query_template.replace("{domain}", domain)
        console.print(f"\n[cyan]Dorking:[/cyan] {query}")
        try:
            resp = requests.get(
                "https://www.googleapis.com/customsearch/v1",
                params={"key": google_api_key, "cx": google_cx, "q": query, "num": 5},
                timeout=10
            )
            data = resp.json()
            hits = []
            for item in data.get("items", []):
                hits.append({"title": item.get("title"), "link": item.get("link"), "snippet": item.get("snippet")})
                console.print(f"  [white]→ {item.get('link')}[/white]")
            results[query] = hits
            time.sleep(1)  # Avoid rate limiting
        except Exception as e:
            console.print(f"  [red]Error: {e}[/red]")
            results[query] = []

    console.print(f"\n[green]✔ Google Dorking complete.[/green]")
    return results

# ─────────────────────────────────────────────
# Nmap Fingerprinting
# ─────────────────────────────────────────────

def get_nmap_flags(intensity):
    flags = {
        "stealth": ["-sS", "-T2", "-O", "--version-light", "-sV", "--script=banner,http-headers"],
        "normal":  ["-sS", "-T3", "-O", "-sV", "--script=banner,http-headers,http-title"],
        "aggressive": ["-sS", "-T4", "-A", "-sV", "--script=banner,http-headers,http-title,vulners"],
    }
    return flags.get(intensity, flags["normal"])

def run_nmap(target, intensity, output_dir):
    console.print(Rule("[bold green]Nmap Fingerprinting[/bold green]"))
    domain = extract_domain(target)
    out_file = str(Path(output_dir) / f"nmap_{domain.replace('.', '_')}.xml")
    flags = get_nmap_flags(intensity)
    cmd = ["nmap"] + flags + ["-oX", out_file, domain]
    output = run_live(cmd, label=f"Nmap scan: {domain} [{intensity}]")

    # Parse key findings from output
    findings = {
        "target": domain,
        "intensity": intensity,
        "xml_output": out_file,
        "open_ports": [],
        "os_guess": None,
        "services": [],
        "raw": output
    }

    for line in output.splitlines():
        # Open ports
        port_match = re.search(r"(\d+)/tcp\s+open\s+(\S+)\s*(.*)", line)
        if port_match:
            findings["open_ports"].append(port_match.group(1))
            findings["services"].append({
                "port": port_match.group(1),
                "service": port_match.group(2),
                "detail": port_match.group(3).strip()
            })
        # OS detection
        if "OS details:" in line or "Running:" in line:
            findings["os_guess"] = line.strip()

    console.print(f"\n[green]✔ Nmap complete. Open ports: {', '.join(findings['open_ports']) or 'None found'}[/green]")
    return findings

# ─────────────────────────────────────────────
# Shodan
# ─────────────────────────────────────────────

def run_shodan(domain, shodan_key):
    console.print(Rule("[bold green]Shodan Scanning[/bold green]"))

    if not shodan_key:
        console.print("[yellow]⚠ SHODAN_API_KEY not configured. Skipping Shodan scan.[/yellow]")
        return {"skipped": True}

    try:
        import shodan as shodan_lib
        api = shodan_lib.Shodan(shodan_key)

        # Resolve to IP
        try:
            ip = socket.gethostbyname(domain)
        except Exception:
            ip = domain

        console.print(f"[cyan]Querying Shodan for IP: {ip}[/cyan]")
        host = api.host(ip)

        result = {
            "ip": ip,
            "org": host.get("org"),
            "country": host.get("country_name"),
            "city": host.get("city"),
            "isp": host.get("isp"),
            "os": host.get("os"),
            "ports": host.get("ports", []),
            "vulns": list(host.get("vulns", [])),
            "services": []
        }

        for item in host.get("data", []):
            svc = {
                "port": item.get("port"),
                "transport": item.get("transport"),
                "product": item.get("product"),
                "version": item.get("version"),
                "banner": item.get("data", "")[:200],
            }
            result["services"].append(svc)
            console.print(f"  [white]Port {svc['port']}/{svc['transport']} — {svc['product']} {svc['version']}[/white]")

        if result["vulns"]:
            console.print(f"\n  [bold red]⚠ Known CVEs: {', '.join(result['vulns'])}[/bold red]")

        console.print(f"\n[green]✔ Shodan scan complete.[/green]")
        return result

    except Exception as e:
        console.print(f"[red]✘ Shodan error: {e}[/red]")
        return {"error": str(e)}

# ─────────────────────────────────────────────
# Source Code Analysis
# ─────────────────────────────────────────────

SECRET_PATTERNS = [
    (r"(?i)(api[_\-]?key|apikey)\s*[:=]\s*['\"]?([A-Za-z0-9\-_]{16,})", "API Key"),
    (r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?([^\s'\"]{4,})", "Hardcoded Password"),
    (r"(?i)(secret[_\-]?key|secret)\s*[:=]\s*['\"]?([A-Za-z0-9\-_]{8,})", "Secret Key"),
    (r"(?i)(access[_\-]?token|auth[_\-]?token)\s*[:=]\s*['\"]?([A-Za-z0-9\-_.]{16,})", "Auth Token"),
    (r"(?i)(aws[_\-]?access[_\-]?key|AKIA[0-9A-Z]{16})", "AWS Key"),
    (r"(?i)(db[_\-]?password|database[_\-]?pass)\s*[:=]\s*['\"]?([^\s'\"]{4,})", "DB Password"),
    (r"<!--.*?-->", "HTML Comment"),
    (r"(?i)todo[:\s]+(.*)", "TODO Comment"),
    (r"(?i)fixme[:\s]+(.*)", "FIXME Comment"),
    (r"(?i)(error|exception|stacktrace|traceback)[:\s]+(.*)", "Error Message"),
]

def run_source_analysis(target):
    console.print(Rule("[bold green]Source Code Analysis[/bold green]"))
    base_url = extract_base_url(target)
    findings = {"url": base_url, "secrets": [], "comments": [], "forms": [], "links": [], "has_login": False}

    console.print(f"[cyan]Fetching: {base_url}[/cyan]")

    try:
        from bs4 import BeautifulSoup
        headers = {"User-Agent": "Mozilla/5.0 (HexStrike Scanner)"}
        resp = requests.get(base_url, headers=headers, timeout=15, verify=False)
        html = resp.text

        # Regex scan for secrets
        for pattern, label in SECRET_PATTERNS:
            for match in re.finditer(pattern, html):
                snippet = match.group(0)[:120]
                if label not in ["HTML Comment", "TODO Comment", "FIXME Comment", "Error Message"]:
                    console.print(f"  [bold red]🔑 {label}:[/bold red] [white]{snippet}[/white]")
                    findings["secrets"].append({"type": label, "snippet": snippet})
                else:
                    findings["comments"].append({"type": label, "snippet": snippet})

        # Parse HTML
        soup = BeautifulSoup(html, "html.parser")

        # Forms
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "GET").upper()
            inputs = [i.get("name", "") for i in form.find_all("input")]
            findings["forms"].append({"action": action, "method": method, "inputs": inputs})
            console.print(f"  [cyan]Form:[/cyan] {method} → {action} | inputs: {inputs}")
            if any(k in str(inputs).lower() for k in ["password", "passwd", "pass", "pwd"]):
                findings["has_login"] = True

        # Links
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if href and not href.startswith("#"):
                findings["links"].append(href)

        # Check for login indicators
        login_keywords = ["login", "signin", "sign-in", "auth", "password", "username", "email"]
        if any(kw in html.lower() for kw in login_keywords):
            findings["has_login"] = True

        console.print(f"\n  Found {len(findings['forms'])} form(s), {len(findings['secrets'])} secret(s), login page: {'Yes' if findings['has_login'] else 'No'}")
        console.print(f"[green]✔ Source analysis complete.[/green]")

    except requests.exceptions.SSLError:
        console.print("[yellow]⚠ SSL verification failed. Retrying without verification...[/yellow]")
        try:
            import urllib3
            urllib3.disable_warnings()
            resp = requests.get(base_url, headers={"User-Agent": "Mozilla/5.0"}, timeout=15, verify=False)
            findings["raw_length"] = len(resp.text)
        except Exception as e:
            console.print(f"[red]✘ Failed: {e}[/red]")
    except Exception as e:
        console.print(f"[red]✘ Error during source analysis: {e}[/red]")

    return findings

# ─────────────────────────────────────────────
# Subdomain Enumeration
# ─────────────────────────────────────────────

def run_subdomain_enum(domain, wordlist_path, output_dir, intensity):
    console.print(Rule("[bold green]Subdomain Enumeration[/bold green]"))
    found_subs = []

    # Method 1: Sublist3r
    console.print("[cyan]Running Sublist3r...[/cyan]")
    sub_out = str(Path(output_dir) / f"subdomains_{domain.replace('.', '_')}.txt")
    output = run_live(
        ["sublist3r", "-d", domain, "-o", sub_out, "-t", "10"],
        label=f"Sublist3r: {domain}"
    )

    if Path(sub_out).exists():
        with open(sub_out) as f:
            found_subs = [line.strip() for line in f if line.strip()]

    # Method 2: Brute-force from wordlist
    console.print(f"\n[cyan]Brute-forcing subdomains from wordlist ({wordlist_path})...[/cyan]")
    try:
        with open(wordlist_path, "r") as f:
            words = [line.strip() for line in f if line.strip()][:2000]  # Limit for speed

        console.print(f"[dim]Testing {len(words)} subdomain prefixes...[/dim]")
        for word in words:
            sub = f"{word}.{domain}"
            try:
                socket.setdefaulttimeout(1)
                ip = socket.gethostbyname(sub)
                if sub not in found_subs:
                    found_subs.append(sub)
                    console.print(f"  [green]✔ Found:[/green] [white]{sub}[/white] → {ip}")
            except (socket.gaierror, socket.timeout):
                pass
    except FileNotFoundError:
        console.print(f"[yellow]⚠ Wordlist not found: {wordlist_path}[/yellow]")

    # Deduplicate
    found_subs = list(set(found_subs))
    console.print(f"\n[green]✔ Subdomain enum complete. Found {len(found_subs)} subdomain(s).[/green]")
    return found_subs

# ─────────────────────────────────────────────
# Pentest Surface Check
# ─────────────────────────────────────────────

def check_pentest_surface(source_results, nmap_results, subdomains):
    """Determine if there's anything meaningful to pentest."""
    has_forms = len(source_results.get("forms", [])) > 0
    has_login = source_results.get("has_login", False)
    has_open_ports = len(nmap_results.get("open_ports", [])) > 0
    has_subdomains = len(subdomains) > 0
    has_secrets = len(source_results.get("secrets", [])) > 0

    surface = {
        "has_forms": has_forms,
        "has_login": has_login,
        "has_open_ports": has_open_ports,
        "has_subdomains": has_subdomains,
        "has_secrets": has_secrets,
        "has_anything": any([has_forms, has_login, has_open_ports, has_secrets]),
    }
    return surface

# ─────────────────────────────────────────────
# Main Recon Runner
# ─────────────────────────────────────────────

def run_recon(config):
    import config as cfg

    targets = config["targets"]
    intensity = config["intensity"]
    output_dir = config["output_dir"]
    wordlist = config["wordlist"]

    all_results = {}

    for target in targets:
        console.print()
        console.print(Panel(
            f"[bold white]Target:[/bold white] [bold cyan]{target}[/bold cyan]",
            title="[bold yellow]RECONNAISSANCE[/bold yellow]",
            border_style="yellow"
        ))

        domain = extract_domain(target)
        result = {"target": target, "domain": domain}

        # WHOIS
        result["whois"] = run_whois(domain)

        # Google Dorking
        result["dorking"] = run_google_dorking(domain, cfg.GOOGLE_API_KEY, cfg.GOOGLE_CX)

        # Nmap
        result["nmap"] = run_nmap(target, intensity, output_dir)

        # Shodan
        result["shodan"] = run_shodan(domain, cfg.SHODAN_API_KEY)

        # Source Code Analysis
        result["source"] = run_source_analysis(target)

        # Subdomain Enumeration
        result["subdomains"] = run_subdomain_enum(domain, wordlist, output_dir, intensity)

        # Surface check
        surface = check_pentest_surface(result["source"], result["nmap"], result["subdomains"])
        result["surface"] = surface

        if not surface["has_anything"]:
            console.print(Panel(
                "[bold yellow]⚠ Nothing significant found to pentest on this target.[/bold yellow]\n"
                "[white]No open ports, no forms, no login pages, and no exposed secrets were detected.\n"
                "This target may not have exploitable attack surface.[/white]",
                title="[yellow]LOW ATTACK SURFACE[/yellow]",
                border_style="yellow"
            ))
        else:
            console.print(Panel(
                f"[green]✔ Attack surface identified![/green]\n"
                f"  Login page: {'Yes' if surface['has_login'] else 'No'}\n"
                f"  Forms: {'Yes' if surface['has_forms'] else 'No'}\n"
                f"  Open ports: {'Yes' if surface['has_open_ports'] else 'No'}\n"
                f"  Hardcoded secrets: {'Yes' if surface['has_secrets'] else 'No'}\n"
                f"  Subdomains: {'Yes' if surface['has_subdomains'] else 'No'}",
                title="[green]ATTACK SURFACE SUMMARY[/green]",
                border_style="green"
            ))

        all_results[target] = result

    return all_results
