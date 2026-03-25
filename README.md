```
 ██╗  ██╗███████╗██╗  ██╗███████╗████████╗██████╗ ██╗██╗  ██╗███████╗
 ██║  ██║██╔════╝╚██╗██╔╝██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝
 ███████║█████╗   ╚███╔╝ ███████╗   ██║   ██████╔╝██║█████╔╝ █████╗
 ██╔══██║██╔══╝   ██╔██╗ ╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝
 ██║  ██║███████╗██╔╝ ██╗███████║   ██║   ██║  ██║██║██║  ██╗███████╗
 ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝
```

<div align="center">

**Web Penetration Testing Automation Framework**

`v2.0.0` &nbsp;|&nbsp; `Python 3.9+` &nbsp;|&nbsp; `Parrot OS` &nbsp;|&nbsp; `Plugin-Ready` &nbsp;|&nbsp; `Async-First`

[![License: MIT](https://img.shields.io/badge/License-MIT-red.svg)]()
[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)]()
[![Platform](https://img.shields.io/badge/Platform-Parrot%20OS%20%2F%20Kali-darkred.svg)]()
[![Status](https://img.shields.io/badge/Status-Active-brightgreen.svg)]()

> ⚠️ **For authorized penetration testing only. Unauthorized use is illegal.**

</div>

---

## Table of Contents

- [What is HexStrike?](#what-is-hexstrike)
- [What's New in v2.0.0](#whats-new-in-v200)
- [Architecture Overview](#architecture-overview)
- [Project Structure](#project-structure)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Scan Profiles](#scan-profiles)
- [Usage](#usage)
  - [Interactive Menu](#interactive-menu)
  - [Command-Line Mode](#command-line-mode)
  - [Authentication](#authentication)
  - [Request Console](#request-console)
- [Modules](#modules)
  - [Step 1 — Reconnaissance](#step-1--reconnaissance)
  - [Step 2 — Exploitation](#step-2--exploitation)
  - [Step 3 — Reporting](#step-3--reporting)
- [Plugin System](#plugin-system)
- [Auto Decision Engine](#auto-decision-engine)
- [CVSS Scoring Reference](#cvss-scoring-reference)
- [Output Files](#output-files)
- [Legal Disclaimer](#legal-disclaimer)

---

## What is HexStrike?

HexStrike is a **Python-based web penetration testing automation framework** designed for professional security researchers on Parrot OS. It automates the full pentest lifecycle — from passive reconnaissance to exploitation and reporting — while keeping the tester in control at every step.

Unlike ad-hoc script collections, HexStrike correlates all scan data into a **central graph object** (`ScanGraph`) so every module builds on what the previous one discovered. Subdomains feed into endpoint crawling, endpoints feed into parameter discovery, parameters feed into injection testing and IDOR detection — all automatically.

Key design principles:

- **Correlated, not dumped.** All recon data flows through a single structured graph. Modules cross-reference each other's findings.
- **Auth-aware throughout.** One `HexSession` object carries cookies, headers, and login state into every HTTP request across all modules.
- **Async where it matters.** Crawling, IDOR detection, XSS testing, and parameter fuzzing all use `asyncio` + `httpx` for genuine concurrency.
- **Plugin-ready.** Drop a Python file into `/plugins/` and it loads automatically. Plugins can auto-trigger based on what recon finds.
- **Profile-driven.** Switch between `recon`, `stealth`, `normal`, `full`, and `api` profiles to control speed, noise, and which modules run.

---

## What's New in v2.0.0

Version 2 is a ground-up rewrite. The original single-file modules have been replaced with a proper layered architecture.

| Feature | v1.x | v2.0.0 |
|---|---|---|
| Data model | Dict dumps per module | Correlated `ScanGraph` with typed dataclasses |
| HTTP client | `requests` (sync) | `httpx` (async + sync), session-aware |
| Authentication | None | Cookies, headers, login automation |
| IDOR testing | ✗ | Async numeric-ID mutation + response diff |
| Parameter discovery | ✗ | Async canary-value fuzzing across all endpoints |
| API testing | Basic | REST discovery, Swagger/OpenAPI fuzzing, GraphQL introspection |
| Business logic | ✗ | Race conditions, replay, negative values, token reuse |
| Request console | ✗ | Interactive CLI repeater (Burp-lite) |
| Plugin system | ✗ | `HexPlugin` base class + auto-discovery |
| Auto Decision Engine | ✗ | Graph-driven module triggering |
| Scan profiles | Intensity only | 5 profiles controlling all scan parameters |
| CLI mode | Menu only | Full `argparse` subcommands + flags |
| Session resume | Basic | Full graph + state persistence |
| Vulnerability priority | CVSS only | CVSS + sensitivity bonus scoring |

---

## Architecture Overview

```
hexstrike.py  (entry point)
      │
      ├── collect_config()          Runtime config: targets, profile, auth, paths
      │
      ├── core/session.py           HexSession — auth-aware, used by ALL modules
      │
      ├── core/models.py            ScanGraph — central correlated data store
      │         │
      │         ├── Subdomain → Endpoint → Parameter
      │         └── Finding (CVSS score, priority, evidence)
      │
      ├── modules/recon.py          Writes: subdomains, endpoints, params, technologies
      │
      ├── core/decisions.py         Reads graph → returns ordered module trigger list
      │
      ├── modules/exploit.py        Reads graph surface → writes Finding objects
      │       ├── idor.py
      │       ├── param_fuzzer.py
      │       ├── api_testing.py
      │       └── biz_logic.py
      │
      ├── core/plugins.py           Auto-loads /plugins/*.py → runs by phase
      │
      └── modules/report.py         Reads graph.findings → JSON + TXT output
```

Data flows in one direction: **recon builds the graph → decisions read the graph → exploitation writes findings into the graph → report reads findings from the graph.**

---

## Project Structure

```
hexstrike_v2/
│
├── hexstrike.py              # Entry point — CLI args, menu, scan pipeline (739 lines)
├── config.py                 # .env loader for API keys
├── .env                      # API key template (fill before running)
├── requirements.txt          # Python dependencies
│
├── core/                     # Engine — no I/O, pure logic
│   ├── __init__.py
│   ├── models.py             # ScanGraph, Subdomain, Endpoint, Parameter, Finding (255 lines)
│   ├── session.py            # HexSession + AsyncHexSession (185 lines)
│   ├── profiles.py           # 5 built-in scan profiles (159 lines)
│   ├── plugins.py            # HexPlugin base class + PluginRegistry (125 lines)
│   └── decisions.py          # Auto Decision Engine (209 lines)
│
├── modules/                  # Scan modules — each reads/writes ScanGraph
│   ├── __init__.py
│   ├── toolcheck.py          # Verify + auto-install 18 required tools (108 lines)
│   ├── recon.py              # WHOIS, Dorking, Nmap, Shodan, crawl, API detection (643 lines)
│   ├── exploit.py            # SQLi, XSS, Hydra, misconfig, Metasploit (614 lines)
│   ├── idor.py               # Async IDOR engine — numeric ID mutation + response diff (233 lines)
│   ├── param_fuzzer.py       # Async hidden parameter discovery (181 lines)
│   ├── api_testing.py        # REST, Swagger/OpenAPI, GraphQL testing (325 lines)
│   ├── biz_logic.py          # Race conditions, replay, negative values (274 lines)
│   ├── req_console.py        # Interactive CLI request console (314 lines)
│   └── report.py             # CVSS scoring, priority sort, JSON + TXT output (233 lines)
│
├── plugins/                  # Drop .py files here — auto-loaded at startup
│   └── wordpress_scanner.py  # Example: WP xmlrpc, user enum (auto-triggered)
│
├── profiles/                 # Custom scan profile JSONs
│   └── custom.json           # User-editable profile template
│
└── wordlists/
    └── subdomains.txt        # 160-entry bundled subdomain list
```

**Total: 19 Python files · 4,747 lines · all syntax-verified**

---

## Requirements

| Requirement | Version |
|---|---|
| Operating System | Parrot OS (recommended), Kali Linux |
| Python | 3.9 or higher |
| Privileges | Must run as **root** (`sudo`) |
| RAM | 512 MB minimum, 2 GB recommended for full scans |
| Network | Active internet connection |

### Required system tools (auto-installed by Tool Check)

`nmap` `sqlmap` `hydra` `john` `wfuzz` `metasploit-framework` `whois` `curl` `sublist3r`

### Python dependencies

```
rich >= 13.0.0
httpx >= 0.27.0
requests >= 2.31.0
python-dotenv >= 1.0.0
beautifulsoup4 >= 4.12.0
shodan >= 1.30.0
dnspython >= 2.4.0
python-whois >= 0.8.0
sublist3r >= 1.0
urllib3 >= 2.0.0
```

---

## Installation

```bash
# 1. Clone or download the project
git clone https://github.com/yourrepo/hexstrike.git
cd hexstrike_v2

# 2. Install Python dependencies
pip3 install -r requirements.txt --break-system-packages

# 3. Configure API keys (see Configuration below)
nano .env

# 4. Run — must be root
sudo python3 hexstrike.py
```

The first time you run HexStrike, select **option 1 (Tool Check)** from the menu. It will verify all required system tools and auto-install any that are missing via `apt-get` and `pip3`.

---

## Configuration

Edit `.env` in the project root before running:

```env
# HexStrike v2 — API Keys

# Shodan (https://account.shodan.io/)
SHODAN_API_KEY=your_shodan_key_here

# Google Custom Search API (https://console.cloud.google.com/)
# Enable "Custom Search API" in your Google Cloud project
GOOGLE_API_KEY=your_google_api_key_here

# Google Custom Search Engine ID (https://programmablesearchengine.google.com/)
GOOGLE_CX=your_google_cx_id_here
```

**HexStrike runs without API keys** — Shodan and Google Dorking modules will be skipped gracefully, and manual dork queries will be printed instead.

---

## Scan Profiles

Profiles control concurrency, intensity, which modules run, Nmap flags, crawl depth, and feature toggles. Pass `--profile <name>` on the CLI or select at the interactive prompt.

| Profile | Description | Intensity | MSF | IDOR | Brute Force | Concurrency |
|---|---|---|:---:|:---:|:---:|:---:|
| `recon` | Passive + active recon only, no exploitation | Stealth | ✗ | ✗ | ✗ | 5 |
| `stealth` | Full scan, slow and low-noise, evades basic IDS | Stealth | ✗ | ✓ | ✗ | 3 |
| `normal` | Balanced speed and coverage. **Default.** | Normal | ✗ | ✓ | ✓ | 10 |
| `full` | All modules, aggressive, maximum coverage | Aggressive | ✓ | ✓ | ✓ | 20 |
| `api` | API-focused — REST, Swagger, GraphQL | Normal | ✗ | ✓ | ✗ | 15 |
| `custom` | User-defined via `profiles/custom.json` | Any | — | — | — | — |

### Creating a custom profile

Copy `profiles/custom.json` and edit as needed:

```json
{
  "name": "myprofile",
  "description": "My custom scan profile",
  "intensity": "normal",
  "concurrency": 8,
  "timeout": 15,
  "delay": 0.3,
  "modules": ["toolcheck", "recon", "exploit"],
  "nmap_flags": ["-sS", "-T3", "-sV", "--script=banner,http-headers"],
  "crawl_depth": 2,
  "max_urls": 80,
  "fuzz_params": true,
  "run_msf": false,
  "run_bruteforce": true,
  "run_idor": true,
  "run_api": true,
  "run_biz_logic": false
}
```

Then use it with `--profile myprofile`. HexStrike looks for the file at `profiles/myprofile.json`.

---

## Usage

### Interactive Menu

Run without arguments for the full interactive experience:

```bash
sudo python3 hexstrike.py
```

You will be prompted for: target(s), scan profile, authentication, output directory, wordlists, and scope. Previous sessions are automatically detected and can be resumed.

```
 ┌─────────────────────────────────────────────────────────┐
 │  HexStrike v2 — Main Menu                               │
 │                                                         │
 │   1   Tool Check        Verify & auto-install tools     │
 │   2   Reconnaissance    WHOIS, Nmap, Shodan, crawl      │
 │   3   Exploitation      SQLi, XSS, IDOR, MSF            │
 │   4   API Testing       REST, Swagger, GraphQL          │
 │   5   Business Logic    Race conditions, replay         │
 │   6   Param Fuzzing     Hidden parameter discovery      │
 │   7   Full Auto Scan    Recon → ADE → All → Report      │
 │   8   Request Console   Interactive request editor      │
 │   9   Generate Report   JSON + TXT from session         │
 │  10   Show Scan Graph   Correlated recon tree           │
 │  11   List Plugins      Show loaded plugins             │
 │  12   Clear Session     Wipe saved state                │
 │   0   Exit                                              │
 └─────────────────────────────────────────────────────────┘
```

### Command-Line Mode

HexStrike supports a full `argparse`-based CLI for scripting, CI pipelines, and faster workflows.

```bash
# Basic scan with default (normal) profile
sudo python3 hexstrike.py scan target.com

# Full scan — all modules, aggressive
sudo python3 hexstrike.py scan target.com --profile full

# Recon only — no exploitation
sudo python3 hexstrike.py scan target.com --profile recon

# API-focused scan
sudo python3 hexstrike.py scan target.com --profile api --steps recon api report

# Run specific steps only
sudo python3 hexstrike.py scan target.com --steps recon exploit report

# Bulk targets from file
sudo python3 hexstrike.py scan --targets-file targets.txt --profile stealth

# Custom output directory
sudo python3 hexstrike.py scan target.com --output /tmp/pentest_results

# Route through Burp Suite proxy
sudo python3 hexstrike.py scan target.com --proxy http://127.0.0.1:8080

# Skip consent prompt (for automated/CI use)
sudo python3 hexstrike.py scan target.com --no-consent --profile recon

# List available profiles
sudo python3 hexstrike.py profiles

# List loaded plugins
sudo python3 hexstrike.py plugins
```

**Available `--steps` values:** `toolcheck` `recon` `exploit` `api` `biz_logic` `report`

### Authentication

HexStrike carries authentication state across all modules via a single `HexSession` object. Three auth methods are supported:

**Cookie injection**
```bash
sudo python3 hexstrike.py scan target.com --cookie "PHPSESSID=abc123; token=xyz789"
```

**Custom header**
```bash
sudo python3 hexstrike.py scan target.com --header "Authorization: Bearer eyJhbGci..."
# Multiple headers are supported
sudo python3 hexstrike.py scan target.com \
    --header "Authorization: Bearer TOKEN" \
    --header "X-API-Key: secretkey"
```

**Login form automation**
```bash
sudo python3 hexstrike.py scan target.com \
    --login-url http://target.com/login \
    --login-user admin \
    --login-pass secret123
```

Login automation performs a `GET` to capture CSRF tokens before `POST`ing credentials. Session cookies from the login response are carried into all subsequent requests.

**Interactive auth setup** — when running in menu mode, select "Configure authentication" during setup and choose from `cookie`, `header`, or `login` methods.

### Request Console

The request console is a lightweight interactive HTTP repeater — similar to Burp Suite's Repeater tab — for manually inspecting, modifying, and resending requests discovered during a scan.

```bash
# Open console standalone
sudo python3 hexstrike.py console target.com --cookie "session=abc"

# Or select option 8 from the main menu after a scan
```

**Console commands:**

| Command | Description |
|---|---|
| `send` | Send the current request and display the response |
| `view` | Print the current request (method, URL, params, headers, body) |
| `set url <url>` | Change the target URL |
| `set method <GET\|POST\|PUT\|DELETE\|PATCH>` | Change HTTP method |
| `set param <key> <value>` | Add or update a query/body parameter |
| `del param <key>` | Remove a parameter |
| `set header <Name> <Value>` | Set a request header |
| `set body <data>` | Set the raw request body |
| `repeat <N>` | Send N parallel requests (race condition testing) |
| `compare` | Diff the last two responses (status, length, body) |
| `history` | Show the last 10 request/response pairs |
| `list` | List all endpoints discovered in the current scan |
| `load <number>` | Load a discovered endpoint by index |
| `clear` | Reset the request to defaults |
| `exit` | Exit the console |

---

## Modules

### Step 1 — Reconnaissance

**`modules/recon.py`** builds the `ScanGraph`. Every sub-module writes structured data into the graph rather than printing to a log.

| Sub-module | What it does |
|---|---|
| **WHOIS Lookup** | Domain registration, registrar, nameservers, creation/expiry dates |
| **Google Dorking** | Sends 10 targeted dork queries via Google Custom Search API — finds exposed files, admin panels, error messages, credentials |
| **Nmap Fingerprinting** | Port scan with OS detection and service version identification. Flags are controlled by scan profile. |
| **Shodan Scanning** | Queries Shodan for the target's public IP — open ports, running services, known CVEs, ISP, geolocation |
| **Source Code Analysis** | Fetches root page and scans for hardcoded API keys, passwords, tokens, HTML comments, and error messages using 8 regex patterns |
| **Async Crawler** | BFS crawl to `crawl_depth` using `httpx.AsyncClient` — discovers endpoints, extracts URL parameters, detects forms, flags admin/API paths |
| **Subdomain Enumeration** | Sublist3r passive enum + async brute-force from bundled 160-entry wordlist (or custom `--wordlist`). Each alive subdomain is probed for its own attack surface. |
| **API / Swagger / GraphQL Detection** | Probes 10 common Swagger/OpenAPI paths and 4 GraphQL paths. Parses OpenAPI spec to extract all defined endpoints and their parameters. |
| **Tech Detection** | Signature-based detection of 18 technologies (WordPress, Drupal, React, Angular, PHP, ASP.NET, Nginx, Apache, Cloudflare, etc.) from HTML and response headers |
| **Real-Time Intelligence** | Pattern-matches detected versions against a ruleset of known-vulnerable software and prints actionable CVE advisories inline |
| **Attack Surface Check** | After recon completes, evaluates whether the target has anything worth testing. Reports if no forms, open ports, parameters, or secrets were found. |

### Step 2 — Exploitation

The Auto Decision Engine runs between recon and exploitation (see [Auto Decision Engine](#auto-decision-engine)). Each exploit module reads directly from the `ScanGraph` rather than rescanning.

#### SQL Injection — SQLMap

Runs SQLMap against all endpoints with parameters discovered during recon. Intensity flags (`--level`, `--risk`, `--threads`, `--tamper`) are set automatically by scan profile. Session cookies are injected into SQLMap via `--cookie`. Confirmed injections are written back into the graph, marking the relevant `Parameter` objects as injectable.

```
Profile stealth  → --level 1 --risk 1
Profile normal   → --level 2 --risk 2
Profile full     → --level 5 --risk 3 --tamper=space2comment,between --threads=N
```

#### Cross-Site Scripting — Async XSS Scanner

Tests all discovered forms and URL parameters with 10 payloads using `httpx.AsyncClient`. Detects reflected XSS by checking whether the payload appears in the response body. Concurrency is controlled by scan profile.

#### IDOR Detection — `modules/idor.py`

Automatically identifies parameters matching patterns like `user_id`, `account_id`, `order_id`, `uid`, `pid`, and any parameter with a numeric integer value. For each candidate, sends requests with adjacent IDs (`+1`, `+2`, `-1`, `+100`, `1`, `2`, `3`) and compares responses using status code, body length, and MD5 hash. Flags access control failures where a different user's data is returned.

#### Brute Force — Hydra

Runs Hydra HTTP form brute force against all discovered login endpoints. Username and password fields are detected automatically from form input names. Falls back to SSH brute force if port 22 is open. Wordlist defaults to `/usr/share/wordlists/rockyou.txt` or a user-specified path.

#### Security Misconfigurations

Probes 20 common sensitive paths (`.env`, `.git/config`, `/phpmyadmin`, `/wp-admin`, `/actuator/env`, `/server-status`, etc.), checks all 7 recommended HTTP security headers, tests default credential pairs against discovered admin panels, and flags server version disclosure in response headers.

#### API Testing — `modules/api_testing.py`

Discovers REST endpoints by probing a list of 30 common API paths. Tests all discovered API endpoints for unexpected HTTP method acceptance (PUT, DELETE, PATCH on read-only endpoints). Fuzzes Swagger/OpenAPI-defined parameters with SQLi and XSS payloads. Tests GraphQL for enabled introspection and query batching (DoS potential).

#### Business Logic — `modules/biz_logic.py`

Sends identical requests in parallel (count controlled by profile concurrency setting) and compares responses to detect race conditions. Replays requests 5 times to detect non-idempotent behavior. Tests numeric form fields (`amount`, `price`, `quantity`) with negative values, zero, and overflow payloads. Tests one-time tokens for reuse vulnerabilities.

#### Parameter Fuzzing — `modules/param_fuzzer.py`

Tests 100+ common hidden parameter names against all reachable endpoints using async requests. Detects processing by comparing response body hash and length against a baseline. Flags dangerous parameters (`debug`, `admin`, `cmd`, `exec`, `trace`) as High severity findings when they produce different responses.

#### Metasploit Auto-Launch

Matches detected service names, versions, and Shodan CVEs against a map of 14 Metasploit modules. Generates a resource script (`.rc` file) and launches `msfconsole -q -r` autonomously. Detected sessions are written into the graph as Critical findings.

### Step 3 — Reporting

`modules/report.py` reads all `Finding` objects from the `ScanGraph` and generates two output files.

Every finding has a **priority score** calculated as:

```
priority_score = cvss_score + sensitivity_bonus + exploitation_bonus
```

where `sensitivity_bonus` adds up to 0.5 for findings on admin, payment, auth, or API endpoints, and `exploitation_bonus` adds 1.0 if the vulnerability was actively exploited (e.g. an MSF session was opened). Findings in all outputs are sorted by priority score, not CVSS alone.

**JSON report** (`hexstrike_report_TIMESTAMP.json`) — full machine-readable output including the complete `ScanGraph` with all subdomains, endpoints, parameters, technologies, and findings with evidence.

**TXT report** (`hexstrike_report_TIMESTAMP.txt`) — human-readable executive summary including risk counts, all findings with remediation advice, subdomain map, WHOIS summary, Shodan CVEs, and scan intelligence notes.

**Graph file** (`hexstrike_graph_TIMESTAMP.json`) — raw `ScanGraph` serialization for post-processing or custom tooling.

---

## Plugin System

HexStrike auto-discovers Python files in the `/plugins/` directory at startup. Any class subclassing `HexPlugin` is registered and executed at the appropriate phase.

### Creating a plugin

```python
# plugins/my_plugin.py
from core.plugins import HexPlugin
from core.models import ScanGraph, Finding

class MyPlugin(HexPlugin):
    name = "my_plugin"
    description = "Does something useful"
    version = "1.0.0"
    author = "You"
    phase = "exploit"        # recon | exploit | report | post
    auto_trigger = True
    trigger_condition = "api_detected"   # fires when API is found

    def can_run(self, graph: ScanGraph) -> bool:
        # Optional: pre-condition check before run() is called
        return bool(graph.api_endpoints())

    def run(self, graph, session, profile, console) -> dict:
        # graph   → ScanGraph, read and write freely
        # session → HexSession, make authenticated requests
        # profile → Profile, check intensity/concurrency
        # console → Rich Console for output
        
        console.print("  [cyan]My plugin running...[/cyan]")
        
        # Write findings directly into the graph
        f = Finding(
            title="Example Finding",
            finding_type="misconfig",
            severity="Medium",
            cvss_score=5.3,
            cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            target=graph.target,
            detail="Found by my_plugin",
            recommendation="Fix it.",
        )
        graph.add_finding(f)
        
        return {"findings": 1}
```

Drop the file in `/plugins/`. It loads automatically on next startup. No registration, no imports required in the main codebase.

### Auto-trigger conditions

| Condition | Triggered when |
|---|---|
| `api_detected` | API endpoints discovered in recon |
| `login_found` | Login page or auth forms detected |
| `graphql_detected` | GraphQL endpoint found |
| `ssh_open` | Port 22 open in Nmap/Shodan |
| `smb_open` | Ports 445/139 open |
| `cve_detected` | Shodan reports known CVEs |
| `admin_found` | Admin panel exposed |
| `params_found` | URL parameters discovered |
| `outdated_software` | Outdated tech version detected |

---

## Auto Decision Engine

After recon completes, the `AutoDecisionEngine` reads the `ScanGraph` and produces a prioritized list of modules to run. This means HexStrike adapts its attack surface automatically rather than blindly running every module on every target.

**Example decision output:**

```
⚡ Auto Decision Engine
┌──────────┬──────────────────┬─────────────────────────────────────┬──────────────┐
│ Priority │ Module           │ Reason                              │ Trigger      │
├──────────┼──────────────────┼─────────────────────────────────────┼──────────────┤
│ 1        │ sqli             │ Login forms are prime SQLi targets  │ login_found  │
│ 1        │ api_testing      │ API endpoints detected              │ api_detected │
│ 2        │ bruteforce       │ Login page detected                 │ login_found  │
│ 2        │ idor             │ API with parameters                 │ api_detected │
│ 2        │ metasploit       │ Shodan CVEs detected                │ cve_detected │
│ 3        │ xss              │ Forms found                         │ login_found  │
│ 3        │ param_fuzzing    │ API endpoints — fuzz params         │ api_detected │
└──────────┴──────────────────┴─────────────────────────────────────┴──────────────┘
```

In **full auto scan** (menu option 7 or `--steps recon exploit`), the engine's output drives the exploit phase. In **menu mode**, it runs as an advisory — you see what it recommends before choosing what to run.

---

## CVSS Scoring Reference

Every finding is assigned a CVSS v3.1 base score and a HexStrike priority score.

| Severity | CVSS Range | Description | Example |
|---|---|---|---|
| **Critical** | 9.0 – 10.0 | Remote code execution, full system compromise, confirmed exploitation | MSF session opened, SQLi with DB dump |
| **High** | 7.0 – 8.9 | Severe risk requiring urgent remediation | IDOR exposing other users' data, brute-forced credentials |
| **Medium** | 4.0 – 6.9 | Exploitable with user interaction or specific conditions | Reflected XSS, exposed admin panel, GraphQL introspection enabled |
| **Low** | 0.1 – 3.9 | Minimal impact, low exploitation likelihood | Missing security headers, server version disclosure |
| **Info** | 0.0 | Informational — no direct security impact | Tech stack identified, subdomains discovered |

**Priority score** = CVSS base + sensitivity bonus (up to +0.5 for admin/payment/auth endpoints) + exploitation bonus (+1.0 if actively exploited). Findings are sorted by priority score in all reports.

---

## Output Files

All outputs are saved to `~/hexstrike_reports/` by default (configurable via `--output` or the interactive prompt).

```
~/hexstrike_reports/
├── hexstrike_report_20241201_143022.json   # Full JSON report
├── hexstrike_report_20241201_143022.txt    # Human-readable summary + remediation
├── hexstrike_graph_20241201_143022.json    # Raw ScanGraph for post-processing
├── nmap_target_com.xml                     # Raw Nmap XML output
└── subs_target_com.txt                     # Discovered subdomains
```

Session state is saved to `~/.hexstrike_v2_session.json` after each step. If a scan is interrupted, re-running HexStrike will detect the session and offer to resume from the last completed step.

---

## Legal Disclaimer

HexStrike is designed **exclusively** for:

- Authorized penetration testing engagements with written permission
- CTF (Capture The Flag) competitions
- Security research on systems you own
- Educational use in controlled lab environments

---

<div align="center">

**HexStrike v2.0.0** · Python · Parrot OS · `sudo python3 hexstrike.py`

</div>
