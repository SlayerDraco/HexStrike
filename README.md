# HexStrike — Web Penetration Testing Automation Framework

```
 ██╗  ██╗███████╗██╗  ██╗███████╗████████╗██████╗ ██╗██╗  ██╗███████╗
 ██║  ██║██╔════╝╚██╗██╔╝██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝
 ███████║█████╗   ╚███╔╝ ███████╗   ██║   ██████╔╝██║█████╔╝ █████╗
 ██╔══██║██╔══╝   ██╔██╗ ╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝
 ██║  ██║███████╗██╔╝ ██╗███████║   ██║   ██║  ██║██║██║  ██╗███████╗
 ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝
```

**For authorized penetration testing ONLY.**

---

## Requirements

- **OS**: Parrot OS (recommended) / Kali Linux
- **Python**: 3.9+
- **Must run as root**: `sudo python3 hexstrike.py`

---

## Setup

### 1. Install Python dependencies

```bash
pip3 install -r requirements.txt --break-system-packages
```

### 2. Configure API keys

Edit the `.env` file in the HexStrike directory:

```bash
nano .env
```

Fill in:
```
SHODAN_API_KEY=your_shodan_key_here
GOOGLE_API_KEY=your_google_api_key_here
GOOGLE_CX=your_google_custom_search_cx_here
```

- **Shodan key**: https://account.shodan.io/
- **Google API key**: https://console.cloud.google.com/ → Enable "Custom Search API"
- **Google CX**: https://programmablesearchengine.google.com/ → Create engine, get CX ID

### 3. Run HexStrike

```bash
sudo python3 hexstrike.py
```

---

## Tool Architecture

```
hexstrike/
├── hexstrike.py            # Main entry point — banner, menu, session management
├── config.py               # .env loader
├── requirements.txt        # Python dependencies
├── .env                    # API keys (edit this!)
├── modules/
│   ├── toolcheck.py        # Auto-checks & installs required system tools
│   ├── recon.py            # Step 1: WHOIS, Dorking, Nmap, Shodan, subdomains, source
│   ├── exploit.py          # Step 2: SQLi, XSS, brute force, misconfig, Metasploit
│   └── report.py           # Step 3: CVSS scoring, JSON + TXT report
└── wordlists/
    └── subdomains.txt      # Bundled subdomain brute-force wordlist
```

---

## Modules

### Step 1 — Reconnaissance
| Sub-module | Description |
|---|---|
| WHOIS Lookup | Domain registration, registrar, nameservers |
| Google Dorking | Custom Search API — finds exposed files, admin panels, errors |
| Nmap Fingerprinting | Port scan, OS detection, service versions, banner grabbing |
| Shodan Scanning | Public IP intelligence, open ports, known CVEs |
| Source Code Analysis | Hardcoded secrets, API keys, forms, login detection |
| Subdomain Enumeration | Sublist3r + custom brute-force wordlist |

### Step 2 — Exploitation
| Sub-module | Tool | Description |
|---|---|---|
| SQL Injection | SQLMap | Auto-detects injectable parameters, extracts DBs |
| XSS Testing | Custom | Tests all forms/URLs with 8 payloads |
| Brute Force | Hydra | HTTP forms + SSH if port 22 open |
| Misconfigurations | Custom | Admin panels, default creds, missing headers |
| Metasploit | msfconsole | Auto-selects and runs modules based on findings |

### Step 3 — Reporting
- **CVSS Scores** for every finding
- **Risk categories**: Critical / High / Medium / Low
- **JSON report** — machine-readable, full detail
- **TXT report** — human-readable summary + remediation steps
- **Session resume** — interrupted scans resume from last step

---

## Required System Tools

HexStrike's Tool Check (menu option 1) will auto-install these:

| Tool | Purpose |
|---|---|
| nmap | Port scanning, fingerprinting |
| sqlmap | SQL injection testing |
| hydra | Brute-force login attacks |
| john | Password cracking |
| wfuzz | Web fuzzing |
| metasploit-framework | Exploitation framework |
| whois | Domain lookup |
| sublist3r | Subdomain enumeration |

---

## Output

Reports are saved to `~/hexstrike_reports/` by default (configurable at runtime):

```
~/hexstrike_reports/
├── hexstrike_report_20241201_143022.json   # Full JSON report
├── hexstrike_report_20241201_143022.txt    # Human-readable summary
├── nmap_target_com.xml                     # Raw Nmap output
└── subdomains_target_com.txt               # Discovered subdomains
```

---

## Legal

HexStrike is designed **exclusively** for:
- Authorized penetration testing engagements
- CTF (Capture The Flag) challenges
- Testing systems you own

**Unauthorized use is illegal.** The authors accept no responsibility for misuse.

---

## CVSS Scoring Reference

| Score | Severity | Description |
|---|---|---|
| 9.0 – 10.0 | Critical | Remote code execution, full compromise |
| 7.0 – 8.9 | High | Severe risk, urgent remediation required |
| 4.0 – 6.9 | Medium | Exploitable with user interaction |
| 0.1 – 3.9 | Low | Minimal impact, low priority |
