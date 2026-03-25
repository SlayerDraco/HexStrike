"""
HexStrike - Report Generation Module
Step 3: Reporting & Recommendations
- CVSS Score assignment
- Risk categorization
- JSON report
- Human-readable TXT summary
"""

import json
import os
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.rule import Rule
from rich import box

console = Console()

# ─────────────────────────────────────────────
# CVSS Scoring Logic
# ─────────────────────────────────────────────

def cvss_category(score):
    if score >= 9.0:
        return "Critical", "bold red"
    elif score >= 7.0:
        return "High", "red"
    elif score >= 4.0:
        return "Medium", "yellow"
    elif score > 0:
        return "Low", "green"
    else:
        return "Informational", "dim"

# Predefined CVSS scores for finding types
FINDING_CVSS = {
    "sqli_vulnerable":          {"score": 9.8,  "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "desc": "SQL Injection allows database manipulation and data exfiltration."},
    "xss_reflected":            {"score": 6.1,  "vector": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",  "desc": "Reflected XSS can hijack user sessions or steal credentials."},
    "xss_stored":               {"score": 8.2,  "vector": "AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N",  "desc": "Stored XSS persists and affects all users visiting the page."},
    "default_credentials":      {"score": 9.1,  "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  "desc": "Default credentials allow full administrative access."},
    "exposed_admin":            {"score": 5.3,  "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  "desc": "Exposed admin panel increases attack surface."},
    "missing_security_headers": {"score": 3.1,  "vector": "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",  "desc": "Missing HTTP security headers reduce browser-side protections."},
    "server_disclosure":        {"score": 2.7,  "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  "desc": "Server version disclosure aids attacker enumeration."},
    "hardcoded_secret":         {"score": 8.6,  "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",  "desc": "Hardcoded secrets expose API keys, credentials, or tokens."},
    "open_port":                {"score": 3.7,  "vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",  "desc": "Unnecessary open ports increase attack surface."},
    "msf_session":              {"score": 10.0, "vector": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",  "desc": "Metasploit session opened — full remote code execution achieved."},
    "known_cve":                {"score": 9.0,  "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  "desc": "Known CVE detected via Shodan — publicly exploitable vulnerability."},
    "ssh_credential":           {"score": 9.8,  "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  "desc": "SSH credentials brute-forced — full shell access possible."},
    "bruteforce_credential":    {"score": 8.8,  "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",  "desc": "Login credentials brute-forced — unauthorized access possible."},
    "sensitive_file_exposed":   {"score": 7.5,  "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",  "desc": "Sensitive file (.env, .git, backup) publicly accessible."},
}

RECOMMENDATIONS = {
    "sqli_vulnerable":          "Use parameterized queries / prepared statements. Implement input validation and a WAF.",
    "xss_reflected":            "Encode all user input in output. Implement Content-Security-Policy headers.",
    "xss_stored":               "Sanitize and encode user input before storage and rendering. Use CSP.",
    "default_credentials":      "Change all default credentials immediately. Enforce strong password policies.",
    "exposed_admin":            "Restrict admin panels to trusted IPs. Require MFA for all admin access.",
    "missing_security_headers": "Add X-Frame-Options, CSP, HSTS, X-Content-Type-Options, Referrer-Policy headers.",
    "server_disclosure":        "Remove or obscure Server and X-Powered-By response headers.",
    "hardcoded_secret":         "Rotate all exposed secrets immediately. Use environment variables or a secrets manager.",
    "open_port":                "Close unused ports via firewall. Apply principle of least privilege.",
    "msf_session":              "Patch the exploited vulnerability immediately. Conduct full incident response.",
    "known_cve":                "Apply vendor security patches immediately. Subscribe to CVE notifications.",
    "ssh_credential":           "Disable password auth for SSH. Use key-based authentication only.",
    "bruteforce_credential":    "Implement account lockout, CAPTCHA, and rate limiting on login endpoints.",
    "sensitive_file_exposed":   "Remove sensitive files from public web root. Block access via server config.",
}

# ─────────────────────────────────────────────
# Finding Extraction
# ─────────────────────────────────────────────

def extract_findings(target, recon_data, exploit_data):
    findings = []

    # --- Recon findings ---
    source = recon_data.get("source", {})
    nmap = recon_data.get("nmap", {})
    shodan = recon_data.get("shodan", {})

    # Hardcoded secrets
    for secret in source.get("secrets", []):
        f = FINDING_CVSS["hardcoded_secret"].copy()
        f.update({
            "type": "hardcoded_secret",
            "title": f"Hardcoded {secret['type']} in Source Code",
            "detail": secret.get("snippet", ""),
            "target": target,
        })
        findings.append(f)

    # Shodan CVEs
    for cve in shodan.get("vulns", []):
        f = FINDING_CVSS["known_cve"].copy()
        f.update({
            "type": "known_cve",
            "title": f"Known CVE: {cve}",
            "detail": f"Shodan detected {cve} on {target}",
            "target": target,
        })
        findings.append(f)

    # Open ports (high-risk ones)
    risky_ports = ["21", "23", "3389", "445", "139", "5900"]
    for port in nmap.get("open_ports", []):
        if port in risky_ports:
            f = FINDING_CVSS["open_port"].copy()
            f.update({
                "type": "open_port",
                "title": f"Risky Port Open: {port}",
                "detail": f"Port {port} is open and may expose sensitive services.",
                "target": target,
            })
            findings.append(f)

    if exploit_data.get("skipped"):
        return findings

    # --- Exploitation findings ---

    # SQL Injection
    sqli_all = exploit_data.get("sqli", {})
    for t, sqli_list in sqli_all.items():
        for sqli in sqli_list:
            if sqli.get("vulnerable"):
                f = FINDING_CVSS["sqli_vulnerable"].copy()
                f.update({
                    "type": "sqli_vulnerable",
                    "title": f"SQL Injection: {sqli['url']}",
                    "detail": f"SQLMap confirmed injection. Databases: {sqli.get('databases', [])}. Params: {sqli.get('injections', [])}",
                    "target": target,
                })
                findings.append(f)

    # XSS
    xss_all = exploit_data.get("xss", {})
    for t, xss_list in xss_all.items():
        for xss in xss_list:
            key = "xss_stored" if xss.get("type") == "stored" else "xss_reflected"
            f = FINDING_CVSS[key].copy()
            f.update({
                "type": key,
                "title": f"XSS ({xss.get('type', 'reflected').title()}): {xss['url']}",
                "detail": f"Payload: {xss.get('payload', '')} | Method: {xss.get('method', '')}",
                "target": target,
            })
            findings.append(f)

    # Brute force
    for bf in exploit_data.get("bruteforce", []):
        key = "ssh_credential" if bf.get("type") == "ssh" else "bruteforce_credential"
        f = FINDING_CVSS[key].copy()
        f.update({
            "type": key,
            "title": f"Credential Brute-Forced ({bf.get('type', 'http')})",
            "detail": bf.get("finding", ""),
            "target": target,
        })
        findings.append(f)

    # Misconfigs
    misconfig = exploit_data.get("misconfig", {})
    for cred in misconfig.get("default_creds", []):
        f = FINDING_CVSS["default_credentials"].copy()
        f.update({
            "type": "default_credentials",
            "title": f"Default Credentials: {cred['user']}:{cred['password']} @ {cred['url']}",
            "detail": f"Successfully authenticated with default credentials.",
            "target": target,
        })
        findings.append(f)

    for path_entry in misconfig.get("exposed_paths", []):
        if path_entry["status"] == 200:
            is_sensitive = any(k in path_entry["url"] for k in [".env", ".git", "backup", "db.sql"])
            key = "sensitive_file_exposed" if is_sensitive else "exposed_admin"
            f = FINDING_CVSS[key].copy()
            f.update({
                "type": key,
                "title": f"{'Sensitive File' if is_sensitive else 'Admin Panel'} Exposed: {path_entry['url']}",
                "detail": f"HTTP {path_entry['status']} — Publicly accessible.",
                "target": target,
            })
            findings.append(f)

    missing_headers = [h for h, v in misconfig.get("headers", {}).items() if v == "MISSING"]
    if missing_headers:
        f = FINDING_CVSS["missing_security_headers"].copy()
        f.update({
            "type": "missing_security_headers",
            "title": "Missing HTTP Security Headers",
            "detail": f"Missing: {', '.join(missing_headers)}",
            "target": target,
        })
        findings.append(f)

    for finding in misconfig.get("findings", []):
        if finding["type"] == "server_disclosure":
            f = FINDING_CVSS["server_disclosure"].copy()
            f.update({
                "type": "server_disclosure",
                "title": f"Server Version Disclosure",
                "detail": f"Server: {finding['value']}",
                "target": target,
            })
            findings.append(f)

    # Metasploit sessions
    msf = exploit_data.get("metasploit", {})
    for session in msf.get("sessions", []):
        f = FINDING_CVSS["msf_session"].copy()
        f.update({
            "type": "msf_session",
            "title": "Remote Code Execution — Metasploit Session Opened",
            "detail": session,
            "target": target,
        })
        findings.append(f)

    return findings

# ─────────────────────────────────────────────
# Report Printer (Rich terminal)
# ─────────────────────────────────────────────

def print_report_summary(all_findings):
    console.print()
    console.print(Rule("[bold yellow]VULNERABILITY REPORT SUMMARY[/bold yellow]"))
    console.print()

    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for f in all_findings:
        cat, _ = cvss_category(f["score"])
        counts[cat] = counts.get(cat, 0) + 1

    # Summary table
    summary = Table(title="Risk Summary", box=box.ROUNDED, border_style="cyan")
    summary.add_column("Severity", style="bold")
    summary.add_column("Count", justify="center")
    summary.add_column("CVSS Range")

    summary.add_row("[bold red]Critical[/bold red]", str(counts["Critical"]), "9.0 – 10.0")
    summary.add_row("[red]High[/red]",               str(counts["High"]),     "7.0 – 8.9")
    summary.add_row("[yellow]Medium[/yellow]",       str(counts["Medium"]),   "4.0 – 6.9")
    summary.add_row("[green]Low[/green]",            str(counts["Low"]),      "0.1 – 3.9")
    summary.add_row("[dim]Info[/dim]",               str(counts["Informational"]), "0.0")
    console.print(summary)
    console.print()

    # Findings table
    if all_findings:
        findings_table = Table(title="Findings", box=box.ROUNDED, border_style="red")
        findings_table.add_column("#", width=3)
        findings_table.add_column("Severity", width=10)
        findings_table.add_column("CVSS", width=6, justify="center")
        findings_table.add_column("Title")
        findings_table.add_column("Target")

        for i, f in enumerate(sorted(all_findings, key=lambda x: x["score"], reverse=True), 1):
            cat, style = cvss_category(f["score"])
            findings_table.add_row(
                str(i),
                f"[{style}]{cat}[/{style}]",
                f"[{style}]{f['score']}[/{style}]",
                f["title"],
                f["target"]
            )
        console.print(findings_table)
    else:
        console.print("[bold green]✔ No vulnerabilities found.[/bold green]")

# ─────────────────────────────────────────────
# JSON + TXT Report Writers
# ─────────────────────────────────────────────

def write_json_report(report, output_dir, timestamp):
    path = Path(output_dir) / f"hexstrike_report_{timestamp}.json"
    with open(path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    console.print(f"[green]✔ JSON report saved:[/green] {path}")
    return str(path)

def write_txt_report(report, all_findings, output_dir, timestamp):
    path = Path(output_dir) / f"hexstrike_report_{timestamp}.txt"
    lines = []
    lines.append("=" * 70)
    lines.append("  HexStrike — Web Penetration Testing Report")
    lines.append(f"  Generated: {report['metadata']['generated_at']}")
    lines.append(f"  Targets:   {', '.join(report['metadata']['targets'])}")
    lines.append(f"  Intensity: {report['metadata']['intensity']}")
    lines.append("=" * 70)
    lines.append("")

    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for f in all_findings:
        cat, _ = cvss_category(f["score"])
        counts[cat] = counts.get(cat, 0) + 1

    lines.append("RISK SUMMARY")
    lines.append("-" * 40)
    for cat, count in counts.items():
        lines.append(f"  {cat:<15}: {count}")
    lines.append("")

    lines.append("FINDINGS")
    lines.append("-" * 70)
    for i, f in enumerate(sorted(all_findings, key=lambda x: x["score"], reverse=True), 1):
        cat, _ = cvss_category(f["score"])
        lines.append(f"\n[{i}] {f['title']}")
        lines.append(f"    Severity   : {cat} (CVSS {f['score']})")
        lines.append(f"    CVSS Vector: {f.get('vector', 'N/A')}")
        lines.append(f"    Target     : {f['target']}")
        lines.append(f"    Description: {f.get('desc', '')}")
        lines.append(f"    Detail     : {f.get('detail', '')}")
        recommendation = RECOMMENDATIONS.get(f["type"], "Apply security best practices.")
        lines.append(f"    Fix        : {recommendation}")

    lines.append("")
    lines.append("=" * 70)
    lines.append("  RECOMMENDATIONS")
    lines.append("=" * 70)
    rec_types = list(set(f["type"] for f in all_findings))
    for rt in rec_types:
        lines.append(f"\n  [{rt.upper()}]")
        lines.append(f"  → {RECOMMENDATIONS.get(rt, 'Apply security best practices.')}")

    lines.append("")
    lines.append("=" * 70)
    lines.append("  END OF REPORT — HexStrike")
    lines.append("=" * 70)

    with open(path, "w") as f:
        f.write("\n".join(lines))

    console.print(f"[green]✔ TXT report saved:[/green] {path}")
    return str(path)

# ─────────────────────────────────────────────
# Main Report Generator
# ─────────────────────────────────────────────

def generate_report(config, session):
    console.print()
    console.print(Panel(
        "[bold white]Generating HexStrike Penetration Test Report...[/bold white]",
        title="[bold yellow]REPORT GENERATION[/bold yellow]",
        border_style="yellow"
    ))

    targets = config["targets"]
    output_dir = config["output_dir"]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    recon_results  = session.get("recon_results", {})
    exploit_results = session.get("exploit_results", {})

    all_findings = []

    for target in targets:
        recon_data   = recon_results.get(target, {})
        exploit_data = exploit_results.get(target, {})
        findings = extract_findings(target, recon_data, exploit_data)
        all_findings.extend(findings)

    # Print to terminal
    print_report_summary(all_findings)

    # Build full JSON report
    report = {
        "metadata": {
            "tool": "HexStrike",
            "version": "1.0.0",
            "generated_at": datetime.now().isoformat(),
            "targets": targets,
            "intensity": config.get("intensity"),
            "total_findings": len(all_findings),
        },
        "risk_summary": {
            "critical": sum(1 for f in all_findings if cvss_category(f["score"])[0] == "Critical"),
            "high":     sum(1 for f in all_findings if cvss_category(f["score"])[0] == "High"),
            "medium":   sum(1 for f in all_findings if cvss_category(f["score"])[0] == "Medium"),
            "low":      sum(1 for f in all_findings if cvss_category(f["score"])[0] == "Low"),
        },
        "findings": [
            {
                **f,
                "severity": cvss_category(f["score"])[0],
                "recommendation": RECOMMENDATIONS.get(f.get("type", ""), "Apply security best practices.")
            }
            for f in sorted(all_findings, key=lambda x: x["score"], reverse=True)
        ],
        "recon": recon_results,
        "exploitation": exploit_results,
    }

    json_path = write_json_report(report, output_dir, timestamp)
    txt_path  = write_txt_report(report, all_findings, output_dir, timestamp)

    console.print()
    console.print(Panel(
        f"[bold green]✔ Report generation complete![/bold green]\n\n"
        f"  [white]JSON:[/white] {json_path}\n"
        f"  [white]TXT :[/white] {txt_path}\n\n"
        f"  [bold]Total findings:[/bold] {len(all_findings)} "
        f"({report['risk_summary']['critical']} critical, "
        f"{report['risk_summary']['high']} high, "
        f"{report['risk_summary']['medium']} medium, "
        f"{report['risk_summary']['low']} low)",
        title="[bold green]REPORT SAVED[/bold green]",
        border_style="green"
    ))

    return report
