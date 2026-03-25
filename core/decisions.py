"""
HexStrike v2 - Auto Decision Engine
Analyzes recon graph and automatically decides which exploit modules to trigger.
Fires relevant modules based on discovered conditions.
"""

from __future__ import annotations
from typing import List, Tuple
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

console = Console()


class Decision:
    def __init__(self, module: str, reason: str, condition: str, priority: int = 5):
        self.module = module
        self.reason = reason
        self.condition = condition
        self.priority = priority  # 1=highest

    def __repr__(self):
        return f"Decision({self.module}: {self.reason})"


class AutoDecisionEngine:
    """
    Inspects the ScanGraph after recon and determines what to run next.
    Returns an ordered list of Decision objects.
    """

    def analyze(self, graph) -> List[Decision]:
        decisions: List[Decision] = []

        surface = self._surface_check(graph)

        # ── Login page / forms ─────────────────────────────────────
        if surface["has_login"]:
            decisions.append(Decision(
                "bruteforce", "Login page detected — brute force applicable",
                "login_found", priority=2
            ))
            decisions.append(Decision(
                "sqli", "Login forms are prime SQLi targets",
                "login_found", priority=1
            ))
            decisions.append(Decision(
                "xss", "Forms found — XSS testing applicable",
                "login_found", priority=3
            ))

        # ── API detected ───────────────────────────────────────────
        if surface["has_api"]:
            decisions.append(Decision(
                "api_testing", "API endpoints detected — REST/GraphQL testing",
                "api_detected", priority=1
            ))
            decisions.append(Decision(
                "idor", "API with parameters — IDOR testing applicable",
                "api_detected", priority=2
            ))
            decisions.append(Decision(
                "param_fuzzing", "API endpoints — parameter fuzzing applicable",
                "api_detected", priority=3
            ))

        # ── Open ports ─────────────────────────────────────────────
        if surface["has_ssh"]:
            decisions.append(Decision(
                "bruteforce_ssh", "SSH open — credential brute force",
                "ssh_open", priority=2
            ))
        if surface["has_db_port"]:
            decisions.append(Decision(
                "metasploit", "Database port exposed — MSF scanning",
                "db_port_open", priority=1
            ))
        if surface["has_smb"]:
            decisions.append(Decision(
                "metasploit", "SMB port open — EternalBlue/MS17-010 check",
                "smb_open", priority=1
            ))

        # ── Parameters in URLs ─────────────────────────────────────
        if surface["has_url_params"]:
            decisions.append(Decision(
                "sqli", "URL parameters detected — SQLi testing",
                "params_found", priority=1
            ))
            decisions.append(Decision(
                "idor", "Numeric parameters detected — IDOR testing",
                "params_found", priority=2
            ))
            decisions.append(Decision(
                "param_fuzzing", "Parameters found — hidden param discovery",
                "params_found", priority=3
            ))

        # ── Admin panels ───────────────────────────────────────────
        if surface["has_admin"]:
            decisions.append(Decision(
                "misconfig", "Admin panel found — default cred + misconfig test",
                "admin_found", priority=1
            ))

        # ── Known CVEs from Shodan ─────────────────────────────────
        if surface["has_cves"]:
            decisions.append(Decision(
                "metasploit", f"Shodan CVEs detected — MSF exploitation",
                "cve_detected", priority=1
            ))

        # ── Outdated tech ──────────────────────────────────────────
        if surface["outdated_tech"]:
            for tech in surface["outdated_tech"]:
                decisions.append(Decision(
                    "metasploit", f"Outdated {tech} detected — exploit check",
                    "outdated_software", priority=2
                ))

        # ── GraphQL ────────────────────────────────────────────────
        if graph.graphql_detected:
            decisions.append(Decision(
                "api_testing", "GraphQL detected — introspection + fuzzing",
                "graphql_detected", priority=1
            ))

        # ── Plugin auto-triggers ───────────────────────────────────
        conditions_met = list(set(d.condition for d in decisions))
        for cond in conditions_met:
            decisions.append(Decision(
                f"plugin:{cond}", f"Plugin trigger: {cond}",
                cond, priority=9
            ))

        # Sort by priority
        decisions.sort(key=lambda d: d.priority)
        return decisions

    def _surface_check(self, graph) -> dict:
        all_eps = graph.all_endpoints()
        shodan = graph.shodan

        has_url_params = any("?" in e.url for e in all_eps)
        has_login = any(e.forms for e in all_eps) or \
                    any("login" in e.url.lower() or "auth" in e.url.lower() for e in all_eps)
        has_api = bool(graph.api_endpoints())
        has_admin = bool(graph.admin_endpoints())

        all_ports = shodan.get("ports", [])
        # Also check from all subdomains
        for sub in graph.subdomains:
            all_ports.extend(sub.open_ports)
        all_ports = list(set(str(p) for p in all_ports))

        has_ssh = "22" in all_ports
        has_smb = "445" in all_ports or "139" in all_ports
        has_db_port = any(p in all_ports for p in ["3306", "5432", "27017", "6379", "1433"])
        has_cves = bool(shodan.get("vulns", []))

        # Detect outdated tech
        outdated = []
        outdated_keywords = {
            "apache 2.2": "Apache 2.2", "apache/2.2": "Apache 2.2",
            "php/5": "PHP 5.x", "php/7.0": "PHP 7.0",
            "openssl/1.0": "OpenSSL 1.0",
            "nginx/1.0": "Nginx 1.0", "nginx/1.1": "Nginx 1.1",
            "iis/6": "IIS 6", "iis/7": "IIS 7",
            "tomcat/6": "Tomcat 6", "tomcat/7": "Tomcat 7",
        }
        for tech in graph.technologies:
            tech_str = f"{tech.name.lower()}/{tech.version or ''}".lower()
            for kw, label in outdated_keywords.items():
                if kw in tech_str:
                    outdated.append(label)

        return {
            "has_url_params": has_url_params,
            "has_login": has_login,
            "has_api": has_api,
            "has_admin": has_admin,
            "has_ssh": has_ssh,
            "has_smb": has_smb,
            "has_db_port": has_db_port,
            "has_cves": has_cves,
            "outdated_tech": outdated,
        }

    def print_decisions(self, decisions: List[Decision]):
        if not decisions:
            console.print("[yellow]Auto Decision Engine: No specific modules triggered.[/yellow]")
            return

        console.print()
        table = Table(
            title="[bold yellow]⚡ Auto Decision Engine[/bold yellow]",
            box=box.ROUNDED, border_style="yellow"
        )
        table.add_column("Priority", width=8, justify="center")
        table.add_column("Module", style="bold cyan")
        table.add_column("Reason", style="white")
        table.add_column("Trigger", style="dim")

        for d in decisions[:15]:  # Show top 15
            table.add_row(str(d.priority), d.module, d.reason, d.condition)

        console.print(table)
