"""
HexStrike Plugin: WordPress Scanner
Example plugin demonstrating the plugin architecture.
Auto-triggered when WordPress technology is detected.
"""

import re
from typing import Optional
from core.plugins import HexPlugin
from core.models import ScanGraph, Finding


class WordPressPlugin(HexPlugin):
    name = "wordpress_scanner"
    description = "Scans WordPress sites for common vulns: xmlrpc, user enum, outdated plugins"
    version = "1.0.0"
    author = "HexStrike"
    phase = "exploit"
    auto_trigger = True
    trigger_condition = "api_detected"   # also runs when WordPress tech found

    WP_PATHS = [
        "/xmlrpc.php", "/wp-json/wp/v2/users",
        "/wp-content/debug.log", "/wp-config.php.bak",
        "/?author=1", "/?author=2",
    ]

    def can_run(self, graph: ScanGraph) -> bool:
        tech_names = [t.name.lower() for t in graph.technologies]
        return "wordpress" in tech_names

    def run(self, graph: ScanGraph, session, profile, console) -> dict:
        base = graph.target if graph.target.startswith("http") else "http://" + graph.target
        results = {"findings": 0, "exposed": []}
        console.print(f"  [dim]WordPress Plugin scanning {base}...[/dim]")

        for path in self.WP_PATHS:
            url = base.rstrip("/") + path
            try:
                resp = session.get(url)
                if resp.status_code == 200:
                    console.print(f"  [yellow]⚠ WP exposed:[/yellow] {url}")
                    results["exposed"].append(url)

                    # XMLRPC
                    if "xmlrpc.php" in path:
                        f = Finding(
                            title="WordPress XML-RPC Enabled",
                            finding_type="misconfig",
                            severity="Medium",
                            cvss_score=5.3,
                            cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                            target=graph.target,
                            endpoint=url,
                            detail="XML-RPC allows brute force amplification attacks.",
                            recommendation="Disable XML-RPC if not needed. Use security plugin.",
                        )
                        graph.add_finding(f)
                        results["findings"] += 1

                    # User enumeration
                    if "wp/v2/users" in path and len(resp.text) > 50:
                        users = re.findall(r'"slug":"([^"]+)"', resp.text)
                        if users:
                            f = Finding(
                                title=f"WordPress User Enumeration: {', '.join(users[:5])}",
                                finding_type="info",
                                severity="Medium",
                                cvss_score=5.3,
                                cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                                target=graph.target,
                                endpoint=url,
                                detail=f"User slugs exposed via REST API: {users[:5]}",
                                recommendation="Restrict REST API user endpoint or require authentication.",
                            )
                            graph.add_finding(f)
                            results["findings"] += 1
            except Exception:
                pass

        return results
