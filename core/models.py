"""
HexStrike v2 - Core Data Models
Structured graph for recon correlation and cross-referencing.
All scan data flows through these models.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from datetime import datetime
import json


@dataclass
class Technology:
    name: str
    version: Optional[str] = None
    category: str = "unknown"   # e.g. cms, framework, server, language

    def to_dict(self) -> dict:
        return {"name": self.name, "version": self.version, "category": self.category}


@dataclass
class Parameter:
    name: str
    value: str = ""
    param_type: str = "query"   # query | body | header | cookie | path
    endpoint: Optional[str] = None
    injectable: bool = False
    idor_tested: bool = False
    findings: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name, "value": self.value,
            "param_type": self.param_type, "endpoint": self.endpoint,
            "injectable": self.injectable, "idor_tested": self.idor_tested,
            "findings": self.findings,
        }


@dataclass
class Endpoint:
    url: str
    method: str = "GET"
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    parameters: List[Parameter] = field(default_factory=list)
    technologies: List[Technology] = field(default_factory=list)
    authenticated: bool = False
    is_api: bool = False
    is_admin: bool = False
    forms: List[dict] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    response_hash: Optional[str] = None  # for IDOR diff detection
    notes: List[str] = field(default_factory=list)

    def add_parameter(self, param: Parameter):
        existing = [p.name for p in self.parameters]
        if param.name not in existing:
            param.endpoint = self.url
            self.parameters.append(param)

    def to_dict(self) -> dict:
        return {
            "url": self.url, "method": self.method,
            "status_code": self.status_code, "content_type": self.content_type,
            "parameters": [p.to_dict() for p in self.parameters],
            "technologies": [t.to_dict() for t in self.technologies],
            "authenticated": self.authenticated, "is_api": self.is_api,
            "is_admin": self.is_admin, "forms": self.forms,
            "headers": self.headers, "notes": self.notes,
        }


@dataclass
class Subdomain:
    fqdn: str
    ip: Optional[str] = None
    open_ports: List[int] = field(default_factory=list)
    services: List[dict] = field(default_factory=list)
    endpoints: List[Endpoint] = field(default_factory=list)
    technologies: List[Technology] = field(default_factory=list)
    cnames: List[str] = field(default_factory=list)
    alive: bool = False

    def add_endpoint(self, ep: Endpoint):
        urls = [e.url for e in self.endpoints]
        if ep.url not in urls:
            self.endpoints.append(ep)

    def to_dict(self) -> dict:
        return {
            "fqdn": self.fqdn, "ip": self.ip,
            "open_ports": self.open_ports, "services": self.services,
            "endpoints": [e.to_dict() for e in self.endpoints],
            "technologies": [t.to_dict() for t in self.technologies],
            "cnames": self.cnames, "alive": self.alive,
        }


@dataclass
class Finding:
    title: str
    finding_type: str           # sqli, xss, idor, misconfig, cred, rce, info
    severity: str               # Critical | High | Medium | Low | Info
    cvss_score: float
    cvss_vector: str
    target: str
    endpoint: Optional[str] = None
    parameter: Optional[str] = None
    detail: str = ""
    evidence: str = ""
    recommendation: str = ""
    cve: Optional[str] = None
    exploited: bool = False
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    @property
    def priority_score(self) -> float:
        """Priority = CVSS + bonuses for sensitive context."""
        bonus = 0.0
        sensitive_keywords = ["admin", "payment", "auth", "api/user", "account", "password"]
        if self.endpoint:
            for kw in sensitive_keywords:
                if kw in self.endpoint.lower():
                    bonus += 0.5
        if self.exploited:
            bonus += 1.0
        return min(self.cvss_score + bonus, 10.0)

    def to_dict(self) -> dict:
        return {
            "title": self.title, "type": self.finding_type,
            "severity": self.severity, "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector, "priority_score": self.priority_score,
            "target": self.target, "endpoint": self.endpoint,
            "parameter": self.parameter, "detail": self.detail,
            "evidence": self.evidence, "recommendation": self.recommendation,
            "cve": self.cve, "exploited": self.exploited,
            "timestamp": self.timestamp,
        }


@dataclass
class ScanGraph:
    """
    Central graph object. All modules read from and write to this.
    Represents the full correlation of: target → subdomains → endpoints → parameters → findings.
    """
    target: str
    domain: str
    scan_id: str
    started_at: str = field(default_factory=lambda: datetime.now().isoformat())
    subdomains: List[Subdomain] = field(default_factory=list)
    root_endpoints: List[Endpoint] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    whois: Dict[str, Any] = field(default_factory=dict)
    shodan: Dict[str, Any] = field(default_factory=dict)
    dork_results: Dict[str, Any] = field(default_factory=dict)
    api_spec: Optional[dict] = None       # Swagger/OpenAPI parsed spec
    graphql_detected: bool = False
    technologies: List[Technology] = field(default_factory=list)
    raw_nmap: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    # ── helpers ──────────────────────────────────────────

    def add_subdomain(self, sub: Subdomain):
        fqdns = [s.fqdn for s in self.subdomains]
        if sub.fqdn not in fqdns:
            self.subdomains.append(sub)

    def get_subdomain(self, fqdn: str) -> Optional[Subdomain]:
        for s in self.subdomains:
            if s.fqdn == fqdn:
                return s
        return None

    def add_root_endpoint(self, ep: Endpoint):
        urls = [e.url for e in self.root_endpoints]
        if ep.url not in urls:
            self.root_endpoints.append(ep)

    def all_endpoints(self) -> List[Endpoint]:
        """Return every endpoint across root + all subdomains."""
        eps = list(self.root_endpoints)
        for sub in self.subdomains:
            eps.extend(sub.endpoints)
        return eps

    def all_parameters(self) -> List[Parameter]:
        params = []
        for ep in self.all_endpoints():
            params.extend(ep.parameters)
        return params

    def add_finding(self, f: Finding):
        self.findings.append(f)

    def findings_by_severity(self) -> Dict[str, List[Finding]]:
        result: Dict[str, List[Finding]] = {
            "Critical": [], "High": [], "Medium": [], "Low": [], "Info": []
        }
        for f in sorted(self.findings, key=lambda x: x.priority_score, reverse=True):
            result.setdefault(f.severity, []).append(f)
        return result

    def add_technology(self, tech: Technology):
        names = [t.name.lower() for t in self.technologies]
        if tech.name.lower() not in names:
            self.technologies.append(tech)

    def api_endpoints(self) -> List[Endpoint]:
        return [e for e in self.all_endpoints() if e.is_api]

    def admin_endpoints(self) -> List[Endpoint]:
        return [e for e in self.all_endpoints() if e.is_admin]

    def injectable_parameters(self) -> List[Parameter]:
        return [p for p in self.all_parameters() if p.injectable]

    def summary(self) -> dict:
        sev = self.findings_by_severity()
        return {
            "target": self.target,
            "subdomains_found": len(self.subdomains),
            "endpoints_found": len(self.all_endpoints()),
            "parameters_found": len(self.all_parameters()),
            "technologies": [t.name for t in self.technologies],
            "api_endpoints": len(self.api_endpoints()),
            "findings": {k: len(v) for k, v in sev.items()},
            "total_findings": len(self.findings),
        }

    def to_dict(self) -> dict:
        return {
            "target": self.target, "domain": self.domain,
            "scan_id": self.scan_id, "started_at": self.started_at,
            "subdomains": [s.to_dict() for s in self.subdomains],
            "root_endpoints": [e.to_dict() for e in self.root_endpoints],
            "findings": [f.to_dict() for f in self.findings],
            "whois": self.whois, "shodan": self.shodan,
            "dork_results": self.dork_results,
            "api_spec": self.api_spec,
            "graphql_detected": self.graphql_detected,
            "technologies": [t.to_dict() for t in self.technologies],
            "metadata": self.metadata,
            "summary": self.summary(),
        }

    def save(self, path: str):
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2, default=str)
