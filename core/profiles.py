"""
HexStrike v2 - Scan Profiles
Controls which modules run, speed, concurrency, and intensity.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Optional
import json
from pathlib import Path


@dataclass
class Profile:
    name: str
    description: str
    intensity: str              # stealth | normal | aggressive
    concurrency: int            # max parallel async workers
    timeout: int                # per-request timeout (seconds)
    delay: float                # seconds between requests (0 = no delay)
    modules: List[str]          # which modules to run
    nmap_flags: List[str]       # nmap CLI flags
    crawl_depth: int            # how deep to crawl links
    max_urls: int               # max URLs to scan per target
    fuzz_params: bool           # run param discovery
    run_msf: bool               # run Metasploit
    run_bruteforce: bool        # run Hydra
    run_idor: bool              # run IDOR tests
    run_api: bool               # run API-specific tests
    run_biz_logic: bool         # run business logic tests

    def to_dict(self) -> dict:
        return self.__dict__.copy()

    @classmethod
    def from_dict(cls, d: dict) -> "Profile":
        return cls(**d)


# ─── Built-in profiles ───────────────────────────────────────────────────────

PROFILES: dict[str, Profile] = {

    "recon": Profile(
        name="recon",
        description="Passive + active recon only. No exploitation.",
        intensity="stealth",
        concurrency=5,
        timeout=10,
        delay=0.5,
        modules=["toolcheck", "recon"],
        nmap_flags=["-sS", "-T2", "--version-light", "-sV"],
        crawl_depth=1,
        max_urls=30,
        fuzz_params=False,
        run_msf=False,
        run_bruteforce=False,
        run_idor=False,
        run_api=True,
        run_biz_logic=False,
    ),

    "stealth": Profile(
        name="stealth",
        description="Full scan but slow and low-noise. Evades basic IDS.",
        intensity="stealth",
        concurrency=3,
        timeout=15,
        delay=1.5,
        modules=["toolcheck", "recon", "exploit"],
        nmap_flags=["-sS", "-T2", "-O", "--version-light", "-sV", "--script=banner"],
        crawl_depth=2,
        max_urls=50,
        fuzz_params=True,
        run_msf=False,
        run_bruteforce=False,
        run_idor=True,
        run_api=True,
        run_biz_logic=False,
    ),

    "full": Profile(
        name="full",
        description="Complete scan — all modules, all tests, aggressive.",
        intensity="aggressive",
        concurrency=20,
        timeout=20,
        delay=0.0,
        modules=["toolcheck", "recon", "exploit", "api", "biz_logic"],
        nmap_flags=["-sS", "-T4", "-A", "-sV", "--script=banner,http-headers,http-title,vulners"],
        crawl_depth=4,
        max_urls=200,
        fuzz_params=True,
        run_msf=True,
        run_bruteforce=True,
        run_idor=True,
        run_api=True,
        run_biz_logic=True,
    ),

    "normal": Profile(
        name="normal",
        description="Balanced speed and coverage. Default profile.",
        intensity="normal",
        concurrency=10,
        timeout=15,
        delay=0.2,
        modules=["toolcheck", "recon", "exploit"],
        nmap_flags=["-sS", "-T3", "-O", "-sV", "--script=banner,http-headers,http-title"],
        crawl_depth=2,
        max_urls=100,
        fuzz_params=True,
        run_msf=False,
        run_bruteforce=True,
        run_idor=True,
        run_api=True,
        run_biz_logic=False,
    ),

    "api": Profile(
        name="api",
        description="API-focused scan. REST, GraphQL, Swagger detection.",
        intensity="normal",
        concurrency=15,
        timeout=10,
        delay=0.1,
        modules=["recon", "api"],
        nmap_flags=["-sS", "-T3", "-sV", "-p", "80,443,8080,8443,3000,4000,5000"],
        crawl_depth=3,
        max_urls=150,
        fuzz_params=True,
        run_msf=False,
        run_bruteforce=False,
        run_idor=True,
        run_api=True,
        run_biz_logic=True,
    ),
}


def get_profile(name: str) -> Profile:
    """Return a built-in profile or load custom from profiles/ directory."""
    if name in PROFILES:
        return PROFILES[name]
    # Try loading from profiles/ directory
    custom_path = Path(__file__).parent.parent / "profiles" / f"{name}.json"
    if custom_path.exists():
        with open(custom_path) as f:
            return Profile.from_dict(json.load(f))
    raise ValueError(
        f"Unknown profile '{name}'. Available: {', '.join(PROFILES.keys())}"
    )


def list_profiles() -> List[dict]:
    return [
        {"name": p.name, "description": p.description, "intensity": p.intensity}
        for p in PROFILES.values()
    ]
