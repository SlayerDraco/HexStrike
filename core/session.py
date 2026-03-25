"""
HexStrike v2 - Session Manager
Authentication-aware HTTP session.
Supports: cookies, headers, form-based login automation.
All modules use this single session for consistency.
"""

from __future__ import annotations
import httpx
import asyncio
from typing import Dict, Optional, Any
from rich.console import Console

console = Console()


class HexSession:
    """
    Central HTTP session used by every module.
    Carries auth state across all requests.
    """

    def __init__(
        self,
        cookies: Optional[str] = None,      # "NAME=val; NAME2=val2"
        headers: Optional[Dict[str, str]] = None,
        login_url: Optional[str] = None,
        login_data: Optional[Dict[str, str]] = None,  # form POST fields
        proxy: Optional[str] = None,
        verify_ssl: bool = False,
        timeout: int = 15,
        user_agent: str = "Mozilla/5.0 (HexStrike/2.0; Parrot OS) AppleWebKit/537.36",
    ):
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.proxy = proxy

        # Build base headers
        self._headers: Dict[str, str] = {
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml,application/json,*/*;q=0.9",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
        }

        # Inject custom headers
        if headers:
            self._headers.update(headers)

        # Parse cookie string into dict
        self._cookies: Dict[str, str] = {}
        if cookies:
            for part in cookies.split(";"):
                part = part.strip()
                if "=" in part:
                    k, v = part.split("=", 1)
                    self._cookies[k.strip()] = v.strip()

        # Build sync httpx client
        self._client = self._build_client()

        # Optional login automation
        if login_url and login_data:
            self._do_login(login_url, login_data)

    def _build_client(self) -> httpx.Client:
        proxies = {"http://": self.proxy, "https://": self.proxy} if self.proxy else None
        return httpx.Client(
            headers=self._headers,
            cookies=self._cookies,
            verify=self.verify_ssl,
            timeout=self.timeout,
            follow_redirects=True,
            proxies=proxies,
        )

    def _do_login(self, login_url: str, login_data: Dict[str, str]):
        """Perform form-based login and capture the session cookie."""
        console.print(f"[cyan]→ Authenticating at {login_url}...[/cyan]")
        try:
            # First GET to collect any CSRF tokens
            resp = self._client.get(login_url)
            # Try to find csrf token
            import re
            csrf_match = re.search(
                r'(?:name=["\']_?csrf[_\-]?token["\']|name=["\']authenticity_token["\'])\s+value=["\']([^"\']+)["\']',
                resp.text, re.I
            )
            if csrf_match:
                login_data["_csrf_token"] = csrf_match.group(1)
                console.print(f"[dim]  CSRF token captured: {csrf_match.group(1)[:20]}...[/dim]")

            resp = self._client.post(login_url, data=login_data)
            if resp.status_code in [200, 302]:
                console.print(f"[green]✔ Login submitted (HTTP {resp.status_code}). Session cookies captured.[/green]")
                # Merge response cookies back
                for k, v in resp.cookies.items():
                    self._cookies[k] = v
            else:
                console.print(f"[yellow]⚠ Login returned {resp.status_code} — may have failed.[/yellow]")
        except Exception as e:
            console.print(f"[red]✘ Login automation failed: {e}[/red]")

    def get(self, url: str, **kwargs) -> httpx.Response:
        return self._client.get(url, **kwargs)

    def post(self, url: str, **kwargs) -> httpx.Response:
        return self._client.post(url, **kwargs)

    def request(self, method: str, url: str, **kwargs) -> httpx.Response:
        return self._client.request(method, url, **kwargs)

    def close(self):
        self._client.close()

    @property
    def cookie_header(self) -> str:
        return "; ".join(f"{k}={v}" for k, v in self._cookies.items())

    @property
    def is_authenticated(self) -> bool:
        return bool(self._cookies)

    def inject_cookie(self, name: str, value: str):
        self._cookies[name] = value
        self._client.cookies.set(name, value)

    def inject_header(self, name: str, value: str):
        self._headers[name] = value
        self._client = self._build_client()


class AsyncHexSession:
    """
    Async version for parallel scanning (recon, fuzzing, IDOR).
    """

    def __init__(self, sync_session: HexSession):
        self._headers = sync_session._headers.copy()
        self._cookies = sync_session._cookies.copy()
        self.verify_ssl = sync_session.verify_ssl
        self.timeout = sync_session.timeout
        self.proxy = sync_session.proxy

    def build(self) -> httpx.AsyncClient:
        proxies = {"http://": self.proxy, "https://": self.proxy} if self.proxy else None
        return httpx.AsyncClient(
            headers=self._headers,
            cookies=self._cookies,
            verify=self.verify_ssl,
            timeout=self.timeout,
            follow_redirects=True,
            proxies=proxies,
        )


def session_from_args(
    cookie: Optional[str] = None,
    header: Optional[list] = None,     # ["Authorization: Bearer xxx", ...]
    login_url: Optional[str] = None,
    login_user: Optional[str] = None,
    login_pass: Optional[str] = None,
    login_user_field: str = "username",
    login_pass_field: str = "password",
    proxy: Optional[str] = None,
) -> HexSession:
    """Factory — build a HexSession from CLI args."""
    extra_headers: Dict[str, str] = {}
    if header:
        for h in header:
            if ":" in h:
                k, v = h.split(":", 1)
                extra_headers[k.strip()] = v.strip()

    login_data = None
    if login_url and login_user and login_pass:
        login_data = {login_user_field: login_user, login_pass_field: login_pass}

    return HexSession(
        cookies=cookie,
        headers=extra_headers if extra_headers else None,
        login_url=login_url,
        login_data=login_data,
        proxy=proxy,
    )
