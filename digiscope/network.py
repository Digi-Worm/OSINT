"""Shared, defensive network helpers.

All modules use one AsyncClient per scan.  Requests are bounded, use HTTP/1.1
for compatibility with strict egress proxies, and are converted into a
structured response instead of raising into the scan engine.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional
from urllib.parse import urlsplit

import httpx

USER_AGENT = "DigiScope/1.0 (+https://github.com/Digi-Worm/OSINT; passive research)"


@dataclass
class FetchResponse:
    ok: bool
    status: int = 0
    url: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    text: str = ""
    data: Any = None
    error: str = ""
    elapsed_ms: int = 0
    source: str = ""

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "")


class AsyncFetcher:
    """One safe, semaphore-bounded HTTP client for a scan."""

    def __init__(
        self,
        timeout: float = 8.0,
        concurrency: int = 8,
        safe_mode: bool = True,
        user_agent: str = USER_AGENT,
    ) -> None:
        self.timeout = max(1.0, min(float(timeout), 60.0))
        self.safe_mode = safe_mode
        self.user_agent = user_agent
        self.semaphore = asyncio.Semaphore(max(1, min(int(concurrency), 32)))
        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self) -> "AsyncFetcher":
        context = ssl.create_default_context()
        # Some sandboxes/proxies drop HTTP/2 ALPN negotiation.  Explicitly
        # offering HTTP/1.1 keeps public lookups reliable without disabling TLS
        # verification.
        try:
            context.set_alpn_protocols(["http/1.1"])
        except (AttributeError, NotImplementedError):  # pragma: no cover
            pass
        self._client = httpx.AsyncClient(
            http2=False,
            verify=context,
            follow_redirects=False,
            timeout=httpx.Timeout(self.timeout, connect=min(self.timeout, 5.0)),
            headers={"User-Agent": self.user_agent, "Accept": "*/*"},
            limits=httpx.Limits(max_connections=32, max_keepalive_connections=8),
        )
        return self

    async def __aexit__(self, *_exc: Any) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    @staticmethod
    def _blocked_host(host: str) -> bool:
        hostname = host.rstrip(".").lower()
        if hostname in {"localhost", "localhost.localdomain", "ip6-localhost"}:
            return True
        if hostname.endswith((".local", ".localhost", ".internal", ".lan")):
            return True
        try:
            address = ipaddress.ip_address(hostname)
        except ValueError:
            return False
        return bool(
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_reserved
            or address.is_unspecified
        )

    async def _resolves_to_blocked_address(self, host: str, port: int) -> bool:
        """Best-effort DNS rebinding/SSRF guard for hostname destinations."""

        try:
            records = await asyncio.wait_for(
                asyncio.to_thread(socket.getaddrinfo, host, port, type=socket.SOCK_STREAM),
                timeout=min(2.0, self.timeout / 2),
            )
        except (OSError, asyncio.TimeoutError):
            # Let the HTTP client return the useful DNS/connection error when
            # resolution itself is unavailable.
            return False
        return any(self._blocked_host(str(item[4][0])) for item in records if item and len(item) > 4)

    def _validate_url(self, url: str) -> Optional[str]:
        try:
            parsed = urlsplit(url)
            host = parsed.hostname
        except ValueError:
            return "malformed URL"
        if parsed.scheme not in {"http", "https"} or not host:
            return "only HTTP(S) URLs are allowed"
        if parsed.username or parsed.password:
            return "URLs with embedded credentials are blocked"
        if self.safe_mode and self._blocked_host(host):
            return "safe mode blocked a private or local destination"
        try:
            port = parsed.port
        except ValueError:
            return "invalid URL port"
        if port is not None and not 1 <= port <= 65535:
            return "invalid URL port"
        return None

    async def request(
        self,
        method: str,
        url: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        json_body: Any = None,
        data_body: Any = None,
        follow_redirects: bool = False,
        max_bytes: int = 1_000_000,
        source: str = "",
    ) -> FetchResponse:
        """Perform a request and *never* raise a network exception."""

        error = self._validate_url(url)
        if error:
            return FetchResponse(False, url=url, error=error, source=source)
        if self._client is None:
            return FetchResponse(False, url=url, error="HTTP client is not open", source=source)
        if self.safe_mode:
            parsed = urlsplit(url)
            try:
                port = parsed.port or (443 if parsed.scheme == "https" else 80)
            except ValueError:
                port = 0
            if parsed.hostname and port and await self._resolves_to_blocked_address(parsed.hostname, port):
                return FetchResponse(False, url=url, error="safe mode blocked a hostname resolving to a private or local address", source=source)

        request_headers = {"User-Agent": self.user_agent}
        if headers:
            request_headers.update(headers)
        started = time.perf_counter()
        try:
            async with self.semaphore:
                response = await self._client.request(
                    method.upper(),
                    url,
                    params=params,
                    headers=request_headers,
                    json=json_body,
                    data=data_body,
                    follow_redirects=follow_redirects,
                )
                raw = response.content
                truncated = len(raw) > max_bytes
                if truncated:
                    raw = raw[:max_bytes]
                encoding = response.encoding or "utf-8"
                text = raw.decode(encoding, errors="replace")
                result = FetchResponse(
                    ok=200 <= response.status_code < 400,
                    status=response.status_code,
                    url=str(response.url),
                    headers={key.lower(): value for key, value in response.headers.items()},
                    text=text,
                    elapsed_ms=int((time.perf_counter() - started) * 1000),
                    source=source,
                )
                if truncated:
                    result.error = f"response truncated at {max_bytes:,} bytes"
                return result
        except (httpx.HTTPError, OSError, asyncio.TimeoutError) as exc:
            return FetchResponse(
                False,
                url=url,
                error=f"{type(exc).__name__}: {str(exc)[:240]}",
                elapsed_ms=int((time.perf_counter() - started) * 1000),
                source=source,
            )
        except Exception as exc:  # pragma: no cover - defensive last resort
            return FetchResponse(
                False,
                url=url,
                error=f"unexpected {type(exc).__name__}: {str(exc)[:240]}",
                elapsed_ms=int((time.perf_counter() - started) * 1000),
                source=source,
            )

    async def get_json(
        self,
        url: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        follow_redirects: bool = False,
        source: str = "",
        max_bytes: int = 1_000_000,
    ) -> FetchResponse:
        response = await self.request(
            "GET",
            url,
            params=params,
            headers={"Accept": "application/json", **(headers or {})},
            follow_redirects=follow_redirects,
            source=source,
            max_bytes=max_bytes,
        )
        if response.text:
            try:
                response.data = json.loads(response.text)
            except (TypeError, ValueError):
                if response.ok:
                    response.error = response.error or "source returned non-JSON content"
        return response

    async def post_form(
        self,
        url: str,
        *,
        payload: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        source: str = "",
        max_bytes: int = 1_000_000,
    ) -> FetchResponse:
        response = await self.request(
            "POST",
            url,
            params=params,
            headers={"Accept": "application/json", **(headers or {})},
            data_body=payload or {},
            source=source,
            max_bytes=max_bytes,
        )
        if response.text:
            try:
                response.data = json.loads(response.text)
            except (TypeError, ValueError):
                if response.ok:
                    response.error = response.error or "source returned non-JSON content"
        return response

    async def post_json(
        self,
        url: str,
        *,
        payload: Any = None,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        source: str = "",
        max_bytes: int = 1_000_000,
    ) -> FetchResponse:
        response = await self.request(
            "POST",
            url,
            params=params,
            headers={"Accept": "application/json", **(headers or {})},
            json_body=payload,
            source=source,
            max_bytes=max_bytes,
        )
        if response.text:
            try:
                response.data = json.loads(response.text)
            except (TypeError, ValueError):
                if response.ok:
                    response.error = response.error or "source returned non-JSON content"
        return response

    async def get_text(
        self,
        url: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        follow_redirects: bool = False,
        source: str = "",
        max_bytes: int = 1_000_000,
    ) -> FetchResponse:
        return await self.request(
            "GET",
            url,
            params=params,
            headers=headers,
            follow_redirects=follow_redirects,
            source=source,
            max_bytes=max_bytes,
        )


__all__ = ["AsyncFetcher", "FetchResponse", "USER_AGENT"]
