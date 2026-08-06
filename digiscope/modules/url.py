"""Low-impact URL breakdown and redirect/header inspection."""

from __future__ import annotations

import ipaddress
from typing import Any
from urllib.parse import parse_qsl, quote, urljoin, urlsplit

from bs4 import BeautifulSoup

from ..models import Section
from .base import ScanContext, add_entity, add_failure, add_finding, add_link, new_result, register

SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
)


def _title(html: str) -> str:
    try:
        soup = BeautifulSoup(html[:250_000], "html.parser")
        return soup.title.get_text(" ", strip=True)[:240] if soup.title else ""
    except Exception:
        return ""


@register(
    "url",
    "URL analysis",
    "URL component breakdown, bounded redirect chain, response headers/title and host pivot.",
    category="web",
    sources=["target HTTP(S)"],
)
async def run_url(ctx: ScanContext, target: str) -> Any:
    result = new_result("url", target)
    raw = target.strip()
    candidate = raw if "://" in raw else f"https://{raw}"
    parsed = urlsplit(candidate)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        result.status = "error"
        result.error = "Only HTTP(S) URLs with a host are supported"
        return result
    host = parsed.hostname.lower().rstrip(".")
    query_keys = [key for key, _value in parse_qsl(parsed.query, keep_blank_values=True)]
    result.sections.append(
        Section(
            "URL breakdown",
            "kv",
            {
                "scheme": parsed.scheme,
                "host": host,
                "port": parsed.port or (443 if parsed.scheme == "https" else 80),
                "path": parsed.path or "/",
                "query_keys": query_keys,
                "fragment_present": bool(parsed.fragment),
                "username_present": bool(parsed.username),
            },
            "Query values are intentionally not echoed into the report.",
        )
    )
    add_entity(result, "domain", host, "url.host", label="URL host")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        result.entities[-1].type = "ip"
        result.entities[-1].label = "URL IP host"

    chain = []
    current = candidate
    for index in range(5):
        response = await ctx.fetcher.get_text(current, follow_redirects=False, source=f"URL hop {index + 1}", max_bytes=600_000)
        row = {
            "hop": index + 1,
            "requested_url": current,
            "final_url": response.url or current,
            "status": response.status,
            "title": _title(response.text),
            "content_type": response.content_type,
            "server": response.headers.get("server", ""),
            "location": response.headers.get("location", ""),
            "security_headers": {header: bool(response.headers.get(header)) for header in SECURITY_HEADERS},
            "elapsed_ms": response.elapsed_ms,
        }
        if response.error:
            row["error"] = response.error
        chain.append(row)
        location = response.headers.get("location", "") if response.status in {301, 302, 303, 307, 308} else ""
        if not location:
            break
        next_url = urljoin(current, location)
        if next_url == current:
            break
        current = next_url
    result.sections.append(Section("Redirect chain & response", "table", chain, "Maximum five public HTTP(S) hops; no crawling."))
    if chain and chain[-1].get("error") and not chain[-1].get("status"):
        add_failure(result, "target HTTP(S)", chain[-1]["error"])
    if parsed.scheme == "http":
        add_finding(result, "URL uses cleartext HTTP", "medium", 6, "The supplied URL is not HTTPS.", "URL")
    if len(chain) >= 5 and chain[-1].get("location"):
        add_finding(result, "Redirect chain limit reached", "low", 2, "Further redirects were not followed.", "URL")
    final_headers = chain[-1].get("security_headers", {}) if chain else {}
    if chain and chain[-1].get("status") and parsed.scheme == "https":
        missing = [key for key, present in final_headers.items() if not present]
        if missing:
            add_finding(result, "Response security headers missing", "low", min(8, len(missing) * 2), ", ".join(missing), "URL")

    for row in chain:
        location = row.get("location")
        if location:
            try:
                redirect_host = urlsplit(urljoin(row.get("requested_url", candidate), location)).hostname
            except ValueError:
                redirect_host = None
            if redirect_host and redirect_host.lower() != host:
                add_entity(result, "domain", redirect_host, "url.redirect", label="Redirect host", confidence=0.9)
    add_link(result, "Wayback URL history", f"https://web.archive.org/web/*/{quote(candidate, safe='')}", "history", "Internet Archive")
    add_link(result, "urlscan.io search", f"https://urlscan.io/search/#{quote('page.url:' + candidate, safe='')}", "threat-intel", "urlscan.io")
    add_link(result, "VirusTotal URL view", f"https://www.virustotal.com/gui/url/{quote(candidate, safe='')}", "threat-intel", "VirusTotal")
    result.coverage.update({"hops": len(chain), "redirects": max(0, len(chain) - 1)})
    return result


__all__ = ["run_url"]
