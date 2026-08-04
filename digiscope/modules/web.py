"""Bounded, same-host passive web-surface mapper for authorised assets.

This module is intentionally opt-in. It reads robots.txt/sitemaps, performs
small GET-only requests with a delay, stays on the supplied host, skips forms
and binary assets, and stores metadata/links rather than page bodies.
"""

from __future__ import annotations

import asyncio
import hashlib
import html
import re
import urllib.robotparser
from collections import deque
from typing import Any, Dict, List, Set, Tuple
from urllib.parse import urljoin, urlsplit, urlunsplit

from bs4 import BeautifulSoup

from ..models import ModuleResult, Section
from .base import ScanContext, add_entity, add_failure, add_finding, add_link, new_result, register

SKIP_EXTENSIONS = {
    ".7z",
    ".avi",
    ".bin",
    ".css",
    ".csv",
    ".doc",
    ".docx",
    ".gif",
    ".ico",
    ".jpeg",
    ".jpg",
    ".js",
    ".m4a",
    ".mp3",
    ".mp4",
    ".pdf",
    ".png",
    ".svg",
    ".tar",
    ".tgz",
    ".woff",
    ".woff2",
    ".xls",
    ".xlsx",
    ".zip",
}
SECURITY_HEADERS = ("strict-transport-security", "content-security-policy", "x-content-type-options", "referrer-policy")


def _host(value: str) -> str:
    candidate = value.strip()
    if "://" not in candidate:
        candidate = f"https://{candidate}"
    try:
        return (urlsplit(candidate).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def _normalise_url(value: str, host: str) -> str:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return ""
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.hostname.lower().rstrip(".") != host:
        return ""
    path = parsed.path or "/"
    if any(path.lower().endswith(extension) for extension in SKIP_EXTENSIONS):
        return ""
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def _title_and_links(text: str, current_url: str, host: str) -> Tuple[str, List[str]]:
    try:
        soup = BeautifulSoup(text[:350_000], "html.parser")
    except Exception:
        return "", []
    title = soup.title.get_text(" ", strip=True)[:240] if soup.title else ""
    links: List[str] = []
    for anchor in soup.find_all("a", href=True):
        href = str(anchor.get("href", "")).strip()
        if not href or href.startswith(("#", "mailto:", "tel:", "javascript:", "data:")):
            continue
        candidate = _normalise_url(urljoin(current_url, html.unescape(href)), host)
        if candidate and candidate not in links:
            links.append(candidate)
        if len(links) >= 80:
            break
    return title, links


def _sitemap_locations(text: str, host: str) -> List[str]:
    values = []
    for match in re.findall(r"<loc[^>]*>\s*(.*?)\s*</loc>", text, flags=re.I | re.S):
        candidate = _normalise_url(html.unescape(match.strip()), host)
        if candidate and candidate not in values:
            values.append(candidate)
        if len(values) >= 200:
            break
    return values


async def _get_first(ctx: ScanContext, urls: List[str], source: str, max_bytes: int = 200_000):
    for url in urls:
        response = await ctx.fetcher.get_text(url, source=source, max_bytes=max_bytes)
        if response.ok or response.status:
            return response
    return response if urls else None


@register(
    "web",
    "Authorized web surface map",
    "Opt-in same-host robots/sitemap/link mapper for assets you own or are authorized to assess; GET-only and bounded.",
    category="web",
    sources=["target robots.txt", "target sitemap.xml", "same-host HTML links"],
)
async def run_web(ctx: ScanContext, target: str) -> ModuleResult:
    host = _host(target)
    result = new_result("web", host or target)
    if not ctx.key("authorized_asset_crawl", False):
        result.status = "partial"
        result.notes.append("Authorized asset crawl is disabled. Enable the explicit opt-in before running same-host requests.")
        return result
    if not host or "." not in host:
        result.status = "error"
        result.error = "An internet domain or URL host is required"
        return result

    max_pages = max(5, min(int(ctx.key("crawl_max_pages", 30)), 100))
    max_depth = max(0, min(int(ctx.key("crawl_depth", 1)), 2))
    delay = max(0.1, min(float(ctx.key("crawl_delay_ms", 250)) / 1000.0, 2.0))
    base = target if "://" in target else f"https://{host}/"
    base = _normalise_url(base, host) or f"https://{host}/"
    robots_url = f"{urlsplit(base).scheme}://{host}/robots.txt"
    robots_response = await ctx.fetcher.get_text(robots_url, source="asset robots.txt", max_bytes=100_000)
    robots = urllib.robotparser.RobotFileParser()
    robots.set_url(robots_url)
    sitemap_urls: List[str] = []
    robots_available = bool(robots_response.ok and robots_response.text)
    if robots_available:
        robots.parse(robots_response.text.splitlines())
        for line in robots_response.text.splitlines():
            if line.lower().startswith("sitemap:"):
                candidate = _normalise_url(line.split(":", 1)[1].strip(), host)
                if candidate:
                    sitemap_urls.append(candidate)
    else:
        result.notes.append("robots.txt was unavailable; crawl stayed same-host and page-bounded but robots restrictions could not be evaluated.")
        result.status = "partial"
    sitemap_urls.extend([f"{urlsplit(base).scheme}://{host}/sitemap.xml", f"{urlsplit(base).scheme}://{host}/sitemap_index.xml"])
    sitemap_urls = list(dict.fromkeys(sitemap_urls))[:8]

    sitemap_pages: List[str] = []
    for sitemap_url in sitemap_urls:
        if robots_available and not robots.can_fetch("DigiScope", sitemap_url):
            continue
        sitemap_response = await ctx.fetcher.get_text(sitemap_url, source="asset sitemap", max_bytes=500_000)
        if sitemap_response.ok:
            sitemap_pages.extend(_sitemap_locations(sitemap_response.text, host))
    sitemap_pages = list(dict.fromkeys(sitemap_pages))[: max_pages * 3]

    queue = deque([(base, 0)])
    for url in sitemap_pages:
        queue.append((url, 0))
    queued: Set[str] = {url for url, _depth in queue}
    seen: Set[str] = set()
    pages: List[Dict[str, Any]] = []
    link_edges: List[Dict[str, str]] = []
    skipped_robots = 0
    last_request = 0.0

    while queue and len(pages) < max_pages:
        current, depth = queue.popleft()
        if current in seen or depth > max_depth:
            continue
        seen.add(current)
        if robots_available and not robots.can_fetch("DigiScope", current):
            skipped_robots += 1
            continue
        wait_for = delay - (asyncio.get_running_loop().time() - last_request)
        if last_request and wait_for > 0:
            await asyncio.sleep(wait_for)
        response = await ctx.fetcher.get_text(current, source="authorized asset page", max_bytes=350_000)
        last_request = asyncio.get_running_loop().time()
        row: Dict[str, Any] = {
            "url": current,
            "status": response.status,
            "content_type": response.content_type,
            "title": "",
            "server": response.headers.get("server", ""),
            "security_headers": {header: bool(response.headers.get(header)) for header in SECURITY_HEADERS},
            "sha256": hashlib.sha256(response.text.encode("utf-8", errors="replace")).hexdigest() if response.text else "",
            "bytes_sampled": len(response.text.encode("utf-8", errors="replace")),
            "depth": depth,
            "outlinks": 0,
            "error": response.error,
        }
        if response.ok and "html" in response.content_type.lower():
            title, links = _title_and_links(response.text, current, host)
            row["title"] = title
            row["outlinks"] = len(links)
            for link in links:
                link_edges.append({"source": current, "target": link})
                if depth < max_depth and link not in queued and len(queued) < max_pages * 5:
                    queued.add(link)
                    queue.append((link, depth + 1))
        pages.append(row)
        add_entity(result, "url", current, "web.crawl", pivot=False, label="Same-host page")
    if not pages:
        add_failure(result, "authorized asset page", "no pages responded")
    elif pages[0].get("status") == 200 and pages[0].get("content_type", "").lower().find("html") >= 0:
        missing = [header for header, present in pages[0].get("security_headers", {}).items() if not present]
        if missing:
            add_finding(result, "Asset response security headers missing", "info", 0, ", ".join(missing), "authorized asset crawl")

    result.sections.append(
        Section(
            "Crawl policy",
            "kv",
            {
                "authorized_opt_in": True,
                "host_scope": host,
                "robots_checked": robots_available,
                "sitemaps_checked": len(sitemap_urls),
                "max_pages": max_pages,
                "max_depth": max_depth,
                "delay_seconds": delay,
                "method": "GET only; same host; no forms, authentication, query strings or binary assets.",
            },
            "Page bodies are not stored in the result; only bounded metadata, hashes and links are retained.",
        )
    )
    result.sections.append(Section("Page inventory", "table", pages, "Same-host pages reached within the explicit crawl budget."))
    result.sections.append(Section("Discovered link edges", "table", link_edges[:300], "URLs are normalised without query strings or fragments."))
    result.sections.append(Section("Sitemap URLs", "tags", sitemap_pages[:200], "Public sitemap locations observed during the crawl."))
    for page in pages[:100]:
        add_link(result, page["title"] or page["url"], page["url"], "discovered-page", "authorized asset crawl")
    result.coverage.update(
        {
            "pages_checked": len(pages),
            "pages_discovered": len(queued),
            "link_edges": len(link_edges),
            "skipped_robots": skipped_robots,
            "robots_available": robots_available,
        }
    )
    return result


__all__ = ["run_web"]
