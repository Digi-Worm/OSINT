"""Passive domain, DNS, certificate and HTTP posture intelligence."""

from __future__ import annotations

import asyncio
import json
import re
import uuid
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import quote, urlsplit

from bs4 import BeautifulSoup

from ..models import ModuleResult, Section
from ..network import FetchResponse
from .base import (
    ScanContext,
    add_entity,
    add_failure,
    add_finding,
    add_link,
    add_timeline,
    dedupe_strings,
    new_result,
    register,
)

DKIM_SELECTORS = (
    "default",
    "selector1",
    "selector2",
    "google",
    "k1",
    "mail",
    "s1",
    "s2",
    "dkim",
    "mandrill",
    "smtp",
    "sendgrid",
    "protonmail",
)
SECURITY_HEADERS = (
    ("strict-transport-security", "HSTS"),
    ("content-security-policy", "CSP"),
    ("x-content-type-options", "X-Content-Type-Options"),
    ("referrer-policy", "Referrer-Policy"),
    ("permissions-policy", "Permissions-Policy"),
)


def _hostname(value: str) -> str:
    candidate = value.strip()
    if "://" in candidate:
        parsed = urlsplit(candidate)
        candidate = parsed.hostname or candidate
    candidate = candidate.split("/", 1)[0].split(":", 1)[0]
    return candidate.strip(". ").lower()


def _valid_subdomain(value: str, domain: str) -> bool:
    value = value.lower().strip().lstrip("*.").rstrip(".")
    return value == domain or value.endswith(f".{domain}")


def _parse_title(html: str) -> str:
    if not html:
        return ""
    try:
        soup = BeautifulSoup(html[:250_000], "html.parser")
        return soup.title.get_text(" ", strip=True)[:240] if soup.title else ""
    except Exception:
        return ""


def _organization_metadata(page: str, domain: str) -> Dict[str, Any]:
    """Extract public Organization JSON-LD and official profile links."""

    organization: Dict[str, Any] = {}
    public_links = []
    try:
        soup = BeautifulSoup(page[:350_000], "html.parser")
    except Exception:
        return {"organization": organization, "public_links": public_links}
    for script in soup.find_all("script", attrs={"type": re.compile("ld\\+json", re.I)}):
        try:
            data = json.loads(script.get_text(strip=True))
        except (TypeError, ValueError):
            continue
        candidates = data if isinstance(data, list) else [data]
        if isinstance(data, dict) and isinstance(data.get("@graph"), list):
            candidates.extend(data["@graph"])
        for item in candidates:
            if not isinstance(item, dict):
                continue
            types = item.get("@type", [])
            types = types if isinstance(types, list) else [types]
            if not any("organization" in str(value).lower() or str(value).lower() in {"localbusiness", "corporation"} for value in types):
                continue
            for key in ("name", "url", "logo", "email", "telephone", "address", "description"):
                if item.get(key) not in (None, ""):
                    organization[key] = item[key]
            same_as = item.get("sameAs", [])
            organization["sameAs"] = same_as if isinstance(same_as, list) else [same_as]
            break
    for anchor in soup.find_all("a", href=True):
        href = str(anchor.get("href", "")).strip()
        lower = href.lower()
        if href.startswith(("http://", "https://")) and any(host in lower for host in ("linkedin.com", "github.com", "facebook.com", "instagram.com", "x.com", "youtube.com", "maps.google.", "google.com/maps")):
            if href not in public_links:
                public_links.append(href)
        if len(public_links) >= 30:
            break
    if organization.get("sameAs"):
        public_links.extend(value for value in organization["sameAs"] if isinstance(value, str) and value not in public_links)
    organization["sameAs"] = [value for value in organization.get("sameAs", []) if isinstance(value, str) and value.startswith(("http://", "https://"))][:30]
    return {"organization": organization, "public_links": public_links[:30]}


async def _http_fingerprint(ctx: ScanContext, domain: str) -> Dict[str, Any]:
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}/"
        response = await ctx.fetcher.get_text(
            url,
            follow_redirects=False,
            source=f"HTTP {scheme.upper()}",
            max_bytes=600_000,
        )
        if response.ok or response.status:
            headers = response.headers
            html_lower = response.text.lower()
            tech = []
            server = headers.get("server", "")
            powered = headers.get("x-powered-by", "")
            if server:
                tech.append(f"Server: {server}")
            if powered:
                tech.append(f"X-Powered-By: {powered}")
            for marker, technology in (
                ("wp-content", "WordPress"),
                ("/cdn-cgi/", "Cloudflare"),
                ("__next_data__", "Next.js"),
                ("drupal-settings-json", "Drupal"),
                ("shopify", "Shopify"),
                ("webpack", "Webpack"),
            ):
                if marker in html_lower and technology not in tech:
                    tech.append(technology)
            security = {label: bool(headers.get(header)) for header, label in SECURITY_HEADERS}
            organization = _organization_metadata(response.text, domain)
            return {
                "url": response.url or url,
                "scheme": scheme,
                "status": response.status,
                "title": _parse_title(response.text),
                "server": server,
                "powered_by": powered,
                "content_type": response.content_type,
                "redirect": headers.get("location", ""),
                "security_headers": security,
                "technology_hints": tech,
                "organization": organization.get("organization", {}),
                "public_links": organization.get("public_links", []),
                "elapsed_ms": response.elapsed_ms,
                "error": response.error,
            }
        if response.error and scheme == "http":
            return {"url": url, "error": response.error}
    return {"url": f"https://{domain}/", "error": "HTTPS and HTTP probes were unreachable"}


async def _rdap(ctx: ScanContext, domain: str) -> Dict[str, Any]:
    url = f"https://rdap.org/domain/{quote(domain, safe='') }"
    response = await ctx.fetcher.get_json(url, follow_redirects=True, source="rdap.org")
    if not response.ok or not isinstance(response.data, dict):
        return {"ok": False, "url": url, "error": response.error or f"HTTP {response.status}"}
    payload = response.data
    events = []
    for event in payload.get("events", []) or []:
        if isinstance(event, dict) and event.get("eventDate"):
            events.append({"action": event.get("eventAction", "event"), "date": event["eventDate"]})
    nameservers = []
    for server in payload.get("nameservers", []) or []:
        if isinstance(server, dict) and server.get("ldhName"):
            nameservers.append(server["ldhName"].rstrip("."))
    registrar = ""
    for entity in payload.get("entities", []) or []:
        if "registrar" in (entity.get("roles") or []):
            for item in entity.get("vcardArray", ["vcard", []])[1] if isinstance(entity.get("vcardArray"), list) else []:
                if isinstance(item, list) and item and item[0] == "fn" and len(item) > 3:
                    registrar = str(item[3])
                    break
    return {
        "ok": True,
        "url": url,
        "name": payload.get("ldhName") or payload.get("name") or domain,
        "handle": payload.get("handle", ""),
        "status": payload.get("status", []),
        "registrar": registrar,
        "nameservers": nameservers,
        "events": events,
        "secure_dns": payload.get("secureDNS", {}),
    }


async def _commoncrawl(ctx: ScanContext, domain: str) -> FetchResponse:
    """Query the newest Common Crawl CDX index for historical hostnames."""

    collections = await ctx.fetcher.get_json("https://index.commoncrawl.org/collinfo.json", source="Common Crawl collections", max_bytes=500_000)
    if not collections.ok or not isinstance(collections.data, list) or not collections.data:
        return FetchResponse(False, status=collections.status, url=collections.url, error=collections.error or "Common Crawl collections unavailable", source="Common Crawl")
    latest = collections.data[0] if isinstance(collections.data[0], dict) else {}
    api_url = str(latest.get("cdx-api", ""))
    if not api_url:
        return FetchResponse(False, error="Common Crawl collection did not provide a CDX API", source="Common Crawl")
    response = await ctx.fetcher.get_text(
        api_url,
        params={"url": f"*.{domain}/*", "output": "json", "filter": "status:200", "collapse": "urlkey", "limit": int(ctx.key("max_subdomains", 100)) * 10},
        source="Common Crawl CDX",
        max_bytes=2_000_000,
    )
    if response.text:
        rows = []
        for line in response.text.splitlines():
            try:
                item = json.loads(line)
            except (TypeError, ValueError):
                continue
            if isinstance(item, dict):
                rows.append(item)
        response.data = rows
    return response


async def _certificates(ctx: ScanContext, domain: str) -> Dict[str, Any]:
    """Union passive hostnames from CT, archives and public DNS datasets."""

    max_subdomains = max(1, min(int(ctx.key("max_subdomains", 100)), 500))
    source_requests = [
        (
            "crt.sh",
            ctx.fetcher.get_json(
                "https://crt.sh/",
                params={"q": f"%.{domain}", "output": "json"},
                source="crt.sh",
                max_bytes=2_000_000,
            ),
        ),
        (
            "Cert Spotter",
            ctx.fetcher.get_json(
                "https://api.certspotter.com/v1/issuances",
                params={"domain": domain, "include_subdomains": "true", "expand": "dns_names"},
                source="Cert Spotter",
                max_bytes=2_000_000,
            ),
        ),
        (
            "Wayback CDX",
            ctx.fetcher.get_json(
                "https://web.archive.org/cdx/search/cdx",
                params={
                    "url": f"*.{domain}/*",
                    "output": "json",
                    "fl": "original,timestamp,mimetype,statuscode",
                    "filter": "statuscode:200",
                    "collapse": "urlkey",
                    "limit": max_subdomains * 10,
                },
                source="Wayback CDX",
                max_bytes=2_000_000,
            ),
        ),
        (
            "HackerTarget",
            ctx.fetcher.get_text(
                "https://api.hackertarget.com/hostsearch/",
                params={"q": domain},
                source="HackerTarget hostsearch",
                max_bytes=500_000,
            ),
        ),
        (
            "BufferOver",
            ctx.fetcher.get_json(
                "https://dns.bufferover.run/dns",
                params={"q": f".{domain}"},
                source="BufferOver DNS dataset",
                max_bytes=1_000_000,
            ),
        ),
        (
            "urlscan.io",
            ctx.fetcher.get_json(
                "https://urlscan.io/api/v1/search/",
                params={"q": f"domain:{domain}", "size": min(max_subdomains, 100)},
                source="urlscan.io public search",
                max_bytes=2_000_000,
            ),
        ),
        (
            "Anubis-DB",
            ctx.fetcher.get_json(
                f"https://anubisdb.com/anubis/subdomains/{quote(domain, safe='')}",
                source="Anubis-DB public subdomains",
                max_bytes=2_000_000,
            ),
        ),
        (
            "ThreatMiner",
            ctx.fetcher.get_json(
                "https://api.threatminer.org/v2/domain.php",
                params={"q": domain, "rt": "5"},
                source="ThreatMiner domain subdomains",
                max_bytes=1_000_000,
            ),
        ),
        (
            "AlienVault OTX",
            ctx.fetcher.get_json(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{quote(domain, safe='')}/passive_dns",
                source="AlienVault OTX passive DNS",
                max_bytes=1_500_000,
            ),
        ),
        ("Common Crawl", _commoncrawl(ctx, domain)),
    ]
    responses = await asyncio.gather(*(request for _source, request in source_requests))
    names = set()
    source_map: Dict[str, set] = {}
    source_status = []
    records = []
    issuers = set()
    failures = []

    def add_name(value: Any, source: str) -> None:
        candidate = str(value or "").strip().lower().lstrip("*.").rstrip(".")
        if not candidate or not _valid_subdomain(candidate, domain):
            return
        names.add(candidate)
        source_map.setdefault(candidate, set()).add(source)

    for (source, _request), response in zip(source_requests, responses):
        found_before = len(names)
        if not response.ok:
            error = response.error or f"HTTP {response.status}"
            failures.append(f"{source}: {error}")
            source_status.append({"source": source, "status": "unreachable", "records": 0, "error": error})
            continue
        data = response.data
        if source == "crt.sh" and isinstance(data, list):
            for item in data:
                if not isinstance(item, dict):
                    continue
                raw_names = str(item.get("name_value", "")).splitlines()
                valid_names = []
                for raw_name in raw_names:
                    before = len(names)
                    add_name(raw_name, source)
                    normalized = str(raw_name).strip().lower().lstrip("*.").rstrip(".")
                    if len(names) > before and normalized in names:
                        valid_names.append(normalized)
                issuer = item.get("issuer_name") or ""
                if issuer:
                    issuers.add(str(issuer))
                if len(records) < 150:
                    records.append(
                        {
                            "source": source,
                            "common_name": item.get("common_name", ""),
                            "names": valid_names,
                            "issuer": issuer,
                            "not_before": item.get("not_before", ""),
                            "not_after": item.get("not_after", ""),
                            "serial": item.get("serial_number", ""),
                        }
                    )
        elif source == "Cert Spotter" and isinstance(data, list):
            for item in data:
                if not isinstance(item, dict):
                    continue
                valid_names = []
                for raw_name in item.get("dns_names", []) or []:
                    add_name(raw_name, source)
                    normalized = str(raw_name).strip().lower().lstrip("*.").rstrip(".")
                    if normalized in names and _valid_subdomain(normalized, domain):
                        valid_names.append(normalized)
                issuer_data = item.get("issuer") or {}
                issuer = issuer_data.get("name", "") if isinstance(issuer_data, dict) else str(issuer_data)
                if issuer:
                    issuers.add(str(issuer))
                if len(records) < 150:
                    records.append(
                        {
                            "source": source,
                            "common_name": valid_names[0] if valid_names else "",
                            "names": valid_names,
                            "issuer": issuer,
                            "not_before": item.get("not_before", ""),
                            "not_after": item.get("not_after", ""),
                            "serial": item.get("id", ""),
                        }
                    )
        elif source == "Wayback CDX" and isinstance(data, list):
            header = data[0] if data and isinstance(data[0], list) else []
            try:
                original_index = header.index("original")
            except ValueError:
                original_index = 0
            for row in data[1:] if header else data:
                if not isinstance(row, list) or len(row) <= original_index:
                    continue
                original = str(row[original_index])
                try:
                    add_name(urlsplit(original).hostname or "", source)
                except ValueError:
                    continue
        elif source == "HackerTarget":
            text = response.text or ""
            if text.lower().startswith(("error", "please")):
                failures.append(f"{source}: {text[:180]}")
            else:
                for line in text.splitlines():
                    if "," in line:
                        add_name(line.split(",", 1)[0], source)
        elif source == "BufferOver" and isinstance(data, dict):
            for key in ("FDNS_A", "RDNS"):
                for value in data.get(key, []) or []:
                    for part in str(value).split(","):
                        add_name(part, source)
        elif source == "urlscan.io" and isinstance(data, dict):
            for item in data.get("results", []) or []:
                if not isinstance(item, dict):
                    continue
                page = item.get("page") or {}
                task = item.get("task") or {}
                for value in (page.get("domain"), task.get("domain"), page.get("url"), task.get("url")):
                    try:
                        add_name(urlsplit(str(value)).hostname or str(value), source)
                    except ValueError:
                        continue
        elif source == "Anubis-DB":
            values = data.get("subdomains", data.get("results", data)) if isinstance(data, dict) else data
            for item in values or []:
                if isinstance(item, dict):
                    add_name(item.get("subdomain") or item.get("hostname") or item.get("domain"), source)
                else:
                    add_name(item, source)
        elif source == "ThreatMiner" and isinstance(data, dict):
            for item in data.get("results", []) or []:
                add_name(item.get("domain") if isinstance(item, dict) else item, source)
        elif source == "AlienVault OTX" and isinstance(data, dict):
            for item in data.get("passive_dns", []) or []:
                if isinstance(item, dict):
                    add_name(item.get("hostname") or item.get("domain"), source)
        elif source == "Common Crawl" and isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    try:
                        add_name(urlsplit(str(item.get("url", ""))).hostname or "", source)
                    except ValueError:
                        continue
        else:
            failures.append(f"{source}: source returned an unexpected response shape")
        source_status.append({"source": source, "status": "responded", "records": max(0, len(names) - found_before)})

    ordered = sorted(names)
    source_rows = [
        {"hostname": name, "sources": sorted(source_map.get(name, set()))}
        for name in ordered[:max_subdomains]
    ]
    return {
        "ok": bool(names) or any(item["status"] == "responded" for item in source_status),
        "url": "https://crt.sh/",
        "subdomains": ordered[:max_subdomains],
        "total_unique_subdomains": len(ordered),
        "truncated": len(ordered) > max_subdomains,
        "issuers": sorted(issuers),
        "certificates": records,
        "source_rows": source_rows,
        "source_status": source_status,
        "responded_sources": sum(item["status"] == "responded" for item in source_status),
        "failures": failures,
    }


async def _resolve_passive_hosts(ctx: ScanContext, subdomains: Any) -> List[Dict[str, Any]]:
    """Resolve a bounded number of observed names to A/AAAA records only."""

    if not ctx.key("resolve_subdomains", True):
        return []
    names = list(dict.fromkeys(str(value) for value in (subdomains or [])))[:100]
    limiter = asyncio.Semaphore(16)

    async def resolve(name: str) -> Dict[str, Any]:
        async with limiter:
            answers = await ctx.dns.query_many(name, ["A", "AAAA"])
        addresses = []
        sources = []
        errors = []
        for answer in answers:
            addresses.extend(answer.values)
            if answer.source:
                sources.append(answer.source)
            if answer.error:
                errors.append(f"{answer.record_type}: {answer.error}")
        return {
            "hostname": name,
            "addresses": dedupe_strings(addresses),
            "resolver": ", ".join(dedupe_strings(sources)),
            "status": "resolved" if addresses else "no A/AAAA answer",
            "error": "; ".join(errors)[:300],
        }

    return list(await asyncio.gather(*(resolve(name) for name in names)))


async def _wildcard_dns(ctx: ScanContext, domain: str) -> Dict[str, Any]:
    label = f"_digiscope-{uuid.uuid4().hex[:12]}.{domain}"
    answers = await ctx.dns.query_many(label, ["A", "AAAA"])
    addresses = dedupe_strings([value for answer in answers for value in answer.values])
    return {
        "probe": label,
        "wildcard_observed": bool(addresses),
        "addresses": addresses,
        "resolvers": dedupe_strings([answer.source for answer in answers if answer.source]),
        "errors": [f"{answer.record_type}: {answer.error}" for answer in answers if answer.error],
    }


async def _dns_wordlist_enumeration(ctx: ScanContext, domain: str, wildcard: Dict[str, Any]) -> Dict[str, Any]:
    """Explicit, rate-limited DNS label verification for authorized domains."""

    if not ctx.key("authorized_dns_enum", False):
        return {"enabled": False, "checked": 0, "found": [], "note": "Authorized DNS wordlist enumeration is disabled."}
    raw = str(ctx.key("dns_wordlist", "") or "")
    if raw.strip():
        labels = re.split(r"[\s,;]+", raw)
    else:
        wordlist_path = Path(__file__).resolve().parent.parent / "data" / "subdomains.txt"
        try:
            labels = wordlist_path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            return {"enabled": True, "checked": 0, "found": [], "note": f"Bundled wordlist unavailable: {exc}"}
    clean = []
    seen = set()
    for label in labels:
        label = label.strip().lower()
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) or label in seen:
            continue
        seen.add(label)
        clean.append(label)
        if len(clean) >= max(100, min(int(ctx.key("dns_enum_max", 1000)), 5000)):
            break
    delay = max(0.05, min(float(ctx.key("dns_enum_delay_ms", 100)) / 1000.0, 1.0))
    limiter = asyncio.Semaphore(max(1, min(int(ctx.key("concurrency", 8)), 16)))
    rate_lock = asyncio.Lock()
    next_allowed = 0.0
    wildcard_addresses = set(wildcard.get("addresses", []) or [])
    found: List[Dict[str, Any]] = []
    wildcard_filtered = 0
    errors = 0

    async def probe(label: str) -> None:
        nonlocal next_allowed, wildcard_filtered, errors
        async with rate_lock:
            now = asyncio.get_running_loop().time()
            wait = max(0.0, next_allowed - now)
            next_allowed = max(now, next_allowed) + delay
        if wait:
            await asyncio.sleep(wait)
        name = f"{label}.{domain}"
        async with limiter:
            answers = await ctx.dns.query_many(name, ["A", "AAAA", "CNAME"])
        values = dedupe_strings([value for answer in answers for value in answer.values])
        errors += sum(bool(answer.error) for answer in answers)
        if not values:
            return
        if wildcard_addresses and wildcard_addresses.intersection(values):
            wildcard_filtered += 1
            return
        found.append(
            {
                "hostname": name,
                "values": values,
                "record_types": [answer.record_type for answer in answers if answer.values],
                "resolver": ", ".join(dedupe_strings([answer.source for answer in answers if answer.source])),
            }
        )

    await asyncio.gather(*(probe(label) for label in clean))
    found.sort(key=lambda row: row["hostname"])
    return {
        "enabled": True,
        "wordlist_source": "custom per-scan list" if raw.strip() else "bundled 1,200-label list",
        "checked": len(clean),
        "found": found[:500],
        "wildcard_filtered": wildcard_filtered,
        "dns_errors": errors,
        "delay_ms": int(delay * 1000),
    }


async def _wayback(ctx: ScanContext, domain: str) -> Dict[str, Any]:
    url = "https://archive.org/wayback/available"
    response = await ctx.fetcher.get_json(
        url,
        params={"url": f"https://{domain}/"},
        source="Internet Archive Wayback",
    )
    if not response.ok or not isinstance(response.data, dict):
        return {"ok": False, "url": url, "error": response.error or f"HTTP {response.status}"}
    archived = response.data.get("archived_snapshots", {}).get("closest", {})
    return {
        "ok": True,
        "url": url,
        "available": bool(archived.get("available")),
        "timestamp": archived.get("timestamp", ""),
        "snapshot": archived.get("url", ""),
    }


@register(
    "domain",
    "Domain & DNS posture",
    "DNS records, RDAP registration, certificate transparency, HTTP fingerprint and historical availability.",
    category="infrastructure",
    sources=["DNS / DNS-over-HTTPS", "rdap.org", "crt.sh", "Internet Archive", "target HTTP(S)"],
)
async def run_domain(ctx: ScanContext, target: str) -> ModuleResult:
    domain = _hostname(target)
    result = new_result("domain", domain)
    if not domain or "." not in domain:
        result.status = "error"
        result.error = "A DNS domain or hostname is required"
        return result

    record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "CAA", "DS"]
    dns_answers, rdap, certificates, wayback, http_fingerprint = await asyncio.gather(
        ctx.dns.query_many(domain, record_types),
        _rdap(ctx, domain),
        _certificates(ctx, domain),
        _wayback(ctx, domain),
        _http_fingerprint(ctx, domain),
    )
    resolved_hosts, wildcard = await asyncio.gather(
        _resolve_passive_hosts(ctx, certificates.get("subdomains", [])),
        _wildcard_dns(ctx, domain),
    )
    wordlist_enum = await _dns_wordlist_enumeration(ctx, domain, wildcard)

    dns_rows = []
    answers: Dict[str, Any] = {}
    dns_failures = 0
    for answer in dns_answers:
        answers[answer.record_type] = answer
        if not answer.ok:
            dns_failures += 1
        dns_rows.append(
            {
                "record": answer.record_type,
                "values": answer.values,
                "resolver": answer.source,
                "dnssec_ad": answer.dnssec,
                "error": answer.error,
            }
        )
    result.sections.append(
        Section(
            "DNS records", "table", dns_rows, "UDP resolver with Google DoH fallback", "https://developers.google.com/speed/public-dns/docs/doh/json"
        )
    )

    ips = []
    for record_type in ("A", "AAAA"):
        ips.extend(answers.get(record_type).values if answers.get(record_type) else [])
    ips = dedupe_strings(ips)
    for ip in ips:
        add_entity(result, "ip", ip, "domain.dns", pivot=True, label=f"{domain} address")

    mx_values = answers.get("MX").values if answers.get("MX") else []
    ns_values = answers.get("NS").values if answers.get("NS") else []
    cname_values = answers.get("CNAME").values if answers.get("CNAME") else []
    for mx in mx_values:
        add_entity(result, "domain", mx, "domain.mx", pivot=False, label="Mail exchanger")
    for nameserver in ns_values:
        add_entity(result, "domain", nameserver, "domain.ns", pivot=False, label="Authoritative nameserver")
    for cname in cname_values:
        add_entity(result, "domain", cname, "domain.cname", pivot=False, label="CNAME target")

    txt_values = answers.get("TXT").values if answers.get("TXT") else []
    spf = [value for value in txt_values if value.lower().startswith("v=spf1")]
    dmarc_answer = await ctx.dns.query(f"_dmarc.{domain}", "TXT")
    dmarc = dmarc_answer.values
    public_emails = sorted({
        match.lower()
        for value in [*txt_values, *dmarc]
        for match in re.findall(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", value, flags=re.I)
    })
    for public_email in public_emails:
        add_entity(result, "email", public_email, "domain.dns.txt", pivot=True, label="Public email in DNS TXT/DMARC", confidence=0.95)
    dkim_answers = await asyncio.gather(
        *(ctx.dns.query(f"{selector}._domainkey.{domain}", "TXT") for selector in DKIM_SELECTORS)
    )
    dkim_found = {
        selector: answer.values
        for selector, answer in zip(DKIM_SELECTORS, dkim_answers)
        if answer.ok and answer.values
    }
    mta_sts = await ctx.fetcher.get_text(
        f"https://mta-sts.{domain}/.well-known/mta-sts.txt",
        source="MTA-STS",
        max_bytes=30_000,
    )
    security_data = {
        "SPF": spf or "Not observed",
        "Public emails in DNS TXT": public_emails or "None observed",
        "DMARC": dmarc or "Not observed",
        "DKIM selectors found": dkim_found or "No common selector observed",
        "MTA-STS": mta_sts.text.strip()[:2_000] if mta_sts.ok else "Not observed",
        "DNSSEC / DS": (answers.get("DS").values if answers.get("DS") else []) or "Not observed",
        "CAA": (answers.get("CAA").values if answers.get("CAA") else []) or "Not observed",
    }
    result.sections.append(
        Section(
            "Mail & DNS security", "kv", security_data, "Configuration observations; absence is not proof of compromise."
        )
    )

    if answers.get("MX") and answers["MX"].ok and not mx_values:
        add_finding(result, "No MX record observed", "medium", 9, "Mail deliverability may be unavailable or delegated elsewhere.", "DNS")
    if answers.get("TXT") and answers["TXT"].ok and not spf:
        add_finding(result, "SPF policy not observed", "low", 4, "No v=spf1 TXT record was returned.", "DNS")
    if dmarc_answer.ok and not dmarc:
        add_finding(result, "DMARC policy not observed", "low", 4, "No _dmarc TXT record was returned.", "DNS")
    if answers.get("DS") and answers["DS"].ok and not answers["DS"].values:
        add_finding(result, "DNSSEC DS record not observed", "info", 2, "The parent zone did not return a DS record.", "DNS")
    if mta_sts.status and not mta_sts.ok:
        result.notes.append("MTA-STS policy endpoint was not reachable; absence is inconclusive.")

    if rdap.get("ok"):
        result.sections.append(Section("RDAP registration", "kv", {key: value for key, value in rdap.items() if key not in {"ok", "url"}}, "Machine-readable registration data", rdap.get("url", "")))
        for event in rdap.get("events", []):
            add_timeline(result, event.get("date"), f"RDAP {event.get('action', 'event')}", "rdap.org")
        for nameserver in rdap.get("nameservers", []):
            add_entity(result, "domain", nameserver, "domain.rdap", pivot=False, label="RDAP nameserver")
    else:
        add_failure(result, "rdap.org", rdap.get("error", "unavailable"))

    if certificates.get("source_status"):
        result.sections.append(Section("Passive subdomain source coverage", "table", certificates["source_status"], "Union of public CT, historical DNS/URL datasets and certificate sources; a source failure never stops the scan."))
    if certificates.get("source_rows"):
        result.sections.append(Section("Subdomain source map", "table", certificates["source_rows"], "Each hostname is annotated with the passive sources that observed it."))
    if certificates.get("ok"):
        result.sections.append(Section("Certificate Transparency", "table", certificates.get("certificates", []), "Certificate observations from crt.sh and Cert Spotter", "https://crt.sh/"))
        result.sections.append(Section("Observed subdomains", "tags", certificates.get("subdomains", []), "Names unioned from passive sources; wildcard names are normalised."))
        for subdomain in certificates.get("subdomains", []):
            # Passive names are valuable analyst pivots but are not
            # automatically fanned out into dozens of follow-up requests.
            add_entity(result, "domain", subdomain, "domain.passive", pivot=False, label="Passive subdomain observation", confidence=0.85)
        for cert in certificates.get("certificates", [])[:30]:
            add_timeline(result, cert.get("not_before"), "Certificate first observed", cert.get("source", "passive CT"), cert.get("common_name", ""))
        result.coverage.update(
            {
                "passive_subdomains": certificates.get("total_unique_subdomains", 0),
                "passive_sources_responded": certificates.get("responded_sources", 0),
            }
        )
    else:
        failure = "; ".join(certificates.get("failures", [])) or "no passive subdomain source responded"
        add_failure(result, "passive subdomain sources", failure)

    result.sections.append(Section("Resolved passive hosts", "table", resolved_hosts, "A/AAAA lookups for observed names only; no ports or web probes are performed."))
    result.sections.append(Section("Wildcard DNS detection", "kv", wildcard, "A random-label DNS probe helps distinguish wildcard answers from concrete subdomains."))
    result.sections.append(Section("Authorized DNS wordlist enumeration", "kv", {key: value for key, value in wordlist_enum.items() if key != "found"}, "Disabled by default. Enable only for a domain you own or are explicitly authorized to assess."))
    result.sections.append(Section("Wordlist DNS hits", "table", wordlist_enum.get("found", []), "A/AAAA/CNAME answers only; this does not prove that a web service is present."))
    for hit in wordlist_enum.get("found", []):
        add_entity(result, "domain", hit["hostname"], "domain.dns_wordlist", pivot=False, label="Authorized DNS wordlist hit", confidence=0.9)
        for address in hit.get("values", []):
            add_entity(result, "ip", address, "domain.dns_wordlist", pivot=False, label=f"Address for {hit['hostname']}", confidence=0.9)
    for host_row in resolved_hosts:
        for address in host_row.get("addresses", []):
            add_entity(result, "ip", address, "domain.subdomain_dns", pivot=False, label=f"Address for {host_row['hostname']}", confidence=0.9)
    if wildcard.get("wildcard_observed"):
        result.notes.append("Wildcard DNS answered for a random label; some discovered names may resolve to the same default service.")

    if wayback.get("ok"):
        result.sections.append(Section("Wayback availability", "kv", {key: value for key, value in wayback.items() if key not in {"ok", "url"}}, "Closest public archive snapshot", wayback.get("snapshot") or wayback.get("url", "")))
        if wayback.get("timestamp"):
            add_timeline(result, wayback["timestamp"], "Closest Wayback snapshot", "Internet Archive", wayback.get("snapshot", ""))
    else:
        add_failure(result, "Internet Archive", wayback.get("error", "unavailable"))

    if http_fingerprint.get("status"):
        result.sections.append(Section("Live HTTP fingerprint", "records", [http_fingerprint], "A single low-impact GET to HTTPS, then HTTP fallback; no crawling."))
        headers = http_fingerprint.get("security_headers", {})
        if http_fingerprint.get("scheme") == "https":
            missing = [label for label, present in headers.items() if not present]
            if missing:
                add_finding(result, "HTTP security headers missing", "low", min(10, len(missing) * 2), ", ".join(missing), "HTTP")
        if http_fingerprint.get("redirect"):
            add_link(result, "Observed HTTP redirect", http_fingerprint["redirect"], "redirect", "HTTP")
    else:
        add_failure(result, "target HTTP(S)", http_fingerprint.get("error", "unreachable"))

    organization = http_fingerprint.get("organization", {}) or {}
    if organization:
        result.sections.append(Section("Public organization metadata", "kv", organization, "Structured data published by the target website; not independently verified."))
        organization_name = organization.get("name")
        organization_url = organization.get("url", "")
        same_host = False
        try:
            same_host = (urlsplit(str(organization_url)).hostname or "").lower().rstrip(".") == domain
        except ValueError:
            pass
        if organization_name:
            add_entity(result, "company", organization_name, "domain.organization_jsonld", pivot=same_host, label="Website Organization metadata", confidence=0.8)
        for public_link in http_fingerprint.get("public_links", [])[:30]:
            add_link(result, "Public organization profile", public_link, "organization-profile", "target JSON-LD/HTML")

    add_link(result, "RDAP registration",
 f"https://rdap.org/domain/{quote(domain, safe='')}", "registration", "rdap.org")
    add_link(result, "Certificate Transparency search", f"https://crt.sh/?q=%25.{quote(domain, safe='')}", "certificates", "crt.sh")
    add_link(result, "Wayback snapshots", f"https://web.archive.org/web/*/{quote(domain, safe='')}", "history", "Internet Archive")
    add_link(result, "urlscan.io search", f"https://urlscan.io/search/#{quote('domain:' + domain, safe='')}", "threat-intel", "urlscan.io")
    add_link(result, "VirusTotal domain view", f"https://www.virustotal.com/gui/domain/{quote(domain, safe='')}", "threat-intel", "VirusTotal")
    add_link(result, "SecurityTrails analyst view", f"https://securitytrails.com/domain/{quote(domain, safe='')}/history/a", "analyst", "SecurityTrails")

    result.coverage.update(
        {
            "dns_records_checked": len(record_types),
            "dns_failures": dns_failures,
            "ips_found": len(ips),
            "public_dns_emails": len(public_emails),
            "sources_checked": 5,
            "passive_subdomain_sources": len(certificates.get("source_status", [])),
            "resolved_passive_hosts": sum(row.get("status") == "resolved" for row in resolved_hosts),
            "wildcard_dns_observed": wildcard.get("wildcard_observed", False),
            "authorized_dns_enum": wordlist_enum.get("enabled", False),
            "dns_wordlist_checked": wordlist_enum.get("checked", 0),
            "dns_wordlist_hits": len(wordlist_enum.get("found", [])),
        }
    )
    if dns_failures == len(record_types):
        result.status = "partial"
    return result


__all__ = ["run_domain"]
