"""Passive domain, DNS, certificate and HTTP posture intelligence."""

from __future__ import annotations

import asyncio
from typing import Any, Dict
from urllib.parse import quote, urlsplit

from bs4 import BeautifulSoup

from ..models import ModuleResult, Section
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

    add_link(result, "RDAP registration", f"https://rdap.org/domain/{quote(domain, safe='')}", "registration", "rdap.org")
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
            "sources_checked": 5,
            "passive_subdomain_sources": len(certificates.get("source_status", [])),
        }
    )
    if dns_failures == len(record_types):
        result.status = "partial"
    return result


__all__ = ["run_domain"]
