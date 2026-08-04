"""IP allocation, reputation and passive InternetDB intelligence."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from typing import Any, Dict
from urllib.parse import quote

from ..models import Section
from .base import (
    ScanContext,
    add_entity,
    add_failure,
    add_finding,
    add_link,
    add_timeline,
    new_result,
    register,
)


def _valid_ip(value: str) -> str:
    return str(ipaddress.ip_address(value.strip("[]")))


async def _reverse_dns(ip: str) -> Dict[str, Any]:
    try:
        host, aliases, _addresses = await asyncio.to_thread(socket.gethostbyaddr, ip)
        return {"ok": True, "hostname": host, "aliases": aliases}
    except (OSError, socket.herror, socket.gaierror) as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {str(exc)[:160]}"}


async def _geo(ctx: ScanContext, ip: str) -> Dict[str, Any]:
    response = await ctx.fetcher.get_json(
        f"http://ip-api.com/json/{quote(ip, safe=':')}",
        params={"fields": "status,message,continent,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,reverse,mobile,proxy,hosting"},
        source="ip-api.com",
    )
    if not response.ok or not isinstance(response.data, dict):
        return {"ok": False, "error": response.error or f"HTTP {response.status}"}
    if response.data.get("status") != "success":
        return {"ok": False, "error": response.data.get("message", "geolocation failed")}
    return {"ok": True, **response.data}


async def _rdap(ctx: ScanContext, ip: str) -> Dict[str, Any]:
    url = f"https://rdap.org/ip/{quote(ip, safe=':') }"
    response = await ctx.fetcher.get_json(url, follow_redirects=True, source="rdap.org")
    if not response.ok or not isinstance(response.data, dict):
        return {"ok": False, "url": url, "error": response.error or f"HTTP {response.status}"}
    payload = response.data
    events = [
        {"action": item.get("eventAction", "event"), "date": item.get("eventDate", "")}
        for item in payload.get("events", []) or []
        if isinstance(item, dict) and item.get("eventDate")
    ]
    abuse_contacts = []
    for entity in payload.get("entities", []) or []:
        if not isinstance(entity, dict) or "abuse" not in (entity.get("roles") or []):
            continue
        vcard = entity.get("vcardArray")
        for item in vcard[1] if isinstance(vcard, list) and len(vcard) > 1 else []:
            if isinstance(item, list) and item and item[0] in {"email", "tel"} and len(item) > 3:
                abuse_contacts.append(str(item[3]))
    return {
        "ok": True,
        "url": url,
        "handle": payload.get("handle", ""),
        "name": payload.get("name", ""),
        "start_address": payload.get("startAddress", ""),
        "end_address": payload.get("endAddress", ""),
        "ip_version": payload.get("ipVersion", ""),
        "type": payload.get("type", ""),
        "country": payload.get("country", ""),
        "status": payload.get("status", []),
        "events": events,
        "abuse_contacts": abuse_contacts,
    }


async def _bgpview(ctx: ScanContext, ip: str) -> Dict[str, Any]:
    url = f"https://api.bgpview.io/ip/{quote(ip, safe=':')}"
    response = await ctx.fetcher.get_json(url, source="bgpview.io")
    if not response.ok or not isinstance(response.data, dict):
        return {"ok": False, "url": url, "error": response.error or f"HTTP {response.status}"}
    data = response.data.get("data", response.data)
    prefixes = data.get("prefixes", []) if isinstance(data, dict) else []
    asns = []
    for item in prefixes or []:
        if not isinstance(item, dict):
            continue
        for key in ("asn", "asn_info"):
            value = item.get(key)
            if isinstance(value, dict):
                asns.append(value)
            elif value:
                asns.append({"asn": value})
    return {"ok": True, "url": url, "prefixes": prefixes[:50], "asns": asns[:20]}


async def _internetdb(ctx: ScanContext, ip: str) -> Dict[str, Any]:
    url = f"https://internetdb.shodan.io/{quote(ip, safe=':')}"
    response = await ctx.fetcher.get_json(url, source="Shodan InternetDB")
    if not response.ok or not isinstance(response.data, dict):
        return {"ok": False, "url": url, "error": response.error or f"HTTP {response.status}"}
    return {"ok": True, "url": url, **response.data}


async def _shodan_full(ctx: ScanContext, ip: str) -> Dict[str, Any]:
    key = ctx.api_key("shodan_api_key")
    if not key:
        return {"skipped": True, "error": "optional Shodan API key not configured"}
    response = await ctx.fetcher.get_json(
        f"https://api.shodan.io/shodan/host/{quote(ip, safe=':')}",
        params={"key": key, "minify": "false"},
        source="Shodan host API",
        max_bytes=1_500_000,
    )
    if not response.ok or not isinstance(response.data, dict):
        return {"ok": False, "error": response.error or f"HTTP {response.status}"}
    return {"ok": True, **response.data}


async def _abuseipdb(ctx: ScanContext, ip: str) -> Dict[str, Any]:
    key = ctx.api_key("abuseipdb_api_key")
    if not key:
        return {"ok": False, "skipped": True, "error": "optional AbuseIPDB API key not configured"}
    response = await ctx.fetcher.get_json(
        "https://api.abuseipdb.com/api/v2/check",
        params={"ipAddress": ip, "maxAgeInDays": "90"},
        headers={"Key": key, "Accept": "application/json"},
        source="AbuseIPDB",
    )
    if not response.ok or not isinstance(response.data, dict):
        return {"ok": False, "error": response.error or f"HTTP {response.status}"}
    return {"ok": True, **(response.data.get("data", response.data) or {})}


@register(
    "ip",
    "IP infrastructure & reputation",
    "Reverse DNS, geolocation, RDAP allocation, ASN context, InternetDB and optional abuse reputation.",
    category="infrastructure",
    sources=["reverse DNS", "ip-api.com", "rdap.org", "bgpview.io", "Shodan InternetDB", "AbuseIPDB (key)"],
)
async def run_ip(ctx: ScanContext, target: str) -> Any:
    result = new_result("ip", target)
    try:
        ip = _valid_ip(target)
    except ValueError:
        result.status = "error"
        result.error = "Not a valid IPv4 or IPv6 address"
        return result

    reverse, geo, rdap, bgp, internetdb, shodan, abuse = await asyncio.gather(
        _reverse_dns(ip),
        _geo(ctx, ip),
        _rdap(ctx, ip),
        _bgpview(ctx, ip),
        _internetdb(ctx, ip),
        _shodan_full(ctx, ip),
        _abuseipdb(ctx, ip),
    )
    add_entity(result, "ip", ip, "ip.input", pivot=False, label="Investigated IP")

    if reverse.get("ok"):
        result.sections.append(Section("Reverse DNS", "kv", reverse, "System resolver lookup"))
        for name in [reverse.get("hostname"), *(reverse.get("aliases") or [])]:
            add_entity(result, "domain", name, "ip.reverse_dns", label="PTR hostname")
    else:
        result.sections.append(Section("Reverse DNS", "kv", {"status": "No PTR observed", "detail": reverse.get("error", "")}, "Negative results are not conclusive."))

    if geo.get("ok"):
        result.sections.append(Section("Geolocation & network", "kv", {key: value for key, value in geo.items() if key != "ok"}, "ip-api.com response; approximate, not a person location.", "https://ip-api.com/"))
        if geo.get("as"):
            add_entity(result, "asn", geo["as"], "ip-api.com", pivot=False, label="Observed ASN")
    else:
        add_failure(result, "ip-api.com", geo.get("error", "unavailable"))

    if rdap.get("ok"):
        result.sections.append(Section("RDAP allocation", "kv", {key: value for key, value in rdap.items() if key not in {"ok", "url"}}, "RIR registration data", rdap.get("url", "")))
        for event in rdap.get("events", []):
            add_timeline(result, event.get("date"), f"RDAP {event.get('action', 'event')}", "rdap.org")
    else:
        add_failure(result, "rdap.org", rdap.get("error", "unavailable"))

    if bgp.get("ok"):
        result.sections.append(Section("BGP / ASN", "records", bgp.get("asns") or bgp.get("prefixes", []), "Public routing context", bgp.get("url", "")))
        for asn in bgp.get("asns", []) or []:
            if isinstance(asn, dict) and asn.get("asn"):
                add_entity(result, "asn", asn["asn"], "bgpview.io", pivot=False, label=asn.get("name", "ASN"))
    else:
        add_failure(result, "bgpview.io", bgp.get("error", "unavailable"))

    if internetdb.get("ok"):
        ports = internetdb.get("ports") or []
        vulns = internetdb.get("vulns") or []
        result.sections.append(Section("Shodan InternetDB (passive snapshot)", "kv", {key: internetdb.get(key, []) for key in ("ip", "hostnames", "ports", "cpes", "tags", "vulns")}, "This is a public historical snapshot; DigiScope does not port-scan targets.", internetdb.get("url", "")))
        for hostname in internetdb.get("hostnames", []) or []:
            add_entity(result, "domain", hostname, "internetdb.shodan.io", label="InternetDB hostname")
        if vulns:
            add_finding(result, "Known CVE identifiers in InternetDB", "high", min(25, 5 + len(vulns) * 3), ", ".join(str(value) for value in vulns[:20]), "Shodan InternetDB")
        if ports:
            add_finding(result, "Public services observed in InternetDB", "medium", min(12, len(ports) * 2), "Ports: " + ", ".join(str(port) for port in ports[:20]), "Shodan InternetDB")
    else:
        add_failure(result, "Shodan InternetDB", internetdb.get("error", "unavailable"))

    if shodan.get("skipped"):
        result.notes.append("Full Shodan host details skipped: supply a per-scan Shodan key to enable the optional enrichment; InternetDB ran without one.")
    elif shodan.get("ok"):
        result.sections.append(Section("Shodan host enrichment", "records", shodan.get("data", []) or shodan.get("ports", []) or [shodan], "Optional keyed historical host data; key is not persisted."))
    else:
        add_failure(result, "Shodan host API", shodan.get("error", "unavailable"))

    if abuse.get("skipped"):
        result.notes.append("AbuseIPDB skipped: supply a per-scan key to enable the optional reputation lookup.")
    elif abuse.get("ok"):
        result.sections.append(Section("AbuseIPDB reputation", "kv", {key: value for key, value in abuse.items() if key != "ok"}, "Optional keyed source; key is not persisted."))
        confidence = int(abuse.get("abuseConfidenceScore") or 0)
        if confidence:
            add_finding(result, "AbuseIPDB reports abuse confidence", "high" if confidence >= 50 else "medium", min(20, confidence // 5), f"Confidence score: {confidence}/100", "AbuseIPDB")
    else:
        add_failure(result, "AbuseIPDB", abuse.get("error", "unavailable"))

    add_link(result, "Shodan InternetDB", f"https://internetdb.shodan.io/{quote(ip, safe=':')}", "snapshot", "Shodan")
    add_link(result, "RDAP allocation", f"https://rdap.org/ip/{quote(ip, safe=':')}", "registration", "rdap.org")
    add_link(result, "BGPView lookup", f"https://bgpview.io/ip/{quote(ip, safe=':')}", "routing", "BGPView")
    add_link(result, "AbuseIPDB analyst page", f"https://www.abuseipdb.com/check/{quote(ip, safe=':')}", "reputation", "AbuseIPDB")
    add_link(result, "VirusTotal IP view", f"https://www.virustotal.com/gui/ip-address/{quote(ip, safe=':')}", "threat-intel", "VirusTotal")

    result.coverage.update({"sources_checked": 7, "optional_shodan": not shodan.get("skipped", False), "optional_abuseipdb": not abuse.get("skipped", False), "ports_observed": len(internetdb.get("ports", []) or []) if internetdb.get("ok") else 0})
    return result


__all__ = ["run_ip"]
