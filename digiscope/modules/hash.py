"""File-hash identification and reputation pivots."""

from __future__ import annotations

import re
from typing import Any, Dict
from urllib.parse import quote

from ..models import Section
from .base import ScanContext, add_failure, add_finding, add_link, new_result, register

ALGORITHMS = {32: "MD5", 40: "SHA-1", 64: "SHA-256", 128: "SHA-512"}
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


async def _virustotal(ctx: ScanContext, digest: str) -> Dict[str, Any]:
    key = ctx.api_key("virustotal_api_key")
    if not key:
        return {"skipped": True, "error": "optional VirusTotal API key not configured"}
    response = await ctx.fetcher.get_json(
        f"https://www.virustotal.com/api/v3/files/{quote(digest, safe='')}",
        headers={"x-apikey": key},
        source="VirusTotal",
        max_bytes=500_000,
    )
    if response.status == 404:
        return {"ok": True, "found": False}
    if not response.ok or not isinstance(response.data, dict):
        return {"ok": False, "error": response.error or f"HTTP {response.status}"}
    attributes = ((response.data.get("data") or {}).get("attributes") or {})
    stats = attributes.get("last_analysis_stats", {}) or {}
    return {"ok": True, "found": True, "name": attributes.get("meaningful_name", ""), "type": attributes.get("type_description", ""), "size": attributes.get("size", ""), "analysis_stats": stats, "first_submission": attributes.get("first_submission_date", "")}


async def _malwarebazaar(ctx: ScanContext, digest: str) -> Dict[str, Any]:
    response = await ctx.fetcher.post_form(
        "https://mb-api.abuse.ch/api/v1/",
        payload={"query": "get_info", "hash": digest},
        source="MalwareBazaar",
        max_bytes=500_000,
    )
    if not response.ok or not isinstance(response.data, dict):
        return {"ok": False, "error": response.error or f"HTTP {response.status}"}
    return {"ok": True, **response.data}


@register(
    "hash",
    "Hash intelligence",
    "Algorithm identification, optional keyed VirusTotal reputation, MalwareBazaar lookup and analyst pivots.",
    category="threat-intel",
    sources=["offline length/hex", "VirusTotal (key)", "MalwareBazaar", "analyst links"],
)
async def run_hash(ctx: ScanContext, target: str) -> Any:
    digest = target.strip().lower()
    result = new_result("hash", digest)
    algorithm = ALGORITHMS.get(len(digest), "Unknown") if HEX_RE.fullmatch(digest) else "Invalid hexadecimal"
    result.sections.append(Section("Digest identification", "kv", {"hash": digest, "length": len(digest), "algorithm": algorithm}, "Length-based identification is not cryptographic proof of origin."))
    if algorithm == "Invalid hexadecimal" or algorithm == "Unknown":
        result.status = "error"
        result.error = "Expected an MD5, SHA-1, SHA-256 or SHA-512 hexadecimal digest"
        return result

    virustotal, malwarebazaar = await __import__("asyncio").gather(_virustotal(ctx, digest), _malwarebazaar(ctx, digest))
    if virustotal.get("skipped"):
        result.notes.append("VirusTotal skipped: supply a per-scan API key for optional reputation details.")
    elif virustotal.get("ok"):
        result.sections.append(Section("VirusTotal", "kv", {key: value for key, value in virustotal.items() if key not in {"ok"}}, "Optional keyed lookup; key is not persisted.", f"https://www.virustotal.com/gui/file/{digest}"))
        stats = virustotal.get("analysis_stats", {}) or {}
        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        if malicious or suspicious:
            add_finding(result, "Hash has positive VirusTotal detections", "high", min(25, malicious * 4 + suspicious * 2), f"{malicious} malicious and {suspicious} suspicious engines.", "VirusTotal")
    else:
        add_failure(result, "VirusTotal", virustotal.get("error", "unavailable"))

    if malwarebazaar.get("ok"):
        data = malwarebazaar.get("data") or []
        result.sections.append(Section("MalwareBazaar", "records", data[:20] if isinstance(data, list) else data, "Public malware sample metadata when indexed."))
        if data:
            add_finding(result, "Hash indexed by MalwareBazaar", "high", 12, "A public malware sample record was returned; validate independently.", "MalwareBazaar")
    else:
        add_failure(result, "MalwareBazaar", malwarebazaar.get("error", "unavailable"))

    add_link(result, "VirusTotal file view", f"https://www.virustotal.com/gui/file/{quote(digest, safe='')}", "threat-intel", "VirusTotal")
    add_link(result, "MalwareBazaar hash search", f"https://bazaar.abuse.ch/sample/{quote(digest, safe='')}/", "threat-intel", "MalwareBazaar")
    add_link(result, "Hybrid Analysis search", f"https://www.hybrid-analysis.com/search?query={quote(digest, safe='')}", "threat-intel", "Hybrid Analysis")
    exact_query = quote('"' + digest + '"', safe="")
    add_link(result, "Google exact-hash search", "https://www.google.com/search?q=" + exact_query, "search", "Google")
    result.coverage.update({"algorithm": algorithm, "optional_virustotal": not virustotal.get("skipped", False), "malwarebazaar": malwarebazaar.get("ok", False)})
    return result


__all__ = ["run_hash"]
