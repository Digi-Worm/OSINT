"""Email syntax, deliverability and public-profile pivots."""

from __future__ import annotations

import asyncio
import hashlib
import re
from email.utils import parseaddr
from typing import Any, Dict
from urllib.parse import quote

from ..models import Section, TimelineEvent
from .base import (
    ScanContext,
    add_entity,
    add_failure,
    add_finding,
    add_link,
    new_result,
    register,
)

ROLE_LOCAL_PARTS = {
    "abuse",
    "admin",
    "billing",
    "compliance",
    "contact",
    "hello",
    "help",
    "hostmaster",
    "info",
    "legal",
    "marketing",
    "noc",
    "postmaster",
    "privacy",
    "sales",
    "security",
    "support",
    "webmaster",
}
DISPOSABLE_DOMAINS = {
    "10minutemail.com",
    "20minutemail.com",
    "dispostable.com",
    "emailondeck.com",
    "guerrillamail.com",
    "maildrop.cc",
    "mailinator.com",
    "sharklasers.com",
    "temp-mail.org",
    "tempmail.com",
    "throwaway.email",
    "yopmail.com",
}
EMAIL_RE = re.compile(r"^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$")


def _parse_email(value: str) -> Dict[str, str]:
    name, address = parseaddr(value.strip())
    address = address.lower()
    if not EMAIL_RE.fullmatch(address):
        return {"address": address, "local": "", "domain": "", "display_name": name}
    local, domain = address.rsplit("@", 1)
    return {"address": address, "local": local, "domain": domain, "display_name": name}


async def _gravatar(ctx: ScanContext, address: str) -> Dict[str, Any]:
    digest = hashlib.md5(address.strip().lower().encode("utf-8"), usedforsecurity=False).hexdigest()
    avatar_url = f"https://www.gravatar.com/avatar/{digest}?d=404"
    profile_url = f"https://www.gravatar.com/{digest}.json"
    avatar = await ctx.fetcher.get_text(avatar_url, source="Gravatar", max_bytes=64_000)
    profile = await ctx.fetcher.get_json(profile_url, source="Gravatar profile", max_bytes=200_000)
    data = profile.data if profile.ok and isinstance(profile.data, dict) else {}
    return {
        "hash": digest,
        "avatar_url": avatar_url,
        "avatar_present": avatar.status == 200,
        "profile_url": profile_url,
        "profile": data,
        "profile_status": profile.status,
    }


async def _github_commits(ctx: ScanContext, address: str) -> Dict[str, Any]:
    headers = {"Accept": "application/vnd.github+json"}
    token = ctx.api_key("github_token")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    response = await ctx.fetcher.get_json(
        "https://api.github.com/search/commits",
        params={"q": f"author-email:{address}", "per_page": 20},
        headers=headers,
        source="GitHub commit search",
        max_bytes=500_000,
    )
    if not response.ok or not isinstance(response.data, dict):
        return {"ok": False, "error": response.error or f"HTTP {response.status}", "status": response.status}
    items = []
    for item in response.data.get("items", []) or []:
        if not isinstance(item, dict):
            continue
        commit = item.get("commit", {}) or {}
        author = commit.get("author", {}) or {}
        items.append(
            {
                "repository": (item.get("repository") or {}).get("full_name", ""),
                "message": str(commit.get("message", "")).splitlines()[0][:180],
                "date": author.get("date", ""),
                "author_login": (item.get("author") or {}).get("login", ""),
                "url": item.get("html_url", ""),
            }
        )
    return {"ok": True, "total_count": response.data.get("total_count", 0), "items": items}


async def _hibp(ctx: ScanContext, address: str) -> Dict[str, Any]:
    key = ctx.api_key("hibp_api_key")
    if not key:
        return {"skipped": True, "error": "optional HIBP API key not configured"}
    response = await ctx.fetcher.get_json(
        f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(address, safe='')}",
        params={"truncateResponse": "false"},
        headers={"hibp-api-key": key, "user-agent": "DigiScope passive research"},
        source="Have I Been Pwned",
        max_bytes=500_000,
    )
    if response.status == 404:
        return {"ok": True, "breaches": []}
    if not response.ok or not isinstance(response.data, list):
        return {"ok": False, "error": response.error or f"HTTP {response.status}"}
    return {"ok": True, "breaches": response.data}


@register(
    "email",
    "Email footprint",
    "Syntax and role analysis, MX deliverability, Gravatar, public GitHub commit references and optional breach lookup.",
    category="identity",
    sources=["offline parser", "DNS", "Gravatar", "GitHub API", "Have I Been Pwned (key)"],
)
async def run_email(ctx: ScanContext, target: str) -> Any:
    result = new_result("email", target)
    parsed = _parse_email(target)
    address, local, domain = parsed["address"], parsed["local"], parsed["domain"]
    if not local or not domain:
        result.status = "error"
        result.error = "Input is not a valid email-shaped value"
        return result

    mx, gravatar, commits, breaches = await asyncio.gather(
        ctx.dns.query(domain, "MX"),
        _gravatar(ctx, address),
        _github_commits(ctx, address),
        _hibp(ctx, address),
    )
    role_account = local.lower() in ROLE_LOCAL_PARTS
    disposable = domain.lower() in DISPOSABLE_DOMAINS
    syntax = {
        "address": address,
        "domain": domain,
        "local_part": local,
        "display_name": parsed.get("display_name", ""),
        "syntax_valid": bool(EMAIL_RE.fullmatch(address)),
        "role_account_candidate": role_account,
        "disposable_domain_match": disposable,
    }
    result.sections.append(Section("Syntax & classification", "kv", syntax, "Offline analysis; classification is heuristic."))
    result.sections.append(Section("Mail exchanger", "table", [{"host": value, "resolver": mx.source} for value in mx.values], "DNS MX records"))

    if mx.ok and not mx.values:
        add_finding(result, "No MX record observed", "medium", 9, "The domain did not publish an MX answer at scan time.", "DNS")
    elif not mx.ok:
        add_failure(result, "DNS MX", mx.error)
    if role_account:
        add_finding(result, "Role-account local part", "info", 1, "This looks like a shared mailbox rather than an individual address.", "offline")
    if disposable:
        add_finding(result, "Disposable email domain match", "medium", 8, "The domain is in DigiScope's small offline disposable-domain set; verify manually.", "offline")

    if gravatar.get("avatar_present") or gravatar.get("profile"):
        result.sections.append(Section("Gravatar footprint", "kv", {key: value for key, value in gravatar.items() if key not in {"profile"}}, "MD5-derived public profile/asset check; no account login is attempted.", gravatar.get("profile_url", "")))
        if gravatar.get("profile"):
            result.sections.append(Section("Gravatar profile", "records", [gravatar["profile"]], "Public profile response, if available."))
    else:
        result.sections.append(Section("Gravatar footprint", "kv", {"md5": gravatar.get("hash"), "avatar_present": False, "profile_status": gravatar.get("profile_status")}, "No public Gravatar profile was observed."))

    if commits.get("ok"):
        result.sections.append(Section("GitHub commit-email search", "table", commits.get("items", []), "Public commit metadata returned by GitHub; search totals may be approximate.", "https://api.github.com/"))
        for item in commits.get("items", []):
            if item.get("author_login"):
                add_entity(result, "username", item["author_login"], "github.commit_search", label="GitHub author", confidence=0.8)
            if item.get("date"):
                result.timeline.append(TimelineEvent(item["date"], "GitHub commit observed", "GitHub", item.get("repository", "")))
    else:
        add_failure(result, "GitHub commit search", commits.get("error", "unavailable"))

    if breaches.get("skipped"):
        result.notes.append("HIBP skipped: supply a per-scan API key to enable the optional breach lookup.")
    elif breaches.get("ok"):
        breach_rows = []
        for breach in breaches.get("breaches", []) or []:
            if isinstance(breach, dict):
                breach_rows.append({key: breach.get(key) for key in ("Name", "Title", "Domain", "BreachDate", "DataClasses", "IsVerified")})
        result.sections.append(Section("Have I Been Pwned", "table", breach_rows, "Optional keyed lookup; returned data is not written to disk.", "https://haveibeenpwned.com/"))
        if breach_rows:
            add_finding(result, "Email appears in HIBP breach history", "high", min(25, 5 + len(breach_rows) * 2), f"{len(breach_rows)} breach record(s) returned.", "Have I Been Pwned")
    else:
        add_failure(result, "Have I Been Pwned", breaches.get("error", "unavailable"))

    add_entity(result, "domain", domain, "email.domain", label="Email domain")
    if re.fullmatch(r"[A-Za-z0-9_.-]{2,64}", local):
        add_entity(result, "username", local, "email.local_part", label="Candidate username", confidence=0.55)
    add_link(result, "Gravatar profile", f"https://www.gravatar.com/{gravatar.get('hash', '')}.json", "profile", "Gravatar")
    add_link(result, "GitHub commit search", f"https://github.com/search?q={quote(f'author-email:{address}', safe='')}&type=commits", "search", "GitHub")
    add_link(result, "HIBP account check", f"https://haveibeenpwned.com/account/{quote(address, safe='')}", "breach-check", "Have I Been Pwned")
    exact_query = quote('"' + address + '"', safe="")
    add_link(result, "Google exact-address search", "https://www.google.com/search?q=" + exact_query, "search", "Google")

    result.coverage.update({"mx_checked": True, "github_commit_hits": len(commits.get("items", [])) if commits.get("ok") else 0, "optional_hibp": not breaches.get("skipped", False)})
    return result


__all__ = ["run_email"]
