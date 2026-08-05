"""Public company/organization footprint planning and enrichment."""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List
from urllib.parse import quote, quote_plus, urlsplit

from ..models import Section
from .base import ScanContext, add_entity, add_failure, add_finding, add_link, new_result, register


def _domain(value: str) -> str:
    candidate = value.strip()
    if "://" not in candidate:
        candidate = f"https://{candidate}"
    try:
        return (urlsplit(candidate).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def _record(source: str, title: str, summary: str, url: str) -> Dict[str, str]:
    return {"source": source, "title": title[:240], "summary": summary[:500], "url": url}


async def _github_orgs(ctx: ScanContext, name: str) -> Dict[str, Any]:
    headers = {"Accept": "application/vnd.github+json"}
    token = ctx.api_key("github_token")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    response = await ctx.fetcher.get_json(
        "https://api.github.com/search/users",
        params={"q": f"{name} type:org", "per_page": 10},
        headers=headers,
        source="GitHub organization search",
        max_bytes=500_000,
    )
    if not response.ok or not isinstance(response.data, dict):
        return {"ok": False, "error": response.error or f"HTTP {response.status}", "orgs": [], "members": []}
    orgs = []
    members = []
    for item in (response.data.get("items", []) or [])[:5]:
        if not isinstance(item, dict) or not item.get("login"):
            continue
        login = str(item["login"])
        org_response, members_response = await asyncio.gather(
            ctx.fetcher.get_json(f"https://api.github.com/orgs/{quote(login, safe='')}", headers=headers, source="GitHub organization profile", max_bytes=400_000),
            ctx.fetcher.get_json(f"https://api.github.com/orgs/{quote(login, safe='')}/members", params={"per_page": 30}, headers=headers, source="GitHub public organization members", max_bytes=700_000),
        )
        profile = org_response.data if org_response.ok and isinstance(org_response.data, dict) else {}
        orgs.append(
            {
                "login": login,
                "name": profile.get("name", ""),
                "description": profile.get("description", ""),
                "blog": profile.get("blog", ""),
                "location": profile.get("location", ""),
                "public_repos": profile.get("public_repos", ""),
                "followers": profile.get("followers", ""),
                "url": profile.get("html_url", item.get("html_url", "")),
            }
        )
        if members_response.ok and isinstance(members_response.data, list):
            for member in members_response.data[:30]:
                if isinstance(member, dict) and member.get("login"):
                    members.append({"organization": login, "login": member["login"], "profile": member.get("html_url", ""), "type": member.get("type", "User")})
    return {"ok": True, "orgs": orgs, "members": members}


async def _public_indexes(ctx: ScanContext, name: str) -> Dict[str, Any]:
    wikipedia, wikidata, institutions = await asyncio.gather(
        ctx.fetcher.get_json(
            "https://en.wikipedia.org/w/rest.php/v1/search/page",
            params={"q": name, "limit": 5},
            source="Wikipedia organization search",
            max_bytes=500_000,
        ),
        ctx.fetcher.get_json(
            "https://www.wikidata.org/w/api.php",
            params={"action": "query", "list": "search", "srsearch": name, "format": "json", "utf8": "1", "srlimit": 5},
            source="Wikidata organization search",
            max_bytes=500_000,
        ),
        ctx.fetcher.get_json(
            "https://api.openalex.org/institutions",
            params={"search": name, "per-page": 5},
            source="OpenAlex institution search",
            max_bytes=700_000,
        ),
    )
    records: List[Dict[str, str]] = []
    failures = []
    responded = 0
    if wikipedia.ok and isinstance(wikipedia.data, dict):
        responded += 1
        for page in wikipedia.data.get("pages", []) or []:
            if isinstance(page, dict):
                title = str(page.get("title", ""))
                key = str(page.get("key", "")).strip() or title.replace(" ", "_")
                records.append(_record("Wikipedia", title, str(page.get("description", "") or page.get("excerpt", "")), f"https://en.wikipedia.org/wiki/{quote_plus(key)}"))
    else:
        failures.append(f"Wikipedia: {wikipedia.error or f'HTTP {wikipedia.status}'}")
    if wikidata.ok and isinstance(wikidata.data, dict):
        responded += 1
        for item in (wikidata.data.get("query", {}) or {}).get("search", []) or []:
            if isinstance(item, dict):
                title = str(item.get("title", ""))
                records.append(_record("Wikidata", title, str(item.get("snippet", "")), f"https://www.wikidata.org/wiki/{quote_plus(title)}"))
    else:
        failures.append(f"Wikidata: {wikidata.error or f'HTTP {wikidata.status}'}")
    if institutions.ok and isinstance(institutions.data, dict):
        responded += 1
        for item in institutions.data.get("results", []) or []:
            if isinstance(item, dict):
                records.append(_record("OpenAlex", str(item.get("display_name", "")), f"{item.get('works_count', 0)} works · {item.get('cited_by_count', 0)} citations", str(item.get("id", ""))))
    else:
        failures.append(f"OpenAlex: {institutions.error or f'HTTP {institutions.status}'}")
    return {"records": records[:20], "responded": responded, "attempted": 3, "failures": failures}


@register(
    "company",
    "Company & organization footprint",
    "Public company context, organization indexes, GitHub organization enrichment, map/professional links and public employee leads.",
    category="organization",
    sources=["Wikipedia", "Wikidata", "OpenAlex", "GitHub API", "Google/Bing/LinkedIn/Maps links"],
)
async def run_company(ctx: ScanContext, target: str) -> Any:
    name = " ".join(target.strip().split())
    domain = _domain(name)
    display_name = domain or name
    result = new_result("company", display_name)
    if len(display_name) < 2:
        result.status = "error"
        result.error = "Company or organization name is required"
        return result

    query_name = domain or name
    indexes, github = await asyncio.gather(_public_indexes(ctx, query_name), _github_orgs(ctx, query_name))
    result.sections.append(
        Section(
            "Organization scope",
            "kv",
            {
                "input": target,
                "organization_query": query_name,
                "domain": domain or "Not supplied",
                "identity_resolution": False,
                "employee_scope": "Public GitHub organization members only; LinkedIn results are manual links.",
            },
            "Company names can collide. Verify ownership and jurisdiction before treating a candidate as the target organization.",
        )
    )
    result.sections.append(Section("Public organization indexes", "table", indexes["records"], "Candidate public records from knowledge and scholarly indexes."))
    result.sections.append(Section("Organization index coverage", "kv", {"providers_attempted": indexes["attempted"], "providers_responded": indexes["responded"], "candidate_records": len(indexes["records"])}, "Providers may be rate-limited or unavailable."))
    for failure in indexes["failures"]:
        result.notes.append(failure)
    if indexes["failures"]:
        result.status = "partial"

    if github.get("ok"):
        result.sections.append(Section("GitHub organization candidates", "table", github.get("orgs", []), "Public GitHub organization records; not proof of corporate ownership."))
        result.sections.append(Section("Public GitHub organization members", "table", github.get("members", []), "Only public GitHub member listings; not a complete employee directory."))
        for org in github.get("orgs", []):
            add_entity(result, "username", org.get("login"), "github.organization", pivot=False, label="Public GitHub organization", confidence=0.65)
            if org.get("url"):
                add_link(result, f"GitHub organization · {org['login']}", org["url"], "organization", "GitHub")
        for member in github.get("members", [])[:100]:
            add_entity(result, "username", member.get("login"), "github.organization_member", pivot=False, label="Public GitHub organization member", confidence=0.45)
            if member.get("profile"):
                add_link(result, f"GitHub member · {member['login']}", member["profile"], "public-member", "GitHub")
    else:
        add_failure(result, "GitHub organization search", github.get("error", "unavailable"))

    if domain:
        add_entity(result, "domain", domain, "company.domain", pivot=False, label="Company domain")
    add_entity(result, "company", name, "company.input", pivot=False, label="Investigated organization")
    encoded = quote_plus(name)
    add_link(result, "Google exact company search", f"https://www.google.com/search?q={quote_plus(chr(34) + name + chr(34))}", "search", "Google")
    add_link(result, "Google Maps company search", f"https://www.google.com/maps/search/?api=1&query={encoded}", "maps", "Google Maps")
    add_link(result, "Bing Maps company search", f"https://www.bing.com/maps?q={encoded}", "maps", "Bing Maps")
    add_link(result, "LinkedIn company search", f"https://www.linkedin.com/search/results/companies/?keywords={encoded}", "professional", "LinkedIn")
    add_link(result, "LinkedIn public people search", f"https://www.linkedin.com/search/results/people/?keywords={encoded}", "employees", "LinkedIn")
    add_link(result, "GitHub organization search", f"https://github.com/search?q={encoded}&type=users", "developer", "GitHub")
    add_link(result, "Crunchbase company search", f"https://www.crunchbase.com/search-home/organizations/field/organizations/short_description/{encoded}", "company", "Crunchbase")
    add_link(result, "OpenCorporates search", f"https://opencorporates.com/companies?q={encoded}", "registry", "OpenCorporates")
    add_finding(result, "Company results require ownership verification", "info", 0, "Public organization records, maps and employee links are leads, not proof that all records refer to the same company.", "DigiScope")
    result.coverage.update({"index_records": len(indexes["records"]), "github_orgs": len(github.get("orgs", [])), "public_github_members": len(github.get("members", [])), "links": len(result.links)})
    return result


__all__ = ["run_company"]
