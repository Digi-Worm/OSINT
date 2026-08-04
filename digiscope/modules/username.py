"""Concurrent public username presence checks with GitHub enrichment."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import quote, urlsplit

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

DATA_PATH = Path(__file__).resolve().parent.parent / "data" / "sites.json"


def _sites() -> List[Dict[str, Any]]:
    try:
        with DATA_PATH.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def _site_url(template: str, username: str) -> str:
    return template.replace("{username}", quote(username, safe=""))


async def _probe_site(ctx: ScanContext, site: Dict[str, Any], username: str) -> Dict[str, Any]:
    name = str(site.get("name", "Unknown"))
    url = _site_url(str(site.get("url", "")), username)
    response = await ctx.fetcher.get_text(url, source=f"username:{name}", max_bytes=260_000)
    body = response.text.lower()
    missing_markers = [str(marker).lower() for marker in site.get("missing", [])]
    if response.status in {401, 403, 429}:
        state = "inconclusive"
        reason = f"HTTP {response.status} / access-limited"
    elif response.status in {404, 410}:
        state = "not_found"
        reason = f"HTTP {response.status}"
    elif response.ok and any(marker and marker in body for marker in missing_markers):
        state = "not_found"
        reason = "site missing-page marker"
    elif response.ok:
        state = "found"
        reason = "HTTP success without a known missing-page marker"
    else:
        state = "inconclusive"
        reason = response.error or f"HTTP {response.status}"
    return {
        "platform": name,
        "category": site.get("category", "Other"),
        "url": url,
        "state": state,
        "reason": reason,
        "status": response.status,
        "elapsed_ms": response.elapsed_ms,
    }


async def _github_enrichment(ctx: ScanContext, username: str) -> Dict[str, Any]:
    headers = {"Accept": "application/vnd.github+json"}
    token = ctx.api_key("github_token")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    profile_response = await ctx.fetcher.get_json(
        f"https://api.github.com/users/{quote(username, safe='')}",
        headers=headers,
        source="GitHub profile API",
        max_bytes=400_000,
    )
    if not profile_response.ok or not isinstance(profile_response.data, dict):
        return {"ok": False, "error": profile_response.error or f"HTTP {profile_response.status}", "status": profile_response.status}
    profile = profile_response.data
    repos_response = await ctx.fetcher.get_json(
        f"https://api.github.com/users/{quote(username, safe='')}/repos",
        params={"per_page": 10, "sort": "updated", "direction": "desc"},
        headers=headers,
        source="GitHub repository API",
        max_bytes=700_000,
    )
    repos = []
    if repos_response.ok and isinstance(repos_response.data, list):
        for repo in repos_response.data:
            if isinstance(repo, dict):
                repos.append(
                    {
                        "name": repo.get("full_name", repo.get("name", "")),
                        "description": repo.get("description", ""),
                        "language": repo.get("language", ""),
                        "stars": repo.get("stargazers_count", 0),
                        "updated_at": repo.get("updated_at", ""),
                        "url": repo.get("html_url", ""),
                    }
                )
    return {"ok": True, "profile": profile, "repos": repos, "repos_status": repos_response.status}


@register(
    "username",
    "Username presence",
    "Concurrent heuristic profile checks across a 70+ site catalogue plus live GitHub profile and repository enrichment.",
    category="identity",
    sources=["public profile URLs", "GitHub API"],
)
async def run_username(ctx: ScanContext, target: str) -> Any:
    username = target.strip().lstrip("@")
    result = new_result("username", username)
    if not username or len(username) > 64 or any(character.isspace() for character in username):
        result.status = "error"
        result.error = "Username must be a non-empty handle without whitespace"
        return result

    sites = _sites()
    if not sites:
        result.status = "error"
        result.error = "Username site catalogue is unavailable"
        return result
    probes, github = await asyncio.gather(
        asyncio.gather(*(_probe_site(ctx, site, username) for site in sites)),
        _github_enrichment(ctx, username),
    )
    records = list(probes)
    found = [record for record in records if record["state"] == "found"]
    inconclusive = [record for record in records if record["state"] == "inconclusive"]
    not_found = [record for record in records if record["state"] == "not_found"]
    result.sections.append(
        Section(
            "Presence coverage",
            "kv",
            {
                "checked": len(records),
                "found": len(found),
                "not_found": len(not_found),
                "inconclusive": len(inconclusive),
                "method": "Concurrent public profile URL probes; status and missing-page markers are heuristic.",
            },
            "A found result is a lead, not proof that profiles belong to the same person.",
        )
    )
    result.sections.append(Section("Detected profiles", "table", found, "Open each profile for analyst verification."))
    result.sections.append(Section("All checks", "table", records, "Includes negative and inconclusive responses for auditability."))
    if found:
        add_finding(result, "Public username presence observed", "info", min(12, 2 + len(found)), f"{len(found)} of {len(records)} public profile checks returned a positive heuristic.", "Username catalogue")
    if inconclusive:
        result.notes.append(f"{len(inconclusive)} username checks were inconclusive because of rate limits, access controls or network errors.")
        result.status = "partial"

    for record in found:
        add_link(result, record["platform"], record["url"], "profile", "username catalogue")

    if github.get("ok"):
        profile = github.get("profile", {}) or {}
        profile_data = {
            key: profile.get(key)
            for key in (
                "login",
                "name",
                "bio",
                "company",
                "location",
                "blog",
                "twitter_username",
                "public_repos",
                "public_gists",
                "followers",
                "following",
                "created_at",
                "updated_at",
                "html_url",
            )
            if profile.get(key) not in (None, "")
        }
        result.sections.append(Section("GitHub profile enrichment", "kv", profile_data, "Public GitHub API profile fields", profile.get("html_url", "")))
        if github.get("repos"):
            result.sections.append(Section("Recent public repositories", "table", github["repos"], "Latest repositories returned by the public GitHub API."))
        if profile.get("created_at"):
            add_timeline(result, profile["created_at"], "GitHub account created", "GitHub", profile.get("login", username))
        blog = str(profile.get("blog", "")).strip()
        if blog:
            blog_url = blog if blog.startswith(("http://", "https://")) else f"https://{blog}"
            host = urlsplit(blog_url).hostname
            if host:
                add_entity(result, "domain", host, "github.profile.blog", label="GitHub profile blog")
            add_link(result, "GitHub profile blog", blog_url, "profile", "GitHub")
        if profile.get("email"):
            add_entity(result, "email", profile["email"], "github.profile", label="Public GitHub email", confidence=0.95)
        if profile.get("twitter_username"):
            add_entity(result, "username", profile["twitter_username"], "github.profile", pivot=False, label="GitHub-linked social handle", confidence=0.8)
    else:
        add_failure(result, "GitHub profile API", github.get("error", "unavailable"))

    exact_query = quote('"' + username + '"', safe="")
    add_link(result, "Google exact-username search", "https://www.google.com/search?q=" + exact_query, "search", "Google")
    add_link(result, "GitHub user", f"https://github.com/{quote(username, safe='')}", "profile", "GitHub")
    result.coverage.update({"checked": len(records), "found": len(found), "inconclusive": len(inconclusive), "not_found": len(not_found), "github_profile": bool(github.get("ok"))})
    return result


__all__ = ["run_username"]
