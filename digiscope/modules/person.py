"""Person-name investigation planner; deliberately does not resolve identity."""

from __future__ import annotations

import asyncio
import re
from typing import Any, Dict, List
from urllib.parse import quote, quote_plus

from ..models import Section
from .base import ScanContext, add_entity, add_finding, add_link, new_result, register


def _username_permutations(name: str) -> List[str]:
    parts = [re.sub(r"[^a-z0-9]", "", word.lower()) for word in name.split()]
    parts = [part for part in parts if part]
    if not parts:
        return []
    first, last = parts[0], parts[-1]
    candidates = [
        first,
        last,
        f"{first}{last}",
        f"{first}.{last}",
        f"{first}_{last}",
        f"{first}-{last}",
        f"{first[0]}{last}" if first else last,
        f"{first}{last[0]}" if last else first,
        f"{first[0]}.{last}" if first else last,
        f"{first[0]}_{last}" if first else last,
    ]
    output = []
    for candidate in candidates:
        if 2 <= len(candidate) <= 64 and candidate not in output:
            output.append(candidate)
    return output


def _query_links(name: str, context: str) -> List[Dict[str, str]]:
    exact = f'"{name}"'
    suffix = f" {context}" if context else ""
    queries = [
        ("Broad exact-name search", f"{exact}{suffix}"),
        ("Professional profiles", f"{exact}{suffix} (site:linkedin.com/in OR site:github.com)"),
        ("Public social profiles", f"{exact}{suffix} (site:x.com OR site:instagram.com OR site:facebook.com)"),
        ("Public documents", f"{exact}{suffix} (filetype:pdf OR filetype:doc OR filetype:txt)"),
        ("Public-sector references", f"{exact}{suffix} (site:gov OR site:gov.uk OR site:gc.ca)"),
        ("News and publications", f"{exact}{suffix} (site:news.google.com OR site:medium.com OR site:substack.com)"),
    ]
    return [{"label": label, "query": query} for label, query in queries]


def _match_label(name: str, text: str) -> str:
    tokens = [token.lower() for token in re.findall(r"[a-z0-9]+", name.lower()) if len(token) > 1]
    candidate = text.lower()
    return "token match" if tokens and all(token in candidate for token in tokens) else "search candidate"


def _record(source: str, name: str, title: str, summary: str, url: str) -> Dict[str, str]:
    return {
        "source": source,
        "match": _match_label(name, f"{title} {summary}"),
        "title": title[:240],
        "summary": summary[:500],
        "url": url,
    }


async def _public_index_discovery(ctx: ScanContext, name: str) -> Dict[str, Any]:
    """Query bounded, documented public indexes without scraping search pages.

    These are candidate generators only.  They intentionally do not pivot to
    accounts automatically because a common name can match unrelated people.
    """

    base_responses = await asyncio.gather(
        ctx.fetcher.get_json(
            "https://en.wikipedia.org/w/rest.php/v1/search/page",
            params={"q": name, "limit": 5},
            source="Wikipedia public search",
            max_bytes=500_000,
        ),
        ctx.fetcher.get_json(
            "https://www.wikidata.org/w/api.php",
            params={"action": "query", "list": "search", "srsearch": f'\"{name}\"', "format": "json", "utf8": "1", "srlimit": 5},
            source="Wikidata public search",
            max_bytes=500_000,
        ),
        ctx.fetcher.get_json(
            "https://api.openalex.org/authors",
            params={"search": name, "per-page": 5},
            headers={"Accept": "application/json"},
            source="OpenAlex author search",
            max_bytes=700_000,
        ),
        ctx.fetcher.get_json(
            "https://api.crossref.org/works",
            params={"query.author": name, "rows": 5, "select": "DOI,title,author,published,URL,publisher,type"},
            source="Crossref author search",
            max_bytes=900_000,
        ),
        ctx.fetcher.get_json(
            "https://api.github.com/search/users",
            params={"q": f'\"{name}\"', "per_page": 5},
            headers={"Accept": "application/vnd.github+json"},
            source="GitHub public user search",
            max_bytes=500_000,
        ),
    )
    optional_requests = []
    optional_labels: List[str] = []
    optional_skipped: List[str] = []
    search_query = f'"{name}"'
    if ctx.key("person_context", ""):
        search_query += " " + str(ctx.key("person_context"))[:200]
    google_key = ctx.api_key("google_cse_api_key")
    google_cx = ctx.api_key("google_cse_cx")
    if google_key and google_cx:
        optional_labels.append("Google CSE")
        optional_requests.append(
            ctx.fetcher.get_json(
                "https://www.googleapis.com/customsearch/v1",
                params={"key": google_key, "cx": google_cx, "q": search_query, "num": 10},
                source="Google Programmable Search API",
                max_bytes=1_000_000,
            )
        )
    else:
        optional_skipped.append("Google CSE (API key + search engine ID not configured)")
    bing_key = ctx.api_key("bing_search_api_key")
    if bing_key:
        optional_labels.append("Bing Web Search")
        optional_requests.append(
            ctx.fetcher.get_json(
                "https://api.bing.microsoft.com/v7.0/search",
                params={"q": search_query, "count": 10, "responseFilter": "Webpages"},
                headers={"Ocp-Apim-Subscription-Key": bing_key},
                source="Bing Web Search API",
                max_bytes=1_000_000,
            )
        )
    else:
        optional_skipped.append("Bing Web Search API (subscription key not configured)")
    optional_responses = await asyncio.gather(*optional_requests) if optional_requests else []
    responses = list(base_responses) + list(optional_responses)
    records: List[Dict[str, str]] = []
    failures: List[str] = []
    empty_sources: List[str] = []
    responded = 0

    wikipedia = responses[0]
    if wikipedia.ok and isinstance(wikipedia.data, dict):
        responded += 1
        pages = wikipedia.data.get("pages", []) or []
        if not pages:
            empty_sources.append("Wikipedia")
        for page in pages:
            if not isinstance(page, dict):
                continue
            title = str(page.get("title", ""))
            description = str(page.get("description", "") or page.get("excerpt", ""))
            page_key = str(page.get("key", "")).strip() or title.replace(" ", "_")
            records.append(_record("Wikipedia", name, title, description, f"https://en.wikipedia.org/wiki/{quote(page_key, safe='')}"))
    else:
        failures.append(f"Wikipedia: {wikipedia.error or f'HTTP {wikipedia.status}'}")

    wikidata = responses[1]
    if wikidata.ok and isinstance(wikidata.data, dict):
        responded += 1
        items = (wikidata.data.get("query", {}) or {}).get("search", []) or []
        if not items:
            empty_sources.append("Wikidata")
        for item in items:
            if not isinstance(item, dict):
                continue
            title = str(item.get("title", ""))
            snippet = re.sub(r"<[^>]+>", "", str(item.get("snippet", "")))
            records.append(_record("Wikidata", name, title, snippet, f"https://www.wikidata.org/wiki/{quote(title, safe='')}"))
    else:
        failures.append(f"Wikidata: {wikidata.error or f'HTTP {wikidata.status}'}")

    openalex = responses[2]
    if openalex.ok and isinstance(openalex.data, dict):
        responded += 1
        authors = openalex.data.get("results", []) or []
        if not authors:
            empty_sources.append("OpenAlex")
        for author in authors:
            if not isinstance(author, dict):
                continue
            institutions = [str(item.get("display_name", "")) for item in author.get("last_known_institutions", []) or [] if isinstance(item, dict) and item.get("display_name")]
            ids = author.get("ids", {}) or {}
            summary_parts = [f"{author.get('works_count', 0)} works", f"{author.get('cited_by_count', 0)} citations"]
            if institutions:
                summary_parts.append("Institutions: " + ", ".join(institutions[:3]))
            if ids.get("orcid"):
                summary_parts.append(f"ORCID: {ids['orcid']}")
            records.append(_record("OpenAlex", name, str(author.get("display_name", "")), " · ".join(summary_parts), str(author.get("id", ""))))
    else:
        failures.append(f"OpenAlex: {openalex.error or f'HTTP {openalex.status}'}")

    crossref = responses[3]
    if crossref.ok and isinstance(crossref.data, dict):
        responded += 1
        works = (crossref.data.get("message", {}) or {}).get("items", []) or []
        if not works:
            empty_sources.append("Crossref")
        for work in works:
            if not isinstance(work, dict):
                continue
            title_values = work.get("title", []) or []
            title = str(title_values[0] if title_values else work.get("DOI", ""))
            authors = []
            for author in work.get("author", []) or []:
                if isinstance(author, dict):
                    authors.append(" ".join(str(author.get(key, "")).strip() for key in ("given", "family") if author.get(key)))
            published = work.get("published", {}) or {}
            date_parts = (published.get("date-parts", [[]]) or [[]])[0]
            summary = ", ".join(part for part in (work.get("publisher", ""), "; ".join(authors[:5]), "-".join(str(part) for part in date_parts)) if part)
            url = str(work.get("URL", "") or (f"https://doi.org/{work.get('DOI')}" if work.get("DOI") else ""))
            records.append(_record("Crossref", name, title, summary, url))
    else:
        failures.append(f"Crossref: {crossref.error or f'HTTP {crossref.status}'}")

    github = responses[4]
    if github.ok and isinstance(github.data, dict):
        responded += 1
        items = github.data.get("items", []) or []
        if not items:
            empty_sources.append("GitHub")
        for item in items:
            if not isinstance(item, dict):
                continue
            login = str(item.get("login", ""))
            records.append(_record("GitHub", name, login, f"Public GitHub user candidate · relevance score {item.get('score', '')}", str(item.get("html_url", ""))))
    else:
        failures.append(f"GitHub: {github.error or f'HTTP {github.status}'}")

    for label, response in zip(optional_labels, optional_responses):
        if not response.ok or not isinstance(response.data, dict):
            failures.append(f"{label}: {response.error or f'HTTP {response.status}'}")
            continue
        responded += 1
        if label == "Google CSE":
            items = response.data.get("items", []) or []
            if not items:
                empty_sources.append(label)
            for item in items:
                if not isinstance(item, dict):
                    continue
                records.append(_record(label, name, str(item.get("title", "")), str(item.get("snippet", "")), str(item.get("link", ""))))
        else:
            items = (response.data.get("webPages", {}) or {}).get("value", []) or []
            if not items:
                empty_sources.append(label)
            for item in items:
                if not isinstance(item, dict):
                    continue
                records.append(_record(label, name, str(item.get("name", "")), str(item.get("snippet", "")), str(item.get("url", ""))))

    return {
        "records": records[:60],
        "responded": responded,
        "attempted": len(responses),
        "failures": failures,
        "empty_sources": empty_sources,
        "optional_skipped": optional_skipped,
    }


@register(
    "person",
    "Person research plan",
    "Curated public-search dorks, candidate-only public-index discovery, image/social/professional pivots and username permutations; no automatic identity resolution.",
    category="planning",
    sources=["Google/Bing links", "Google CSE (optional key)", "Bing Web Search (optional key)", "Wikipedia", "Wikidata", "OpenAlex", "Crossref", "GitHub API"],
)
async def run_person(ctx: ScanContext, target: str) -> Any:
    name = " ".join(target.strip().split())
    result = new_result("person", name)
    context = str(ctx.key("person_context", "") or "").strip()
    if len(name) < 2:
        result.status = "error"
        result.error = "A person-name plan needs at least two characters"
        return result

    queries = _query_links(name, context)
    permutations = _username_permutations(name)
    discovery = {"records": [], "responded": 0, "attempted": 0, "failures": [], "empty_sources": [], "optional_skipped": []}
    if ctx.key("person_public_discovery", True):
        discovery = await _public_index_discovery(ctx, name)
        result.sections.append(
            Section(
                "Public index coverage",
                "kv",
                {
                    "providers_attempted": discovery["attempted"],
                    "providers_responded": discovery["responded"],
                    "providers_with_no_candidates": discovery["empty_sources"],
                    "optional_search_apis_skipped": discovery["optional_skipped"],
                    "candidate_records": len(discovery["records"]),
                    "method": "Bounded documented public APIs; search-engine result pages are not scraped.",
                },
                "Records are candidate leads and are not merged into one identity.",
            )
        )
        result.sections.append(
            Section(
                "Public index candidates",
                "table",
                discovery["records"],
                "Wikipedia, Wikidata, OpenAlex, Crossref and GitHub API candidates; independently verify every match.",
            )
        )
        for failure in discovery["failures"]:
            result.notes.append(failure)
        for provider in discovery["empty_sources"]:
            result.notes.append(f"{provider}: responded successfully with no candidate records.")
        if discovery["failures"]:
            result.status = "partial"
        for record in discovery["records"]:
            if record.get("url"):
                add_link(result, f"{record['source']} · {record['title']}", record["url"], "public-index", record["source"])
            if record["source"] == "GitHub" and record.get("title"):
                add_entity(result, "username", record["title"], "person.github_index", pivot=False, label="Public GitHub candidate", confidence=0.45)
    else:
        result.notes.append("Public index discovery disabled for this scan.")
    result.sections.append(
        Section(
            "Investigation scope",
            "kv",
            {
                "name": name,
                "context": context or "Not provided",
                "mode": "Lead generation and manual verification only",
                "automatic_identity_resolution": False,
                "suggested_username_pivots": len(permutations),
            },
            "Names are ambiguous. Confirm identity using independent, lawful context before recording a match.",
        )
    )
    result.sections.append(Section("Search plan", "table", queries, "Open a query in the selected search engine and review results manually."))
    result.sections.append(Section("Probable username permutations", "tags", permutations, "Candidate handles are suggestions, not evidence."))
    add_entity(result, "person", name, "person.input", pivot=False, label="Investigated name")
    for candidate in permutations:
        # The safer default is to show candidates without launching 70-site
        # probes.  An explicit advanced opt-in can enable username pivots.
        add_entity(result, "username", candidate, "person.permutation", pivot=bool(ctx.key("person_auto_pivot", False)), label="Suggested handle", confidence=0.35)

    for item in queries:
        query = item["query"]
        encoded = quote_plus(query)
        add_link(result, f"Google · {item['label']}", f"https://www.google.com/search?q={encoded}", "search", "Google")
        add_link(result, f"Bing · {item['label']}", f"https://www.bing.com/search?q={encoded}", "search", "Bing")
        add_link(result, f"DuckDuckGo · {item['label']}", f"https://html.duckduckgo.com/html/?q={encoded}", "search", "DuckDuckGo")
    encoded_name = quote_plus(name)
    add_link(result, "Google Images", f"https://www.google.com/search?tbm=isch&q={encoded_name}", "image-search", "Google Images")
    add_link(result, "Bing Images", f"https://www.bing.com/images/search?q={encoded_name}", "image-search", "Bing Images")
    add_link(result, "LinkedIn people search", f"https://www.linkedin.com/search/results/people/?keywords={encoded_name}", "professional", "LinkedIn")
    add_link(result, "GitHub name search", f"https://github.com/search?q={encoded_name}&type=users", "developer", "GitHub")
    add_finding(result, "Person-name plan requires manual verification", "info", 0, "DigiScope intentionally does not claim that public search results identify a person.", "DigiScope")
    result.notes.append("Responsible-use reminder: do not use this planner for stalking, harassment, doxxing or unlawful surveillance.")
    result.coverage.update(
        {
            "queries": len(queries) * 3,
            "username_candidates": len(permutations),
            "network_sources": discovery["responded"],
            "public_index_providers": discovery["attempted"],
            "public_index_records": len(discovery["records"]),
            "public_index_empty_sources": discovery["empty_sources"],
            "optional_search_apis_skipped": discovery["optional_skipped"],
        }
    )
    return result


__all__ = ["run_person"]
