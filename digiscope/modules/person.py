"""Person-name investigation planner; deliberately does not resolve identity."""

from __future__ import annotations

import re
from typing import Any, Dict, List
from urllib.parse import quote_plus

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


@register(
    "person",
    "Person research plan",
    "Curated public-search dorks, image/social/professional pivots and username permutations; no automatic identity resolution.",
    category="planning",
    sources=["Google", "Bing", "DuckDuckGo", "public profile search links"],
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
    result.coverage.update({"queries": len(queries) * 3, "username_candidates": len(permutations), "network_sources": 0})
    return result


__all__ = ["run_person"]
