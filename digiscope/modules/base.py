"""Module registry and execution context."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, List, Optional

from ..dns import DNSClient
from ..models import Entity, Finding, Link, ModuleResult, TimelineEvent
from ..network import AsyncFetcher

ModuleCallable = Callable[["ScanContext", str], Awaitable[ModuleResult]]


@dataclass
class ModuleSpec:
    key: str
    title: str
    description: str
    category: str
    sources: List[str]
    run: ModuleCallable


REGISTRY: Dict[str, ModuleSpec] = {}


def register(
    key: str,
    title: str,
    description: str,
    *,
    category: str = "intelligence",
    sources: Optional[List[str]] = None,
) -> Callable[[ModuleCallable], ModuleCallable]:
    """Register a module when its file is imported."""

    def decorator(function: ModuleCallable) -> ModuleCallable:
        REGISTRY[key] = ModuleSpec(
            key=key,
            title=title,
            description=description,
            category=category,
            sources=sources or [],
            run=function,
        )
        return function

    return decorator


@dataclass
class ScanContext:
    fetcher: AsyncFetcher
    dns: DNSClient
    options: Dict[str, Any]
    selector_type: str
    depth: int = 0
    job_id: str = ""

    @property
    def safe_mode(self) -> bool:
        return bool(self.options.get("safe_mode", True))

    def key(self, name: str, default: Any = None) -> Any:
        return self.options.get(name, default)

    def api_key(self, name: str) -> str:
        value = self.options.get(name, "")
        return value.strip() if isinstance(value, str) else ""


def new_result(key: str, target: str, title: Optional[str] = None) -> ModuleResult:
    spec = REGISTRY.get(key)
    return ModuleResult(key=key, title=title or (spec.title if spec else key), target=target)


def add_failure(result: ModuleResult, source: str, error: str, *, note: bool = True) -> None:
    """Mark a module partial without allowing a source failure to abort a scan."""

    result.status = "partial"
    message = f"{source}: {error or 'source unavailable'}"
    if note and message not in result.notes:
        result.notes.append(message[:400])


def add_entity(
    result: ModuleResult,
    entity_type: str,
    value: Any,
    source: str,
    *,
    pivot: bool = True,
    label: str = "",
    confidence: float = 1.0,
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    if value is None:
        return
    text = str(value).strip()
    if not text:
        return
    result.entities.append(
        Entity(
            type=entity_type,
            value=text,
            source=source,
            pivot=pivot,
            label=label,
            confidence=max(0.0, min(1.0, confidence)),
            metadata=metadata or {},
        )
    )


def add_finding(
    result: ModuleResult,
    label: str,
    severity: str,
    score: int = 0,
    detail: str = "",
    source: str = "",
) -> None:
    result.findings.append(
        Finding(
            label=label,
            severity=severity,
            score=max(0, min(int(score), 30)),
            detail=detail,
            source=source,
        )
    )


def add_link(result: ModuleResult, title: str, url: str, kind: str = "reference", source: str = "") -> None:
    if not url:
        return
    result.links.append(Link(title=title, url=url, kind=kind, source=source))


def add_timeline(result: ModuleResult, date: Any, label: str, source: str, detail: str = "") -> None:
    if date:
        result.timeline.append(TimelineEvent(str(date), label, source, detail))


def dedupe_strings(values: List[str]) -> List[str]:
    seen = set()
    output = []
    for value in values:
        normalized = str(value).strip()
        if normalized and normalized not in seen:
            seen.add(normalized)
            output.append(normalized)
    return output


def get_specs() -> List[ModuleSpec]:
    return list(REGISTRY.values())


__all__ = [
    "ModuleSpec",
    "REGISTRY",
    "ScanContext",
    "add_entity",
    "add_failure",
    "add_finding",
    "add_link",
    "add_timeline",
    "dedupe_strings",
    "get_specs",
    "new_result",
    "register",
]
