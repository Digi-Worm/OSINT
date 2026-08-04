"""Core serialisable data structures used by DigiScope.

The application deliberately keeps the scan model small and JSON friendly.  A
module can return rich sections for the UI without coupling itself to the
frontend, while entities/findings/links are normalised by the engine.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List


@dataclass
class Section:
    """A renderable module section.

    ``kind`` is one of ``kv``, ``table``, ``tags``, ``list``, ``records``,
    ``links`` or ``text``.  The frontend intentionally accepts unknown kinds
    and renders them as JSON, which lets new modules evolve independently.
    """

    title: str
    kind: str
    data: Any
    description: str = ""
    source_url: str = ""


@dataclass
class Entity:
    """A discovered value that may be useful as a future pivot."""

    type: str
    value: str
    source: str
    pivot: bool = True
    label: str = ""
    confidence: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    """A security/privacy observation.

    Scores are intentionally conservative and are not a vulnerability score.
    They describe exposure signals observed in public data and are capped by
    the aggregate engine at 100.
    """

    label: str
    severity: str
    score: int = 0
    detail: str = ""
    source: str = ""


@dataclass
class Link:
    title: str
    url: str
    kind: str = "reference"
    source: str = ""


@dataclass
class TimelineEvent:
    date: str
    label: str
    source: str
    detail: str = ""


@dataclass
class ModuleResult:
    key: str
    title: str
    target: str
    status: str = "complete"
    started_at: str = ""
    completed_at: str = ""
    duration_ms: int = 0
    sections: List[Section] = field(default_factory=list)
    entities: List[Entity] = field(default_factory=list)
    links: List[Link] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    timeline: List[TimelineEvent] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    error: str = ""
    coverage: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Node:
    id: str
    type: str
    value: str
    label: str = ""
    sources: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Edge:
    source: str
    target: str
    label: str = "discovered"
    source_module: str = ""


@dataclass
class Detection:
    type: str
    confidence: float
    normalized: str
    reason: str
    candidates: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Job:
    id: str
    input: str
    selector_type: str
    normalized_input: str
    options: Dict[str, Any]
    status: str = "queued"
    progress: int = 0
    phase: str = "Queued"
    created_at: str = ""
    started_at: str = ""
    completed_at: str = ""
    source_statuses: List[Dict[str, Any]] = field(default_factory=list)
    module_results: List[ModuleResult] = field(default_factory=list)
    nodes: List[Node] = field(default_factory=list)
    edges: List[Edge] = field(default_factory=list)
    timeline: List[TimelineEvent] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    exposure_score: int = 0
    exposure_label: str = "Unknown"
    coverage: Dict[str, Any] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)
    error: str = ""

    def public_options(self) -> Dict[str, Any]:
        """Return options safe to send to a browser or history view.

        API keys are accepted per scan and kept in memory for the lifetime of
        the job.  They are never copied into this response.
        """

        redacted = {}
        secret_names = {
            "hibp_api_key",
            "shodan_api_key",
            "abuseipdb_api_key",
            "virustotal_api_key",
            "github_token",
            "numverify_api_key",
        }
        for key, value in self.options.items():
            redacted[key] = "••••••••" if key in secret_names and value else value
        return redacted

    def to_dict(self, include_results: bool = True) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "id": self.id,
            "input": self.input,
            "selector_type": self.selector_type,
            "normalized_input": self.normalized_input,
            "status": self.status,
            "progress": self.progress,
            "phase": self.phase,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "source_statuses": self.source_statuses,
            "exposure_score": self.exposure_score,
            "exposure_label": self.exposure_label,
            "coverage": self.coverage,
            "notes": self.notes,
            "error": self.error,
            "options": self.public_options(),
        }
        if include_results:
            payload.update(
                {
                    "modules": [result.to_dict() for result in self.module_results],
                    "graph": {
                        "nodes": [asdict(node) for node in self.nodes],
                        "edges": [asdict(edge) for edge in self.edges],
                    },
                    "timeline": [asdict(event) for event in self.timeline],
                    "findings": [asdict(finding) for finding in self.findings],
                }
            )
        return payload


SELECTOR_TYPES = [
    "email",
    "domain",
    "ip",
    "username",
    "phone",
    "person",
    "url",
    "hash",
    "crypto",
]

EXPOSURE_BANDS = (
    (20, "Guarded"),
    (40, "Elevated"),
    (60, "High"),
    (80, "Critical"),
)


def exposure_label(score: int) -> str:
    score = max(0, min(int(score), 100))
    if score < 20:
        return "Low"
    if score < 40:
        return "Guarded"
    if score < 60:
        return "Elevated"
    if score < 80:
        return "High"
    return "Critical"


__all__ = [
    "Detection",
    "Edge",
    "Entity",
    "Finding",
    "Job",
    "Link",
    "ModuleResult",
    "Node",
    "Section",
    "TimelineEvent",
    "SELECTOR_TYPES",
    "exposure_label",
]
