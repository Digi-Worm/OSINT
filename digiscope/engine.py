"""Automatic breadth-first scan orchestration and correlation."""

from __future__ import annotations

import asyncio
import re
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from .detection import detect_selector, normalize_selector
from .dns import DNSClient
from .models import Edge, Finding, Job, ModuleResult, Node, TimelineEvent, exposure_label
from .modules import load_modules
from .modules.base import REGISTRY, ScanContext
from .network import AsyncFetcher

SECRET_OPTIONS = (
    "hibp_api_key",
    "shodan_api_key",
    "abuseipdb_api_key",
    "virustotal_api_key",
    "github_token",
    "numverify_api_key",
    "google_cse_api_key",
    "google_cse_cx",
    "bing_search_api_key",
)
DEFAULT_OPTIONS: Dict[str, Any] = {
    "modules": None,
    "auto_pivot": True,
    "pivot_depth": 1,
    "concurrency": 8,
    "timeout": 8,
    "safe_mode": True,
    "max_subdomains": 100,
    "phone_region": "US",
    "person_context": "",
    "person_auto_pivot": False,
    "person_public_discovery": True,
}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def clamp(value: Any, minimum: int, maximum: int, fallback: int) -> int:
    try:
        return max(minimum, min(maximum, int(value)))
    except (TypeError, ValueError):
        return fallback


def normalize_options(raw: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Validate and clamp browser-supplied per-scan controls."""

    raw = raw or {}
    # Accept an optional nested shape from API clients while keeping the
    # dashboard's flat controls convenient.
    options = dict(raw)
    nested_keys = options.pop("api_keys", {})
    if isinstance(nested_keys, dict):
        for key, value in nested_keys.items():
            options.setdefault(key, value)
    normalized = dict(DEFAULT_OPTIONS)
    normalized.update(
        {
            "auto_pivot": bool(options.get("auto_pivot", DEFAULT_OPTIONS["auto_pivot"])),
            "pivot_depth": clamp(options.get("pivot_depth"), 0, 3, 1),
            "concurrency": clamp(options.get("concurrency"), 1, 16, 8),
            "timeout": clamp(options.get("timeout"), 2, 30, 8),
            "safe_mode": bool(options.get("safe_mode", True)),
            "max_subdomains": clamp(options.get("max_subdomains"), 1, 500, 100),
            "phone_region": str(options.get("phone_region", "US") or "US").upper()[:8],
            "person_context": str(options.get("person_context", "") or "")[:300],
            "person_auto_pivot": bool(options.get("person_auto_pivot", False)),
            "person_public_discovery": bool(options.get("person_public_discovery", True)),
        }
    )
    selected = options.get("modules", None)
    if selected is None:
        normalized["modules"] = None
    elif isinstance(selected, (list, tuple, set)):
        normalized["modules"] = [str(value) for value in selected if str(value) in REGISTRY or str(value) in {"domain", "ip", "email", "username", "phone", "person", "url", "hash", "crypto"}]
    else:
        normalized["modules"] = None
    for name in SECRET_OPTIONS:
        value = options.get(name, "")
        if isinstance(value, str):
            normalized[name] = value.strip()[:500]
        elif value:
            normalized[name] = str(value)[:500]
        else:
            normalized[name] = ""
    return normalized


@dataclass(frozen=True)
class ScanTask:
    module_key: str
    target: str
    depth: int
    parent: str = ""


ENTITY_MODULES = {
    "domain": "domain",
    "hostname": "domain",
    "ip": "ip",
    "email": "email",
    "username": "username",
    "phone": "phone",
    "person": "person",
    "url": "url",
    "hash": "hash",
    "crypto": "crypto",
}


def _normalised_task_value(module_key: str, value: str) -> str:
    return normalize_selector(value, module_key)


def _node_id(entity_type: str, value: str) -> str:
    compact = re.sub(r"\s+", " ", str(value).strip().lower())
    return f"{entity_type}:{compact}"


class ScanEngine:
    """Runs jobs without letting one source failure abort the scan."""

    def __init__(self) -> None:
        load_modules()
        self._tasks: Set[asyncio.Task[Any]] = set()

    def schedule(self, job: Job) -> None:
        task = asyncio.create_task(self.run(job), name=f"digiscope-scan-{job.id}")
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def run(self, job: Job) -> None:
        job.status = "running"
        job.started_at = utc_now()
        job.phase = "Preparing sources"
        options = normalize_options(job.options)
        job.options = options
        try:
            enabled = options.get("modules")
            if enabled is None:
                enabled_set = set(REGISTRY)
            else:
                enabled_set = {key for key in enabled if key in REGISTRY}
            initial = []
            if job.selector_type in REGISTRY and job.selector_type in enabled_set:
                initial.append(ScanTask(job.selector_type, job.normalized_input, 0, "root"))
            if not initial:
                job.notes.append("No enabled module matches this selector. Turn on the corresponding module chip and scan again.")
            root_id = _node_id(job.selector_type, job.normalized_input)
            job.nodes = [Node(root_id, job.selector_type, job.normalized_input, job.input, ["input"])]

            async with AsyncFetcher(
                timeout=options["timeout"],
                concurrency=options["concurrency"],
                safe_mode=options["safe_mode"],
            ) as fetcher:
                dns = DNSClient(fetcher, timeout=min(options["timeout"], 6))
                seen: Set[Tuple[str, str]] = set()
                wave = initial
                total_cap = 200
                while wave and wave[0].depth <= options["pivot_depth"]:
                    current_depth = wave[0].depth
                    current = []
                    for task in wave:
                        key = (task.module_key, _normalised_task_value(task.module_key, task.target))
                        if task.module_key not in enabled_set or key in seen:
                            continue
                        seen.add(key)
                        current.append(task)
                    if not current:
                        break
                    job.phase = f"Wave {current_depth + 1}: {len(current)} source task(s)"
                    job.progress = max(job.progress, min(92, 8 + current_depth * 24))
                    results = await asyncio.gather(
                        *(self._run_task(job, task, fetcher, dns, options) for task in current),
                        return_exceptions=False,
                    )
                    for task, result in zip(current, results):
                        job.module_results.append(result)
                        self._correlate_module(job, task, result)
                    self._aggregate(job)
                    if not options.get("auto_pivot") or current_depth >= options["pivot_depth"]:
                        break
                    next_wave: List[ScanTask] = []
                    for task, result in zip(current, results):
                        for entity in result.entities:
                            if not entity.pivot:
                                continue
                            module_key = ENTITY_MODULES.get(entity.type)
                            if not module_key or module_key not in enabled_set:
                                continue
                            normalized_value = _normalised_task_value(module_key, entity.value)
                            if not normalized_value:
                                continue
                            candidate_key = (module_key, normalized_value)
                            if candidate_key in seen:
                                continue
                            next_wave.append(ScanTask(module_key, entity.value, current_depth + 1, task.target))
                            if len(next_wave) + len(seen) >= total_cap:
                                job.notes.append(f"Pivot task cap ({total_cap}) reached; remaining pivots were held for analyst review.")
                                break
                        if len(next_wave) + len(seen) >= total_cap:
                            break
                    wave = next_wave
                    job.progress = min(94, job.progress + 12)
            self._aggregate(job)
            job.progress = 100
            job.phase = "Complete"
            job.status = "complete"
            job.completed_at = utc_now()
        except asyncio.CancelledError:
            job.status = "error"
            job.error = "Scan cancelled"
            job.phase = "Cancelled"
            job.completed_at = utc_now()
            raise
        except Exception as exc:  # defensive boundary for the whole job
            job.status = "error"
            job.error = f"{type(exc).__name__}: {str(exc)[:400]}"
            job.phase = "Stopped safely"
            job.completed_at = utc_now()
            self._aggregate(job)

    async def _run_task(
        self,
        job: Job,
        task: ScanTask,
        fetcher: AsyncFetcher,
        dns: DNSClient,
        options: Dict[str, Any],
    ) -> ModuleResult:
        spec = REGISTRY.get(task.module_key)
        started = time.perf_counter()
        source_status = {
            "module": task.module_key,
            "title": spec.title if spec else task.module_key,
            "target": task.target,
            "depth": task.depth,
            "status": "running",
        }
        job.source_statuses.append(source_status)
        if spec is None:
            result = ModuleResult(task.module_key, task.module_key, task.target, status="error", error="module not registered")
        else:
            context = ScanContext(fetcher, dns, options, task.module_key, task.depth, job.id)
            try:
                result = await spec.run(context, task.target)
                if not isinstance(result, ModuleResult):
                    result = ModuleResult(task.module_key, spec.title, task.target, status="error", error="module returned an invalid result")
            except Exception as exc:  # module-specific isolation guarantee
                result = ModuleResult(
                    task.module_key,
                    spec.title,
                    task.target,
                    status="error",
                    error=f"{type(exc).__name__}: {str(exc)[:320]}",
                    notes=["Module failure was isolated; other sources continued."],
                )
        result.key = task.module_key
        result.target = task.target
        result.title = spec.title if spec else result.title
        result.duration_ms = int((time.perf_counter() - started) * 1000)
        result.started_at = utc_now()
        result.completed_at = utc_now()
        source_status.update({"status": result.status, "duration_ms": result.duration_ms, "notes": result.notes[:3]})
        return result

    def _correlate_module(self, job: Job, task: ScanTask, result: ModuleResult) -> None:
        target_id = _node_id(task.module_key, task.target)
        if target_id not in {node.id for node in job.nodes}:
            job.nodes.append(Node(target_id, task.module_key, task.target, task.target, [result.key]))
        for entity in result.entities:
            entity_id = _node_id(entity.type, entity.value)
            existing = next((node for node in job.nodes if node.id == entity_id), None)
            if existing:
                if result.key not in existing.sources:
                    existing.sources.append(result.key)
                if entity.metadata:
                    existing.metadata.update(entity.metadata)
            else:
                job.nodes.append(Node(entity_id, entity.type, entity.value, entity.label or entity.value, [result.key], entity.metadata))
            edge = Edge(target_id, entity_id, entity.label or "discovered", result.key)
            if not any(item.source == edge.source and item.target == edge.target and item.source_module == edge.source_module for item in job.edges):
                job.edges.append(edge)

    def _aggregate(self, job: Job) -> None:
        findings: List[Finding] = []
        seen_findings: Set[Tuple[str, str, str]] = set()
        timeline: List[TimelineEvent] = []
        module_count = len(job.module_results)
        links_count = 0
        entity_count = 0
        coverage: Dict[str, Any] = {
            "modules_checked": module_count,
            "modules_complete": 0,
            "modules_partial": 0,
            "modules_error": 0,
            "entities": 0,
            "links": 0,
            "findings": 0,
        }
        username_coverage = None
        for result in job.module_results:
            if result.status == "complete":
                coverage["modules_complete"] += 1
            elif result.status == "partial":
                coverage["modules_partial"] += 1
            else:
                coverage["modules_error"] += 1
            entity_count += len(result.entities)
            links_count += len(result.links)
            for finding in result.findings:
                key = (finding.label, finding.source, finding.detail)
                if key not in seen_findings:
                    seen_findings.add(key)
                    findings.append(finding)
            timeline.extend(result.timeline)
            if result.key == "username":
                username_coverage = result.coverage
        # Stable timeline order without rejecting human-readable or epoch dates.
        timeline.sort(key=lambda event: str(event.date), reverse=True)
        score = min(100, sum(max(0, finding.score) for finding in findings))
        job.findings = findings
        job.timeline = timeline[:500]
        job.exposure_score = score
        job.exposure_label = exposure_label(score)
        coverage["entities"] = entity_count
        coverage["links"] = links_count
        coverage["findings"] = len(findings)
        if username_coverage is not None:
            coverage["username"] = username_coverage
        job.coverage = coverage


def make_job(input_value: str, selector_type: str = "auto", options: Optional[Dict[str, Any]] = None) -> Job:
    load_modules()
    detected = detect_selector(input_value)
    selected_type = detected.type if selector_type in {"", "auto", None} else selector_type
    normalized = normalize_selector(input_value, selected_type)
    normalized_options = normalize_options(options)
    return Job(
        id=uuid.uuid4().hex,
        input=input_value.strip(),
        selector_type=selected_type,
        normalized_input=normalized,
        options=normalized_options,
        created_at=utc_now(),
    )


__all__ = [
    "DEFAULT_OPTIONS",
    "ENTITY_MODULES",
    "ScanEngine",
    "make_job",
    "normalize_options",
    "utc_now",
]
