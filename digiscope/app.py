"""FastAPI application and REST surface for DigiScope."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .detection import detect_selector, validate_selector_type
from .engine import DEFAULT_OPTIONS, ScanEngine, make_job, normalize_options
from .models import SELECTOR_TYPES
from .modules import load_modules, specs
from .reports import render_export

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"


class ScanRequest(BaseModel):
    input: str = Field(..., min_length=1, max_length=500)
    type: str = Field(default="auto", max_length=24)
    options: Dict[str, Any] = Field(default_factory=dict)


class JobStore:
    def __init__(self, history_cap: int = 20) -> None:
        self.jobs: Dict[str, Any] = {}
        self.history_cap = history_cap
        self.history: List[str] = []

    def add(self, job: Any) -> None:
        self.jobs[job.id] = job
        self.history = [job.id] + [item for item in self.history if item != job.id]
        for stale in self.history[self.history_cap :]:
            self.jobs.pop(stale, None)
        self.history = self.history[: self.history_cap]

    def get(self, job_id: str) -> Any:
        return self.jobs.get(job_id)

    def summaries(self) -> List[Dict[str, Any]]:
        output = []
        for job_id in self.history:
            job = self.jobs.get(job_id)
            if not job:
                continue
            output.append(
                {
                    "id": job.id,
                    "input": job.input,
                    "selector_type": job.selector_type,
                    "status": job.status,
                    "progress": job.progress,
                    "exposure_score": job.exposure_score,
                    "exposure_label": job.exposure_label,
                    "created_at": job.created_at,
                    "completed_at": job.completed_at,
                    "modules": len(job.module_results),
                }
            )
        return output


load_modules()
app = FastAPI(
    title="DigiScope OSINT Dashboard",
    version="1.0.0",
    description="Passive, public-source OSINT correlation dashboard for authorised research.",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

store = JobStore()
engine = ScanEngine()


@app.get("/", include_in_schema=False)
async def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/health")
async def health() -> Dict[str, Any]:
    return {"status": "ok", "service": "digiscope", "version": app.version, "modules": len(specs())}


@app.get("/api/meta")
async def meta() -> Dict[str, Any]:
    return {
        "name": "DigiScope",
        "version": app.version,
        "selector_types": SELECTOR_TYPES,
        "default_options": {key: value for key, value in DEFAULT_OPTIONS.items() if key != "modules"},
        "modules": [
            {
                "key": item.key,
                "title": item.title,
                "description": item.description,
                "category": item.category,
                "sources": item.sources,
            }
            for item in specs()
        ],
        "ethics": "Passive public-source observations for authorised research, own-footprint review, threat intelligence and journalism. No active port scans or intrusive probes are performed.",
    }


@app.get("/api/detect")
async def detect(q: str = Query(default="", max_length=500), region: str = Query(default="", max_length=8)) -> Dict[str, Any]:
    return detect_selector(q, region or None).to_dict()


@app.post("/api/scan", status_code=202)
async def create_scan(request: ScanRequest) -> Dict[str, Any]:
    requested_type = request.type.strip().lower() or "auto"
    if not validate_selector_type(requested_type):
        raise HTTPException(status_code=422, detail=f"type must be auto or one of {', '.join(SELECTOR_TYPES)}")
    detected = detect_selector(request.input, str(request.options.get("phone_region", "") or "") or None)
    if requested_type == "auto" and not request.input.strip():
        raise HTTPException(status_code=422, detail="input cannot be blank")
    job = make_job(request.input, requested_type, request.options)
    job.options = normalize_options(request.options)
    store.add(job)
    engine.schedule(job)
    return {
        "id": job.id,
        "status": job.status,
        "type": job.selector_type,
        "detection": detected.to_dict(),
        "message": "Scan queued; poll /api/scan/{id} for progress.",
    }


@app.get("/api/scan/{job_id}")
async def get_scan(job_id: str) -> Dict[str, Any]:
    job = store.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="scan not found")
    payload = job.to_dict(include_results=True)
    payload["detection"] = detect_selector(job.input, job.options.get("phone_region")).to_dict()
    return payload


@app.get("/api/scan/{job_id}/export")
async def export_scan(job_id: str, format: str = Query(default="json")) -> Response:
    job = store.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="scan not found")
    try:
        content, media_type, filename = render_export(job, format)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/history")
async def history() -> Dict[str, Any]:
    return {"items": store.summaries(), "limit": store.history_cap}


__all__ = ["app", "engine", "store"]
