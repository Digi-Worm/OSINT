# Contributing to DigiScope

Thanks for helping improve a small, transparent OSINT console.

## Principles

1. Add only open/public, documented sources and keep a free/keyless path where practical.
2. Default to passive, low-impact requests. No brute force, active scanning, exploit code or access-control bypass.
3. Treat people data as sensitive. Person mode must remain lead generation with verification reminders.
4. Never log or persist API keys. Keep secrets out of tests, fixtures, screenshots and commits.
5. A provider outage must produce a partial result/note, not crash a scan.

## Adding a module

* Create one file under `digiscope/modules/` and register an async function with `@register`.
* Use the shared `ScanContext.fetcher` and `ScanContext.dns`; do not create one HTTP client per request.
* Return `ModuleResult` sections/entities/links/findings/notes/coverage. Mark uncertain observations as heuristic or inconclusive.
* Add the module key to `digiscope/modules/__init__.py`, `models.SELECTOR_TYPES` if it is a new selector, and the UI/API metadata is then populated automatically.
* Keep pivots typed and bounded. Set `pivot=False` for values that should be manual analyst leads.
* Add or update network-free tests with mocked provider responses.

## Local checks

```bash
python -m pip install -r requirements.txt
pytest
ruff check .
python run.py
```

Keep frontend changes zero-build and accessible with keyboard focus, useful labels and safe `target="_blank" rel="noreferrer"` links. Update the README when a provider, control or safety boundary changes.
