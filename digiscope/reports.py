"""JSON, CSV, Markdown and self-contained HTML report renderers."""

from __future__ import annotations

import csv
import html
import io
import json
from typing import Any, Dict, Tuple

from .models import Job


def _payload(job: Job) -> Dict[str, Any]:
    return job.to_dict(include_results=True)


def as_json(job: Job) -> str:
    return json.dumps(_payload(job), indent=2, ensure_ascii=False, default=str)


def as_csv(job: Job) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["record_type", "type", "value", "source", "status", "severity", "score", "detail", "url"])
    payload = _payload(job)
    for module in payload.get("modules", []):
        writer.writerow(["module", module.get("key", ""), module.get("target", ""), module.get("title", ""), module.get("status", ""), "", "", module.get("error", ""), ""])
        for entity in module.get("entities", []):
            writer.writerow(["entity", entity.get("type", ""), entity.get("value", ""), entity.get("source", ""), "", "", "", entity.get("label", ""), ""])
        for link in module.get("links", []):
            writer.writerow(["link", "", "", link.get("source", ""), "", "", "", link.get("title", ""), link.get("url", "")])
        for finding in module.get("findings", []):
            writer.writerow(["finding", "", "", finding.get("source", ""), "", finding.get("severity", ""), finding.get("score", 0), finding.get("label", ""), ""])
    return output.getvalue()


def as_markdown(job: Job) -> str:
    payload = _payload(job)
    lines = [
        "# DigiScope investigation report",
        "",
        f"- **Input:** `{payload.get('input', '')}`",
        f"- **Detected type:** `{payload.get('selector_type', '')}`",
        f"- **Status:** `{payload.get('status', '')}`",
        f"- **Exposure score:** **{payload.get('exposure_score', 0)}/100 ({payload.get('exposure_label', 'Unknown')})**",
        f"- **Generated:** `{payload.get('completed_at') or payload.get('created_at', '')}`",
        "",
        "> Responsible-use notice: this report contains public-source observations. Use it only for authorised research, own-footprint review, threat intelligence, journalism or other lawful purposes. Verify findings before acting.",
        "",
        "## Key findings",
    ]
    findings = payload.get("findings", [])
    if findings:
        lines.extend(f"- **{item.get('severity', '').title()}** — {item.get('label', '')} ({item.get('detail', '')})" for item in findings)
    else:
        lines.append("- No scored findings were recorded.")
    lines.extend(["", "## Entity graph"])
    for node in payload.get("graph", {}).get("nodes", []):
        lines.append(f"- `{node.get('type', '')}` — `{node.get('value', '')}`")
    lines.extend(["", "## Modules"])
    for module in payload.get("modules", []):
        lines.extend([f"### {module.get('title', module.get('key', 'Module'))} · `{module.get('target', '')}`", f"Status: `{module.get('status', '')}`", ""])
        for section in module.get("sections", []):
            lines.append(f"#### {section.get('title', 'Section')}")
            data = section.get("data")
            if isinstance(data, dict):
                for key, value in data.items():
                    lines.append(f"- **{key}:** `{json.dumps(value, ensure_ascii=False, default=str)}`")
            elif isinstance(data, list):
                lines.append("```")
                lines.append(json.dumps(data, indent=2, ensure_ascii=False, default=str))
                lines.append("```")
            else:
                lines.append(str(data))
        if module.get("notes"):
            lines.append("_Notes:_ " + " · ".join(module["notes"]))
        lines.append("")
    lines.extend(["## Links", ""])
    for module in payload.get("modules", []):
        for link in module.get("links", []):
            lines.append(f"- [{link.get('title', 'link')}]({link.get('url', '')})")
    return "\n".join(lines).replace("\n\n\n", "\n\n")


def as_html(job: Job) -> str:
    payload = _payload(job)
    encoded = json.dumps(payload, ensure_ascii=False, default=str).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    finding_rows = "".join(
        f"<tr><td><span class=\"severity {html.escape(str(item.get('severity', 'info')))}\">{html.escape(str(item.get('severity', 'info')).upper())}</span></td><td>{html.escape(str(item.get('label', '')))}</td><td>{html.escape(str(item.get('detail', '')))}</td></tr>"
        for item in payload.get("findings", [])
    )
    module_cards = []
    for module in payload.get("modules", []):
        sections = []
        for section in module.get("sections", []):
            data = html.escape(json.dumps(section.get("data"), ensure_ascii=False, indent=2, default=str))
            sections.append(f"<details><summary>{html.escape(str(section.get('title', 'Section')))}</summary><pre>{data}</pre></details>")
        module_cards.append(f"<article><h3>{html.escape(str(module.get('title', module.get('key', 'Module'))))}</h3><p><b>Target:</b> <code>{html.escape(str(module.get('target', '')))}</code> · <b>Status:</b> {html.escape(str(module.get('status', '')))}</p>{''.join(sections)}</article>")
    module_markup = "".join(module_cards)
    finding_markup = finding_rows or '<tr><td colspan="3">No scored findings</td></tr>'
    score = int(payload.get("exposure_score", 0) or 0)
    return f"""<!doctype html>
<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>DigiScope report · {html.escape(str(payload.get('input', '')))}</title>
<style>body{{font:15px/1.55 system-ui,sans-serif;background:#0b1020;color:#e5e7eb;max-width:1100px;margin:0 auto;padding:32px}}h1,h2,h3{{color:#fff}}.hero,article,table{{background:#111a2e;border:1px solid #263452;border-radius:14px;padding:20px;margin:16px 0}}.score{{font-size:48px;font-weight:800;color:#70e1c1}}code,pre{{background:#0b1020;border-radius:6px;padding:3px 6px}}pre{{white-space:pre-wrap;padding:14px;overflow:auto}}table{{width:100%;border-collapse:collapse;padding:0}}td,th{{padding:10px;border-bottom:1px solid #263452;text-align:left}}.severity{{font-size:11px;font-weight:700}}.high,.critical{{color:#ff8b9c}}.medium{{color:#ffd18b}}.low,.info{{color:#70e1c1}}a{{color:#8cb4ff}}</style></head>
<body><div class=\"hero\"><h1>DigiScope investigation report</h1><p>Input <code>{html.escape(str(payload.get('input', '')))}</code> · Type <code>{html.escape(str(payload.get('selector_type', '')))}</code></p><div class=\"score\">{score}/100</div><p>{html.escape(str(payload.get('exposure_label', 'Unknown')))} exposure · {html.escape(str(payload.get('status', '')))}</p></div>
<p><b>Responsible use:</b> public-source observations for authorised research, own-footprint review, threat intelligence, journalism or other lawful purposes. Verify findings independently.</p>
<h2>Key findings</h2><table><thead><tr><th>Severity</th><th>Observation</th><th>Detail</th></tr></thead><tbody>{finding_markup}</tbody></table>
<h2>Modules</h2>{module_markup or '<p>No modules returned.</p>'}
<h2>Machine-readable payload</h2><details><summary>Show JSON</summary><pre id=\"payload\"></pre></details>
<script>const payload={encoded};document.getElementById('payload').textContent=JSON.stringify(payload,null,2);</script></body></html>"""


def render_export(job: Job, format_name: str) -> Tuple[str, str, str]:
    format_name = format_name.lower()
    if format_name == "json":
        return as_json(job), "application/json", "digiscope-report.json"
    if format_name == "csv":
        return as_csv(job), "text/csv", "digiscope-report.csv"
    if format_name in {"md", "markdown"}:
        return as_markdown(job), "text/markdown", "digiscope-report.md"
    if format_name == "html":
        return as_html(job), "text/html", "digiscope-report.html"
    raise ValueError("format must be json, csv, md or html")


__all__ = ["render_export", "as_json", "as_csv", "as_markdown", "as_html"]
