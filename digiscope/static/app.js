/* DigiScope dashboard — zero-build browser client. */
(() => {
  "use strict";

  const state = { meta: null, job: null, pollTimer: null, detectTimer: null, graph: { nodes: [], edges: [], scale: 1, panX: 0, panY: 0, dragging: null, moved: false } };
  const $ = (id) => document.getElementById(id);
  const q = (selector, root = document) => Array.from(root.querySelectorAll(selector));
  const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#039;"}[char]));
  const safeHref = (value) => /^https?:\/\//i.test(String(value ?? "")) ? String(value) : "#";
  const pretty = (value) => {
    if (value === null || value === undefined || value === "") return "—";
    if (typeof value === "object") return JSON.stringify(value, null, 2);
    return String(value);
  };
  const toast = (message) => {
    const node = document.createElement("div"); node.className = "error-toast"; node.textContent = message; document.body.appendChild(node);
    setTimeout(() => node.remove(), 5200);
  };
  const getJSON = async (url, options = {}) => {
    const response = await fetch(url, options);
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.detail || `Request failed (${response.status})`);
    return data;
  };

  async function loadMeta() {
    try {
      state.meta = await getJSON("/api/meta");
      $("healthText").textContent = `${state.meta.modules.length} modules ready`;
      renderModuleControls();
      updateControlSummary();
    } catch (error) {
      $("healthText").textContent = "offline / retry later";
      toast(error.message);
    }
  }

  function renderModuleControls() {
    const root = $("moduleControls");
    root.innerHTML = (state.meta?.modules || []).map((module) => `<label class="module-chip" title="${esc(module.description)}"><input type="checkbox" data-module="${esc(module.key)}" checked><span>${esc(module.title)}</span></label>`).join("");
    q("[data-module]", root).forEach((input) => input.addEventListener("change", updateControlSummary));
  }

  function updateControlSummary() {
    const checked = q("[data-module]:checked").length;
    const safe = $("safeMode")?.checked ? "safe mode" : "active network mode";
    $("controlSummary").textContent = `${checked} module${checked === 1 ? "" : "s"} · ${safe}`;
  }

  function setBadge(data) {
    const badge = $("detectedBadge");
    if (!data || !data.type || !$("selectorInput").value.trim()) { badge.textContent = "AUTO-DETECT"; badge.className = "detected-badge"; return; }
    badge.textContent = `${data.type.toUpperCase()} · ${Math.round((data.confidence || 0) * 100)}%`;
    badge.className = `detected-badge ${data.confidence < .6 ? "low-confidence" : ""}`;
  }

  function scheduleDetect() {
    clearTimeout(state.detectTimer);
    const value = $("selectorInput").value.trim();
    if (!value) { setBadge(null); return; }
    state.detectTimer = setTimeout(async () => {
      try { setBadge(await getJSON(`/api/detect?q=${encodeURIComponent(value)}&region=${encodeURIComponent($("phoneRegion").value || "")}`)); }
      catch (_error) { /* input feedback should never interrupt typing */ }
    }, 250);
  }

  function readOptions() {
    const keys = { hibp_api_key: $("hibpKey").value, shodan_api_key: $("shodanKey").value, abuseipdb_api_key: $("abuseKey").value, virustotal_api_key: $("vtKey").value, github_token: $("githubToken").value, numverify_api_key: $("numverifyKey").value };
    return {
      modules: q("[data-module]:checked").map((input) => input.dataset.module),
      auto_pivot: $("autoPivot").checked,
      safe_mode: $("safeMode").checked,
      pivot_depth: Number($("pivotDepth").value),
      concurrency: Number($("concurrency").value),
      timeout: Number($("timeout").value),
      max_subdomains: Number($("maxSubdomains").value),
      phone_region: $("phoneRegion").value.trim().toUpperCase() || "US",
      person_context: $("personContext").value.trim(),
      person_auto_pivot: $("personAutoPivot").checked,
      person_public_discovery: $("personPublicDiscovery").checked,
      ...keys,
    };
  }

  async function startScan(event) {
    event.preventDefault();
    const input = $("selectorInput").value.trim();
    if (!input) { toast("Enter a selector to investigate."); $("selectorInput").focus(); return; }
    if (!q("[data-module]:checked").length) { toast("Enable at least one source module in Advanced controls."); return; }
    const button = $("investigateButton"); button.disabled = true; button.querySelector("span").textContent = "Queueing…";
    state.job = null; $("dashboard").classList.add("hidden"); $("scanState").classList.remove("hidden");
    setProgress({ progress: 0, phase: "Queueing investigation", source_statuses: [] });
    try {
      const data = await getJSON("/api/scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ input, type: $("typeSelect").value, options: readOptions() }) });
      await pollScan(data.id);
    } catch (error) { toast(error.message); $("scanState").classList.add("hidden"); }
    button.disabled = false; button.querySelector("span").textContent = "Investigate";
  }

  async function pollScan(id) {
    clearTimeout(state.pollTimer);
    const tick = async () => {
      try {
        const job = await getJSON(`/api/scan/${encodeURIComponent(id)}`); state.job = job; setProgress(job);
        if (["complete", "error"].includes(job.status)) { renderDashboard(job); return; }
        state.pollTimer = setTimeout(tick, 850);
      } catch (error) { toast(error.message); }
    };
    await tick();
  }

  function setProgress(job) {
    const progress = Math.max(0, Math.min(100, Number(job.progress || 0)));
    $("progressBar").style.width = `${progress}%`; $("progressNumber").textContent = `${progress}%`; $("phaseText").textContent = job.phase || "Working";
    const statuses = job.source_statuses || [];
    $("sourceStatuses").innerHTML = statuses.length ? statuses.map((source) => `<span class="source-status ${esc(source.status)}">${esc(source.title || source.module)}${source.target ? ` · ${esc(source.target)}` : ""}</span>`).join("") : `<span class="source-status running">Starting source workers…</span>`;
    if (job.status === "complete") $("phaseText").textContent = "Investigation complete";
    if (job.status === "error") $("phaseText").textContent = job.error || "Investigation stopped safely";
  }

  function renderDashboard(job) {
    $("scanState").classList.remove("hidden"); $("dashboard").classList.remove("hidden");
    $("resultTitle").textContent = job.input || "Investigation"; $("resultType").textContent = `· ${(job.selector_type || "auto").toUpperCase()}`;
    $("resultMeta").textContent = `${job.status === "complete" ? "Completed" : "Stopped with errors"} · ${job.modules?.length || 0} module runs · ${job.completed_at || job.created_at || ""}`;
    $("moduleCount").textContent = job.modules?.length || 0;
    renderOverview(job); renderModules(job); renderGraph(job); renderTimeline(job); renderLinks(job); $("rawJson").textContent = JSON.stringify(job, null, 2);
    q(".tab").forEach((tab) => tab.classList.toggle("active", tab.dataset.tab === "overview")); q(".tab-panel").forEach((panel) => panel.classList.toggle("active", panel.id === "tab-overview"));
    window.scrollTo({ top: $("dashboard").offsetTop - 20, behavior: "smooth" });
  }

  function renderOverview(job) {
    const score = Number(job.exposure_score || 0); $("scoreNumber").textContent = score; $("scoreLabel").textContent = job.exposure_label || "Unknown"; $("scoreRing").style.setProperty("--score", score);
    const scoreColor = score >= 60 ? "var(--red)" : score >= 20 ? "var(--amber)" : "var(--teal)"; $("scoreLabel").style.color = scoreColor;
    const findings = job.findings || []; $("findingCount").textContent = findings.length;
    $("findingsList").innerHTML = findings.length ? findings.slice(0, 12).map((finding) => `<div class="finding-item"><i class="finding-severity ${esc(finding.severity)}"></i><div><strong>${esc(finding.label)}</strong><small>${esc(finding.detail || finding.source || "")}</small></div><span class="finding-score">+${Number(finding.score || 0)}</span></div>`).join("") : `<div class="empty-state">No scored findings were recorded.</div>`;
    const coverage = job.coverage || {}; const graph = job.graph || {}; const metrics = [[graph.nodes?.length || 0, "graph entities"], [coverage.modules_checked || 0, "source runs"], [coverage.links || 0, "analyst links"], [coverage.modules_partial || 0, "partial sources"]];
    $("metricGrid").innerHTML = metrics.map(([value, label]) => `<div class="metric"><strong>${esc(value)}</strong><span>${esc(label)}</span></div>`).join("");
    const counts = {}; (graph.nodes || []).forEach((node) => { counts[node.type] = (counts[node.type] || 0) + 1; });
    $("pivotSummary").innerHTML = Object.keys(counts).length ? Object.entries(counts).map(([type, count]) => `<div class="pivot-chip"><b>${esc(count)}</b><span>${esc(type)}${count === 1 ? "" : "s"}</span></div>`).join("") : `<span class="muted">No entities correlated yet.</span>`;
  }

  function renderSection(section) {
    const title = `<h5>${esc(section.title || "Section")}</h5>${section.description ? `<p class="section-description">${esc(section.description)}</p>` : ""}`;
    const data = section.data;
    if (section.kind === "kv" || (data && typeof data === "object" && !Array.isArray(data))) {
      const entries = Object.entries(data || {}); return `<div class="result-section">${title}<div class="kv-grid">${entries.map(([key, value]) => `<div class="kv-item"><small>${esc(key)}</small><span>${esc(pretty(value))}</span></div>`).join("") || `<span class="muted">No values returned.</span>`}</div></div>`;
    }
    if (section.kind === "tags") { const tags = Array.isArray(data) ? data : [data]; return `<div class="result-section">${title}<div class="tag-list">${tags.map((tag) => `<span class="tag">${esc(pretty(tag))}</span>`).join("") || `<span class="muted">None observed.</span>`}</div></div>`; }
    if (section.kind === "links") { return `<div class="result-section">${title}<div class="module-links">${(Array.isArray(data) ? data : []).map((link) => `<a href="${esc(safeHref(link.url || link))}" target="_blank" rel="noreferrer">${esc(link.title || link.url || link)} ↗</a>`).join("")}</div></div>`; }
    if (Array.isArray(data)) return `<div class="result-section">${title}${tableHTML(data)}</div>`;
    return `<div class="result-section">${title}<pre class="json-block">${esc(pretty(data))}</pre></div>`;
  }

  function tableHTML(rows) {
    if (!rows.length) return `<span class="muted">No records returned.</span>`;
    const normalized = rows.map((row) => (row && typeof row === "object" && !Array.isArray(row) ? row : { value: row })); const columns = [...new Set(normalized.flatMap((row) => Object.keys(row)))].slice(0, 14);
    return `<div class="data-table-wrap"><table class="data-table"><thead><tr>${columns.map((column) => `<th>${esc(column)}</th>`).join("")}</tr></thead><tbody>${normalized.map((row) => `<tr>${columns.map((column) => `<td>${esc(pretty(row[column]))}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`;
  }

  function renderModules(job) {
    const modules = job.modules || []; const coverage = job.coverage || {}; $("coverageSummary").innerHTML = `<span>${coverage.modules_complete || 0} complete</span><span>·</span><span>${coverage.modules_partial || 0} partial</span><span>·</span><span>${coverage.modules_error || 0} errors</span>`;
    $("moduleCards").innerHTML = modules.length ? modules.map((module) => `<article class="module-card"><div class="module-card-head"><div><h4>${esc(module.title || module.key)}</h4><p>${esc(module.key)} · ${esc(module.duration_ms || 0)} ms</p></div><span class="module-status ${esc(module.status)}">${esc(module.status)}</span></div><div class="module-card-body"><div class="module-target">target · ${esc(module.target)}</div>${(module.sections || []).map(renderSection).join("")}${(module.links || []).length ? `<div class="result-section"><h5>ANALYST LINKS</h5><div class="module-links">${module.links.map((link) => `<a href="${esc(safeHref(link.url))}" target="_blank" rel="noreferrer">${esc(link.title)} ↗</a>`).join("")}</div></div>` : ""}${(module.notes || []).length ? `<div class="module-notes">${module.notes.map((note) => `• ${esc(note)}`).join("<br>")}</div>` : ""}${module.error ? `<div class="module-notes">${esc(module.error)}</div>` : ""}</div></article>`).join("") : `<div class="empty-state">No enabled module matched this selector.</div>`;
  }

  const nodeColors = { domain: "#75a8ff", ip: "#c1a6ff", email: "#ffce83", username: "#70e1c1", phone: "#ff91ac", person: "#f0a5ff", url: "#86d6ff", hash: "#ff9d72", crypto: "#ffd35b", asn: "#98a7ba" };
  function renderGraph(job) {
    state.graph.nodes = (job.graph?.nodes || []).map((node, index) => ({ ...node, x: 0, y: 0, r: node.id.startsWith(`${job.selector_type}:`) ? 13 : 8, index })); state.graph.edges = job.graph?.edges || []; state.graph.scale = 1; state.graph.panX = 0; state.graph.panY = 0;
    const canvas = $("graphCanvas"); const rect = canvas.getBoundingClientRect(); const width = rect.width || 900; const height = rect.height || 540; state.graph.nodes.forEach((node, index) => { const radius = Math.min(width, height) * .31 * ((index % 3 + 1) / 3); const angle = (index / Math.max(1, state.graph.nodes.length)) * Math.PI * 2; node.x = width / 2 + Math.cos(angle) * radius; node.y = height / 2 + Math.sin(angle) * radius; });
    const types = [...new Set(state.graph.nodes.map((node) => node.type))]; $("graphLegend").innerHTML = types.map((type) => `<span class="legend-entry"><i style="background:${nodeColors[type] || "#94a3b8"}"></i>${esc(type)}</span>`).join(""); drawGraph();
  }

  function resizeCanvas() { const canvas = $("graphCanvas"); if (!canvas) return; const ratio = window.devicePixelRatio || 1; const rect = canvas.getBoundingClientRect(); canvas.width = rect.width * ratio; canvas.height = rect.height * ratio; const ctx = canvas.getContext("2d"); ctx.setTransform(ratio, 0, 0, ratio, 0, 0); drawGraph(); }
  function graphPoint(event) { const canvas = $("graphCanvas"); const rect = canvas.getBoundingClientRect(); return { x: (event.clientX - rect.left - state.graph.panX) / state.graph.scale, y: (event.clientY - rect.top - state.graph.panY) / state.graph.scale }; }
  function drawGraph() {
    const canvas = $("graphCanvas"); if (!canvas || !state.graph.nodes.length) { if (canvas) { const ctx = canvas.getContext("2d"); ctx.clearRect(0, 0, canvas.width, canvas.height); } return; }
    const rect = canvas.getBoundingClientRect(); const ctx = canvas.getContext("2d"); ctx.clearRect(0, 0, rect.width, rect.height); ctx.save(); ctx.translate(state.graph.panX, state.graph.panY); ctx.scale(state.graph.scale, state.graph.scale);
    const byId = Object.fromEntries(state.graph.nodes.map((node) => [node.id, node])); ctx.lineWidth = 1; state.graph.edges.forEach((edge) => { const a = byId[edge.source], b = byId[edge.target]; if (!a || !b) return; ctx.strokeStyle = "rgba(107,137,183,.38)"; ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke(); });
    state.graph.nodes.forEach((node) => { const color = nodeColors[node.type] || "#94a3b8"; ctx.fillStyle = color; ctx.shadowColor = color; ctx.shadowBlur = 12; ctx.beginPath(); ctx.arc(node.x, node.y, node.r, 0, Math.PI * 2); ctx.fill(); ctx.shadowBlur = 0; ctx.fillStyle = "#dfe8f7"; ctx.font = `${node.r <= 8 ? 10 : 11}px system-ui`; ctx.textAlign = "center"; ctx.fillText((node.label || node.value).slice(0, 26), node.x, node.y + node.r + 14); }); ctx.restore();
  }
  function showInspector(node) { const inspector = $("nodeInspector"); const value = node.value || ""; let links = []; if (node.type === "domain") links = [["Open host", `https://${value}`], ["RDAP", `https://rdap.org/domain/${encodeURIComponent(value)}`]]; if (node.type === "ip") links = [["RDAP", `https://rdap.org/ip/${encodeURIComponent(value)}`], ["InternetDB", `https://internetdb.shodan.io/${encodeURIComponent(value)}`]]; if (node.type === "username") links = [["GitHub", `https://github.com/${encodeURIComponent(value)}`]]; if (node.type === "email") links = [["Google exact search", `https://www.google.com/search?q=${encodeURIComponent('"' + value + '"')}`]]; inspector.innerHTML = `<h4>${esc(node.type)}</h4><code>${esc(value)}</code><p>${esc((node.sources || []).join(" · "))}</p>${links.map(([label, url]) => `<a href="${esc(safeHref(url))}" target="_blank" rel="noreferrer">${esc(label)} ↗</a>`).join("")}<button class="text-button" style="margin-top:10px" onclick="document.getElementById('nodeInspector').classList.add('hidden')">close</button>`; inspector.classList.remove("hidden"); }

  function renderTimeline(job) { const items = job.timeline || []; $("timelineCount").textContent = `${items.length} event${items.length === 1 ? "" : "s"}`; $("timelineList").innerHTML = items.length ? items.map((item) => `<div class="timeline-item"><div class="timeline-date">${esc(item.date)}</div><strong>${esc(item.label)}</strong><small>${esc(item.source)}${item.detail ? ` · ${esc(item.detail)}` : ""}</small></div>`).join("") : `<div class="empty-state">No source dates were extracted.</div>`; }
  function renderLinks(job) { const groups = {}; (job.modules || []).forEach((module) => (module.links || []).forEach((link) => { const key = link.source || module.title || module.key; (groups[key] ||= []).push(link); })); const count = Object.values(groups).reduce((total, links) => total + links.length, 0); $("linkCount").textContent = `${count} link${count === 1 ? "" : "s"}`; $("linksList").innerHTML = count ? Object.entries(groups).map(([source, links]) => `<section class="link-group"><h4>${esc(source)}</h4>${links.map((link) => `<div class="link-item"><a href="${esc(safeHref(link.url))}" target="_blank" rel="noreferrer">${esc(link.title)} ↗</a><span>${esc(link.kind || "reference")} · ${esc(safeHref(link.url))}</span></div>`).join("")}</section>`).join("") : `<div class="empty-state">No analyst links returned.</div>`; }

  async function loadHistory() { try { const data = await getJSON("/api/history"); $("historyList").innerHTML = data.items?.length ? data.items.map((item) => `<div class="history-item" data-history-id="${esc(item.id)}"><span class="history-score">${esc(item.exposure_score || 0)}</span><strong>${esc(item.input)}</strong><small>${esc(item.selector_type)} · ${esc(item.status)} · ${esc(item.created_at || "")}</small></div>`).join("") : `<div class="empty-state">No scans in memory.</div>`; q("[data-history-id]").forEach((item) => item.addEventListener("click", () => { closeHistory(); pollScan(item.dataset.historyId); })); } catch (error) { toast(error.message); } }
  function openHistory() { $("historyDrawer").classList.add("open"); $("historyDrawer").setAttribute("aria-hidden", "false"); $("drawerBackdrop").classList.remove("hidden"); loadHistory(); }
  function closeHistory() { $("historyDrawer").classList.remove("open"); $("historyDrawer").setAttribute("aria-hidden", "true"); $("drawerBackdrop").classList.add("hidden"); }

  function bind() {
    $("scanForm").addEventListener("submit", startScan); $("selectorInput").addEventListener("input", scheduleDetect); $("advancedToggle").addEventListener("click", () => $("advancedPanel").classList.toggle("open")); $("safeMode").addEventListener("change", updateControlSummary);
    ["pivotDepth", "concurrency", "timeout", "maxSubdomains"].forEach((id) => $(id).addEventListener("input", () => { const labels = { pivotDepth: [`${$(id).value} wave${$(id).value === "1" ? "" : "s"}`, "pivotDepthValue"], concurrency: [`${$(id).value} tasks`, "concurrencyValue"], timeout: [`${$(id).value} sec`, "timeoutValue"], maxSubdomains: [`${$(id).value} names`, "maxSubdomainsValue"] }; $(labels[id][1]).textContent = labels[id][0]; }));
    $("selectAllModules").addEventListener("click", () => { q("[data-module]").forEach((input) => { input.checked = true; }); updateControlSummary(); }); $("selectNoModules").addEventListener("click", () => { q("[data-module]").forEach((input) => { input.checked = false; }); updateControlSummary(); });
    q(".example-chip").forEach((chip) => chip.addEventListener("click", () => { $("selectorInput").value = chip.dataset.value; scheduleDetect(); $("selectorInput").focus(); })); $("historyButton").addEventListener("click", openHistory); $("closeHistory").addEventListener("click", closeHistory); $("drawerBackdrop").addEventListener("click", closeHistory);
    q(".tab").forEach((tab) => tab.addEventListener("click", () => { q(".tab").forEach((item) => item.classList.toggle("active", item === tab)); q(".tab-panel").forEach((panel) => panel.classList.toggle("active", panel.id === `tab-${tab.dataset.tab}`)); if (tab.dataset.tab === "graph") setTimeout(resizeCanvas, 30); }));
    q("[data-export]").forEach((button) => button.addEventListener("click", () => { if (state.job?.id) window.location.href = `/api/scan/${encodeURIComponent(state.job.id)}/export?format=${button.dataset.export}`; else toast("Run an investigation first."); })); $("copyRaw").addEventListener("click", async () => { try { await navigator.clipboard.writeText($("rawJson").textContent); $("copyRaw").textContent = "Copied"; setTimeout(() => { $("copyRaw").textContent = "Copy JSON"; }, 1200); } catch (_error) { toast("Clipboard permission was not available."); } });
    const canvas = $("graphCanvas"); canvas.addEventListener("wheel", (event) => { event.preventDefault(); const before = graphPoint(event); state.graph.scale = Math.max(.45, Math.min(2.5, state.graph.scale * (event.deltaY < 0 ? 1.1 : .9))); const after = graphPoint(event); state.graph.panX += (after.x - before.x) * state.graph.scale; state.graph.panY += (after.y - before.y) * state.graph.scale; drawGraph(); }, { passive: false });
    canvas.addEventListener("pointerdown", (event) => { const point = graphPoint(event); const node = state.graph.nodes.slice().reverse().find((item) => Math.hypot(item.x - point.x, item.y - point.y) < item.r + 8); state.graph.dragging = { node, x: event.clientX, y: event.clientY, panX: state.graph.panX, panY: state.graph.panY }; state.graph.moved = false; canvas.setPointerCapture(event.pointerId); });
    canvas.addEventListener("pointermove", (event) => { const drag = state.graph.dragging; if (!drag) return; const dx = event.clientX - drag.x, dy = event.clientY - drag.y; if (Math.abs(dx) + Math.abs(dy) > 3) state.graph.moved = true; if (drag.node) { drag.node.x += dx / state.graph.scale; drag.node.y += dy / state.graph.scale; drag.x = event.clientX; drag.y = event.clientY; } else { state.graph.panX = drag.panX + dx; state.graph.panY = drag.panY + dy; } drawGraph(); });
    canvas.addEventListener("pointerup", () => { const drag = state.graph.dragging; state.graph.dragging = null; if (drag?.node && !state.graph.moved) showInspector(drag.node); }); window.addEventListener("resize", resizeCanvas);
  }

  bind(); loadMeta();
})();
