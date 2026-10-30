/* CLCA console — vanilla JS, no build step.
   Talks to the stdlib service: /healthz, /v1/scenarios, /v1/runs. */
"use strict";

const $ = (sel, el = document) => el.querySelector(sel);
const $$ = (sel, el = document) => [...el.querySelectorAll(sel)];

const state = {
  scenarios: [],
  runs: [],           // summary list from GET /v1/runs (newest first)
  activeRunId: null,
  pollTimer: null,
  pollGen: 0,         // generation token: only the newest poll may touch the view
  pollAbort: null,    // AbortController for the in-flight poll fetch
  cy: null,           // Cytoscape instance
  graphLoadedFor: null,
};

/* ---------------- theme ---------------- */
const THEME_KEY = "clca-theme";

function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  $("#icon-moon").style.display = theme === "dark" ? "none" : "";
  $("#icon-sun").style.display = theme === "dark" ? "" : "none";
  $("#theme-label").textContent = theme === "dark" ? "Light" : "Dark";
}

function initTheme() {
  const saved = localStorage.getItem(THEME_KEY);
  const theme = saved || (matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark");
  applyTheme(theme);
}

$("#theme-toggle").addEventListener("click", () => {
  const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  localStorage.setItem(THEME_KEY, next);
  applyTheme(next);
  // Graph label backdrops are resolved at mount time — re-render if visible.
  if (state.graphLoadedFor && state.activeRunId) loadGraph(state.activeRunId);
});

/* ---------------- api ---------------- */
async function api(path, opts) {
  const res = await fetch(path, opts);
  const text = await res.text();
  let body;
  try { body = JSON.parse(text); } catch { body = { raw: text }; }
  if (!res.ok) throw new Error(body.error || `${res.status} ${res.statusText}`);
  return body;
}

/* ---------------- health ---------------- */
async function refreshHealth() {
  try {
    const h = await api("/healthz");
    $("#health-dot").className = "health-dot ok";
    $("#health-text").textContent = `v${h.version} · ${h.scenarios} scenarios`;
  } catch {
    $("#health-dot").className = "health-dot down";
    $("#health-text").textContent = "offline";
  }
}

/* ---------------- scenarios ---------------- */
function renderScenarios() {
  const list = $("#scenario-list");
  list.innerHTML = "";
  for (const s of state.scenarios) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "scenario";
    btn.setAttribute("role", "listitem");
    btn.dataset.scenarioId = s.scenario_id;
    btn.innerHTML = `
      <div class="scenario-head">
        <span class="scenario-title">${esc(s.title)}</span>
        <span class="scenario-chip">synthetic case</span>
      </div>
      <span class="scenario-id">${esc(s.scenario_id)}</span>
      <p class="scenario-desc">${esc(s.description)}</p>`;
    btn.addEventListener("click", () => startRun(s.scenario_id));
    list.appendChild(btn);
  }
}

function selectScenario(id) {
  $$(".scenario").forEach((el) => el.classList.toggle("selected", el.dataset.scenarioId === id));
}

/* ---------------- run lifecycle ---------------- */
async function startRun(scenarioId) {
  const gen = ++state.pollGen;   // this click owns the view from here on
  selectScenario(scenarioId);
  stopPolling();
  showView("running");
  resetPipeline();

  try {
    const accepted = await api("/v1/runs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scenario: scenarioId }),
    });
    if (gen !== state.pollGen) return;   // superseded by a newer click/open
    state.activeRunId = accepted.run_id;
    pollRun(accepted.run_id);
  } catch (err) {
    if (gen !== state.pollGen) return;   // stale error must not take over the view
    showError(`Could not start run: ${err.message}`);
  }
}

function pollRun(runId) {
  stopPolling();                  // exactly one interval ever exists
  const gen = ++state.pollGen;
  const started = Date.now();
  state.pollTimer = setInterval(async () => {
    if (gen !== state.pollGen) return;   // superseded poll — never touch the view
    // Honest progress: the server doesn't stream sub-steps, so show the real
    // elapsed time rather than inventing stage names or stage completion.
    const secs = ((Date.now() - started) / 1000).toFixed(0);
    $("#running-detail").textContent = `Working — ${secs}s elapsed`;

    const ctrl = new AbortController();
    state.pollAbort = ctrl;
    try {
      const run = await api(`/v1/runs/${runId}`, { signal: ctrl.signal });
      if (gen !== state.pollGen) return;   // stale result — a newer run owns the view
      if (run.status === "completed") {
        stopPolling();
        renderResult(run);
        refreshHistory();
      } else if (run.status === "failed") {
        stopPolling();
        showError(run.error || "unknown failure");
        refreshHistory();
      }
    } catch (err) {
      // An abort is our own supersede signal, not a lost connection.
      if (gen !== state.pollGen || err.name === "AbortError") return;
      stopPolling();
      showError(`Lost contact with the service: ${err.message}`);
    }
  }, 700);
}

function stopPolling() {
  if (state.pollTimer) clearInterval(state.pollTimer);
  state.pollTimer = null;
  if (state.pollAbort) { state.pollAbort.abort(); state.pollAbort = null; }
}

/* The pipeline is a static checklist: the service reports no per-stage signal,
   so every step stays in its neutral pending state while a run is in flight —
   no fabricated "stage N complete" marching. Progress = the elapsed timer. */
function resetPipeline() {
  $$("#pipeline li").forEach((li) => li.classList.remove("active"));
}

/* ---------------- views ---------------- */
function showView(which) {
  $("#empty-state").classList.toggle("hidden", which === "empty");
  $("#running-state").classList.toggle("hidden", which !== "running");
  $("#result-view").classList.toggle("hidden", which !== "result");
  $("#error-view").classList.toggle("hidden", which !== "error");
}

function showError(message) {
  $("#error-text").textContent = message;
  showView("error");
}
$("#error-dismiss").addEventListener("click", () => showView("empty"));

/* ---------------- result rendering ---------------- */
function renderResult(run) {
  showView("result");
  const decision = run.decision || "INCOMPLETE";

  const banner = $("#decision-banner");
  banner.className = `decision card d-${cls(decision)}`;
  const badge = $("#decision-badge");
  badge.className = `decision-badge b-${cls(decision)}`;
  badge.textContent = decision;
  $("#decision-title").textContent = DECISION_COPY[decision] || decision;
  $("#decision-scenario").textContent = `${run.scenario_id} · ${run.run_id}`;

  $("#stat-expected").textContent = run.expected_decision || "—";
  const match = $("#stat-match");
  match.textContent = run.matches_expectation ? "yes" : "no";
  match.className = `stat-value ${run.matches_expectation ? "yes" : "no"}`;
  $("#stat-duration").textContent = run.duration_ms != null ? `${(run.duration_ms / 1000).toFixed(1)} s` : "—";

  renderReasons(run.reasons || []);
  $("#count-checks").textContent = (run.checks || []).length;
  $("#count-findings").textContent = (run.policy_findings || []).length;
  $("#count-impact").textContent = run.impact ? run.impact.impacted_asset_count ?? 0 : 0;
  $("#count-evidence").textContent = (run.evidence || []).length;
  $("#count-graph").textContent = run.impact
    ? (run.impact.changed_asset_ids || []).length + (run.impact.impacted_asset_ids || []).length
    : 0;

  state.graphLoadedFor = null;   // graph tab lazy-loads on first open
  if (state.cy) { state.cy.destroy(); state.cy = null; }
  $("#graph-dot").href = `/v1/runs/${run.run_id}/graph.dot`;

  renderChecks(run.checks || []);
  renderFindings(run.policy_findings || [], run.coverage_gaps || []);
  renderImpact(run.impact || {}, run.changed_paths || []);
  renderEvidence(run.evidence || [], run.adapters || []);
  renderReport(run);
  renderProvenance(run);

  activateTab("checks");
  window.scrollTo({ top: 0, behavior: "smooth" });
}

const DECISION_COPY = {
  PASS: "All mandatory checks satisfied — merge cleared",
  WARN: "Cleared with disclosed gaps — review before merge",
  BLOCK: "Merge blocked — mandatory evidence missing or negative",
  INCOMPLETE: "Cannot prove the outcome — refusing to guess",
};

function renderReasons(reasons) {
  const box = $("#reasons");
  box.innerHTML = "";
  for (const r of reasons) {
    const div = document.createElement("div");
    div.className = "reason";
    div.textContent = r;
    box.appendChild(div);
  }
  if (!reasons.length) {
    const div = document.createElement("div");
    div.className = "reason";
    div.textContent = "All mandatory checks satisfied; no blocking findings.";
    box.appendChild(div);
  }
}

function renderChecks(checks) {
  const rows = checks.map((c) => `
    <tr>
      <td class="mono">${esc(c.check_id)}</td>
      <td><span class="req-tag req-${cls(c.requirement)}">${esc(c.requirement)}</span></td>
      <td><span class="status-pill st-${cls(c.status)}">${esc(c.status.replace("_", " "))}</span></td>
      <td class="dim">${esc((c.selection_reason || []).join("; "))}</td>
      <td class="dim">${c.duration_ms ? (c.duration_ms / 1000).toFixed(2) + " s" : "—"}</td>
      <td class="dim">${c.artifacts ?? 0}</td>
      <td>
        <button class="log-link" data-log="${esc(c.check_id)}" ${c.log_tail ? "" : "disabled"}>view log</button>
      </td>
    </tr>`).join("");

  $("#panel-checks").innerHTML = `
    <div class="table-wrap"><table class="grid">
      <thead><tr><th>Check</th><th>Requirement</th><th>Status</th><th>Why selected</th><th>Duration</th><th>Artifacts</th><th>Log</th></tr></thead>
      <tbody>${rows}</tbody>
    </table></div>`;

  const tails = Object.fromEntries(checks.map((c) => [c.check_id, c.log_tail || "(no output captured)"]));
  $$("#panel-checks .log-link").forEach((btn) => {
    btn.addEventListener("click", () => openLog(btn.dataset.log, tails[btn.dataset.log]));
  });
}

function renderFindings(findings, gaps) {
  const f = findings.length
    ? findings.map((x) => `
        <div class="finding ${x.action === "BLOCK" ? "" : "warn"}">
          <span class="rule">${esc(x.rule_id)}</span>
          <span class="status-pill ${x.action === "BLOCK" ? "st-blocked" : "st-warned"}" style="margin-left:8px">${esc(x.action)}</span>
          <div class="summary">${esc(x.summary || "")}</div>
        </div>`).join("")
    : `<p class="empty-panel">No policy rules fired for this change.</p>`;

  const g = gaps.length
    ? gaps.map((x) => `
        <div class="gap ${x.blocking ? "blocking-gap" : ""}">
          <div class="gap-head">
            <span class="mono">${esc(x.gap_id)}</span>
            <span class="status-pill ${x.blocking ? "st-blocked" : "st-warned"}">${esc(x.severity)}</span>
            ${x.blocking ? '<span class="req-tag req-mandatory">blocking</span>' : ""}
          </div>
          <div class="gap-why">${esc(x.why_it_matters || "")}</div>
          ${x.remediation ? `<div class="gap-fix">Fix: ${esc(x.remediation)}</div>` : ""}
        </div>`).join("")
    : `<p class="empty-panel">No coverage gaps — every mandatory requirement has current evidence.</p>`;

  $("#panel-findings").innerHTML = `
    <div class="panel-pad"><h3 style="margin-top:0">Policy findings</h3>${f}</div>
    <div class="panel-pad" style="border-top:1px solid var(--border)"><h3 style="margin-top:0">Coverage gaps</h3>${g}</div>`;
}

function renderImpact(impact, changedPaths) {
  if (!impact.changed_asset_ids && !changedPaths.length) {
    $("#panel-impact").innerHTML = `<p class="empty-panel">No impact data recorded.</p>`;
    return;
  }
  const changed = (impact.changed_asset_ids || []).map((id) => `<span class="chip changed">${esc(id)}</span>`).join("");
  const impacted = (impact.impacted_asset_ids || []).map((id) => `<span class="chip">${esc(id)}</span>`).join("");
  const paths = (changedPaths).map((p) => `<li>${esc(p)}</li>`).join("");
  const pathsOut = (impact.impact_paths || []).map((p) => `<li>${esc(Array.isArray(p) ? p.join(" → ") : p)}</li>`).join("");

  $("#panel-impact").innerHTML = `
    <div class="panel-pad">
      <h3 style="margin-top:0">Changed assets</h3>
      <div class="chip-row">${changed || '<span class="faint small">none</span>'}</div>
      <p class="muted small" style="margin-top:8px">Kinds: ${(impact.changed_asset_kinds || []).map(esc).join(", ") || "—"}</p>

      <h3>Impacted downstream assets <span class="faint small">(${impact.impacted_asset_count ?? 0})</span></h3>
      <div class="chip-row">${impacted || '<span class="faint small">none detected</span>'}</div>
      ${impact.unknown_critical_impact ? '<p class="muted small" style="color:var(--warn)">⚠ Unknown critical impact — adapter coverage incomplete, gate will not claim PASS.</p>' : ""}

      <h3>Changed files</h3>
      <ul class="path-list">${paths || "<li>none</li>"}</ul>

      ${pathsOut ? `<h3>Impact paths</h3><ul class="path-list">${pathsOut}</ul>` : ""}
    </div>`;
}

function renderEvidence(evidence, adapters) {
  const adapterRow = adapters.length
    ? `<div class="panel-pad" style="border-bottom:1px solid var(--border)">
        <h3 style="margin-top:0">Adapters</h3>
        <div class="chip-row">${adapters.map((a) => `<span class="chip">${esc(a.name)} · ${a.assets} assets · ${a.relationships} edges</span>`).join("")}</div>
      </div>` : "";

  const cards = evidence.length
    ? evidence.map((e) => `
        <div class="evidence-card">
          <div class="ev-head">
            <span class="ev-id">${esc(e.evidence_id)}</span>
            <span class="freshness ${cls(e.freshness)}">${esc(e.freshness)}</span>
          </div>
          <div class="ev-meta">
            <span>producer <strong>${esc(e.producer)}</strong></span>
            <span>type <strong>${esc(e.evidence_type)}</strong></span>
            <span>support <strong>${esc(e.support)}</strong></span>
            <span>${esc(e.observed_at || "")}</span>
          </div>
          ${e.input_digest ? `<div class="ev-meta"><span>input ${esc(e.input_digest.slice(0, 26))}…</span></div>` : ""}
          ${(e.limitations || []).length ? `<ul class="ev-limits">${e.limitations.map((l) => `<li>${esc(l)}</li>`).join("")}</ul>` : ""}
        </div>`).join("")
    : `<p class="empty-panel">No evidence records.</p>`;

  $("#panel-evidence").innerHTML = `${adapterRow}<div class="panel-pad">${cards}</div>`;
}

/* minimal markdown → HTML (every dynamic run value is escaped server-side
   upstream, and mdToHtml escapes again — defence in depth) */
function renderReport(run) {
  const md = run.report_markdown || run.report_url;
  if (!md) { $("#panel-report").innerHTML = `<p class="empty-panel">Report unavailable.</p>`; return; }
  // Only ever fetch a report path that belongs to this service — never an
  // absolute URL or an attacker-supplied path.
  const sameOriginReport = typeof run.report_url === "string"
    && /^\/v1\/runs\/[\w.-]+\/report$/.test(run.report_url);
  if (sameOriginReport) {
    fetch(run.report_url).then((r) => {
      if (!r.ok) throw new Error(r.status);   // never render a 404 JSON body as a report
      return r.text();
    }).then((text) => {
      $("#panel-report").innerHTML = `<div class="md">${mdToHtml(text)}</div>`;
    }).catch(() => { $("#panel-report").innerHTML = `<p class="empty-panel">Could not load report.</p>`; });
  } else {
    $("#panel-report").innerHTML = `<div class="md">${mdToHtml(md)}</div>`;
  }
}

function mdToHtml(md) {
  const lines = md.split("\n");
  const out = [];
  let inCode = false, inTable = false, inList = false;

  const inline = (s) => esc(s)
    .replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")
    .replace(/`([^`]+)`/g, "<code>$1</code>");

  for (const raw of lines) {
    const line = raw.replace(/\r$/, "");
    if (line.startsWith("```")) {
      out.push(inCode ? "</code></pre>" : '<pre><code>');
      inCode = !inCode; continue;
    }
    if (inCode) { out.push(esc(line)); continue; }

    if (/^\|/.test(line)) {
      if (!inTable) { out.push("<table>"); inTable = true; }
      if (/^\|[\s:-]+\|/.test(line)) continue; // separator
      const cells = line.split("|").slice(1, -1).map((c) => inline(c.trim()));
      const tag = cells.every((c) => !c) ? "th" : "td";
      out.push(`<tr>${cells.map((c) => `<${tag}>${c}</${tag}>`).join("")}</tr>`);
      continue;
    } else if (inTable) { out.push("</table>"); inTable = false; }

    if (/^#{1,3} /.test(line)) {
      if (inList) { out.push("</ul>"); inList = false; }
      const level = line.match(/^#+/)[0].length;
      out.push(`<h${level}>${inline(line.replace(/^#+ /, ""))}</h${level}>`);
    } else if (/^[-*] /.test(line)) {
      if (!inList) { out.push("<ul>"); inList = true; }
      out.push(`<li>${inline(line.replace(/^[-*] /, ""))}</li>`);
    } else if (/^> /.test(line)) {
      if (inList) { out.push("</ul>"); inList = false; }
      out.push(`<blockquote><p>${inline(line.slice(2))}</p></blockquote>`);
    } else if (line.trim() === "") {
      if (inList) { out.push("</ul>"); inList = false; }
    } else {
      if (inList) { out.push("</ul>"); inList = false; }
      out.push(`<p>${inline(line)}</p>`);
    }
  }
  if (inTable) out.push("</table>");
  if (inList) out.push("</ul>");
  if (inCode) out.push("</code></pre>");
  return out.join("");
}

function renderProvenance(run) {
  const items = [
    ["Run", run.run_id],
    ["Base revision", (run.base_revision || "").slice(0, 14)],
    ["Head revision", (run.head_revision || "").slice(0, 14)],
    ["Diff digest", (run.diff_digest || "").slice(0, 26)],
    ["Bundle digest", (run.bundle_digest || "").slice(0, 26)],
    ["Policy", `${run.policy_id || "—"} v${run.policy_version || "—"}`],
    ["Started", run.started_at || "—"],
  ];
  $("#provenance").innerHTML = items
    .map(([label, value]) => `<div class="prov-item"><span class="prov-label">${esc(label)}</span><span class="prov-value">${esc(value || "—")}</span></div>`)
    .join("");
}

/* ---------------- tabs ---------------- */
$$(".tab").forEach((tab) => {
  tab.addEventListener("click", () => activateTab(tab.dataset.tab));
});

function activateTab(name) {
  $$(".tab").forEach((t) => {
    const active = t.dataset.tab === name;
    t.classList.toggle("active", active);
    t.setAttribute("aria-selected", String(active));
  });
  $$(".tab-panel").forEach((p) => p.classList.toggle("hidden", p.id !== `panel-${name}`));
  if (name === "graph" && state.activeRunId && state.graphLoadedFor !== state.activeRunId) {
    loadGraph(state.activeRunId);
  }
}

/* ---------------- impact graph (Cytoscape.js) ---------------- */
const LAYER_COLORS = {
  code: "#6d5efc", data: "#2ecc8f", ai: "#f0b429",
  api: "#58a6ff", test: "#8b93a9", deploy: "#ff8fab",
  metric: "#b48ead", other: "#626c85",
};

async function loadGraph(runId) {
  const canvas = $("#graph-canvas");
  canvas.innerHTML = `<div class="empty-panel">Loading graph…</div>`;
  try {
    const graph = await api(`/v1/runs/${runId}/graph`);
    state.graphLoadedFor = runId;
    renderGraphStats(graph.metrics || {});
    mountGraph(graph);
  } catch (err) {
    canvas.innerHTML = `<div class="empty-panel">Graph unavailable: ${esc(err.message)}</div>`;
  }
}

function renderGraphStats(m) {
  const items = [
    [m.changed, "changed", ""],
    [m.impacted, "impacted", ""],
    [m.impact_depth, "max depth", ""],
    [m.unresolved_edges, "unresolved", m.unresolved_edges ? "warn" : ""],
    [m.cycle_count_label ?? m.cycle_count, "cycles", m.cycle_present ? "alert" : ""],
    [m.hubs && m.hubs.length ? m.hubs[0].score : 0, "top hub score", ""],
  ];
  if (m.unknown_critical_impact) items.push([true, "unknown critical impact", "alert"]);
  $("#graph-stats").innerHTML = items.map(([v, label, tone]) => `
    <div class="gstat ${cls(tone)}">
      <div class="gstat-v">${v === true ? "⚠ yes" : (v ?? "—")}</div>
      <div class="gstat-l">${esc(label)}</div>
    </div>`).join("");
}

function mountGraph(graph) {
  const cyEl = $("#graph-canvas");
  cyEl.innerHTML = "";
  if (typeof cytoscape === "undefined") {
    cyEl.innerHTML = `<div class="empty-panel">Cytoscape failed to load.</div>`;
    return;
  }
  if (!graph.nodes || !graph.nodes.length) {
    cyEl.innerHTML = `<div class="empty-panel">No assets in this change's graph.</div>`;
    return;
  }

  const theme = document.documentElement.dataset.theme;
  const fg = getComputedStyle(document.documentElement).getPropertyValue("--fg-dim").trim() || "#9aa3b8";
  const border = getComputedStyle(document.documentElement).getPropertyValue("--border-strong").trim() || "#303850";

  if (state.cy) state.cy.destroy();
  state.cy = cytoscape({
    container: cyEl,
    elements: [...graph.nodes, ...graph.edges],
    style: [
      { selector: "node", style: {
          "label": "data(label)",
          "font-size": 9.5,
          "color": fg,
          "text-valign": "bottom",
          "text-margin-y": 4,
          "text-background-color": theme === "light" ? "#ffffff" : "#12151d",
          "text-background-opacity": 0.85,
          "text-background-padding": 1.5,
          "shape": "roundrectangle",
          "width": 26, "height": 26,
          "background-color": (el) => LAYER_COLORS[el.data("layer")] || LAYER_COLORS.other,
          "border-width": (el) => el.data("state") === "changed" ? 3.5 : 1,
          "border-color": (el) =>
            el.data("state") === "changed" ? "#f2545b" :
            el.data("state") === "impacted" ? "#58a6ff" : border,
          "opacity": (el) => el.data("state") === "context" ? 0.55 : 1,
      }},
      { selector: "node[state='changed']", style: {
          "width": 40, "height": 40, "font-weight": "bold", "font-size": 11,
      }},
      { selector: "node[state='impacted']", style: { "width": 32, "height": 32 } },
      { selector: "node:selected", style: {
          "border-width": 4, "border-color": "#6d5efc",
          "overlay-opacity": 0.12, "overlay-color": "#6d5efc",
      }},
      { selector: "edge", style: {
          "curve-style": "bezier",
          "width": 1.4,
          "line-color": border,
          "target-arrow-color": border,
          "target-arrow-shape": "triangle",
          "arrow-scale": 0.9,
          "label": (el) => (el.data("in_cone") || el.data("path")) ? el.data("label") : "",
          "font-size": 8,
          "color": fg,
          "text-rotation": "autorotate",
          "text-background-color": theme === "light" ? "#ffffff" : "#12151d",
          "text-background-opacity": 0.85,
          "text-background-padding": 1,
      }},
      { selector: "edge[resolution='unresolved'], edge[resolution='ambiguous']", style: {
          "line-style": "dashed", "line-color": "#f0b429", "target-arrow-color": "#f0b429",
      }},
      { selector: "edge[path='true']", style: {
          "width": 2.6, "line-color": "#6d5efc", "target-arrow-color": "#6d5efc", "z-index": 10,
      }},
      { selector: "edge[edgeIntersect]", style: { "width": 3, "line-color": "#b9b0ff" } },
    ],
    layout: graphLayout($("#graph-layout").value),
    minZoom: 0.15, maxZoom: 3.5,
    wheelSensitivity: 0.25,
    boxSelectionEnabled: false,
  });

  state.cy.on("tap", "node", (evt) => {
    const d = evt.target.data();
    $("#graph-hint").innerHTML =
      `<strong>${esc(d.label)}</strong> · <code>${esc(d.id)}</code> · kind <strong>${esc(d.kind)}</strong>` +
      ` · criticality <strong>${esc(d.criticality)}</strong>` +
      (d.path ? ` · <code>${esc(d.path)}</code>` : "") +
      ` — <span class="faint">state: ${esc(d.state)}</span>`;
  });
  state.cy.on("tap", (evt) => {
    if (evt.target === state.cy) resetGraphHint();
  });
}

function graphLayout(name) {
  switch (name) {
    case "cose": return { name: "cose", animate: false, padding: 24,
      randomize: true, componentSpacing: 60, nodeRepulsion: 4200 };
    case "concentric": return { name: "concentric", padding: 24, minNodeSpacing: 22,
      concentric: (n) => n.indegree() + n.outdegree(), levelWidth: () => 2 };
    case "grid": return { name: "grid", padding: 24, avoidOverlap: true };
    default: return { name: "breadthfirst", directed: true, padding: 24,
      spacingFactor: 1.15, maxZoom: 2 };
  }
}

function resetGraphHint() {
  $("#graph-hint").textContent =
    "Nodes are assets; arrows are declared relationships. Red = changed in this PR, blue = impacted downstream.";
}

$("#graph-layout").addEventListener("change", () => {
  if (!state.cy) return;
  state.cy.layout(graphLayout($("#graph-layout").value)).run();
});

$("#graph-focus").addEventListener("click", () => {
  if (!state.cy) return;
  const cone = state.cy.nodes().filter((n) => n.data("state") !== "context");
  if (cone.nonempty()) {
    state.cy.animate({ fit: { eles: cone, padding: 48 }, duration: 350 });
  } else {
    state.cy.fit(undefined, 40);
  }
});

/* ---------------- integrations panel ---------------- */
async function refreshIntegrations() {
  const box = $("#integration-list");
  try {
    const data = await api("/v1/integrations");
    const gh = data.github || {};
    const items = [];

    const webhook = gh.webhook || {};
    items.push(`
      <div class="integration">
        <div class="int-head">
          <span class="int-name">GitHub webhook</span>
          <span class="${webhook.configured ? "badge-ok" : "badge-off"}">${webhook.configured ? "enabled" : "disabled"}</span>
        </div>
        <div class="int-detail">
          <code>POST ${esc(webhook.endpoint || "/v1/webhooks/github")}</code><br>
          ${esc(webhook.algorithm || "HMAC-SHA256")} · never clones repositories.<br>
          ${webhook.configured
            ? 'Set <code>CLCA_GITHUB_WEBHOOK_SECRET</code> — it is set.'
            : 'Enable with <code>CLCA_GITHUB_WEBHOOK_SECRET</code>.'}
        </div>
      </div>`);

    const checks = gh.checks_api || {};
    items.push(`
      <div class="integration">
        <div class="int-head">
          <span class="int-name">GitHub Checks API</span>
          <span class="${checks.token_present ? "badge-ok" : "badge-off"}">${checks.token_present ? "token ready" : "no token"}</span>
        </div>
        <div class="int-detail">
          Posts <strong>CLCA evidence gate</strong> check runs on PRs.<br>
          <code>clca run --github-repo owner/name</code> ${checks.token_present ? "· GITHUB_TOKEN present" : "· set GITHUB_TOKEN"}
        </div>
      </div>`);

    items.push(`
      <div class="integration">
        <div class="int-head">
          <span class="int-name">GitHub Actions</span>
          <span class="badge-ok">workflow</span>
        </div>
        <div class="int-detail"><code>${esc(gh.actions_workflow || ".github/workflows/clca.yml")}</code><br>
        Runs the gate on every PR and enforces the decision as a status check.</div>
      </div>`);

    items.push(`
      <div class="integration">
        <div class="int-head"><span class="int-name">CLI</span></div>
        <div class="int-detail"><code>${esc((data.cli || {}).command || "clca run …")}</code><br>
        Exit codes gate any CI: 0 pass/warn · 1 block · 2 incomplete.</div>
      </div>`);

    box.innerHTML = items.join("");
  } catch (err) {
    box.innerHTML = `<p class="muted small">Unavailable: ${esc(err.message)}</p>`;
  }
}

/* ---------------- log dialog ---------------- */
function openLog(checkId, body) {
  $("#log-dialog-title").textContent = `${checkId} — log tail`;
  $("#log-dialog-body").textContent = body;
  $("#log-dialog").showModal();
}
$("#log-dialog-close").addEventListener("click", () => $("#log-dialog").close());
$("#log-dialog").addEventListener("click", (e) => {
  if (e.target === e.currentTarget) e.currentTarget.close(); // backdrop click
});

/* ---------------- history ---------------- */
async function refreshHistory() {
  try {
    const data = await api("/v1/runs");
    state.runs = data.runs || [];
  } catch { return; }
  const list = $("#run-history");
  $("#history-count").textContent = state.runs.length ? `${state.runs.length}` : "";
  if (!state.runs.length) {
    list.innerHTML = `<p class="muted small">No runs yet. Pick a scenario above.</p>`;
    return;
  }
  list.innerHTML = "";
  for (const r of state.runs) {
    const row = document.createElement("button");
    row.type = "button";
    row.className = `run-row ${r.run_id === state.activeRunId ? "active" : ""}`;
    row.setAttribute("role", "listitem");
    const dotClass = cls(r.status === "running" ? "running" : r.status === "failed" ? "failed" : r.decision || "");
    const sub = r.status === "running" ? "running…" : r.status === "failed" ? "failed" : r.decision;
    row.innerHTML = `
      <span class="run-dot ${dotClass}"></span>
      <span class="run-name">${esc(r.scenario_id || "?")}<br><span class="run-sub">${esc(sub)}</span></span>
      <span class="run-time">${esc(relTime(r.submitted_at))}</span>`;
    row.addEventListener("click", () => openRun(r.run_id));
    list.appendChild(row);
  }
}

async function openRun(runId) {
  const gen = ++state.pollGen;   // this open supersedes any in-flight start/poll
  stopPolling();
  state.activeRunId = runId;
  refreshHistory();
  try {
    const run = await api(`/v1/runs/${runId}`);
    if (gen !== state.pollGen) return;   // a newer click owns the view now
    if (run.status === "running") {
      showView("running");
      resetPipeline();
      pollRun(runId);
    } else if (run.status === "failed") {
      showError(run.error || "run failed");
    } else {
      renderResult(run);
    }
  } catch (err) {
    if (gen !== state.pollGen) return;
    showError(err.message);
  }
}

function relTime(iso) {
  if (!iso) return "";
  const secs = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (secs < 60) return `${secs.toFixed(0)}s ago`;
  if (secs < 3600) return `${(secs / 60).toFixed(0)}m ago`;
  return `${(secs / 3600).toFixed(1)}h ago`;
}

/* ---------------- utils ---------------- */
function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (ch) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[ch]));
}

/* Sanitize a value before it is placed in a class attribute. The API constrains
   these fields via pydantic enums, but class interpolation is a DOM-clobbering
   vector — only word characters, hyphen and underscore ever reach class.
   Case is deliberately PRESERVED: the CSS hooks are case-sensitive
   (.decision.d-PASS, .decision-badge.b-PASS, .expect-PASS, .run-dot.PASS …) and
   with <!doctype html> the document is in no-quirks mode, so lowercasing would
   silently break every decision colour rule. Underscores are kept for the same
   reason (.st-budget_skipped, .st-not_run). */
function cls(s) {
  return String(s ?? "").replace(/[^A-Za-z0-9_-]/g, "");
}

/* ---------------- boot ---------------- */
async function boot() {
  initTheme();
  refreshHealth();
  setInterval(refreshHealth, 15000);
  try {
    const data = await api("/v1/scenarios");
    state.scenarios = data.scenarios || [];
    renderScenarios();
  } catch (err) {
    $("#scenario-list").innerHTML = `<p class="muted small">Could not load scenarios: ${esc(err.message)}</p>`;
  }
  refreshHistory();
  refreshIntegrations();
}

boot();
