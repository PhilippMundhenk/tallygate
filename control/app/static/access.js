"use strict";
/* What the agent can reach (#121): each destination once, with the rule, the per-request limits (read-only,
   credentials, repositories) and the grants that apply, from GET /access. Read-only: every part is changed where
   it is defined, and the table says where.
   Uses the helpers of app.js ($, esc, gw, fmtLeft, fmtDate, showTab). */
(() => {
  const box = $("#accessBox");
  if (!box) return;
  box.innerHTML = `<p class="hint">Each destination once, with everything that applies to it. Rules are changed in
      the table below, grants on the <i>Grants</i> tab; read-only hosts, added credentials and repository limits
      come from the gateway config file.</p>
    <div class="toolbar"><input id="acFilter" type="search" aria-label="Filter destinations" placeholder="filter destination / grant"></div>
    <div class="table-wrap"><table class="access"><thead><tr><th>Destination</th><th>Access</th><th>Limits</th>
      <th>On request</th><th>Last used</th></tr></thead><tbody id="acBody"></tbody></table></div>`;
  const ACCESS = { allow: ["Allowed", "a-allow"], ask: ["Asks you", "a-ask"], deny: ["Blocked", "a-deny"],
    request: ["On request only", "a-ask"] };
  const MODE = { ask: "asks you", deny: "blocked", allow: "allowed (log only)" };
  let view = null;

  function accessCell(r) {
    const [label, cls] = ACCESS[r.access] || ["Decided by the rules", ""];
    let how = "";
    if (r.rule) {
      how = `rule ${r.rule.position}${r.rule.note ? ` (${r.rule.note})` : ""}`;
      if (r.rule.expires) how += `, ends in ${fmtLeft(r.rule.expires)}`;
    } else if (r.access && r.access !== "request") how = "no rule names it: the mode decides";
    return `<span class="${cls}">${esc(label)}</span>${how ? `<div class="muted small-text">${esc(how)}</div>` : ""}`;
  }
  function limitsCell(r) {
    const out = [];
    if (r.read_only) out.push(r.read_only.post_is_write ? "read-only (POST counts as a write)" : "read-only (no PUT, PATCH, DELETE)");
    if (r.credentials) out.push("your credentials are added; the agent's own are removed");
    if (r.repos) out.push(`repositories: ${r.repos.join(", ")}`);
    return out.map((t) => `<div>${esc(t)}</div>`).join("") || '<span class="muted">–</span>';
  }
  function grantsCell(r) {
    return r.grants.map((g) => {
      const what = [g.levels.join(" / "), g.scheme === "tcp" ? "raw TCP" : "", g.paths ? `paths ${g.paths.join(", ")}` : "",
        g.lan ? "local network" : "", g.credentials ? "credentials added" : ""].filter(Boolean).join(" · ");
      const state = g.active ? `<span class="tag warn">active: ${esc(g.active.level)}, ${esc(fmtLeft(g.active.expires))} left</span>` : "";
      return `<div><button class="link" data-grant="${esc(g.name)}">${esc(g.name)}</button> <span class="muted">${esc(what)}</span> ${state}</div>`;
    }).join("") || '<span class="muted">–</span>';
  }
  function render() {
    if (!view) return;
    const q = $("#acFilter").value.trim().toLowerCase(), body = $("#acBody");
    body.innerHTML = "";
    for (const r of view.rows) {
      if (q && !`${r.host} ${r.grants.map((g) => g.name).join(" ")}`.toLowerCase().includes(q)) continue;
      const tr = document.createElement("tr");
      tr.innerHTML = `<td><code>${esc(r.host)}</code>${r.port === "*" ? "" : `<span class="muted">:${esc(r.port)}</span>`}</td>
        <td>${accessCell(r)}</td><td>${limitsCell(r)}</td><td>${grantsCell(r)}</td>
        <td class="muted">${r.last_used ? esc(fmtDate(r.last_used)) : `not in the last ${esc(view.last_used_days)} days`}</td>`;
      body.appendChild(tr);
    }
    const tr = document.createElement("tr");
    tr.innerHTML = `<td><i>Everything else</i></td><td>${esc(MODE[view.default] || view.default)}</td>
      <td colspan="3" class="muted">the mode under <i>Shortcuts → Unknown destinations</i>; local networks and the other
      ranges under <i>Never reachable</i> stay closed whatever is set here</td>`;
    body.appendChild(tr);
  }
  async function load() {
    const v = await gw("GET", "/access");
    if (!v || !Array.isArray(v.rows)) return;  // an older gateway without the route
    view = v; render();
  }
  $("#acFilter").oninput = render;
  $("#acBody").addEventListener("click", (e) => { if (e.target.closest("[data-grant]")) showTab("grants"); });
  $("#accessCard").addEventListener("toggle", () => { if ($("#accessCard").open) load().catch(() => {}); });
  document.addEventListener("tg:tab", (e) => { if (e.detail === "rules" && $("#accessCard").open) load().catch(() => {}); });
  document.addEventListener("tg:event", (e) => {
    if (["policy", "grants", "grant_resolved"].includes(e.detail && e.detail.type) && $("#accessCard").open) load().catch(() => {});
  });
})();
