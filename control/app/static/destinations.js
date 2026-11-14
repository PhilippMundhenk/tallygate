"use strict";
/* Destinations (ADR-0014 / #122): every destination in one place, from GET /model.
   Access entries (rules) are added, edited, deleted and grouped here; on-request destinations (grants) open on
   the Grants tab; read-only hosts, credentials and repository scope come from the gateway config file and are
   shown read-only. Uses app.js helpers: $, esc, gw, toast, fmtDate, fmtLeft, parsePort, portText, guard,
   showTab, checkMatch, tabHooks. */
(() => {
  const box = $("#destBox");
  if (!box) return;
  const RULE_ACTIONS = ["allow", "deny", "ask"];
  const ACCESS = {
    allow: ["allow", "a-allow"], ask: ["ask", "a-ask"], deny: ["deny", "a-deny"], request: ["on request", "a-ask"],
  };
  const MODE = { ask: "asks you", deny: "blocked", allow: "allowed (log only)" };
  let model = null;

  box.innerHTML = `<p class="hint">Every destination the agent may reach, in one place. Access rules are edited
      here; on-request destinations (grants) are defined on the <i>Grants</i> tab; read-only hosts, added
      credentials and repository limits come from the gateway config file and are shown read-only.</p>
    <div class="toolbar">
      <select id="dAction" aria-label="Access">${RULE_ACTIONS.map((a) => `<option>${a}</option>`).join("")}</select>
      <select id="dKind" aria-label="Match by"><option value="host">host</option><option value="cidr">cidr</option></select>
      <input id="dMatch" aria-label="Host or CIDR" placeholder="*.example.com  or  203.0.113.0/24">
      <input id="dPort" aria-label="Ports" placeholder="port(s): 443 | 80,443 | *" class="portw">
      <input id="dNote" aria-label="Note" placeholder="note">
      <input id="dTtl" type="number" aria-label="TTL in seconds (optional)" placeholder="TTL s" class="port">
      <button id="dAdd">Add rule (top)</button>
    </div>
    <div class="rules-toolbar">
      <input id="dGroupName" aria-label="Group name" placeholder="group name, e.g. used-car shops">
      <button id="dGroupSel" class="small secondary">Group selected</button>
      <button id="dUngroupSel" class="small secondary">Ungroup selected</button>
      <input id="dFilter" type="search" aria-label="Filter destinations" placeholder="filter">
    </div>
    <div class="table-wrap"><table class="dests"><thead><tr><th><span class="sr-only">Select</span></th>
      <th>Destination</th><th>Access</th><th>Limits</th><th>On request</th><th>Group</th><th>Source</th>
      <th><span class="sr-only">Actions</span></th></tr></thead><tbody id="destBody"></tbody></table></div>
    <p class="hint" id="destMode"></p>`;

  function matchText(d) {
    const host = d.match.host || d.match.cidr || "?";
    const port = d.match.port === undefined || d.match.port === "*" ? "" : `:${portText(d.match.port)}`;
    return `<code>${esc(host)}</code>${port ? `<span class="muted">${esc(port)}</span>` : ""}`;
  }
  function limitsText(d) {
    const out = [];
    if (d.methods === "read") out.push("read-only (GET/HEAD/OPTIONS)");
    else if (d.methods === "no-writes") out.push("no PUT/PATCH/DELETE");
    else if (d.methods === "no-writes+post") out.push("no writes (POST too)");
    if (d.paths) out.push(`paths: ${d.paths.join(", ")}`);
    if (d.read_paths && d.read_paths.length) out.push(`read paths: ${d.read_paths.join(", ")}`);
    if (d.credentials && d.credentials.length) out.push("credentials added");
    if (d.repos) out.push(`repositories: ${d.repos.patterns.join(", ")}${d.repos.graphql ? " (+graphql)" : ""}`);
    if (d.lan) out.push("local network");
    if (d.scheme && d.scheme !== "https") out.push(d.scheme);
    if (d.tls && d.tls.fingerprint) out.push("pinned TLS");
    return out.map((t) => `<div>${esc(t)}</div>`).join("") || '<span class="muted">–</span>';
  }
  function requestText(d) {
    if (d.access !== "request" || !d.request) return '<span class="muted">–</span>';
    return `<div>${esc(d.request.name)} <span class="muted">(${esc((d.request.levels || []).join(" / "))})</span></div>`;
  }
  const isRule = (d) => RULE_ACTIONS.includes(d.access) && d.id;

  function render() {
    const q = $("#dFilter").value.trim().toLowerCase(), body = $("#destBody");
    body.innerHTML = "";
    for (const d of model.destinations) {
      const label = (d.match.host || d.match.cidr || "") + " " + (d.request ? d.request.name : "");
      if (q && !label.toLowerCase().includes(q)) continue;
      const [al, cls] = ACCESS[d.access] || ["property", "muted"];
      const tr = document.createElement("tr");
      tr.innerHTML = `<td>${isRule(d) ? '<input type="checkbox" class="dsel" aria-label="select rule">' : ""}</td>
        <td>${matchText(d)}</td>
        <td><span class="${cls}">${esc(al)}</span>${d.expires ? `<div class="muted small-text">ends in ${esc(fmtLeft(d.expires))}</div>` : ""}</td>
        <td>${limitsText(d)}</td><td>${requestText(d)}</td>
        <td>${d.group ? `<span class="chip">${esc(d.group)}</span>` : ""}</td>
        <td class="muted small-text">${esc(d.source || "")}</td><td></td>`;
      if (isRule(d)) tr.querySelector(".dsel").dataset.id = d.id;
      const actions = tr.lastElementChild;
      if (isRule(d)) {
        const e = mkbtn("edit", () => editRow(tr, d));
        const del = mkbtn("delete", guard(async () => { await gw("DELETE", `/rules/${d.id}`); await load(); }));
        actions.append(e, del);
      } else if (d.access === "request") {
        actions.append(mkbtn("Grants", () => showTab("grants")));
      } else {
        actions.innerHTML = '<span class="muted small-text">config file</span>';
      }
      body.appendChild(tr);
    }
    $("#destMode").innerHTML = `<i>Everything else:</i> ${esc(MODE[model.default] || model.default)}. `
      + `${model.never.length} never-reachable range(s). Change the mode and never list on the <i>Rules</i> tab.`;
  }

  function mkbtn(text, onclick) {
    const b = document.createElement("button");
    b.textContent = text; b.className = "small secondary"; b.onclick = onclick;
    return b;
  }
  // columns: [0] select, [1] destination, [2] access, [3] limits, [4] on request, [5] group, [6] source, [7] actions
  function editRow(tr, d) {
    tr.cells[2].innerHTML = `<select class="eA">${RULE_ACTIONS.map((a) => `<option${a === d.access ? " selected" : ""}>${a}</option>`).join("")}</select>`
      + `<input class="eP" size="6" value="${esc(portText(d.match.port))}" aria-label="ports">`;
    tr.cells[3].innerHTML = `<input class="eN" value="${esc(d.note || "")}" placeholder="note" aria-label="note">`
      + `<input class="eT" size="8" placeholder="${d.expires ? `${esc(fmtLeft(d.expires))} left` : "permanent"}" aria-label="expiry seconds"><span class="muted"> s</span>`;
    tr.cells[5].innerHTML = `<input class="eG" size="10" value="${esc(d.group || "")}" placeholder="group" aria-label="group">`;
    const cell = tr.cells[7]; cell.innerHTML = "";
    cell.append(
      mkbtn("save", guard(async () => {
        const changes = {
          action: tr.querySelector(".eA").value,
          port: parsePort(tr.querySelector(".eP").value),
          note: tr.querySelector(".eN").value,
          group: tr.querySelector(".eG").value.trim(),
        };
        const t = tr.querySelector(".eT").value.trim();
        if (t) { if (!/^\d+$/.test(t) || +t <= 0) throw new Error("Expiry: whole seconds from now, or blank for permanent"); changes.expires = Date.now() / 1000 + +t; }
        else changes.expires = null;
        await gw("PATCH", `/rules/${d.id}`, changes); toast("Rule updated"); await load();
      })),
      mkbtn("cancel", () => load()),
    );
  }

  function selectedIds() {
    return [...document.querySelectorAll("#destBody .dsel:checked")].map((c) => c.dataset.id);
  }
  async function group(name) {
    const ids = selectedIds();
    if (!ids.length) throw new Error("Tick one or more access rules first");
    if (name && !$("#dGroupName").value.trim()) throw new Error("Enter a group name");
    await gw("POST", "/rules/group", { ids, group: name });
    toast(name ? `${ids.length} rule(s) grouped as “${name}”` : `${ids.length} rule(s) ungrouped`);
    $("#dGroupName").value = ""; await load();
  }

  $("#dAdd").onclick = guard(async () => {
    const kind = $("#dKind").value, match = $("#dMatch").value.trim();
    checkMatch(kind, match);
    const rule = { action: $("#dAction").value, [kind]: match, port: parsePort($("#dPort").value) };
    if ($("#dNote").value) rule.note = $("#dNote").value;
    if (+$("#dTtl").value > 0) rule.expires = Date.now() / 1000 + +$("#dTtl").value;
    await gw("POST", "/rules", rule); $("#dMatch").value = ""; toast("Rule added"); await load();
  });
  $("#dGroupSel").onclick = guard(() => group($("#dGroupName").value.trim()));
  $("#dUngroupSel").onclick = guard(() => group(""));
  $("#dFilter").oninput = () => { if (model) render(); };

  async function load() {
    const m = await gw("GET", "/model");
    if (!m || !Array.isArray(m.destinations)) return;  // an older gateway without the route
    model = m; render();
  }
  tabHooks.destinations = load;  // app.js calls this when the tab opens
  // the initial tab is chosen in app.js before this script registered its hook, so load now if already open
  if (!$("#tab-destinations").classList.contains("hidden")) load().catch(() => {});
  document.addEventListener("tg:tab", (e) => { if (e.detail === "destinations") load().catch(() => {}); });
  document.addEventListener("tg:event", (e) => {
    const t = e.detail && e.detail.type;
    if (["policy", "grants", "grant_resolved"].includes(t) && !$("#tab-destinations").classList.contains("hidden")) {
      load().catch(() => {});
    }
  });
})();
