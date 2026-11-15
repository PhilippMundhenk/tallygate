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
  const MODE = { ask: "you decide each time", deny: "blocked", allow: "log only" };
  let model = null;

  box.innerHTML = `<h3>Rules and blocked ranges</h3>
    <p class="hint">Every destination the agent may reach, in one place; the first matching rule from the top wins.</p>
    <details class="help"><summary>What does this table show?</summary>
      <p>Access rules are edited here. On-request destinations (grants) are defined on the <i>Grants</i> tab.
        Read-only hosts, added credentials and repository limits come from the gateway config file and are shown
        read-only (tagged <i>config file</i>).</p>
      <p>The never-reachable deny floor is listed too, each blocked range with its reason: your own LAN and other
        removable ranges can be unblocked here (with a warning before the agent can reach them), while the
        gateway's own networks stay locked: they are structural and cannot be removed here.</p>
      <p><a href="https://github.com/PhilippMundhenk/tallygate/blob/main/docs/rules.md" target="_blank" rel="noopener">Rules by example</a></p></details>
    <div class="toolbar">
      <select id="dAction" aria-label="Access">${RULE_ACTIONS.map((a) => `<option>${a}</option>`).join("")}</select>
      <select id="dKind" aria-label="Match by"><option value="host">Host</option><option value="cidr">CIDR</option></select>
      <input id="dMatch" aria-label="Host or CIDR" placeholder="*.example.com or 203.0.113.0/24">
      <input id="dPort" aria-label="Ports" placeholder="Ports: 443, 80,443 or *" class="portw">
      <input id="dNote" aria-label="Note" placeholder="Note">
      <input id="dTtl" type="number" aria-label="TTL in seconds (optional)" placeholder="TTL (s)" class="port">
      <button id="dAdd">Add rule</button>
    </div>
    <div class="rules-toolbar">
      <input id="dGroupName" aria-label="Group name" placeholder="Group name, e.g. used-car shops">
      <button id="dGroupSel" class="small secondary">Group selected</button>
      <button id="dUngroupSel" class="small secondary">Ungroup selected</button>
      <input id="dFilter" type="search" aria-label="Filter destinations" placeholder="Filter">
    </div>
    <div class="table-wrap"><table class="dests"><thead><tr><th scope="col"><span class="sr-only">Select</span></th>
      <th scope="col">Destination</th><th scope="col">Access</th><th scope="col">Limits</th><th scope="col">Group</th><th scope="col">Source</th>
      <th scope="col"><span class="sr-only">Actions</span></th></tr></thead><tbody id="destBody"></tbody></table></div>
    <p class="hint" id="destMode"></p>
`;

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
  const isRule = (d) => RULE_ACTIONS.includes(d.access) && d.id;

  function render() {
    const q = $("#dFilter").value.trim().toLowerCase(), body = $("#destBody");
    body.innerHTML = "";
    let shown = 0;
    for (const d of model.destinations) {
      if (d.access === "request") continue;  // on-request destinations (grants) are managed in the section below
      const label = d.match.host || d.match.cidr || "";
      if (q && !label.toLowerCase().includes(q)) continue;
      const [al, cls] = ACCESS[d.access] || ["property", "muted"];
      const tr = document.createElement("tr");
      shown++;
      tr.innerHTML = `<td>${isRule(d) ? '<input type="checkbox" class="dsel" aria-label="Select rule">' : ""}</td>
        <td>${matchText(d)}</td>
        <td><span class="${cls}">${esc(al)}</span>${d.expires ? `<div class="muted small-text">ends in ${esc(fmtLeft(d.expires))}</div>` : ""}</td>
        <td>${limitsText(d)}</td>
        <td>${d.group ? `<span class="tag">${esc(d.group)}</span>` : ""}</td>
        <td class="muted small-text">${esc(d.source || "")}</td><td></td>`;
      if (isRule(d)) tr.querySelector(".dsel").dataset.id = d.id;
      const actions = tr.lastElementChild;
      if (isRule(d)) {
        const what = `${d.access} ${label}`;
        const del = mkbtn("Delete", null, `Delete rule ${what}`, true);
        del.onclick = confirmClick(del, `Delete rule ${what}?`, async () => {
          await gw("DELETE", `/destinations/${d.id}`); toast("Rule deleted"); await load();
        });
        actions.append(mkbtn("Edit", () => editRow(tr, d), `Edit rule ${what}`), del);
      } else {
        actions.innerHTML = '<span class="tag">config file</span>';
      }
      body.appendChild(tr);
    }
    if (!shown) {
      body.innerHTML = `<tr><td colspan="7" class="muted">${q ? "No rule matches the filter."
        : "No rules yet. Add the first one with the form above."}</td></tr>`;
    }
    renderNever(body, q);
    const blocked = (model.never || []).filter((n) => !n.open).length;
    const mode = ACCESS[model.default] || [model.default, "muted"];
    $("#destMode").innerHTML = `Everything else: <b class="${mode[1]}">${esc(mode[0])}</b> (${esc(MODE[model.default] || "mode")}; change it under <i>Settings</i>). `
      + `${blocked} blocked range${blocked === 1 ? " is" : "s are"} listed at the end of the table.`;
  }

  // The never-reachable deny floor (ADR-0017), shown as blocked rows in the one table. A removable range
  // (your LAN, the cloud metadata address, your own deny additions) can be unblocked behind a scary confirm;
  // the gateway's own networks are locked and have no action.
  function scopeText(d) {
    const base = d.scope === "all+lan" ? "all connections, incl. LAN grants" : "all connections";
    return d.open ? `${base} — unblocked for normal connections` : base;
  }
  function renderNever(body, q) {
    for (const d of model.never || []) {
      if (q && !d.range.toLowerCase().includes(q)) continue;
      const tr = document.createElement("tr");
      tr.innerHTML = `<td></td>
        <td><code>${esc(d.range)}</code></td>
        <td>${d.open ? '<span class="status warn">unblocked</span>' : '<span class="a-deny">deny</span>'}</td>
        <td>${esc(scopeText(d))}</td>
        <td></td>
        <td class="muted small-text">${esc(d.reason || "")}</td><td></td>`;
      const actions = tr.lastElementChild;
      if (!d.removable) {
        actions.innerHTML = '<span class="tag">locked</span>';  // structural: explained in the help above
      } else if (d.open) {
        actions.append(mkbtn("Undo unblock", guard(() => floorOpen(d.range, false)), `Block ${d.range} again`));
      } else {
        // security-lowering: danger colour, and the confirmation names the range and the consequence
        const b = mkbtn("Unblock range", null, `Unblock ${d.range}`, true);
        b.onclick = confirmClick(b, `Unblock ${d.range}? The agent will be able to reach your local network.`,
          () => floorOpen(d.range, true));
        actions.append(b);
      }
      body.appendChild(tr);
    }
  }
  // Add or remove a range from the policy's floor_open and PUT the whole policy (start from the policy as it
  // is now, like the raw editor, so a change elsewhere is not lost).
  async function floorOpen(range, open) {
    const fresh = await gw("GET", "/policy");
    const set = new Set(fresh.floor_open || []);
    if (open) set.add(range); else set.delete(range);
    await gw("PUT", "/policy", { ...fresh, floor_open: [...set] });
    toast(open ? `Range ${range} unblocked` : `Range ${range} blocked again`);
    await load();
  }

  // a row action: ghost rank; destructive or security-lowering ones in the danger colour (and confirmed)
  function mkbtn(text, onclick, label, danger) {
    const b = document.createElement("button");
    b.textContent = text; b.className = danger ? "small ghost danger" : "small ghost"; b.onclick = onclick;
    if (label) b.setAttribute("aria-label", label);
    return b;
  }
  // columns: [0] select, [1] destination, [2] access, [3] limits, [4] group, [5] source, [6] actions
  function editRow(tr, d) {
    tr.cells[2].innerHTML = `<select class="eA">${RULE_ACTIONS.map((a) => `<option${a === d.access ? " selected" : ""}>${a}</option>`).join("")}</select>`
      + `<input class="eP" size="6" value="${esc(portText(d.match.port))}" aria-label="Ports">`;
    tr.cells[3].innerHTML = `<input class="eN" value="${esc(d.note || "")}" placeholder="Note" aria-label="Note">`
      + `<input class="eT" size="8" placeholder="${d.expires ? `${esc(fmtLeft(d.expires))} left` : "permanent"}" aria-label="Expiry in seconds"><span class="muted"> s</span>`;
    tr.cells[4].innerHTML = `<input class="eG" size="10" value="${esc(d.group || "")}" placeholder="Group" aria-label="Group">`;
    const cell = tr.cells[6]; cell.innerHTML = "";
    cell.append(
      mkbtn("Save", guard(async () => {
        const changes = {
          action: tr.querySelector(".eA").value,
          port: parsePort(tr.querySelector(".eP").value),
          note: tr.querySelector(".eN").value,
          group: tr.querySelector(".eG").value.trim(),
        };
        const t = tr.querySelector(".eT").value.trim();
        if (t) { if (!/^\d+$/.test(t) || +t <= 0) throw new Error("Expiry: whole seconds from now, or blank for permanent"); changes.expires = Date.now() / 1000 + +t; }
        else changes.expires = null;
        const dest = { access: changes.action, match: { port: changes.port }, note: changes.note, group: changes.group, expires: changes.expires };
        await gw("PATCH", `/destinations/${d.id}`, dest); toast("Rule saved"); await load();
      })),
      mkbtn("Cancel", () => load()),
    );
  }

  function selectedIds() {
    return [...document.querySelectorAll("#destBody .dsel:checked")].map((c) => c.dataset.id);
  }
  async function group(name) {
    const ids = selectedIds();
    if (!ids.length) throw new Error("Tick one or more access rules first");
    if (name && !$("#dGroupName").value.trim()) throw new Error("Enter a group name");
    await gw("POST", "/destinations/group", { ids, group: name });
    toast(name ? `${ids.length} rule(s) grouped as “${name}”` : `${ids.length} rule(s) ungrouped`);
    $("#dGroupName").value = ""; await load();
  }

  $("#dAdd").onclick = guard(async () => {
    const action = $("#dAction").value, kind = $("#dKind").value, match = $("#dMatch").value.trim();
    checkMatch(kind, match);
    const port = parsePort($("#dPort").value);
    const dest = { match: { [kind]: match }, access: action };
    if (port !== "*") dest.match.port = port;
    if ($("#dNote").value) dest.note = $("#dNote").value;
    if (+$("#dTtl").value > 0) dest.expires = Date.now() / 1000 + +$("#dTtl").value;
    await gw("POST", "/destinations", dest); toast("Rule added");
    $("#dMatch").value = ""; await load();
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
