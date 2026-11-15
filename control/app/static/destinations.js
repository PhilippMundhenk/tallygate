"use strict";
/* Destinations (ADR-0014 / #122, ADR-0019): every destination in one place, from GET /model.
   One ordered rule list, shown in the order it is evaluated: the rules (the built-in blocks are rules among
   them), then the locked ranges, then the default. Rules are added, edited, moved, deleted and grouped here;
   on-request destinations (grants) open on the Grants tab; read-only hosts, credentials and repository scope
   come from the gateway config file and are shown read-only. Uses app.js helpers: $, esc, gw, toast, fmtDate, fmtLeft, parsePort, portText, guard,
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
    <p class="hint">One list, checked from the top: the first matching rule decides. New rules are added at the top.</p>
    <details class="help"><summary>How is a connection decided?</summary>
      <p>The list is checked from top to bottom for every address a destination resolves to; the first rule that
        matches decides, and the default at the end applies when none does. A rule for an <b>address</b> (an IP or
        a range) is final. A rule for a <b>name</b> that says deny is final too.</p>
      <p>A name rule that says allow or ask <b>cannot open a blocked range</b>: if the name resolves to an address
        that a deny rule for a range further down covers, the connection is denied. Names are chosen by whoever
        controls DNS, so only a rule that names the address opens it. To reach one device on your local network,
        add an allow rule for its address (and port): it is added at the top, above the blocked range.</p>
      <p>The built-in blocked ranges (your local network, loopback, cloud metadata and other special addresses) and
        the <code>never</code> entries of the gateway config are ordinary deny rules at the bottom: they can be
        edited, moved and deleted, and <i>Restore built-in blocks</i> adds the missing ones back. The tallygate
        stack's own networks and the gateway's own ports are <b>locked</b>: they are checked before the list and
        cannot be opened by any rule or grant.</p>
      <p>On-request destinations (grants) are defined on the <i>Grants</i> tab. Read-only hosts, added credentials
        and repository limits come from the gateway config file and are shown read-only (tagged <i>config file</i>).</p>
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
      <button id="dRestore" class="small secondary">Restore built-in blocks</button>
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
    if (d.scheme && d.scheme !== "https") out.push(d.scheme);
    if (d.tls && d.tls.fingerprint) out.push("pinned TLS");
    return out.map((t) => `<div>${esc(t)}</div>`).join("") || '<span class="muted">–</span>';
  }
  const isRule = (d) => RULE_ACTIONS.includes(d.access) && d.id;
  const SOURCE = { builtin: "built-in block", config: "never (config file)" };
  // What the operator has to see about a rule that cannot do what it says (ADR-0019), as status lines:
  // a name rule that a blocked range below it stopped, and an address rule an earlier one covers completely.
  function ruleNotes(d) {
    const out = [];
    if (d.shadowed) {
      const s = d.shadowed;
      out.push(`<div class="status warn">blocked by a range rule below</div>
        <div class="muted small-text">last: <code>${esc(s.address)}</code> in <code>${esc(s.range)}</code> (rule <code>${esc(s.by)}</code>),
          ${esc(fmtDate(s.last))}, ${Number(s.count)}&times;. A name cannot open a blocked range: add an allow rule for the address.</div>`);
    }
    if (d.covered_by) {
      out.push(`<div class="status off">never reached</div>
        <div class="muted small-text">covered by rule <code>${esc(d.covered_by)}</code> above it</div>`);
    }
    return out.join("");
  }

  function render() {
    const q = $("#dFilter").value.trim().toLowerCase(), body = $("#destBody");
    body.innerHTML = "";
    const rules = model.destinations.filter(isRule);  // in evaluation order
    let shown = 0;
    for (const d of model.destinations) {
      if (d.access === "request") continue;  // on-request destinations (grants) are managed in the section below
      const label = d.match.host || d.match.cidr || "";
      if (q && !label.toLowerCase().includes(q)) continue;
      const [al, cls] = ACCESS[d.access] || ["property", "muted"];
      const tr = document.createElement("tr");
      shown++;
      tr.innerHTML = `<td>${isRule(d) ? '<input type="checkbox" class="dsel" aria-label="Select rule">' : ""}</td>
        <td>${matchText(d)}${isRule(d) ? ruleNotes(d) : ""}</td>
        <td><span class="${cls}">${esc(al)}</span>${d.expires ? `<div class="muted small-text">ends in ${esc(fmtLeft(d.expires))}</div>` : ""}</td>
        <td>${limitsText(d)}</td>
        <td>${d.group ? `<span class="tag">${esc(d.group)}</span>` : ""}</td>
        <td class="muted small-text">${esc(SOURCE[d.source] || d.source || "")}</td><td></td>`;
      if (isRule(d)) { tr.querySelector(".dsel").dataset.id = d.id; tr.dataset.rule = d.id; }
      const actions = tr.lastElementChild;
      if (isRule(d)) {
        const what = `${d.access} ${label}`, at = rules.indexOf(d);
        // Move up / down: one place in the evaluation order. `before` is the rule this one goes in front of.
        const up = mkbtn("Move up", guard(() => move(d, rules[at - 1].id)), `Move rule ${what} up`);
        const down = mkbtn("Move down", guard(() => move(d, at + 2 < rules.length ? rules[at + 2].id : null)), `Move rule ${what} down`);
        up.disabled = at === 0; down.disabled = at === rules.length - 1;
        up.dataset.move = "up"; down.dataset.move = "down";
        const block = d.access === "deny" && !!d.match.cidr;
        const del = mkbtn("Delete", null, `Delete rule ${what}`, true);
        // deleting a block lowers security: the confirmation names the range and the consequence
        del.onclick = confirmClick(del, block ? `Delete the block of ${label}? The agent will be able to reach these addresses if another rule or the default allows it.`
          : `Delete rule ${what}?`, async () => {
          await gw("DELETE", `/destinations/${encodeURIComponent(d.id)}`); toast("Rule deleted"); await load();
        });
        actions.append(up, down, mkbtn("Edit", () => editRow(tr, d), `Edit rule ${what}`), del);
      } else {
        actions.innerHTML = '<span class="tag">config file</span>';
      }
      body.appendChild(tr);
    }
    if (!shown) {
      body.innerHTML = `<tr><td colspan="7" class="muted">${q ? "No rule matches the filter."
        : "No rules yet. Add the first one with the form above."}</td></tr>`;
    }
    renderLocked(body, q);
    // the default: the last line of the list
    const mode = ACCESS[model.default] || [model.default, "muted"];
    const last = document.createElement("tr"); last.className = "dest-default";
    last.innerHTML = `<td></td><td>Everything else</td><td><b class="${mode[1]}">${esc(mode[0])}</b></td>
      <td>${esc(MODE[model.default] || "mode")}</td><td></td><td class="muted small-text">default</td><td></td>`;
    body.appendChild(last);
    const blocks = rules.filter((d) => d.source === "builtin" || d.source === "config").length;
    $("#destMode").innerHTML = `The default is changed under <i>Settings</i>. ${blocks} built-in or config block${blocks === 1 ? " is" : "s are"} in the list, `
      + `${(model.locked || []).length} locked range${(model.locked || []).length === 1 ? "" : "s"} below it.`;
  }

  // Locked (ADR-0019): the stack's own networks and the gateway's own ports. Shown as the last rows before the
  // default so the operator sees them; checked before the list, so they have a state and no actions.
  function renderLocked(body, q) {
    for (const d of model.locked || []) {
      if (q && !d.range.toLowerCase().includes(q)) continue;
      const tr = document.createElement("tr"); tr.className = "dest-locked";
      tr.innerHTML = `<td></td>
        <td><code>${esc(d.range)}</code></td>
        <td><span class="a-deny">deny</span></td>
        <td>checked before the list</td>
        <td></td>
        <td class="muted small-text">${esc(d.reason || "")}</td><td><span class="status off">locked</span></td>`;
      body.appendChild(tr);
    }
  }
  async function move(d, before) {
    await gw("POST", `/destinations/${encodeURIComponent(d.id)}/move`, { before });
    toast("Rule moved"); await load();
    // keep the keyboard on the rule that moved, so it can be moved again
    const row = [...document.querySelectorAll("#destBody tr")].find((tr) => tr.dataset.rule === d.id);
    const btn = row && [...row.querySelectorAll("button[data-move]")].find((b) => !b.disabled);
    if (btn) btn.focus();
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
        await gw("PATCH", `/destinations/${encodeURIComponent(d.id)}`, dest); toast("Rule saved"); await load();
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
  $("#dRestore").onclick = guard(async () => {
    const r = await gw("POST", "/destinations/restore-blocks", {});
    const n = (r.added || []).length;
    toast(n ? `${n} built-in block${n === 1 ? "" : "s"} restored` : "No built-in block is missing"); await load();
  });

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
