"use strict";
/* Log search (#80): server-side search by host, kind, action and time range, saved filters, destinations
   (with "new"), a per-destination view and CSV/JSON export.
   Uses the helpers of app.js ($, $$, esc, gw, toast, guard, fmtDate). */
(() => {
  const box = $("#searchBox");
  if (!box) return;
  const RANGES = [["3600", "last hour"], ["86400", "last 24 h"], ["today", "today"], ["604800", "last 7 days"],
    ["2592000", "last 30 days"], ["all", "everything"], ["custom", "custom…"]];
  const BUILTIN = [
    { name: "Denied today", f: { view: "events", range: "today", kind: "conn", action: "deny" } },
    { name: "New destinations (24 h)", f: { view: "new", range: "86400" } },
    { name: "Approvals asked (7 days)", f: { view: "events", range: "604800", kind: "ask" } },
    { name: "Admin changes (7 days)", f: { view: "events", range: "604800", kind: "admin" } },
  ];
  const STORE = "tallygate.logFilters";
  box.innerHTML = `<p class="hint">Searches the whole event log on the gateway (kept for <code>log_keep_days</code>), not
      just the rows loaded below.</p>
    <div class="row wrap" role="group" aria-label="Saved filters" id="lsSaved"></div>
    <form id="lsForm" class="search-grid">
      <label>Show <select id="lsView"><option value="events">events</option><option value="dest">destinations</option>
        <option value="new">new destinations</option></select></label>
      <label>Host <input id="lsHost" placeholder="api.example.com or *.example.com" autocomplete="off"></label>
      <label>Kind <select id="lsKind"><option value="">any</option><option>conn</option><option>ask</option><option>dns</option>
        <option>admin</option><option>grant</option></select></label>
      <label>Action <select id="lsAction"><option value="">any</option><option>allow</option><option>deny</option><option>ask</option></select></label>
      <label>Text <input id="lsQ" placeholder="in host / action / reason" autocomplete="off"></label>
      <label>Time <select id="lsRange">${RANGES.map(([v, t]) => `<option value="${v}">${t}</option>`).join("")}</select></label>
      <label class="ls-custom hidden">From <input id="lsFrom" type="datetime-local"></label>
      <label class="ls-custom hidden">To <input id="lsTo" type="datetime-local"></label>
      <div class="btns"><button id="lsGo" type="submit">Search</button>
        <button id="lsSave" type="button" class="secondary">Save filter</button>
        <button id="lsCsv" type="button" class="secondary">Export CSV</button>
        <button id="lsJson" type="button" class="secondary">Export JSON</button></div>
    </form>
    <p id="lsStatus" class="muted" role="status"></p>
    <div id="lsOut"></div>
    <div id="lsDest" class="hidden" role="region" aria-label="Destination" tabindex="-1"></div>`;

  const load = () => { try { return JSON.parse(localStorage.getItem(STORE) || "[]"); } catch { return []; } };
  const store = (v) => { try { localStorage.setItem(STORE, JSON.stringify(v)); } catch { toast("This browser does not keep saved filters", true); } };
  const ts = (local) => (local ? new Date(local).getTime() / 1000 : null);

  function current() {
    return { view: $("#lsView").value, host: $("#lsHost").value.trim(), kind: $("#lsKind").value, action: $("#lsAction").value,
      q: $("#lsQ").value.trim(), range: $("#lsRange").value, from: $("#lsFrom").value, to: $("#lsTo").value };
  }
  function apply(f) {
    $("#lsView").value = f.view || "events"; $("#lsHost").value = f.host || ""; $("#lsKind").value = f.kind || "";
    $("#lsAction").value = f.action || ""; $("#lsQ").value = f.q || ""; $("#lsRange").value = f.range || "86400";
    $("#lsFrom").value = f.from || ""; $("#lsTo").value = f.to || ""; syncCustom();
  }
  function syncCustom() {
    $$(".ls-custom", box).forEach((l) => l.classList.toggle("hidden", $("#lsRange").value !== "custom"));
    // host, kind and action narrow events; destinations are listed by time range and text
    const ev = $("#lsView").value === "events";
    ["#lsHost", "#lsKind", "#lsAction"].forEach((x) => ($(x).disabled = !ev));
  }
  // Query string for the gateway; time range as unix seconds.
  function query(f, extra = {}) {
    const p = new URLSearchParams(), now = Date.now() / 1000;
    if (f.range === "today") { const d = new Date(); d.setHours(0, 0, 0, 0); p.set("since", d.getTime() / 1000); }
    else if (f.range === "custom") { if (ts(f.from)) p.set("since", ts(f.from)); if (ts(f.to)) p.set("until", ts(f.to)); }
    else if (f.range !== "all") p.set("since", Math.floor(now - Number(f.range)));
    if (f.view === "events") {
      if (f.host) p.set("host", f.host); if (f.kind) p.set("kind", f.kind); if (f.action) p.set("action", f.action);
    }
    if (f.q) p.set("q", f.q);
    if (f.view === "new") p.set("new", "1");
    for (const [k, v] of Object.entries(extra)) p.set(k, v);
    return p.toString();
  }
  function renderSaved() {
    const el = $("#lsSaved"); el.innerHTML = '<span class="muted">Filters:</span>';
    const add = (s, user) => {
      const b = document.createElement("button"); b.type = "button"; b.className = "small secondary"; b.textContent = s.name;
      b.onclick = guard(() => { apply(s.f); return search(); }); el.appendChild(b);
      if (user) {
        const x = document.createElement("button"); x.type = "button"; x.className = "small secondary"; x.textContent = "✕";
        x.setAttribute("aria-label", `Delete saved filter ${s.name}`);
        x.onclick = () => { store(load().filter((y) => y.name !== s.name)); renderSaved(); $("#lsSave").focus(); };
        el.appendChild(x);
      }
    };
    BUILTIN.forEach((s) => add(s, false)); load().forEach((s) => add(s, true));
  }

  let rows = [];
  const dest = (e) => `${e.host ?? ""}${e.port ? ":" + e.port : ""}`;
  function destButton(host, port) {
    return `<button type="button" class="link dest-link" data-host="${esc(host)}" data-port="${esc(port ?? "")}">${esc(host)}${port ? ":" + esc(port) : ""}</button>`;
  }
  function renderEvents(more) {
    $("#lsOut").innerHTML = `<div class="table-wrap"><table class="log"><thead><tr><th>Time</th><th>Kind</th><th>Destination</th>
      <th>Action</th><th>Reason</th></tr></thead><tbody>${rows.map((e) => `<tr><td>${esc(fmtDate(e.ts))}</td><td>${esc(e.kind)}</td>
      <td>${e.host && e.kind !== "admin" && e.kind !== "grant" ? destButton(e.host, e.port) : `<code>${esc(dest(e))}</code>`}</td>
      <td class="a-${esc(e.action)}">${esc(e.action)}</td><td>${esc(e.reason)}</td></tr>`).join("")}</tbody></table></div>
      ${more ? '<button id="lsMore" type="button" class="small secondary">More</button>' : ""}`;
    if (more) $("#lsMore").onclick = guard(() => search(true));
  }
  function renderDests(list) {
    $("#lsOut").innerHTML = `<div class="table-wrap"><table class="log"><thead><tr><th>Destination</th><th>Events</th><th>Allowed</th>
      <th>Denied</th><th>Asked</th><th>First seen</th><th>Last</th></tr></thead><tbody>${list.map((d) => `<tr>
      <td>${destButton(d.host, d.port)}${d.new ? ' <span class="tag warn">new</span>' : ""}</td><td>${esc(d.events)}</td>
      <td class="a-allow">${esc(d.allowed)}</td><td class="a-deny">${esc(d.denied)}</td><td>${esc(d.asked)}</td>
      <td>${esc(fmtDate(d.first_seen))}</td><td>${esc(fmtDate(d.last))}</td></tr>`).join("")}</tbody></table></div>`;
  }
  async function search(more = false) {
    const f = current();
    $("#lsDest").classList.add("hidden");
    if (f.view === "events") {
      const before = more && rows.length ? { before: rows[rows.length - 1].id } : {};
      const got = await gw("GET", "/events?" + query(f, { limit: 200, ...before }));
      rows = more ? rows.concat(got) : got;
      renderEvents(got.length === 200);
      $("#lsStatus").textContent = `${rows.length} event${rows.length === 1 ? "" : "s"}${got.length === 200 ? " (more available)" : ""}`;
    } else {
      const list = await gw("GET", "/destinations?" + query(f, { limit: 500 }));
      rows = list; renderDests(list);
      $("#lsStatus").textContent = `${list.length} destination${list.length === 1 ? "" : "s"}`;
    }
  }
  async function showDest(host, port) {
    const d = await gw("GET", `/destinations/detail?host=${encodeURIComponent(host)}&port=${encodeURIComponent(port || 443)}`);
    const r = d.decision.rule, s = d.stats;
    const el = $("#lsDest");
    el.innerHTML = `<div class="row-between"><h4>${esc(d.host)}:${esc(d.port)}</h4><button type="button" id="lsBack" class="small secondary">Back to results</button></div>
      <p>Now: <b class="a-${esc(d.decision.action)}">${esc(d.decision.action)}</b> — ${r ? `rule <code>${esc(r.action)} ${esc(r.host || r.cidr)}${r.port !== undefined ? ":" + esc(Array.isArray(r.port) ? r.port.join(",") : r.port) : ""}</code>${r.note ? " (" + esc(r.note) + ")" : ""}${r.source ? ` [${esc(r.source)}]` : ""}` : esc(d.decision.reason)}
        <span class="muted">(decided on the name; the hard deny is checked again after resolving)</span></p>
      ${s ? `<p class="muted">${esc(s.events)} events · ${esc(s.allowed)} allowed · ${esc(s.denied)} denied · ${esc(s.asked)} asked · first seen ${esc(fmtDate(s.first_seen))} · last ${esc(fmtDate(s.last))}</p>` : '<p class="muted">No connections in the log.</p>'}
      <div class="table-wrap"><table class="log"><thead><tr><th>Time</th><th>Kind</th><th>Action</th><th>Reason</th></tr></thead><tbody>
      ${d.events.map((e) => `<tr><td>${esc(fmtDate(e.ts))}</td><td>${esc(e.kind)}</td><td class="a-${esc(e.action)}">${esc(e.action)}</td><td>${esc(e.reason)}</td></tr>`).join("")}
      </tbody></table></div>`;
    el.classList.remove("hidden"); $("#lsOut").classList.add("hidden"); el.focus();
    $("#lsBack").onclick = () => { el.classList.add("hidden"); $("#lsOut").classList.remove("hidden");
      const b = $(`#lsOut .dest-link[data-host="${CSS.escape(host)}"]`); (b || $("#lsGo")).focus(); };
  }
  // Export: every matching row (paged, at most 50 000), built in the browser.
  async function exportAs(kind) {
    const f = current(); let all = [];
    if (f.view === "events") {
      for (;;) {
        const before = all.length ? { before: all[all.length - 1].id } : {};
        const got = await gw("GET", "/events?" + query(f, { limit: 2000, ...before }));
        all = all.concat(got); $("#lsStatus").textContent = `exporting… ${all.length}`;
        if (got.length < 2000 || all.length >= 50000) break;
      }
    } else all = await gw("GET", "/destinations?" + query(f, { limit: 2000 }));
    const cols = all.length ? Object.keys(all[0]) : [];
    const cell = (v) => { const s = v === null || v === undefined ? "" : typeof v === "object" ? JSON.stringify(v) : String(v);
      return /[",\n\r]/.test(s) || /^[=+\-@\t]/.test(s) ? `"${s.replace(/^([=+\-@\t])/, "'$1").replace(/"/g, '""')}"` : s; };
    const text = kind === "csv" ? [cols.join(","), ...all.map((r) => cols.map((c) => cell(r[c])).join(","))].join("\r\n") + "\r\n"
      : JSON.stringify(all, null, 1);
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([text], { type: kind === "csv" ? "text/csv" : "application/json" }));
    a.download = `tallygate-${f.view === "events" ? "events" : "destinations"}-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "")}.${kind}`;
    document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 1000);
    $("#lsStatus").textContent = `${all.length} rows exported`;
  }

  $("#lsForm").addEventListener("submit", (e) => { e.preventDefault(); guard(search)(); });
  $("#lsRange").addEventListener("change", syncCustom);
  $("#lsView").addEventListener("change", syncCustom);
  $("#lsOut").addEventListener("click", (e) => {
    const b = e.target.closest(".dest-link"); if (b) guard(showDest)(b.dataset.host, b.dataset.port);
  });
  $("#lsSave").onclick = () => {
    const name = ($("#lsQ").value.trim() || $("#lsHost").value.trim() || `${$("#lsView").value} ${$("#lsRange").selectedOptions[0].text}`).slice(0, 40);
    store(load().filter((s) => s.name !== name).concat([{ name, f: current() }])); renderSaved(); toast(`Filter "${name}" saved in this browser`);
  };
  $("#lsCsv").onclick = guard(() => exportAs("csv"));
  $("#lsJson").onclick = guard(() => exportAs("json"));
  apply({ range: "86400" }); renderSaved();
})();
