"use strict";
/* Learning mode (#69): for a limited time, destinations no rule covers are allowed on a few ports and recorded.
   Afterwards the used destinations are proposed as rules to tick and save. The header shows it while active.
   Uses the helpers of app.js ($, $$, esc, gw, toast, guard, confirmClick, fmtDate, fmtLeft, showTab, loadPolicy). */
(() => {
  const box = $("#learnBox"), badge = $("#learnBadge");
  if (!box || !badge) return;
  let state = null, shown = null, focusNext = false;

  function renderBadge() {
    const a = state && state.active;
    badge.classList.toggle("hidden", !a);
    if (a) badge.textContent = `Learning mode · ${fmtLeft(a.until)} left`;
  }
  function render() {
    const a = state.active;
    // the buttons are rebuilt: keep the keyboard focus on the start/stop button (or move it there after the badge)
    const keep = focusNext || ["learnStart", "learnStop"].includes(document.activeElement && document.activeElement.id);
    focusNext = false;
    const portsChoices = [state.ports_allowed.filter((p) => p === 443), state.ports_allowed].filter((x, i, all) => x.length && (i === 0 || x.join() !== all[0].join()));
    const mins = [15, 30, 60, 120].filter((m) => m <= state.max_minutes);
    if (!mins.includes(state.max_minutes) && state.max_minutes < 120) mins.push(state.max_minutes);
    $("#learnState").innerHTML = a
      ? `<p class="learn-on" role="status"><b>Learning mode is on</b> for ports ${esc(a.ports.join(", "))}: ends at
          ${esc(new Date(a.until * 1000).toLocaleTimeString())} (${esc(fmtLeft(a.until))} left), started by ${esc(a.by)}.
          Destinations no rule covers are allowed and recorded.</p><button id="learnStop" class="danger">Stop learning mode</button>`
      : `<div class="row wrap">
          <label class="inline">Duration <select id="learnMin">${mins.map((m) => `<option value="${m}"${m === 30 ? " selected" : ""}>${m} min</option>`).join("")}</select></label>
          <label class="inline">Ports <select id="learnPorts">${portsChoices.map((p) => `<option value="${p.join(",")}">${p.join(" and ")}${p.join() === "443" ? " (HTTPS)" : ""}</option>`).join("")}</select></label>
          <button id="learnStart">Start learning mode</button></div>`;
    if (a) $("#learnStop").onclick = guard(async () => { await gw("DELETE", "/learning"); toast("Learning mode stopped"); await load(); });
    else {
      const b = $("#learnStart");
      b.onclick = confirmClick(b, "Allow every public destination that no rule covers on these ports, for this time?", async () => {
        await gw("POST", "/learning", { minutes: +$("#learnMin").value, ports: $("#learnPorts").value.split(",").map(Number) });
        toast("Learning mode is on"); await load(); $("#learnStop").focus();
      });
    }
    const sessions = state.sessions;
    $("#learnSessions").innerHTML = sessions.length ? `<label class="inline">Session <select id="learnSel">${sessions.map((s) =>
      `<option value="${esc(s.id)}">${esc(fmtDate(s.started))}${s.ended ? "" : " (running)"} · ${esc(s.by)}</option>`).join("")}</select></label>
      <button id="learnShow" class="secondary small">Show what was used</button>` : "";
    if (sessions.length) $("#learnShow").onclick = guard(() => showSummary($("#learnSel").value));
    renderBadge();
    if (keep) ($("#learnStop") || $("#learnStart")).focus();
  }
  async function showSummary(id) {
    shown = id;
    const r = await gw("GET", `/learning/${encodeURIComponent(id)}`);
    const out = $("#learnSummary"), s = r.session, props = r.groups.filter((g) => g.proposal);
    out.innerHTML = `<h4>Used during the session from ${esc(fmtDate(s.started))}${s.ended ? ` to ${esc(fmtDate(s.ended))}` : " (still running)"}</h4>
      ${r.groups.length ? "" : '<p class="muted">No connections in this session.</p>'}
      <ul class="checklist">${r.groups.map((g, i) => `<li><label>${g.proposal ? `<input type="checkbox" data-i="${i}" checked>` : '<input type="checkbox" disabled>'}
        <span><code>${esc(g.proposal ? g.proposal.host : g.domain)}:${esc(g.port)}</code>
        <span class="muted">${esc(g.count)} connection${g.count === 1 ? "" : "s"} · ${g.hosts.map((h) => esc(h.host) + (h.count > 1 ? ` (${esc(h.count)})` : "")).join(", ")}
        ${g.proposal ? "" : g.denied === g.count ? " · denied by your rules" : " · already allowed by your rules"}</span></span></label></li>`).join("")}</ul>
      ${props.length ? '<button id="learnSave">Save selected as allow rules</button>' : ""}`;
    if (!props.length) return;
    $("#learnSave").onclick = guard(async () => {
      const rules = $$("#learnSummary input[data-i]:checked").map((c) => r.groups[+c.dataset.i].proposal);
      if (!rules.length) throw new Error("Nothing selected");
      const res = await gw("POST", "/learning/apply", { rules });
      toast(`${res.added.length} rule${res.added.length === 1 ? "" : "s"} added`); await loadPolicy(true); await showSummary(id);
    });
  }
  async function load() {
    state = await gw("GET", "/learning");
    render();
    if (!state.active && state.sessions.length && shown === null) await showSummary(state.sessions[0].id);
  }
  box.innerHTML = `<p class="hint">Starting a new kind of task? For a limited time, connections to public destinations that
      no rule covers are allowed on the chosen ports and recorded. Afterwards you see what was used, grouped by
      domain, and save the rules you want in one go. The hard deny (local network, Docker host, metadata), your deny
      and ask rules and grants stay in force, names are still decided before they are resolved, and learning mode
      ends by itself (also on the emergency stop and when the gateway restarts).</p>
    <div id="learnState"></div><div id="learnSessions" class="row wrap"></div><div id="learnSummary"></div>`;
  badge.onclick = () => { focusNext = true; showTab("rules"); $("#learnCard").scrollIntoView({ block: "start" }); };  // tg:tab reloads, render() focuses
  setInterval(() => { if (state && state.active) { if (state.active.until <= Date.now() / 1000) load().catch(() => {}); else { renderBadge(); } } }, 15000);
  document.addEventListener("tg:event", (e) => { if (e.detail.type === "learning") { shown = null; load().catch(() => {}); } });
  document.addEventListener("tg:tab", (e) => { if (e.detail === "rules") guard(load)(); });
  guard(load)();
})();
