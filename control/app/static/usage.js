"use strict";
/* Rule usage (#70): hit counters per rule (sortable, filterable), unused rules offered for removal, and
   "make it permanent?" suggestions from repeated temporary approvals.
   Uses the helpers of app.js ($, $$, esc, gw, toast, guard, confirmClick, fmtDate, portText, loadPolicy). */
(() => {
  const box = $("#usageBox");
  if (!box) return;
  box.innerHTML = `<div id="sgList" aria-live="polite"></div>
    <div id="usStale" class="hidden"></div>
    <div class="toolbar">
      <input id="usFilter" type="search" aria-label="Filter rules by host, note or source" placeholder="filter host / note / source">
      <select id="usShow" aria-label="Show"><option value="all">all rules</option><option value="unused">unused only</option>
        <option value="used">matched only</option></select>
      <button id="usRefresh" class="small secondary">Refresh</button>
    </div>
    <div class="table-wrap"><table class="usage"><thead><tr>
      <th aria-sort="ascending"><button class="sort" data-key="pos">#</button></th>
      <th><button class="sort" data-key="match">Rule</button></th>
      <th><button class="sort" data-key="source">Source</button></th>
      <th aria-sort="none"><button class="sort" data-key="hits">Hits</button></th>
      <th aria-sort="none"><button class="sort" data-key="last">Last match</button></th>
    </tr></thead><tbody id="usBody"></tbody></table></div>
    <p class="hint" id="usHint"></p>`;

  let rules = [], staleDays = 30, sort = { key: "pos", dir: 1 }, loaded = false;
  const match = (r) => `${r.action} ${r.host || r.cidr}${r.port !== undefined && r.port !== "*" ? ":" + portText(r.port) : ""}`;
  const val = (r, k) => (k === "match" ? match(r) : k === "source" ? r.source || "user" : k === "last" ? r.last || 0 : r[k]);

  function renderTable() {
    const f = $("#usFilter").value.trim().toLowerCase(), show = $("#usShow").value;
    const rows = rules.filter((r) => (!f || `${match(r)} ${r.note || ""} ${r.source || "user"}`.toLowerCase().includes(f)) &&
      (show === "all" || (show === "unused" ? !r.hits : r.hits > 0)));
    rows.sort((a, b) => { const x = val(a, sort.key), y = val(b, sort.key); return (x > y ? 1 : x < y ? -1 : 0) * sort.dir; });
    $("#usBody").innerHTML = rows.map((r) => `<tr><td>${esc(r.pos)}</td>
      <td><code class="a-${esc(r.action)}">${esc(match(r))}</code>${r.note ? ` <span class="muted">${esc(r.note)}</span>` : ""}
        ${r.stale ? ' <span class="tag warn">unused</span>' : ""}</td>
      <td>${esc(r.source || "user")}</td><td>${esc(r.hits)}</td>
      <td>${r.last ? esc(fmtDate(r.last)) : '<span class="muted">never</span>'}</td></tr>`).join("") ||
      '<tr><td colspan="5" class="muted">No rules match the filter.</td></tr>';
    $$("#usageBox th").forEach((th) => {
      const k = $("button", th).dataset.key;
      th.setAttribute("aria-sort", k === sort.key ? (sort.dir > 0 ? "ascending" : "descending") : "none");
    });
    $("#usHint").textContent = `Hits count connections decided by the rule since it was first seen (updated every 15 s). ` +
      `A permanent rule is "unused" when it has not matched for ${staleDays} days.`;
  }
  function renderStale() {
    const stale = rules.filter((r) => r.stale), el = $("#usStale");
    el.classList.toggle("hidden", !stale.length);
    if (!stale.length) { el.innerHTML = ""; return; }
    el.innerHTML = `<h4>Unused rules</h4><p class="hint">${stale.length} permanent rule${stale.length > 1 ? "s" : ""} did not
      match anything in ${staleDays} days. Removing them keeps the policy small and easy to review; the history
      keeps them if you need one back.</p>
      <ul class="checklist">${stale.map((r) => `<li><label><input type="checkbox" value="${esc(r.id)}" checked>
        <code>${esc(match(r))}</code> <span class="muted">${r.last ? "last " + esc(fmtDate(r.last)) : "never matched"}${r.note ? " · " + esc(r.note) : ""}</span></label></li>`).join("")}</ul>
      <button id="usRemove" class="small danger">Remove selected</button>`;
    const btn = $("#usRemove");
    btn.onclick = confirmClick(btn, "Remove the selected unused rules?", async () => {
      const ids = $$("#usStale input:checked").map((i) => i.value);
      if (!ids.length) throw new Error("Nothing selected");
      const r = await gw("POST", "/rules/cleanup", { ids });
      toast(`${r.removed.length} unused rule${r.removed.length === 1 ? "" : "s"} removed`);
      await loadPolicy(true); await load();
      $("#usFilter").focus();
    });
  }
  function renderSuggestions(list) {
    const el = $("#sgList");
    el.innerHTML = list.length ? "<h4>Make it permanent?</h4>" : "";
    for (const s of list) {
      const card = document.createElement("div"); card.className = "suggest";
      const what = s.hosts.length > 1 ? `${s.hosts.length} hosts of <b>${esc(s.rule.host.slice(2))}</b> (${esc(s.hosts.join(", "))})` : `<b>${esc(s.hosts[0])}</b>`;
      card.innerHTML = `<p>You allowed ${what} on port ${esc(s.rule.port)} for a limited time ${esc(s.count)} times recently
        (last ${esc(fmtDate(s.last))}).</p><div class="btns"></div>`;
      const ok = document.createElement("button"); ok.className = "small";
      ok.textContent = `Allow ${s.rule.host}:${s.rule.port} permanently`;
      ok.onclick = guard(async () => { await gw("POST", "/suggestions/accept", { key: s.key }); toast(`Rule added: allow ${s.rule.host}:${s.rule.port}`); await loadPolicy(true); await load(); });
      const no = document.createElement("button"); no.className = "small secondary"; no.textContent = "Dismiss";
      no.setAttribute("aria-label", `Dismiss the suggestion for ${s.rule.host}:${s.rule.port}`);
      no.onclick = guard(async () => { await gw("POST", "/suggestions/dismiss", { key: s.key }); await load(); });
      $(".btns", card).append(ok, no); el.appendChild(card);
    }
  }
  async function load() {
    const [st, sg] = await Promise.all([gw("GET", "/rules/stats"), gw("GET", "/suggestions")]);
    rules = st.rules; staleDays = st.stale_days; loaded = true;
    renderSuggestions(sg.suggestions); renderStale(); renderTable();
    const n = sg.suggestions.length + rules.filter((r) => r.stale).length, badge = $("#usageBadge");
    badge.textContent = n; badge.title = `${n} to review`; badge.classList.toggle("hidden", !n);
  }
  $$("#usageBox button.sort").forEach((b) => (b.onclick = () => {
    sort = { key: b.dataset.key, dir: sort.key === b.dataset.key ? -sort.dir : b.dataset.key === "hits" || b.dataset.key === "last" ? -1 : 1 };
    renderTable();
  }));
  $("#usFilter").addEventListener("input", renderTable);
  $("#usShow").addEventListener("change", renderTable);
  $("#usRefresh").onclick = guard(load);
  document.addEventListener("tg:tab", (e) => { if (e.detail === "rules") guard(load)(); });
  document.addEventListener("tg:event", (e) => {
    if (loaded && ["policy", "resolved"].includes(e.detail.type) && !$("#tab-rules").classList.contains("hidden")) load().catch(() => {});
  });
})();
