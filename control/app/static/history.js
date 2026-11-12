"use strict";
/* Policy history (#71): versions with who/when/what, a diff between any two, restore, export and import.
   Uses the helpers of app.js ($, $$, esc, gw, toast, guard, confirmClick, fmtDate, portText, loadPolicy). */
(() => {
  const box = $("#historyBox");
  if (!box) return;
  box.innerHTML = `<p class="hint">Every change to the policy is kept as a version: from this UI, the API, approvals,
      templates and the emergency stop. Compare two versions or go back to one. The hard-deny floor and secrets
      are never part of a version.</p>
    <div class="row wrap">
      <label class="inline">From <select id="hiFrom"></select></label>
      <label class="inline">To <select id="hiTo"></select></label>
      <button id="hiDiff" class="secondary">Show changes</button>
    </div>
    <div id="hiDiffOut" class="diff hidden" role="region" aria-label="Changes between the versions" tabindex="-1"></div>
    <div class="table-wrap"><table class="history"><thead><tr><th>Version</th><th>When</th><th>By</th><th>What</th>
      <th>Mode</th><th>Rules</th><th><span class="sr-only">Actions</span></th></tr></thead><tbody id="hiBody"></tbody></table></div>
    <button id="hiMore" class="small secondary">Older versions</button>
    <h4>Export and import</h4>
    <p class="hint">One YAML file with the policy and the grants defined in the UI, to move a setup to another host
      or share it as a template. Secrets are not included. An import is checked like a normal policy change and
      shown before anything is replaced; the hard-deny floor stays as configured.</p>
    <div class="row wrap">
      <button id="hiExport" class="secondary">Export (YAML)</button>
      <label class="filebtn">Import from file&hellip;<input id="hiImport" type="file" accept=".yaml,.yml,text/yaml"></label>
    </div>
    <div id="hiImportOut" class="diff hidden" role="region" aria-label="Import preview"></div>`;

  let versions = [], loaded = false;

  function ruleText(r) {
    return `${r.action} ${r.host || r.cidr}${r.port !== undefined && r.port !== "*" ? ":" + portText(r.port) : ""}` +
      (r.note ? ` (${r.note})` : "") + (r.expires ? `, until ${fmtDate(r.expires)}` : "");
  }
  // A diff from the gateway ({default, ask_timeout, hard_deny, rules, reordered, identical}) as a list.
  function renderDiff(d) {
    if (d.identical) return '<p class="muted">No differences.</p>';
    const li = [];
    if (d.default) li.push(`<li>Mode <code>${esc(d.default[0])}</code> &rarr; <code>${esc(d.default[1])}</code></li>`);
    if (d.ask_timeout) li.push(`<li>Approval timeout ${esc(d.ask_timeout[0])} s &rarr; ${esc(d.ask_timeout[1])} s</li>`);
    if (d.hard_deny) {
      d.hard_deny.added.forEach((c) => li.push(`<li class="add">+ hard deny <code>${esc(c)}</code></li>`));
      d.hard_deny.removed.forEach((c) => li.push(`<li class="del">&minus; hard deny <code>${esc(c)}</code></li>`));
    }
    if (d.rules) {
      d.rules.added.forEach((r) => li.push(`<li class="add">+ rule <code>${esc(ruleText(r))}</code></li>`));
      d.rules.removed.forEach((r) => li.push(`<li class="del">&minus; rule <code>${esc(ruleText(r))}</code></li>`));
      d.rules.changed.forEach((c) => li.push(`<li class="chg">~ rule ${esc(c.id)}: <code>${esc(ruleText(c.before))}</code> &rarr; <code>${esc(ruleText(c.after))}</code></li>`));
    }
    if (d.reordered) li.push("<li>Rule order changed</li>");
    return `<ul>${li.join("")}</ul>`;
  }
  const label = (v) => `#${v.id} · ${fmtDate(v.ts)}`;
  function fillSelects() {
    const opts = versions.map((v) => `<option value="${v.id}">${esc(label(v))}</option>`).join("");
    const from = $("#hiFrom"), to = $("#hiTo"), f = from.value, t = to.value;
    from.innerHTML = opts; to.innerHTML = `<option value="current">current policy</option>${opts}`;
    if (f && versions.some((v) => String(v.id) === f)) from.value = f; else if (versions[1]) from.value = versions[1].id;
    if (t) to.value = t;
  }
  function row(v, i) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>#${esc(v.id)}${i === 0 ? ' <span class="tag">current</span>' : ""}</td><td>${esc(fmtDate(v.ts))}</td>
      <td>${esc(v.by)}</td><td>${esc(v.what)}</td><td>${esc(v.default)}</td><td>${esc(v.rules)}</td><td><div class="cellbtns"></div></td>`;
    const cell = $(".cellbtns", tr);
    const d = document.createElement("button"); d.className = "small secondary"; d.textContent = "Changes";
    d.setAttribute("aria-label", `Changes from version ${v.id} to the current policy`);
    d.onclick = guard(() => showDiff(v.id, "current"));
    cell.appendChild(d);
    if (i > 0) {
      const r = document.createElement("button"); r.className = "small"; r.textContent = "Restore";
      r.setAttribute("aria-label", `Restore version ${v.id}`);
      r.onclick = confirmClick(r, `Replace the current policy with version ${v.id} (${fmtDate(v.ts)})?`, async () => {
        await gw("POST", `/policy/history/${v.id}/restore`); toast(`Version ${v.id} restored`);
        await loadPolicy(true); await load();
      });
      cell.appendChild(r);
    }
    return tr;
  }
  async function load(older = false) {
    const before = older && versions.length ? `&before=${versions[versions.length - 1].id}` : "";
    const r = await gw("GET", `/policy/history?limit=50${before}`);
    versions = older ? versions.concat(r.versions) : r.versions;
    const body = $("#hiBody"); body.innerHTML = "";
    versions.forEach((v, i) => body.appendChild(row(v, i)));
    if (!versions.length) body.innerHTML = '<tr><td colspan="7" class="muted">No versions yet.</td></tr>';
    $("#hiMore").classList.toggle("hidden", r.versions.length < 50);
    fillSelects(); loaded = true;
    if (older && !r.versions.length) toast("No older versions");
  }
  async function showDiff(from, to) {
    const d = await gw("GET", `/policy/diff?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`);
    const out = $("#hiDiffOut");
    out.innerHTML = `<h4>Changes from #${esc(from)} to ${to === "current" ? "the current policy" : "#" + esc(to)}</h4>${renderDiff(d)}`;
    out.classList.remove("hidden"); out.focus();
  }
  $("#hiDiff").onclick = guard(() => showDiff($("#hiFrom").value, $("#hiTo").value));
  $("#hiMore").onclick = guard(() => load(true));
  $("#hiExport").onclick = guard(async () => {
    const r = await gw("GET", "/policy/export");
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([r.yaml], { type: "text/yaml" })); a.download = r.filename;
    document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 1000);
    toast(`Exported ${r.filename}`);
  });
  $("#hiImport").onchange = guard(async (e) => {
    const file = e.target.files[0]; e.target.value = "";
    if (!file) return;
    if (file.size > 512 * 1024) throw new Error("The file is too large for a policy export (max 512 KiB).");
    const text = await file.text();
    const out = $("#hiImportOut"); out.classList.remove("hidden");
    let r;
    try { r = await gw("POST", "/policy/import", { yaml: text }); } catch (err) {
      out.innerHTML = `<p class="bad">Not imported: ${esc(err.message)}</p>`; throw err;
    }
    const g = r.grants;
    out.innerHTML = `<h4>Import ${esc(file.name)}: what would change</h4>${renderDiff(r.diff)}
      ${g.added.length ? `<p>New UI grants: <code>${esc(g.added.join(", "))}</code></p>` : ""}
      ${g.changed.length ? `<p>Replaced UI grants: <code>${esc(g.changed.join(", "))}</code></p>` : ""}
      ${r.warnings.map((w) => `<p class="warn">${esc(w)}</p>`).join("")}
      <div class="btns"><button id="hiApply">Import</button><button id="hiCancel" class="secondary">Cancel</button></div>`;
    $("#hiCancel").onclick = () => { out.classList.add("hidden"); out.innerHTML = ""; $("#hiExport").focus(); };
    $("#hiApply").onclick = confirmClick($("#hiApply"), "Replace the current policy with this file?", async () => {
      await gw("POST", "/policy/import", { yaml: text, apply: true });
      out.classList.add("hidden"); out.innerHTML = ""; toast(`Imported ${file.name}`);
      await loadPolicy(true); await load(); $("#hiExport").focus();
    });
    $("#hiApply").focus();
  });
  const card = box.closest("details");
  card.addEventListener("toggle", () => { if (card.open) guard(load)(); });
  document.addEventListener("tg:event", (e) => { if (e.detail.type === "policy" && loaded && card.open) load().catch(() => {}); });
})();
