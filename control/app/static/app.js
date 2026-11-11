"use strict";
const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmtTime = (ts) => new Date(ts * 1000).toLocaleTimeString();
const fmtDate = (ts) => new Date(ts * 1000).toLocaleString();

async function api(method, path, body) {
  const r = await fetch(path, {
    method, headers: { "Content-Type": "application/json", "X-Tallygate": "1" },
    body: body === undefined ? undefined : JSON.stringify(body), credentials: "same-origin",
  });
  if (r.status === 401) { location.href = "/login"; throw new Error("login required"); }
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || `HTTP ${r.status}`);
  return data;
}
const gw = (method, sub, body) => api(method, "/api/gw" + sub, body);

function toast(msg, bad = false) {
  const t = $("#toast"); t.textContent = msg; t.style.display = "block"; t.style.color = bad ? "#fca5a5" : "";
  clearTimeout(toast._t); toast._t = setTimeout(() => (t.style.display = "none"), 4000);
}
const guard = (fn) => async (...a) => { try { await fn(...a); } catch (e) { toast(e.message, true); } };

/* ---------------- tabs ---------------- */
function showTab(name) {
  $$("main > section").forEach((s) => s.classList.toggle("hidden", s.id !== "tab-" + name));
  $$("#tabs button").forEach((b) => b.classList.toggle("active", b.dataset.tab === name));
  history.replaceState(null, "", "#" + name);
  if (name === "rules") loadPolicy();
  if (name === "grants") { loadGrants(); loadSecrets(); }
  if (name === "setup") loadSetup();
  if (name === "log" && !$("#logBody").children.length) loadLog();
}
$$("#tabs button").forEach((b) => b.addEventListener("click", () => showTab(b.dataset.tab)));

/* ---------------- approvals ---------------- */
const SCOPES = [["once", "Allow 2 min", ""], ["hour", "Allow 1 h", ""], ["always", "Always (host)", ""],
  ["domain", "Always (*.domain)", ""], ["deny", "Deny", "secondary"], ["deny_always", "Block forever", "danger"]];
let pending = [];
async function loadPending() {
  pending = await gw("GET", "/pending");
  renderPending();
}
function renderPending() {
  const list = $("#pendingList"); list.innerHTML = "";
  $("#pendingEmpty").classList.toggle("hidden", pending.length > 0);
  updateBadges();
  for (const p of pending) {
    const el = document.createElement("div"); el.className = "pending";
    // Host names are chosen by the agent: show the registrable domain separately (look-alikes such as
    // github.com.evil.example) and warn about punycode names.
    el.innerHTML = `<div class="dest">${esc(p.host)}:${esc(p.port)}</div>
      ${p.domain && p.domain !== p.host ? `<div class="meta">domain <b>${esc(p.domain)}</b></div>` : ""}
      ${p.idn ? `<div class="meta warn">⚠ internationalised (punycode) name – check for look-alikes</div>` : ""}
      <div class="meta">${esc(p.proto)} · IPs ${esc((p.ips || []).join(", ") || "not resolved yet")} · attempts ${esc(p.attempts)} ·
      <span class="countdown" data-exp="${Number(p.expires)}"></span></div><div class="btns"></div>`;
    for (const [scope, label, cls] of SCOPES) {
      if (scope === "domain" && !p.domain) continue;  // no registrable domain (IP, public suffix)
      const b = document.createElement("button"); if (cls) b.className = cls;
      b.textContent = scope === "domain" ? `Always (*.${p.domain})` : label;
      b.onclick = guard(async () => { await gw("POST", `/pending/${p.id}/decide`, { scope }); await loadPending(); });
      $(".btns", el).appendChild(b);
    }
    list.appendChild(el);
  }
  tickCountdowns();
}
function tickCountdowns() {
  const now = Date.now() / 1000;
  $$(".countdown").forEach((c) => { const s = Math.max(0, Math.round(c.dataset.exp - now)); c.textContent = `auto-deny in ${s}s`; });
}
setInterval(tickCountdowns, 1000);

/* ---------------- log ---------------- */
let oldestId = null;
function logRow(e) {
  const tr = document.createElement("tr");
  const dest = `${e.host ?? ""}${e.port ? ":" + e.port : ""}`;
  tr.dataset.kind = e.kind; tr.dataset.action = e.action;
  tr.dataset.text = `${dest} ${e.action} ${e.reason}`.toLowerCase();
  tr.innerHTML = `<td title="${esc(fmtDate(e.ts))}">${esc(fmtTime(e.ts))}</td><td>${esc(e.kind)}</td><td>${esc(e.proto ?? "")}</td>
    <td><code>${esc(dest)}</code>${e.ips && e.ips.length ? `<br><span class="muted">${esc(e.ips.join(", "))}</span>` : ""}</td>
    <td class="a-${esc(e.action)}">${esc(e.action)}</td><td>${esc(e.reason)}</td><td></td>`;
  const reason = String(e.reason);
  if (e.kind === "conn" && e.host && !reason.startsWith("hard-deny") && reason !== "invalid hostname") {
    const cell = tr.lastElementChild;
    for (const [action, label, cls] of [["allow", "allow", "small"], ["deny", "deny", "small secondary"]]) {
      const b = document.createElement("button"); b.textContent = label; b.className = cls;
      b.onclick = guard(async () => {
        await gw("POST", "/rules", { action, host: e.host, port: e.port, note: "from log" }); toast(`${action} rule added for ${dest}`);
      });
      cell.appendChild(b);
    }
  }
  applyLogFilter(tr);
  return tr;
}
function applyLogFilter(tr) {
  const f = $("#logFilter").value.toLowerCase();
  const hide = (f && !tr.dataset.text.includes(f)) || ($("#logHideDns").checked && tr.dataset.kind === "dns") ||
    ($("#logOnlyBlocked").checked && tr.dataset.action !== "deny");
  tr.classList.toggle("hidden", !!hide);
}
async function loadLog(older = false) {
  const q = older && oldestId ? `?limit=200&before=${oldestId}` : "?limit=200";
  const rows = await gw("GET", "/events" + q);
  if (!older) $("#logBody").innerHTML = "";
  for (const e of rows) { $("#logBody").appendChild(logRow(e)); oldestId = e.id; }
}
["#logFilter", "#logHideDns", "#logOnlyBlocked"].forEach((s) => $(s).addEventListener("input", () => $$("#logBody tr").forEach(applyLogFilter)));
$("#logMore").onclick = guard(() => loadLog(true));

/* ---------------- rules ---------------- */
let policy = null;
function portText(p) { return p === undefined || p === "*" ? "*" : Array.isArray(p) ? p.join(",") : String(p); }
function parsePort(s) {
  s = (s || "").trim(); if (!s || s === "*") return "*";
  if (s.includes(",")) return s.split(",").map((x) => (x.includes("-") ? x.trim() : parseInt(x, 10)));
  return s.includes("-") ? s : parseInt(s, 10);
}
async function loadPolicy() {
  policy = await gw("GET", "/policy");
  $("#defaultAction").value = policy.default; $("#askTimeout").value = policy.ask_timeout;
  $("#hardDenyFloor").textContent = (policy.hard_deny_floor || []).join("  ");
  $("#hardDeny").value = policy.hard_deny.join("\n");
  $("#rawPolicy").value = JSON.stringify(policy, null, 2);
  const body = $("#rulesBody"); body.innerHTML = "";
  policy.rules.forEach((r, i) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${i + 1}</td><td class="a-${esc(r.action)}">${esc(r.action)}</td><td><code>${esc(r.host || r.cidr)}</code></td>
      <td>${esc(portText(r.port))}</td><td>${esc(r.note || "")}${r.source ? ` <span class="muted">[${esc(r.source)}]</span>` : ""}</td>
      <td>${r.expires ? esc(fmtDate(r.expires)) : "–"}</td><td></td>`;
    const b = document.createElement("button"); b.textContent = "delete"; b.className = "small secondary";
    b.onclick = guard(async () => { await gw("DELETE", `/rules/${r.id}`); await loadPolicy(); });
    tr.lastElementChild.appendChild(b); body.appendChild(tr);
  });
  const presets = await gw("GET", "/presets");
  $("#presetSel").innerHTML = presets.map((p) => `<option>${esc(p)}</option>`).join("");
}
async function putPolicy(p) { await gw("PUT", "/policy", p); toast("Policy saved"); await loadPolicy(); }
$("#saveMode").onclick = guard(() => putPolicy({ ...policy, default: $("#defaultAction").value, ask_timeout: +$("#askTimeout").value }));
$("#saveHard").onclick = guard(() => {
  return putPolicy({ ...policy, hard_deny: $("#hardDeny").value.split(/\s+/).filter(Boolean) });
});
$("#saveRaw").onclick = guard(() => putPolicy(JSON.parse($("#rawPolicy").value)));
$("#nrAdd").onclick = guard(async () => {
  const rule = { action: $("#nrAction").value, [$("#nrKind").value]: $("#nrMatch").value.trim(), port: parsePort($("#nrPort").value) };
  if ($("#nrNote").value) rule.note = $("#nrNote").value;
  if (+$("#nrTtl").value > 0) rule.expires = Date.now() / 1000 + +$("#nrTtl").value;
  await gw("POST", "/rules", rule); $("#nrMatch").value = ""; await loadPolicy();
});
$("#testBtn").onclick = guard(async () => {
  const r = await gw("POST", "/test", { host: $("#testHost").value.trim(), port: +$("#testPort").value || 443 });
  $("#testOut").textContent = `${r.action.toUpperCase()} — ${r.reason}\nIPs: ${(r.ips || []).join(", ")}`;
});
$("#presetBtn").onclick = guard(async () => {
  const ttl = +$("#presetTtl").value; await gw("POST", `/presets/${$("#presetSel").value}`, ttl ? { ttl } : {});
  toast("Preset applied"); await loadPolicy();
});

/* ---------------- grants ---------------- */
let grants = { defs: [], active: [], requests: [], lan_allow_ui: [], missing_secrets: {} };
const fmtLeft = (exp) => { const s = Math.max(0, Math.round(exp - Date.now() / 1000)); return s > 5400 ? `${Math.round(s / 3600)} h` : s > 90 ? `${Math.round(s / 60)} min` : `${s} s`; };
async function loadGrants() {
  grants = await gw("GET", "/grants");
  renderGrantRequests(); renderGrants();
}
function grantTargets(d) {
  return d.targets.map((t) => `<code>${esc(t.scheme)}://${esc(t.host)}:${esc(t.port)}${t.paths && t.paths.join(",") !== "/*" ? esc(" " + t.paths.join(",")) : ""}</code>${t.lan ? ' <span class="tag warn">LAN</span>' : ""}`).join("<br>");
}
function renderGrantRequests() {
  const box = $("#grantReqList"); box.innerHTML = "";
  $("#grantReqBox").classList.toggle("hidden", !grants.requests.length);
  for (const r of grants.requests) {
    const d = grants.defs.find((x) => x.name === r.name) || { targets: [], levels: [], description: "" };
    const el = document.createElement("div"); el.className = "pending grantreq";
    el.innerHTML = `<div class="dest">🔑 ${esc(r.name)} <span class="tag ${r.level === "write" ? "warn" : ""}">${esc(r.level)}</span> for ${esc(r.ttl_label)}</div>
      <div class="meta">${esc(d.description)}</div><div class="meta">${grantTargets(d)}</div>
      <div class="meta">Agent's reason: <i>${esc(r.reason || "(none given)")}</i></div>
      <div class="meta"><span class="countdown" data-exp="${Number(r.expires)}"></span></div><div class="btns"></div>`;
    const btn = (label, decision, cls = "") => {
      const b = document.createElement("button"); b.textContent = label; if (cls) b.className = cls;
      b.onclick = guard(async () => { await gw("POST", `/grant-requests/${r.id}/decide`, { decision }); await loadGrants(); });
      $(".btns", el).appendChild(b);
    };
    btn(`Approve ${r.level} (${r.ttl_label})`, "approve");
    if (r.level === "write" && d.levels.includes("read")) btn("Approve read-only", "read", "secondary");
    btn("Deny", "deny", "danger");
    box.appendChild(el);
  }
  updateBadges(); tickCountdowns();
}
function renderGrants() {
  const act = $("#activeGrants"); act.innerHTML = "";
  $("#activeEmpty").classList.toggle("hidden", grants.active.length > 0);
  for (const a of grants.active) {
    const el = document.createElement("div"); el.className = "card row-between";
    el.innerHTML = `<div><b>${esc(a.name)}</b> <span class="tag ${a.level === "write" ? "warn" : ""}">${esc(a.level)}</span>
      <span class="muted">· expires in <span class="left" data-exp="${Number(a.expires)}">${fmtLeft(a.expires)}</span> · by ${esc(a.approved_by)}${a.reason ? ` · “${esc(a.reason)}”` : ""}</span></div>`;
    const b = document.createElement("button"); b.textContent = "Revoke"; b.className = "danger small";
    b.onclick = guard(async () => { await gw("DELETE", `/active-grants/${a.id}`); await loadGrants(); });
    el.appendChild(b); act.appendChild(el);
  }
  const defs = $("#grantDefs"); defs.innerHTML = "";
  for (const d of grants.defs) {
    const missing = grants.missing_secrets[d.name] || [];
    const appr = d.levels.map((l) => `${l}: ${d.approval[l]}`).join(" · ");
    const el = document.createElement("div"); el.className = "card";
    el.innerHTML = `<div class="row-between"><div><b>${esc(d.name)}</b> <span class="tag">${esc(d.source)}</span>
      <span class="muted">${esc(d.description)}</span></div><div class="btns"></div></div>
      <div class="meta">${grantTargets(d)}</div>
      <div class="meta muted">levels ${esc(appr)} · default ${esc(d.default_ttl)}, max ${esc(d.max_ttl)}${d.inject.length ? ` · injects ${esc(d.inject.map((i) => i.header + "@" + i.host).join(", "))}` : ""}</div>
      ${missing.length ? `<div class="meta warn">⚠ missing secret(s): ${esc(missing.join(", "))}</div>` : ""}`;
    const btns = $(".btns", el);
    for (const lvl of d.levels) {
      const b = document.createElement("button"); b.className = "small"; b.textContent = `Activate ${lvl}`;
      b.onclick = guard(async () => { await gw("POST", `/grants/${d.name}/activate`, { level: lvl }); toast(`${d.name} (${lvl}) active for ${d.default_ttl}`); await loadGrants(); });
      btns.appendChild(b);
    }
    if (d.source === "ui") {
      const e = document.createElement("button"); e.className = "small secondary"; e.textContent = "Edit"; e.onclick = () => openGrantEditor(d); btns.appendChild(e);
      const x = document.createElement("button"); x.className = "small danger"; x.textContent = "Delete";
      x.onclick = guard(async () => { if (!confirm(`Delete grant ${d.name}?`)) return; await gw("DELETE", `/grants/${d.name}`); await loadGrants(); });
      btns.appendChild(x);
    }
    defs.appendChild(el);
  }
  $("#geLanAllow").textContent = grants.lan_allow_ui.join(", ") || "nothing (set grants_lan_allow in the config file)";
  updateBadges();
}
function updateBadges() {
  const n = pending.length + grants.requests.length;
  const badge = $("#pendingCount"); badge.textContent = n; badge.classList.toggle("hidden", !n);
  document.title = n ? `(${n}) tallygate` : "tallygate";
  const a = $("#grantActiveCount"); a.textContent = grants.active.length; a.classList.toggle("hidden", !grants.active.length);
}
setInterval(() => $$(".left").forEach((x) => (x.textContent = fmtLeft(Number(x.dataset.exp)))), 15000);

function targetRow(t = { scheme: "https", host: "", port: 443, paths: ["/*"] }) {
  const row = document.createElement("div"); row.className = "target-row";
  row.innerHTML = `<select class="t-scheme"><option>https</option><option>http</option><option>tcp</option></select>
    <input class="t-host" placeholder="ha.lan or 192.168.1.5"><input class="t-port" type="number" min="1" max="65535">
    <input class="t-paths" placeholder="paths, e.g. /api/*"><label><input type="checkbox" class="t-lan"> LAN</label>
    <input class="t-address" placeholder="fixed IP (optional)"><input class="t-fp" placeholder="SHA-256 cert fingerprint (optional)">
    <label title="only for https without fingerprint"><input type="checkbox" class="t-verify" checked> verify TLS</label>
    <button class="small secondary t-del">✕</button>`;
  $(".t-scheme", row).value = t.scheme; $(".t-host", row).value = t.host; $(".t-port", row).value = t.port;
  $(".t-paths", row).value = (t.paths || ["/*"]).join(", "); $(".t-lan", row).checked = !!t.lan;
  $(".t-address", row).value = t.address || ""; $(".t-fp", row).value = t.tls_fingerprint || ""; $(".t-verify", row).checked = t.tls_verify !== false;
  $(".t-del", row).onclick = () => row.remove();
  return row;
}
function injectRow(i = { host: "", header: "Authorization", value: "Bearer ${token_name}" }) {
  const row = document.createElement("div"); row.className = "inject-row";
  row.innerHTML = `<input class="i-host" placeholder="host (an https target)"><input class="i-header" placeholder="header">
    <input class="i-value" placeholder="value template, e.g. Bearer \${ha_token}"><button class="small secondary i-del">✕</button>`;
  $(".i-host", row).value = i.host; $(".i-header", row).value = i.header; $(".i-value", row).value = i.value;
  $(".i-del", row).onclick = () => row.remove();
  return row;
}
function openGrantEditor(d) {
  const ed = $("#grantEditor"); ed.classList.remove("hidden");
  $("#geTitle").textContent = d ? `Edit grant ${d.name}` : "New grant";
  $("#geName").value = d ? d.name : ""; $("#geName").disabled = !!d;
  $("#geDesc").value = d ? d.description : "";
  $("#geRead").checked = d ? d.levels.includes("read") : true; $("#geWrite").checked = d ? d.levels.includes("write") : false;
  $("#geApprRead").value = d?.approval?.read || "ask"; $("#geApprWrite").value = d?.approval?.write || "ask";
  $("#geTtl").value = d ? d.default_ttl : "1h"; $("#geMaxTtl").value = d ? d.max_ttl : "4h";
  $("#geTargets").innerHTML = ""; (d ? d.targets : [undefined]).forEach((t) => $("#geTargets").appendChild(targetRow(t)));
  $("#geInject").innerHTML = ""; (d ? d.inject : []).forEach((i) => $("#geInject").appendChild(injectRow(i)));
  ed.scrollIntoView({ behavior: "smooth" });
}
$("#grantNew").onclick = () => openGrantEditor(null);
$("#geAddTarget").onclick = () => $("#geTargets").appendChild(targetRow());
$("#geAddInject").onclick = () => $("#geInject").appendChild(injectRow());
$("#geCancel").onclick = () => $("#grantEditor").classList.add("hidden");
$("#geSave").onclick = guard(async () => {
  const name = $("#geName").value.trim();
  const levels = [["read", "#geRead"], ["write", "#geWrite"]].filter(([, id]) => $(id).checked).map(([l]) => l);
  const approval = {}; if (levels.includes("read")) approval.read = $("#geApprRead").value; if (levels.includes("write")) approval.write = $("#geApprWrite").value;
  const targets = $$("#geTargets .target-row").map((r) => {
    const t = { scheme: $(".t-scheme", r).value, host: $(".t-host", r).value.trim(), port: Number($(".t-port", r).value) };
    if (t.scheme !== "tcp") t.paths = $(".t-paths", r).value.split(",").map((x) => x.trim()).filter(Boolean);
    if ($(".t-lan", r).checked) t.lan = true;
    if ($(".t-address", r).value.trim()) t.address = $(".t-address", r).value.trim();
    if ($(".t-fp", r).value.trim()) t.tls_fingerprint = $(".t-fp", r).value.trim();
    if (t.scheme === "https" && !$(".t-verify", r).checked && !t.tls_fingerprint) t.tls_verify = false;
    return t;
  });
  const inject = $$("#geInject .inject-row").map((r) => ({ host: $(".i-host", r).value.trim(), header: $(".i-header", r).value.trim(), value: $(".i-value", r).value }));
  const body = { description: $("#geDesc").value.trim(), levels, approval, default_ttl: $("#geTtl").value.trim(), max_ttl: $("#geMaxTtl").value.trim(), targets, inject };
  if (targets.some((t) => t.tls_verify === false) && !confirm("TLS verification is disabled for a target. Anyone on that network path could impersonate it. Prefer pinning the certificate fingerprint. Save anyway?")) return;
  await gw("PUT", `/grants/${encodeURIComponent(name)}`, body);
  $("#grantEditor").classList.add("hidden"); toast(`Grant ${name} saved`); await loadGrants();
});

async function loadSecrets() {
  const sec = await gw("GET", "/secrets"); const list = $("#secretList"); list.innerHTML = "";
  for (const n of sec.names) {
    const row = document.createElement("div"); row.className = "row-between";
    row.innerHTML = `<code>${esc(n)}</code>`;
    const b = document.createElement("button"); b.className = "small danger"; b.textContent = "Remove";
    b.onclick = guard(async () => { if (!confirm(`Remove secret ${n}?`)) return; await gw("PUT", `/secrets/${n}`, { value: "" }); await loadSecrets(); });
    row.appendChild(b); list.appendChild(row);
  }
  if (!sec.names.length) list.innerHTML = '<p class="muted">No secrets stored.</p>';
}
$("#secSave").onclick = guard(async () => {
  const name = $("#secName").value.trim(), value = $("#secValue").value;
  if (!name || !value) return;
  await gw("PUT", `/secrets/${encodeURIComponent(name)}`, { value });
  $("#secName").value = ""; $("#secValue").value = ""; toast(`Secret ${name} stored`); await loadSecrets(); await loadGrants();
});

/* ---------------- console ---------------- */
function openTerm(name) {
  showTab("console"); $("#termFrame").src = `/term/${encodeURIComponent(name)}/`;
  $$("#termButtons button").forEach((b) => b.classList.toggle("secondary", b.dataset.name !== name));
}

/* ---------------- setup ---------------- */
function setStatus(id, html, cls = "") { const s = $(`#${id} .status`); s.className = "status " + cls; s.innerHTML = html; }
async function loadSetup() {
  try {
    const info = await gw("GET", "/info"); const sec = await gw("GET", "/secrets");
    setStatus("st-gw", `${info.ca_pem ? "✔ CA exported" : "✖ CA missing"} · injection for <code>${esc(info.inject_hosts.join(", ") || "none")}</code> · pending ${info.pending}`, info.ca_pem ? "ok" : "bad");
    const needed = info.inject_secrets_needed.filter((n) => !sec.names.includes(n));
    setStatus("st-gh", sec.names.includes("github_token") ? "✔ github_token stored in gateway" : "✖ no token stored", sec.names.includes("github_token") ? "ok" : "warn");
    if (needed.length && !needed.includes("github_token")) toast(`Missing secrets: ${needed.join(", ")}`, true);
  } catch (e) { setStatus("st-gw", esc(e.message), "bad"); }
  try {
    const st = await api("GET", "/api/agent/status");
    setStatus("st-claude", st.claude_logged_in ? "✔ credentials present" : "✖ not logged in", st.claude_logged_in ? "ok" : "warn");
    setStatus("st-git", st.git_name ? `✔ ${esc(st.git_name)} &lt;${esc(st.git_email)}&gt;` : "✖ not set", st.git_name ? "ok" : "warn");
    setStatus("st-rc", st.remote_control_running ? `✔ running (${esc(st.claude_version || "")})` : "✖ not running", st.remote_control_running ? "ok" : "warn");
  } catch (e) { ["st-claude", "st-git", "st-rc"].forEach((id) => setStatus(id, esc(e.message), "bad")); }
  const meta = await api("GET", "/api/meta");
  $("#notifyStatus").textContent = `Telegram: ${meta.notify.telegram ? "configured" : "off"} · Matrix: ${meta.notify.matrix ? "configured" : "off"} (configure via environment)`;
}
$("#ghSave").onclick = guard(async () => {
  const token = $("#ghToken").value.trim(); if (!token) return;
  const r = await api("POST", "/api/github/check", { token, store: true });
  $("#ghToken").value = "";
  if (!r.ok) return setStatus("st-gh", `✖ GitHub says ${esc(r.status)}: ${esc(r.message)}`, "bad");
  setStatus("st-gh", `✔ valid for <b>${esc(r.login)}</b>${r.expires ? ` · expires ${esc(r.expires)}` : ""}${r.scopes ? ` · scopes ${esc(r.scopes)}` : " · fine-grained"} · ${r.stored ? "stored in gateway" : "NOT stored"}`, r.stored ? "ok" : "bad");
});
$("#ghRemove").onclick = guard(async () => { await gw("PUT", "/secrets/github_token", { value: "" }); loadSetup(); });
$("#selftestBtn").onclick = guard(async () => {
  setStatus("st-test", "running… (up to a minute)");
  const r = await api("GET", "/api/agent/selftest");
  const rows = r.results.map((t) => `<tr><td class="${t.pass ? "ok" : "bad"}">${t.pass ? "PASS" : "FAIL"}</td><td>${esc(t.name)}</td><td class="muted">${esc(t.detail)}</td></tr>`).join("");
  setStatus("st-test", `<table class="results">${rows}</table>`, r.results.every((t) => t.pass) ? "ok" : "bad");
});
$$(".wizard [data-term]").forEach((b) => (b.onclick = () => openTerm(b.dataset.term)));
$$("pre.copy").forEach((p) => (p.onclick = () => navigator.clipboard.writeText(p.textContent).then(() => toast("Copied"))));

/* ---------------- live stream ---------------- */
function connectStream() {
  const es = new EventSource("/api/stream");
  es.onopen = () => $("#conn").classList.add("ok");
  es.onerror = () => { $("#conn").classList.remove("ok"); };
  es.onmessage = (m) => {
    const ev = JSON.parse(m.data);
    if (ev.type === "event") { const body = $("#logBody"); body.insertBefore(logRow(ev.event), body.firstChild); while (body.children.length > 2000) body.lastChild.remove(); }
    if (ev.type === "ask" || ev.type === "resolved") loadPending().catch(() => {});
    if (ev.type === "ask" && document.hidden && Notification?.permission === "granted") new Notification("tallygate: approval needed", { body: `${ev.pending.host}:${ev.pending.port}` });
    if (ev.type === "policy" && !$("#tab-rules").classList.contains("hidden")) loadPolicy().catch(() => {});
    if (["grant_request", "grant_resolved", "grants"].includes(ev.type)) loadGrants().catch(() => {});
    if (ev.type === "grant_request" && document.hidden && Notification?.permission === "granted") new Notification("tallygate: grant requested", { body: `${ev.request.name} (${ev.request.level})` });
  };
}

/* ---------------- init ---------------- */
(async () => {
  const meta = await api("GET", "/api/meta");
  for (const name of meta.terminals) {
    const b = document.createElement("button"); b.textContent = name; b.dataset.name = name; b.className = "secondary";
    b.onclick = () => openTerm(name); $("#termButtons").appendChild(b);
  }
  if ("Notification" in window && Notification.permission === "default") Notification.requestPermission().catch(() => {});
  await loadPending().catch((e) => toast(e.message, true));
  await loadGrants().catch((e) => toast(e.message, true));
  connectStream();
  showTab(location.hash.slice(1) || "approvals");
})();
