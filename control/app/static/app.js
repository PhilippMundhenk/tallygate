"use strict";
const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmtTime = (ts) => new Date(ts * 1000).toLocaleTimeString();
const fmtDate = (ts) => new Date(ts * 1000).toLocaleString();

async function api(method, path, body) {
  const r = await fetch(path, {
    method, headers: { "Content-Type": "application/json", "X-Sluicegate": "1" },
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
  const badge = $("#pendingCount"); badge.textContent = pending.length; badge.classList.toggle("hidden", !pending.length);
  document.title = pending.length ? `(${pending.length}) sluicegate` : "sluicegate";
  for (const p of pending) {
    const el = document.createElement("div"); el.className = "pending";
    el.innerHTML = `<div class="dest">${esc(p.host)}:${esc(p.port)}</div>
      <div class="meta">${esc(p.proto)} · IPs ${esc((p.ips || []).join(", ") || "-")} · attempts ${esc(p.attempts)} ·
      <span class="countdown" data-exp="${p.expires}"></span></div><div class="btns"></div>`;
    for (const [scope, label, cls] of SCOPES) {
      const b = document.createElement("button"); b.textContent = label; if (cls) b.className = cls;
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
  if (e.kind === "conn" && e.host && !String(e.reason).startsWith("hard-deny")) {
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
  if (!confirm("Change the hard-deny list? Removing entries can expose your LAN to the agent.")) return;
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
    if (ev.type === "ask" && document.hidden && Notification?.permission === "granted") new Notification("sluicegate: approval needed", { body: `${ev.pending.host}:${ev.pending.port}` });
    if (ev.type === "policy" && !$("#tab-rules").classList.contains("hidden")) loadPolicy().catch(() => {});
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
  connectStream();
  showTab(location.hash.slice(1) || "approvals");
})();
