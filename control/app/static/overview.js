"use strict";
/* Overview tab (#68): what the agent is doing, what needs attention soon, the last hour, shortcuts.
   Uses the helpers and the live `pending` / `grants` state of app.js. Agent data is escaped like everything else. */
const ov = { policy: null, secrets: null, gh: null, timer: null };
const HOUR = 3600;
const ovVisible = () => !$("#tab-overview").classList.contains("hidden");
function fmtBytes(n) {
  if (!Number.isFinite(n)) return "?";
  const u = ["B", "KB", "MB", "GB", "TB"]; let i = 0;
  while (n >= 1000 && i < u.length - 1) { n /= 1000; i++; }
  return `${n >= 10 || i === 0 ? Math.round(n) : n.toFixed(1)} ${u[i]}`;
}
function diskText(d) {
  if (!d || !d.total) return { html: "unknown", warn: false };
  const p = Math.round((d.used / d.total) * 100);
  return { html: `${fmtBytes(d.used)} of ${fmtBytes(d.total)} used (${p} %)`, warn: p >= 90 };
}
const dest = (x) => `${esc(x.host)}:${esc(x.port)}`;

async function loadOverview() {
  const q = (p) => p.then((v) => ({ ok: true, v }), (e) => ({ ok: false, e }));
  const [st, info, pol, sum, sec] = await Promise.all([
    q(api("GET", "/api/agent/status")), q(gw("GET", "/info")), q(gw("GET", "/policy")),
    q(gw("GET", "/events/summary")), q(gw("GET", "/secrets")),
  ]);
  ov.policy = pol.ok ? pol.v : null; ov.secrets = sec.ok ? sec.v.names : null;
  renderOvStatus(st, info); renderOvAttention(); renderOvHour(sum);
  if (ov.secrets && ov.secrets.includes("github_token") && !ov.gh) checkGithub().catch(() => {});
}
tabHooks.overview = loadOverview;
setInterval(() => { if (ovVisible() && !document.hidden) loadOverview().catch(() => {}); }, 30000);
// Requests come and go live: the attention list follows the state app.js keeps (after it has reloaded it).
window.addEventListener("tg:event", (e) => {
  if (!ovVisible() || !["ask", "resolved", "grant_request", "grant_resolved", "grants", "policy"].includes(e.detail.type)) return;
  clearTimeout(ov.timer); ov.timer = setTimeout(() => loadOverview().catch(() => {}), 1500);
});

function row(label, html, cls = "") { return `<dt>${esc(label)}</dt><dd class="${cls}">${html}</dd>`; }
function renderOvStatus(st, info) {
  let h = "";
  if (st.ok) {
    const s = st.v;
    h += row("Claude", s.claude_logged_in ? "✔ logged in" : '✖ not logged in · <button class="small secondary" data-ov-tab="setup">Setup</button>', s.claude_logged_in ? "ok" : "bad");
    const rc = s.remote_control_enabled === false ? ["switched off (RC_ENABLE=0)", "muted"]
      : s.remote_control_prompt ? [`⚠ waiting for an answer: <code>${esc(s.remote_control_prompt)}</code>`, "warn"]
      : s.remote_control_running ? [`✔ running as <b>${esc(s.remote_control_name || "")}</b>`, "ok"] : ["✖ not running", "bad"];
    h += row("Remote Control", rc[0], rc[1]);
    h += row("Claude Code", esc(String(s.claude_version || "?").replace(/\s*\(Claude Code\)$/, "")));
    const ws = diskText(s.workspace_disk);
    h += row("Workspace disk", (ws.warn ? "⚠ " : "") + ws.html, ws.warn ? "warn" : "");
  } else h += row("Agent", `✖ ${esc(st.e.message)}`, "bad");
  if (info.ok) {
    const i = info.v, gd = diskText(i.data_disk);
    h += row("Gateway", `✔ healthy · ${esc(i.pending)} waiting`, "ok");
    h += row("Gateway state disk", `${gd.warn ? "⚠ " : ""}${gd.html} · event log ${fmtBytes(i.events_db_bytes)}`, gd.warn ? "warn" : "");
  } else h += row("Gateway", `✖ ${esc(info.e.message)}`, "bad");
  $("#ovStatus").innerHTML = h;
}

async function checkGithub() {
  ov.gh = { checking: true }; renderOvAttention();
  try { ov.gh = await api("GET", "/api/agent/setup/git-identity"); } catch (e) { ov.gh = { ok: false, message: e.message }; }
  renderOvAttention();
}
function renderOvAttention() {
  const now = Date.now() / 1000, items = [];
  const add = (cls, html, tab, label) => items.push(`<li class="${cls}">${html}${tab ? ` <button class="small secondary" data-ov-tab="${tab}">${esc(label)}</button>` : ""}</li>`);
  if (pending.length) add("warn", `⚠ <b>${pending.length}</b> connection request${pending.length > 1 ? "s" : ""} waiting`, "approvals", "Approvals");
  if (grants.requests.length) add("warn", `⚠ <b>${grants.requests.length}</b> grant request${grants.requests.length > 1 ? "s" : ""} waiting`, "approvals", "Approvals");
  for (const r of (ov.policy?.rules || []).filter((r) => r.expires && r.expires > now && r.expires - now < HOUR))
    add("", `Rule <code>${esc(r.action)} ${esc(r.host || r.cidr)}</code>${r.source && r.source !== "user" ? ` <span class="muted">[${esc(r.source)}]</span>` : ""} ends in ${fmtLeft(r.expires)}`, "rules", "Rules");
  for (const a of grants.active.filter((a) => a.expires - now < HOUR))
    add("", `Grant <b>${esc(a.name)}</b> (${esc(a.level)}) ends in ${fmtLeft(a.expires)}`, "grants", "Grants");
  if (ov.secrets && !ov.secrets.includes("github_token")) add("warn", "⚠ No GitHub token stored", "setup", "Setup");
  else if (ov.gh && ov.gh.checking) add("muted", "Checking the GitHub token…");
  else if (ov.gh && !ov.gh.ok) add("warn", `⚠ GitHub token: ${esc(ov.gh.message)}`, "setup", "Setup");
  else if (ov.gh && ov.gh.token_expires) {
    const exp = Date.parse(ov.gh.token_expires.replace(" UTC", "Z").replace(" ", "T"));
    if (Number.isFinite(exp) && exp / 1000 - now < 7 * 86400) add("warn", `⚠ The GitHub token expires ${esc(ov.gh.token_expires)}`, "setup", "Setup");
  }
  $("#ovAttention").innerHTML = items.join("") || '<li class="ok">✔ Nothing needs your attention.</li>';
}

function renderOvHour(sum) {
  if (!sum.ok) { $("#ovCounts").textContent = sum.e.message; return; }
  const s = sum.v, c = s.counts;
  $("#ovCounts").innerHTML = `<span class="a-allow">${esc(c.allow)} allowed</span> · <span class="a-deny">${esc(c.deny)} denied</span> · <span class="a-ask">${esc(c.ask)} asked</span>`;
  $("#ovTop").innerHTML = s.top.map((t) => `<tr><td><code>${dest(t)}</code></td><td>${esc(t.count)}</td><td><span class="a-allow">${esc(t.allow)}</span> / <span class="a-deny">${esc(t.deny)}</span></td></tr>`).join("")
    || '<tr><td colspan="3" class="muted">No connections in the last hour.</td></tr>';
  $("#ovNew").innerHTML = s.new.map((n) => `<li><code>${dest(n)}</code> <span class="muted">first seen ${esc(fmtTime(n.first))}</span></li>`).join("")
    || '<li class="muted">None in the last hour.</li>';
}

/* ---- actions ---- */
$("#tab-overview").addEventListener("click", (e) => {
  const b = e.target.closest("[data-ov-tab]"); if (b) showTab(b.dataset.ovTab);
});
$("#ovLog").onclick = () => showTab("log");
$("#ovConsole").onclick = () => openTerm("rc");
$("#ovWeb").onclick = guard(async () => {
  const r = await gw("POST", "/presets/open", { ttl: 900 });
  toast(`Web (HTTP/HTTPS) allowed${r && r.expires ? ` for ${fmtLeft(r.expires)}` : ""}`);
  await loadOverview();
});
$("#ovStop").onclick = confirmClick($("#ovStop"), "Revoke all grants, deny everything pending, undo the internet shortcuts and block everything unknown?", async () => {
  const r = await gw("POST", "/emergency-stop", {});
  toast(r.ok ? "Emergency stop: unknown destinations are blocked" : "Emergency stop incomplete: see Rules → Quick actions", !r.ok);
  if (typeof showStopResult === "function") showStopResult(r);
  await Promise.allSettled([loadPending(), loadGrants(), loadOverview()]);
});
