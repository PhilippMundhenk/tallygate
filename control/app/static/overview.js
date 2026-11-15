"use strict";
/* Overview tab (#68): what the agent is doing, what needs attention soon, the last hour, shortcuts.
   Uses the helpers and the live `pending` / `grants` state of app.js. Agent data is escaped like everything else. */
const ov = { policy: null, secrets: null, gh: null, timer: null };
const HOUR = 3600;
const ovVisible = () => !$("#tab-overview").classList.contains("hidden");
function fmtBytes(n) {
  if (!Number.isFinite(n)) return "?";
  const u = ["B", "KiB", "MiB", "GiB", "TiB"]; let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
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

// A state is a .status word with a dot (docs/ux-concept.md); details follow in normal text.
const ovSt = (cls, word) => `<span class="status ${cls}">${word}</span>`;
const ovGo = (tab, label) => ` <button class="small ghost" data-ov-tab="${tab}">${esc(label)}</button>`;
function row(label, html) { return `<dt>${esc(label)}</dt><dd>${html}</dd>`; }
function renderOvStatus(status, info) {
  let h = "";
  if (status.ok) {
    const s = status.v;
    h += row("Claude", s.claude_logged_in ? ovSt("ok", "logged in") : ovSt("bad", "not logged in") + ovGo("setup", "Open Setup"));
    const rc = s.remote_control_enabled === false ? `${ovSt("off", "off")} (RC_ENABLE=0)`
      : s.remote_control_prompt ? `${ovSt("warn", "waiting")} for an answer: <code>${esc(s.remote_control_prompt)}</code>`
      : s.remote_control_running ? `${ovSt("ok", "running")} as <b>${esc(s.remote_control_name || "")}</b>` : ovSt("bad", "not running");
    h += row("Remote Control", rc);
    h += row("Claude Code", esc(String(s.claude_version || "?").replace(/\s*\(Claude Code\)$/, "")));
    const ws = diskText(s.workspace_disk);
    h += row("Workspace disk", (ws.warn ? ovSt("warn", "almost full") + " " : "") + ws.html);
  } else h += row("Agent", `${ovSt("bad", "failed")} ${esc(status.e.message)}`);
  if (info.ok) {
    const i = info.v, gd = diskText(i.data_disk);
    h += row("Gateway", `${ovSt("ok", "healthy")} · ${esc(i.pending)} waiting`);
    h += row("Gateway state disk", `${gd.warn ? ovSt("warn", "almost full") + " " : ""}${gd.html} · event log ${fmtBytes(i.events_db_bytes)}`);
  } else h += row("Gateway", `${ovSt("bad", "failed")} ${esc(info.e.message)}`);
  $("#ovStatus").innerHTML = h;
}

async function checkGithub() {
  ov.gh = { checking: true }; renderOvAttention();
  try { ov.gh = await api("GET", "/api/agent/setup/git-identity"); } catch (e) { ov.gh = { ok: false, message: e.message }; }
  renderOvAttention();
}
function renderOvAttention() {
  const now = Date.now() / 1000, items = [];
  const add = (cls, html, tab, label) => items.push(`<li class="${cls}">${html}${tab ? ovGo(tab, label) : ""}</li>`);
  if (pending.length) add("", `${ovSt("warn", "waiting")} <b>${pending.length}</b> connection request${pending.length > 1 ? "s" : ""}`, "approvals", "Open Approvals");
  if (grants.requests.length) add("", `${ovSt("warn", "waiting")} <b>${grants.requests.length}</b> grant request${grants.requests.length > 1 ? "s" : ""}`, "approvals", "Open Approvals");
  for (const r of (ov.policy?.rules || []).filter((r) => r.expires && r.expires > now && r.expires - now < HOUR))
    add("", `Rule <code>${esc(r.action)} ${esc(r.host || r.cidr)}</code>${r.source && r.source !== "user" ? ` <span class="muted">[${esc(r.source)}]</span>` : ""} ends in ${fmtLeft(r.expires)}`, "destinations", "Open Destinations");
  for (const a of grants.active.filter((a) => a.expires - now < HOUR))
    add("", `Grant <b>${esc(a.name)}</b> (${esc(a.level)}) ends in ${fmtLeft(a.expires)}`, "grants", "Open Grants");
  if (ov.secrets && !ov.secrets.includes("github_token")) add("", `${ovSt("warn", "missing")} No GitHub token saved`, "setup", "Open Setup");
  else if (ov.gh && ov.gh.checking) add("muted", "Checking the GitHub token…");
  else if (ov.gh && !ov.gh.ok) add("", `${ovSt("bad", "failed")} GitHub token: ${esc(ov.gh.message)}`, "setup", "Open Setup");
  else if (ov.gh && ov.gh.token_expires) {
    const exp = Date.parse(ov.gh.token_expires.replace(" UTC", "Z").replace(" ", "T"));
    if (Number.isFinite(exp) && exp / 1000 - now < 7 * 86400) add("", `${ovSt("warn", "expiring")} The GitHub token expires ${esc(ov.gh.token_expires)}`, "setup", "Open Setup");
  }
  $("#ovAttention").innerHTML = items.join("") || '<li class="muted">Nothing needs your attention.</li>';
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
  toast(r.ok ? "Emergency stop: unknown destinations are blocked" : "Emergency stop incomplete: see Quick settings", !r.ok);
  if (typeof showStopResult === "function") showStopResult(r);
  await Promise.allSettled([loadPending(), loadGrants(), loadOverview()]);
});
