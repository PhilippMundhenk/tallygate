"use strict";
/* Setup wizard (#75): one flow. Every step says whether it is done, the first missing one is "next".
   Uses the helpers of app.js ($, esc, api, gw, guard, toast, showTab, openTerm, tabHooks).
   Everything the agent reports is untrusted: it is escaped, and links are only set from URLs control checked. */
const wz = { secrets: null, selftest: null, preview: null };
const STEP_TEXT = { done: "done", missing: "to do", warn: "check", info: "optional" };
const CHECK_ICON = { ok: "✔", warn: "⚠", bad: "✖", info: "•" };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function stepStatus(id, html, cls = "") {
  const s = $(`#${id} > .status`); s.className = "status " + cls; s.innerHTML = html;
}
function step(id, state, html, cls) {
  const li = $("#" + id); li.dataset.state = state;
  const b = $(".step-state", li); b.textContent = STEP_TEXT[state]; b.className = "step-state " + state;
  if (html !== undefined) stepStatus(id, html, cls ?? { done: "ok", missing: "warn", warn: "warn", info: "muted" }[state]);
}
const title = (li) => $("h3", li).firstChild.textContent.trim();
const gotoBtn = (id, label) => ` <button class="small secondary" data-goto="${id}">${esc(label)}</button>`;
function gotoStep(id) {
  const li = $("#" + id); li.scrollIntoView({ behavior: "smooth", block: "start" }); $("h3", li).focus({ preventScroll: true });
}

async function loadWizard() {
  const q = (p) => p.then((v) => ({ ok: true, v }), (e) => ({ ok: false, e }));
  const [checks, info, sec, st, meta, pol] = await Promise.all([
    q(api("GET", "/api/setup/checks?origin=" + encodeURIComponent(location.origin))),
    q(gw("GET", "/info")), q(gw("GET", "/secrets")), q(api("GET", "/api/agent/status")),
    q(api("GET", "/api/meta")), q(gw("GET", "/policy")),
  ]);
  wz.secrets = sec.ok ? sec.v.names : null;
  renderAccess(checks); renderGateway(info, sec); renderToken(sec);
  renderClaude(st); renderGit(st); renderRc(st); renderPolicy(pol); renderNotify(meta); renderSelftest();
  renderSummary();
  if (st.ok && !st.v.claude_logged_in && $("#clFlow").classList.contains("hidden")) {
    const l = await api("GET", "/api/agent/setup/claude-login").catch(() => null);  // resume a waiting login
    if (l && l.state === "waiting_code") showLogin(l);
  }
}
tabHooks.setup = loadWizard;

function renderAccess(r) {
  if (!r.ok) { step("st-access", "missing", esc(r.e.message), "bad"); step("st-password", "missing", ""); return; }
  const c = r.v.checks;
  $("#accessChecks").innerHTML = c.map((x) => `<li class="chk ${esc(x.state)}"><b>${CHECK_ICON[x.state] || ""} ${esc(x.title)}</b>
    <span class="muted">${esc(x.detail)}</span></li>`).join("");
  step("st-access", c.some((x) => x.state === "bad") ? "missing" : c.some((x) => x.state === "warn") ? "warn" : "done", "");
  const change = "Change it on the Docker host: <code>docker compose exec control python -m app.passwd</code>";
  const pw = {
    generated: ["missing", `Still the password generated on first start (it is in the control log). ${change}`],
    "env-plain": ["warn", "Set as plain text in <code>CONTROL_PASSWORD</code>. Prefer <code>CONTROL_PASSWORD_HASH</code>."],
    "env-hash": ["done", "Set by <code>CONTROL_PASSWORD_HASH</code>."],
    proxy: ["done", "Your reverse proxy logs you in (<code>TRUST_PROXY_AUTH_HEADER</code>)."],
    changed: ["done", `Your own password. ${change}`],
  }[r.v.password] || ["warn", "unknown"];
  step("st-password", pw[0], pw[1]);
}

function renderGateway(info, sec) {
  if (!info.ok) return step("st-gw", "missing", esc(info.e.message), "bad");
  const i = info.v, needed = sec.ok ? i.inject_secrets_needed.filter((n) => n !== "github_token" && !sec.v.names.includes(n)) : [];
  step("st-gw", i.ca_pem ? "done" : "missing", `${i.ca_pem ? "✔ CA exported" : "✖ CA missing"} · injection for
    <code>${esc(i.inject_hosts.join(", ") || "none")}</code> · pending ${esc(i.pending)}${needed.length ? ` · ⚠ missing secrets: ${esc(needed.join(", "))}` : ""}`);
}

function renderToken(sec) {
  if (!sec.ok) return step("st-gh", "missing", esc(sec.e.message), "bad");
  const has = sec.v.names.includes("github_token");
  if (!$("#st-gh > .status").dataset.keep) step("st-gh", has ? "done" : "missing", has ? "✔ github_token stored in the gateway" : "No token stored yet.");
  else step("st-gh", has ? "done" : "missing");
}

function renderClaude(st) {
  if (!st.ok) return step("st-claude", "missing", esc(st.e.message), "bad");
  const ok = st.v.claude_logged_in;
  $("#clStart").textContent = ok ? "Log in again" : "Start login";
  $("#clStart").classList.toggle("secondary", ok);
  if (ok) $("#clFlow").classList.add("hidden");
  step("st-claude", ok ? "done" : "missing", ok ? `✔ Logged in${st.v.claude_version ? ` · Claude Code ${esc(st.v.claude_version.replace(/\s*\(Claude Code\)$/, ""))}` : ""}` : "Not logged in yet.");
}

function renderGit(st) {
  if (!st.ok) return step("st-git", "missing", esc(st.e.message), "bad");
  const s = st.v, state = s.git_identity || (s.git_name && s.git_email ? "ok" : "missing");
  if (state === "ok") return step("st-git", "done", `✔ ${esc(s.git_name)} &lt;${esc(s.git_email)}&gt;`);
  step("st-git", "missing", state === "empty"
    ? "Set, but empty: an earlier <code>git config</code> stored nothing (for example because the <code>$(gh api user …)</code> inside it failed). Use the button above."
    : "Not set yet.");
}

function renderRc(st) {
  const btn = $("#rcEnable");
  if (!st.ok) { btn.disabled = true; return step("st-rc", "missing", esc(st.e.message), "bad"); }
  const s = st.v, name = esc(s.remote_control_name || "");
  btn.disabled = !s.remote_control_enabled || !s.claude_logged_in;
  if (s.remote_control_enabled === false) return step("st-rc", "info", "Switched off (<code>RC_ENABLE=0</code>).");
  if (s.remote_control_prompt) return step("st-rc", "missing", `Waiting for an answer in the rc console: <code>${esc(s.remote_control_prompt)}</code>. <i>Enable</i> answers it.`);
  if (s.remote_control_running) {
    btn.disabled = true;
    return step("st-rc", "done", `✔ Running${name ? ` as <b>${name}</b>` : ""}. Open the Claude app → <i>Code</i>, or claude.ai/code.`);
  }
  step("st-rc", "missing", s.claude_logged_in ? "Not running yet." : `Log in to Claude first.${gotoBtn("st-claude", "Go to the login")}`);
}

function renderPolicy(pol) {
  if (!pol.ok) return step("st-policy", "info", esc(pol.e.message), "bad");
  const mode = pol.v.default;
  $$("#st-policy [data-policy]").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.policy === mode)));
  step("st-policy", "done", { ask: "Unknown destinations: you are asked.", deny: "Unknown destinations are blocked.", allow: "⚠ Unknown destinations are allowed (log only)." }[mode] || esc(mode));
}

function renderNotify(meta) {
  if (!meta.ok) return step("st-notify", "info", esc(meta.e.message), "bad");
  const n = meta.v.notify;
  $("#notifyStatus").textContent = `Telegram: ${n.telegram ? "configured" : "off"} · Matrix: ${n.matrix ? "configured" : "off"}`;
  step("st-notify", n.telegram || n.matrix ? "done" : "info", "");
  showNotifyPerm();
}

function renderSelftest() {
  if (!wz.selftest) return step("st-test", "missing", $("#st-test > .status").innerHTML ? undefined : "Not run yet.");
  step("st-test", wz.selftest.every((t) => t.pass) ? "done" : "missing");
}

function renderSummary() {
  const req = $$(".wizard > li[data-required]");
  const done = req.filter((li) => ["done", "warn", "info"].includes(li.dataset.state));
  const next = req.find((li) => li.dataset.state === "missing");
  req.forEach((li) => li.classList.toggle("current", li === next));
  $("#wzSummary").innerHTML = next
    ? `<b>${done.length} of ${req.length} steps done.</b> Next: ${gotoBtn(next.id, title(next))}`
    : `<b class="ok">✔ All ${req.length} steps done.</b> The agent is ready: open the Claude app → <i>Code</i>.`;
}

/* ---- actions ---- */
$(".wizard").addEventListener("click", (e) => { const b = e.target.closest("[data-goto]"); if (b) gotoStep(b.dataset.goto); });
$("#wzSummary").addEventListener("click", (e) => { const b = e.target.closest("[data-goto]"); if (b) gotoStep(b.dataset.goto); });
async function refreshAndNext() { await loadWizard(); const next = $(".wizard > li.current"); if (next) gotoStep(next.id); }

$("#ghSave").onclick = guard(async () => {
  const token = $("#ghToken").value.trim(); if (!token) throw new Error("Paste the token first");
  const r = await api("POST", "/api/github/check", { token, store: true });
  $("#ghToken").value = "";
  const s = $("#st-gh > .status"); s.dataset.keep = "1";
  if (!r.ok) { stepStatus("st-gh", `✖ GitHub says ${esc(r.status)}: ${esc(r.message)}`, "bad"); return renderSummary(); }
  stepStatus("st-gh", `✔ valid for <b>${esc(r.login)}</b>${r.expires ? ` · expires ${esc(r.expires)}` : ""}${r.scopes ? ` · scopes ${esc(r.scopes)}` : " · fine-grained"} · ${r.stored ? "stored in the gateway" : "NOT stored"}`, r.stored ? "ok" : "bad");
  await refreshAndNext();
});
$("#ghRemove").onclick = confirmClick($("#ghRemove"), "Remove the GitHub token from the gateway?", async () => {
  await gw("PUT", "/secrets/github_token", { value: "" }); delete $("#st-gh > .status").dataset.keep; await loadWizard();
});

// Claude login: control only passes on a URL of Anthropic's login page (safe_login_url), never another one.
function showLogin(r) {
  const flow = $("#clFlow");
  if (r.state === "done" || (r.logged_in && r.state !== "waiting_code")) { flow.classList.add("hidden"); return true; }
  if (r.state === "waiting_code" && r.url) {
    $("#clUrl").href = r.url; flow.classList.remove("hidden");
    stepStatus("st-claude", "Waiting for the code from the login page.", "warn"); $("#clUrl").focus();
    return false;
  }
  flow.classList.add("hidden");
  if (r.state === "waiting_code") stepStatus("st-claude", "✖ The agent reported a login address that is not Anthropic's. It is not shown.", "bad");
  else if (r.state === "failed") stepStatus("st-claude", `✖ Login failed${r.message ? `: ${esc(r.message)}` : ""}. Start it again.`, "bad");
  else stepStatus("st-claude", "✖ Claude Code showed no login address in time. Start it again.", "bad");
  return false;
}
$("#clStart").onclick = guard(async () => {
  const b = $("#clStart"); b.disabled = true;
  stepStatus("st-claude", "Starting <code>claude auth login</code> in the agent…");
  try { showLogin(await api("POST", "/api/agent/setup/claude-login", {})); } finally { b.disabled = false; }
});
$("#clFlow").addEventListener("submit", guard(async (e) => {
  e.preventDefault();
  const code = $("#clCode").value.trim(); if (!code) throw new Error("Paste the code from the login page first");
  const b = $("#clSend"); b.disabled = true; stepStatus("st-claude", "Checking the code…");
  try {
    const r = await api("POST", "/api/agent/setup/claude-code", { code });
    $("#clCode").value = "";
    if (showLogin(r)) { toast("Logged in to Claude"); await refreshAndNext(); }
    else if (r.state === "waiting_code") stepStatus("st-claude", "No answer yet. Check the code and send it again, or start the login again.", "warn");
  } finally { b.disabled = false; }
}));

// Git identity: never written empty. The preview comes from GitHub (through the gateway) via `gh api user`.
async function applyGit(name, email) {
  name = String(name || "").trim(); email = String(email || "").trim();
  if (!name || !email) throw new Error("Name and email must not be empty");
  if (!/^[^\s@<>"]+@[^\s@<>"]+$/.test(email)) throw new Error(`"${email}" is not an email address`);
  const r = await api("POST", "/api/agent/setup/git-identity", { name, email });
  $("#gitBox").classList.add("hidden"); toast(`Git identity set: ${r.name} <${r.email}>`);
  await refreshAndNext();
}
$("#gitPreview").onclick = guard(async () => {
  $("#gitBox").classList.add("hidden");
  if (wz.secrets && !wz.secrets.includes("github_token"))
    return stepStatus("st-git", `✖ No GitHub token is stored yet, so GitHub cannot say who you are. Store it first.${gotoBtn("st-gh", "Go to the GitHub token")}`, "bad");
  stepStatus("st-git", "Asking GitHub through the gateway…");
  const r = await api("GET", "/api/agent/setup/git-identity");
  if (!r.ok) {
    const hint = r.reason === "token" ? gotoBtn("st-gh", "Check the GitHub token")
      : r.reason === "network" ? " Is <code>api.github.com</code> allowed? Check it under <i>Rules → Test a destination</i>." : "";
    return stepStatus("st-git", `✖ ${esc(r.message)}.${hint} Or enter it yourself below.`, "bad");
  }
  wz.preview = { name: r.name, email: r.email };
  $("#gitName").textContent = r.name; $("#gitEmail").textContent = r.email;
  $("#gitBox").classList.remove("hidden");
  stepStatus("st-git", `GitHub account <b>${esc(r.login)}</b>. Check the values and apply them.`);
  $("#gitApply").focus();
});
$("#gitApply").onclick = guard(() => applyGit(wz.preview?.name, wz.preview?.email));
$("#gitManual").addEventListener("submit", guard((e) => { e.preventDefault(); return applyGit($("#gitManName").value, $("#gitManEmail").value); }));

$("#rcEnable").onclick = guard(async () => {
  const b = $("#rcEnable"); b.disabled = true;
  try {
    await api("POST", "/api/agent/setup/remote-control", {});
    stepStatus("st-rc", "Consent given. Remote Control restarts…");
    for (let i = 0; i < 10; i++) {
      await sleep(2000);
      const st = await api("GET", "/api/agent/status");
      if (st.remote_control_running && !st.remote_control_prompt) break;
    }
  } finally { b.disabled = false; }
  await refreshAndNext();
});
$$(".wizard [data-term]").forEach((b) => (b.onclick = () => openTerm(b.dataset.term)));

$$("#st-policy [data-policy]").forEach((b) => (b.onclick = guard(async () => {
  await gw("PATCH", "/policy", { default: b.dataset.policy }); toast("Mode saved"); await loadWizard();
})));
$("#wzTemplates").onclick = () => { showTab("rules"); const t = $("#qaTemplates"); t.scrollIntoView({ behavior: "smooth" }); };

$("#selftestBtn").onclick = guard(async () => {
  const b = $("#selftestBtn"); b.disabled = true; stepStatus("st-test", "running… (up to a minute)");
  try {
    const r = await api("GET", "/api/agent/selftest");
    wz.selftest = r.results;
    const rows = r.results.map((t) => `<tr><td class="${t.pass ? "ok" : "bad"}">${t.pass ? "PASS" : "FAIL"}</td><td>${esc(t.name)}</td><td class="muted">${esc(t.detail)}</td></tr>`).join("");
    stepStatus("st-test", `<div class="table-wrap"><table class="results">${rows}</table></div>`, r.results.every((t) => t.pass) ? "ok" : "bad");
  } finally { b.disabled = false; }
  renderSelftest(); renderSummary();
});

// Browsers only show the permission prompt after a user gesture, so it is asked from a button.
function showNotifyPerm() {
  const supported = "Notification" in window;
  $("#notifyBtn").classList.toggle("hidden", !supported || Notification.permission !== "default");
  $("#notifyPerm").textContent = !supported ? "not supported by this browser"
    : Notification.permission === "granted" ? "browser notifications are on"
    : Notification.permission === "denied" ? "blocked in the browser's site settings" : "";
}
$("#notifyBtn").onclick = guard(async () => { await Notification.requestPermission(); showNotifyPerm(); });
showNotifyPerm();
