"use strict";
/* Setup wizard (#75): one flow. Every step says whether it is done, the first missing one is "next".
   Uses the helpers of app.js ($, esc, api, gw, guard, toast, showTab, openTerm, tabHooks).
   Everything the agent reports is untrusted: it is escaped, and links are only set from URLs control checked. */
const wz = { secrets: null, selftest: null, preview: null };
const STEP_TEXT = { done: "done", missing: "to do", warn: "check", info: "optional" };
const CHECK_ICON = { ok: "✔", warn: "⚠", bad: "✖", info: "•" };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function stepStatus(id, html, cls = "") {
  const s = $(`#${id} > .step-msg`); s.className = "step-msg " + cls; s.innerHTML = html;
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
  const [checks, info, sec, st, meta, pol, ncfg] = await Promise.all([
    q(api("GET", "/api/setup/checks?origin=" + encodeURIComponent(location.origin))),
    q(gw("GET", "/info")), q(gw("GET", "/secrets")), q(api("GET", "/api/agent/status")),
    q(api("GET", "/api/meta")), q(gw("GET", "/policy")), q(api("GET", "/api/notify/config")),
  ]);
  wz.secrets = sec.ok ? sec.v.names : null;
  renderAccess(checks); renderGateway(info, sec); renderToken(sec);
  renderClaude(st); renderGit(st); renderRc(st); renderPolicy(pol); renderNotify(meta, ncfg); renderSelftest();
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
  if (!$("#st-gh > .step-msg").dataset.keep) step("st-gh", has ? "done" : "missing", has ? "✔ github_token stored in the gateway" : "No token stored yet.");
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
  if (!$("#st-policy")) return;  // the step was removed (#200): "ask" is the default, the mode is under Settings
  if (!pol.ok) return step("st-policy", "info", esc(pol.e.message), "bad");
  const mode = pol.v.default;
  $$("#st-policy [data-policy]").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.policy === mode)));
  step("st-policy", "done", { ask: "New destinations: you are asked each time.", deny: "New destinations are blocked.", allow: "⚠ New destinations are allowed (log only)." }[mode] || esc(mode));
}

// #180: one Notifications section. Each channel shows whether it is active and why, with a Test
// button that sends a sample through just that channel (disabled, with the reason, when it is off).
// notify_status is the rich per-channel detail; fall back to the plain bool map for older backends.
// #201: each bot channel also has a "Configure" disclosure. Secrets are write-only: the backend only
// says whether one is set and where it comes from, so a password field is always empty ("leave empty
// to keep"). A text field holds the value saved in the UI; a value from the environment is shown as
// the placeholder, and saving the field empty returns it to the environment.
const CHANNEL_LABELS = { telegram: "Telegram", matrix: "Matrix", ntfy: "ntfy", gotify: "Gotify", pushover: "Pushover", webpush: "Web Push" };
function notifyDetail(meta) {
  if (Array.isArray(meta.notify_status)) return meta.notify_status;
  const n = meta.notify || {};
  return Object.entries(CHANNEL_LABELS)
    .filter(([k]) => k in n)
    .map(([k, label]) => ({ channel: k, label, configured: !!n[k], source: null, reason: n[k] ? "Configured." : "Off." }));
}
const NOTIFY_SOURCE = { ui: "web UI", environment: "environment", mixed: "web UI + environment" };
const FIELD_SOURCE = { ui: "saved in the web UI", environment: "from the environment", unset: "not set" };
const notifyOpen = new Set();  // channels whose Configure disclosure is open: kept across re-renders

function notifyConfigForm(c, label) {
  const det = document.createElement("details"); det.className = "more notify-config"; det.open = notifyOpen.has(c.channel);
  det.addEventListener("toggle", () => (det.open ? notifyOpen.add(c.channel) : notifyOpen.delete(c.channel)));
  const sum = document.createElement("summary"); sum.textContent = "Configure";
  sum.setAttribute("aria-label", `Configure ${label}`);
  const form = document.createElement("form"); form.autocomplete = "off";
  for (const f of c.fields) {
    const lab = document.createElement("label"); lab.append(f.label + (f.required ? "" : " (optional)"));
    const input = document.createElement("input");
    input.name = f.name; input.type = f.secret ? "password" : "text"; input.maxLength = 2048;
    input.autocomplete = f.secret ? "new-password" : "off"; input.spellcheck = false;
    if (f.secret) input.placeholder = f.set ? "stored – leave empty to keep" : "";
    else if (f.source === "ui") input.value = f.value || "";
    else if (f.source === "environment") input.placeholder = `${f.value} (environment)`;
    const small = document.createElement("small");
    small.textContent = [f.hint, `${FIELD_SOURCE[f.source] || f.source}${f.source === "environment" ? ` (${f.env})` : ""}`].filter(Boolean).join(" · ");
    lab.append(input, small); form.appendChild(lab);
  }
  const btns = document.createElement("div"); btns.className = "btns";
  const save = document.createElement("button"); save.type = "submit"; save.className = "small"; save.textContent = "Save";
  save.setAttribute("aria-label", `Save the ${label} settings`);
  const remove = document.createElement("button"); remove.type = "button"; remove.className = "small secondary"; remove.textContent = "Remove override";
  remove.setAttribute("aria-label", `Remove the ${label} settings saved in the web UI`);
  remove.disabled = !c.override;
  remove.title = c.override ? "" : "Nothing is saved in the web UI for this channel.";
  btns.append(save, remove); form.appendChild(btns);
  form.addEventListener("submit", guard(async (e) => {
    e.preventDefault();
    const body = {}; for (const f of c.fields) body[f.name] = form.elements[f.name].value;
    await api("PUT", `/api/notify/config/${encodeURIComponent(c.channel)}`, body);
    toast(`${label} settings saved and applied`); await loadWizard();
  }));
  remove.onclick = confirmClick(remove, `Delete what the web UI saved for ${label}? The channel falls back to the environment, or switches off.`, async () => {
    await api("DELETE", `/api/notify/config/${encodeURIComponent(c.channel)}`);
    toast(`${label}: web UI settings removed`); await loadWizard();
  });
  det.append(sum, form);
  return det;
}

async function notifyTest(c) {
  if (c.channel === "webpush") {
    const r = await api("POST", "/api/push/test", {});
    return toast(`Web Push test sent to ${r.delivered} device(s)`);
  }
  await api("POST", "/api/notify/test", { channel: c.channel });
  toast(`${c.label} test notification sent`);
}

function renderNotify(meta, ncfg) {
  if (!meta.ok) return step("st-notify", "info", esc(meta.e.message), "bad");
  const detail = notifyDetail(meta.v);
  const cfg = ncfg && ncfg.ok && Array.isArray(ncfg.v.channels) ? ncfg.v : null;  // null: an older backend
  const ro = $("#notifyReadonly");
  if (ro) {
    ro.textContent = cfg && !cfg.writable
      ? "The control data volume is not writable, so channels cannot be saved here: configure them in the environment." : "";
    ro.classList.toggle("hidden", !ro.textContent);
  }
  const box = $("#notifyChannels");
  if (box) {
    box.innerHTML = "";
    for (const c of detail) {
      const item = document.createElement("div"); item.className = "notify-channel";
      const row = document.createElement("div"); row.className = "row-between";
      const info = document.createElement("div");
      info.innerHTML = `<b>${esc(c.label)}</b> <span class="tag ${c.configured ? "ok" : "warn"}">${c.configured ? "active" : "off"}</span>`
        + (NOTIFY_SOURCE[c.source] ? ` <span class="muted notify-source">· ${NOTIFY_SOURCE[c.source]}</span>` : "")
        + `<div class="muted notify-why">${esc(c.reason)}</div>`;
      const btn = document.createElement("button"); btn.className = "small secondary notify-test"; btn.textContent = "Test";
      btn.setAttribute("aria-label", `Send a test notification through ${c.label}`);
      if (!c.configured) { btn.disabled = true; btn.title = c.reason; }
      else btn.onclick = guard(() => notifyTest(c));
      row.append(info, btn); item.appendChild(row);
      const conf = cfg && cfg.writable && cfg.channels.find((x) => x.channel === c.channel);
      if (conf) item.appendChild(notifyConfigForm(conf, c.label));
      box.appendChild(item);
    }
  }
  const active = detail.filter((c) => c.configured).length;
  $$(".notify-status").forEach((e) => (e.textContent = active ? `${active} of ${detail.length} channels active` : "No notification channel is active yet."));
  step("st-notify", active ? "done" : "info", "");
  showNotifyPerm();
}

function renderSelftest() {
  if (!wz.selftest) return step("st-test", "missing", $("#st-test > .step-msg").innerHTML ? undefined : "Not run yet.");
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
  const s = $("#st-gh > .step-msg"); s.dataset.keep = "1";
  if (!r.ok) { stepStatus("st-gh", `✖ GitHub says ${esc(r.status)}: ${esc(r.message)}`, "bad"); return renderSummary(); }
  stepStatus("st-gh", `✔ valid for <b>${esc(r.login)}</b>${r.expires ? ` · expires ${esc(r.expires)}` : ""}${r.scopes ? ` · scopes ${esc(r.scopes)}` : " · fine-grained"} · ${r.stored ? "stored in the gateway" : "NOT stored"}`, r.stored ? "ok" : "bad");
  await refreshAndNext();
});
$("#ghRemove").onclick = confirmClick($("#ghRemove"), "Remove the GitHub token from the gateway?", async () => {
  await gw("PUT", "/secrets/github_token", { value: "" }); delete $("#st-gh > .step-msg").dataset.keep; await loadWizard();
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
      : r.reason === "network" ? " Is <code>api.github.com</code> allowed? Check it under <i>Destinations → Test a destination</i>." : "";
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

// Browser notifications (#201). Browsers only show the permission prompt after a user gesture, so it is
// asked from a button, and they refuse notifications outside a secure context (HTTPS or localhost), so that
// is said first. When the site is blocked the button stays: some browsers ask again, the others answer
// "denied" at once, and the text says where to allow it without naming one browser's icons.
const NOTIFY_BLOCKED = "Blocked in this browser for this site. Allow notifications in the site permissions "
  + "(address bar → site information / permissions), then reload.";
function showNotifyPerm() {
  const supported = "Notification" in window, secure = !!window.isSecureContext;
  const perm = supported ? Notification.permission : "";
  const ask = secure && supported && perm !== "granted", on = secure && perm === "granted";
  $$(".notify-btn").forEach((b) => b.classList.toggle("hidden", !ask));
  $$(".notify-local-test").forEach((b) => b.classList.toggle("hidden", !on));
  const text = !secure ? "Browser notifications need HTTPS (or localhost): open the UI through your TLS reverse proxy."
    : !supported ? "This browser does not support notifications."
    : on ? "Browser notifications are on"
    : perm === "denied" ? NOTIFY_BLOCKED : "";
  $$(".notify-perm").forEach((e) => (e.textContent = text));  // one Notifications section since #180
}
$$(".notify-btn").forEach((b) => (b.onclick = guard(async () => {
  const before = Notification.permission, result = await Notification.requestPermission();
  showNotifyPerm();
  if (result === "granted") toast("Browser notifications are on");
  else if (before === "denied") toast("Still blocked: the browser did not ask again. Allow notifications in the site permissions, then reload.", true);
})));
// A local notification, no server involved. Android browsers only allow them through the service worker.
async function localNotification(title, options) {
  try { new Notification(title, options); } catch (e) {
    const reg = "serviceWorker" in navigator ? await navigator.serviceWorker.getRegistration() : null;
    if (!reg) throw e;
    await reg.showNotification(title, options);
  }
}
$$(".notify-local-test").forEach((b) => (b.onclick = guard(async () => {
  if (!("Notification" in window) || Notification.permission !== "granted") { showNotifyPerm(); throw new Error("Notifications are not allowed for this site"); }
  await localNotification("tallygate", { body: "Test notification: browser notifications work.", tag: "tallygate-test" });
  toast("Test notification sent");
})));
showNotifyPerm();
