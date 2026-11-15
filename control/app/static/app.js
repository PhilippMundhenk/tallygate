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
  const t = $("#toast"); t.setAttribute("role", bad ? "alert" : "status");
  t.textContent = msg; t.style.display = "block"; t.style.color = bad ? "#fca5a5" : "";
  clearTimeout(toast._t); toast._t = setTimeout(() => (t.style.display = "none"), 4000);
}
const guard = (fn) => async (...a) => { try { await fn(...a); } catch (e) { toast(e.message, true); } };
// In-page confirmation instead of confirm(), which returns false at once when the browser suppresses
// dialogs. The first click arms the button and says what will happen; a second click within 8 s runs fn.
// Escape, the timeout or leaving the button with the keyboard disarms it.
const ARM_MS = 8000;
function confirmClick(btn, question, fn) {
  const disarm = () => {
    clearTimeout(btn._armT); if (btn.dataset.armed !== "1") return;
    delete btn.dataset.armed; btn.textContent = btn._label; btn.classList.remove("armed");
    if (btn._q) { btn._q.remove(); btn._q = null; }
    btn.removeAttribute("aria-describedby");
  };
  btn.addEventListener("keydown", (e) => { if (e.key === "Escape") disarm(); });
  btn.addEventListener("blur", (e) => { if (e.relatedTarget) disarm(); });
  return guard(async (...a) => {
    if (btn.dataset.armed !== "1") {
      btn._label = btn.textContent; btn.dataset.armed = "1"; btn.classList.add("armed");
      btn.textContent = "Confirm: " + btn._label;
      const q = document.createElement("span"); q.className = "confirm-q"; q.setAttribute("role", "status");
      q.id = "cq-" + Math.random().toString(36).slice(2); q.textContent = `${question} Click again to confirm.`;
      btn.after(q); btn._q = q; btn.setAttribute("aria-describedby", q.id);
      btn._armT = setTimeout(disarm, ARM_MS);
      return;
    }
    disarm();
    await fn(...a);
  });
}

/* ---------------- unencrypted access ---------------- */
// Plain HTTP from another machine: the session travels unencrypted (#97). Shown, not blocked.
if (location.protocol === "http:" && !["localhost", "127.0.0.1", "[::1]"].includes(location.hostname)) {
  const b = document.getElementById("insecureBanner");
  if (b) b.hidden = false;
}

/* ---------------- tabs ---------------- */
// Feature scripts loaded after this one (wizard.js, ...) register what to load when their tab opens.
const tabHooks = {};
function showTab(name) {
  $$("main > section").forEach((s) => s.classList.toggle("hidden", s.id !== "tab-" + name));
  $$("#tabs button").forEach((b) => {
    const on = b.dataset.tab === name;
    b.classList.toggle("active", on); b.setAttribute("aria-selected", String(on)); b.tabIndex = on ? 0 : -1;
  });
  history.replaceState(null, "", "#" + name);
  if (name === "destinations") guard(loadPolicy)();  // the rules table
  if (name === "quickstart") { guard(loadPolicy)(); guard(loadGrants)(); }  // shortcuts reflect the policy; the local-network form checks the grant names
  if (name === "settings") guard(loadPolicy)();  // Mode + raw policy JSON come from the policy
  if (name === "grants") { guard(loadGrants)(); guard(loadSecrets)(); }
  if (tabHooks[name]) guard(tabHooks[name])();
  if (name === "log" && !logLoaded) guard(loadLog)();
  document.dispatchEvent(new CustomEvent("tg:tab", { detail: name }));  // hook for the feature scripts
}
// Mobile nav drawer (#138): a hamburger toggles the sidebar; a scrim and Escape close it.
const navToggle = $("#navToggle"), navScrim = $("#navScrim");
function setNav(open) {
  document.body.classList.toggle("nav-open", open);
  if (navToggle) navToggle.setAttribute("aria-expanded", String(open));
}
if (navToggle) navToggle.addEventListener("click", () => {
  const open = !document.body.classList.contains("nav-open");
  setNav(open);
  if (open) ($("#tabs button.active") || $("#tabs button"))?.focus();
});
if (navScrim) navScrim.addEventListener("click", () => setNav(false));
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && document.body.classList.contains("nav-open")) { setNav(false); navToggle?.focus(); }
});
// The sidebar sticks below the header; measure it so the first tab is never hidden.
function setHeaderH() { const h = $("header"); if (h) document.documentElement.style.setProperty("--header-h", h.offsetHeight + "px"); }
setHeaderH(); window.addEventListener("resize", setHeaderH);

$$("#tabs button").forEach((b) => b.addEventListener("click", () => { showTab(b.dataset.tab); setNav(false); }));
// Setup and Quick settings can be hidden from the menu (Settings > Menu); the choice is kept in this browser.
for (const [box, tab] of [["#navShowSetup", "setup"], ["#navShowQuick", "quickstart"]]) {
  const key = "tallygate.nav." + tab, btn = $("#tabbtn-" + tab), cb = $(box);
  const apply = (show) => { btn.classList.toggle("hidden", !show); cb.checked = show; };
  let show = true;
  try { show = localStorage.getItem(key) !== "0"; } catch { /* private mode: not kept */ }
  apply(show);
  cb.onchange = () => {
    apply(cb.checked); try { localStorage.setItem(key, cb.checked ? "1" : "0"); } catch { /* not kept */ }
    toast(`${btn.firstChild.textContent.trim()} ${cb.checked ? "shown in" : "hidden from"} the menu`);  // instant-apply checkbox: confirm with a toast
  };
}
$("#tabs").addEventListener("keydown", (e) => {  // arrow keys move between tabs (WAI-ARIA tabs pattern; vertical sidebar)
  const tabs = $$("#tabs button"), i = tabs.indexOf(document.activeElement);
  if (i < 0 || !["ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown", "Home", "End"].includes(e.key)) return;
  const fwd = e.key === "ArrowRight" || e.key === "ArrowDown";
  const j = e.key === "Home" ? 0 : e.key === "End" ? tabs.length - 1 : (i + (fwd ? 1 : -1) + tabs.length) % tabs.length;
  e.preventDefault(); tabs[j].focus(); showTab(tabs[j].dataset.tab);
});

/* ---------------- approvals ---------------- */
// Decision buttons are built per request in pendingCard: all shown on desktop, the custom-duration ones
// collapse under "More" only on narrow screens (#174). Durations reach the gateway as {scope, ttl} (#173).
let pending = [];
async function loadPending() {
  pending = await gw("GET", "/pending");
  renderPending();
}
// Cards are kept per id. A card that went away (decided elsewhere, expired) while the pointer is over the
// list stays in place, greyed out, until the pointer leaves: the next click must not land on another card.
function syncCards(list, items, build) {
  const byId = new Map($$(":scope > .pending", list).map((el) => [el.dataset.id, el]));
  const hovered = list.matches(":hover");
  for (const [id, el] of byId) {
    if (items.some((it) => it.id === id)) continue;
    if (hovered) { el.classList.add("gone"); $$("button", el).forEach((b) => (b.disabled = true)); }
    else el.remove();
  }
  for (const it of items) {
    const sig = JSON.stringify(it);
    const old = byId.get(it.id);
    if (old && (old.dataset.sig === sig || old.classList.contains("busy"))) continue;
    const el = build(it); el.dataset.id = it.id; el.dataset.sig = sig;
    if (old) old.replaceWith(el); else list.appendChild(el);
  }
  if (hovered && !list._leave) {
    list._leave = () => { $$(":scope > .pending.gone", list).forEach((el) => el.remove()); };
    list.addEventListener("mouseleave", list._leave);
  }
}
// Disables the card's buttons while its decision is in flight (no double submits).
const decide = (el, fn) => async () => {
  el.classList.add("busy"); $$("button", el).forEach((b) => (b.disabled = true));
  try { await fn(); } catch (e) {
    toast(e.message, true); el.classList.remove("busy"); $$("button", el).forEach((b) => (b.disabled = false));
  }
};
function renderPending() {
  syncCards($("#pendingList"), pending, pendingCard);
  $("#pendingEmpty").classList.toggle("hidden", pending.length > 0);
  updateBadges();
  tickCountdowns();
}
function pendingCard(p) {
  const el = document.createElement("div"); el.className = "pending";
  // Host names are chosen by the agent: show the registrable domain separately (look-alikes such as
  // github.com.evil.example) and warn about punycode names.
  el.innerHTML = `<div class="dest">${esc(p.host)}:${esc(p.port)}</div>
    ${p.domain && p.domain !== p.host ? `<div class="meta domain">domain <b>${esc(p.domain)}</b></div>` : ""}
    ${p.idn ? `<div class="meta warn">Internationalised (punycode) name: check for look-alikes</div>` : ""}
    <div class="meta">${esc(p.proto)} · IPs ${esc((p.ips || []).join(", ") || "not resolved yet")} · attempts ${esc(p.attempts)} ·
    <span class="countdown" data-exp="${Number(p.expires)}"></span></div><div class="btns"></div>`;
  const btns = $(".btns", el);
  const send = (body) => decide(el, async () => { await gw("POST", `/pending/${p.id}/decide`, body); await loadPending(); });
  // a plain decision button, with data-scope/data-ttl/data-key hooks for the keyboard shortcuts (keys.js)
  const mk = (label, cls, body, key) => {
    const b = document.createElement("button"); b.type = "button"; b.className = cls;
    b.dataset.scope = body.scope; if (body.ttl) b.dataset.ttl = body.ttl; if (key) b.dataset.key = key;
    b.textContent = label; b.onclick = send(body); btns.appendChild(b); return b;
  };
  // "… min" button: opens an inline minutes field (hence the "…"); Enter or the Allow/Deny button next to it sends
  // a custom-duration decision
  const mkDur = (label, cls, scope) => {
    const wrap = document.createElement("span"); wrap.className = "dur extra";
    wrap.innerHTML = `<button type="button" class="${cls}">${esc(label)}</button>`
      + `<span class="dur-in hidden"><input type="number" min="1" max="43200" value="30" aria-label="for how many minutes"> min <button type="button" class="small secondary">${scope === "allow" ? "Allow" : "Deny"}</button></span>`;
    const open = wrap.firstChild, form = wrap.querySelector(".dur-in"), input = form.querySelector("input"), go = form.querySelector("button");
    open.onclick = () => { form.classList.remove("hidden"); open.classList.add("hidden"); input.focus(); input.select(); };
    const submit = () => send({ scope, ttl: Math.max(1, Math.min(43200, parseInt(input.value, 10) || 0)) * 60 })();
    go.onclick = submit;
    input.onkeydown = (e) => { if (e.key === "Enter") { e.preventDefault(); submit(); } else if (e.key === "Escape") { form.classList.add("hidden"); open.classList.remove("hidden"); } };
    btns.appendChild(wrap); return wrap;
  };
  const more = document.createElement("button");
  more.type = "button"; more.className = "secondary more"; more.textContent = "More"; more.setAttribute("aria-expanded", "false");
  more.onclick = () => { const open = el.classList.toggle("more-open"); more.setAttribute("aria-expanded", String(open)); more.textContent = open ? "Less" : "More"; };

  // One primary per card: the quick allow. A deny lowers nothing, so it is not a (confirmed) danger button.
  mk("Allow for 5 min", "", { scope: "allow", ttl: 300 }, "a");
  mkDur("Allow for … min", "secondary", "allow");
  if (p.domain) mk(`Allow *.${p.domain} permanently`, "secondary", { scope: "domain" });
  else mk("Allow host permanently", "secondary", { scope: "always" });
  mkDur("Deny for … min", "secondary", "deny");
  mk("Deny permanently", "secondary", { scope: "deny_always" }, "d");
  btns.appendChild(more);  // CSS hides it on desktop; only narrow screens collapse the "… min" buttons under it
  document.dispatchEvent(new CustomEvent("tg:card", { detail: { el, item: p, kind: "ask" } }));  // feature scripts
  return el;
}
function tickCountdowns() {
  const now = Date.now() / 1000;
  $$(".countdown").forEach((c) => { const s = Math.max(0, Math.round(c.dataset.exp - now)); c.textContent = `denied in ${s} s`; });
}
setInterval(tickCountdowns, 1000);

/* ---------------- log ---------------- */
let oldestId = null, logLoaded = false;
const logIds = new Set();
// Rows are ordered by event id (newest first) and shown once, whether they came live or from history.
function addLogRow(e, trim = true) {
  if (logIds.has(e.id)) return;
  logIds.add(e.id);
  const body = $("#logBody"), tr = logRow(e);
  let next = body.firstElementChild;
  while (next && Number(next.dataset.id) > e.id) next = next.nextElementSibling;
  body.insertBefore(tr, next);
  while (trim && body.children.length > 2000) { logIds.delete(Number(body.lastElementChild.dataset.id)); body.lastElementChild.remove(); }
  oldestId = Number(body.lastElementChild.dataset.id);
}
function logRow(e) {
  const tr = document.createElement("tr"); tr.dataset.id = e.id;
  const dest = `${e.host ?? ""}${e.port ? ":" + e.port : ""}`;
  tr.dataset.kind = e.kind; tr.dataset.action = e.action;
  tr.dataset.text = `${dest} ${e.action} ${e.reason}`.toLowerCase();
  tr.innerHTML = `<td title="${esc(fmtDate(e.ts))}">${esc(fmtTime(e.ts))}</td><td>${esc(e.kind)}</td><td>${esc(e.proto ?? "")}</td>
    <td><code>${esc(dest)}</code>${e.ips && e.ips.length ? `<br><span class="muted">${esc(e.ips.join(", "))}</span>` : ""}</td>
    <td class="a-${esc(e.action)}">${esc(e.action)}</td><td>${esc(e.reason)}</td><td></td>`;
  const reason = String(e.reason);
  if (e.kind === "conn" && e.host && !reason.startsWith("locked:") && reason !== "invalid hostname") {
    const cell = tr.lastElementChild;
    for (const [action, label] of [["allow", "Allow"], ["deny", "Deny"]]) {
      const b = document.createElement("button"); b.textContent = label; b.className = "small ghost";
      b.setAttribute("aria-label", `${label} ${dest}`);
      b.onclick = guard(async () => {
        await gw("POST", "/destinations", { access: action, match: { host: e.host, port: e.port }, note: "from log" }); toast(`Rule added: ${action} ${dest}`);
      });
      cell.appendChild(b);
    }
  }
  applyLogFilter(tr);
  return tr;
}
const LOG_EMPTY = "No events yet. They appear as soon as the agent connects somewhere.";
function applyLogFilter(tr) {
  const f = $("#logFilter").value.toLowerCase();
  const hide = (f && !tr.dataset.text.includes(f)) || ($("#logHideDns").checked && tr.dataset.kind === "dns") ||
    ($("#logOnlyBlocked").checked && tr.dataset.action !== "deny");
  tr.classList.toggle("hidden", !!hide);
}
async function loadLog(older = false) {
  const q = older && oldestId !== null ? `?limit=200&before=${oldestId}` : "?limit=200";
  const rows = await gw("GET", "/events" + q);
  rows.forEach((e) => addLogRow(e, !older));  // "Load older" may grow the table beyond 2000
  logLoaded = true;
  if (older && !rows.length) toast("No older events");
  const empty = !$("#logBody").children.length;
  $("#logEmpty").textContent = anyLogFilter() ? "No events match the filter. Clear it to see all events." : LOG_EMPTY;
  $("#logEmpty").classList.toggle("hidden", !empty);
}
function anyLogFilter() {
  return $("#logFilter").value.trim() || $("#logHideDns").checked || $("#logOnlyBlocked").checked;
}
["#logFilter", "#logHideDns", "#logOnlyBlocked"].forEach((s) =>
  $(s).addEventListener("input", () => {
    $$("#logBody tr").forEach(applyLogFilter);
    const visible = $$("#logBody tr").some((r) => !r.classList.contains("hidden"));
    $("#logEmpty").textContent = anyLogFilter() ? "No events match the filter. Clear it to see all events." : LOG_EMPTY;
    $("#logEmpty").classList.toggle("hidden", visible || !logLoaded);
  }),
);
$("#logMore").onclick = guard(() => loadLog(true));

/* ---------------- rules ---------------- */
let policy = null;
function portText(p) { return p === undefined || p === "*" ? "*" : Array.isArray(p) ? p.join(",") : String(p); }
function parsePort(s) {
  // Typos must fail visibly: parseInt("https") is NaN (sent as null = all ports) and parseInt("44 3") is 44.
  s = (s || "").trim(); if (!s || s === "*") return "*";
  const one = (x) => {
    x = x.trim();
    if (/^\d{1,5}$/.test(x) && +x >= 1 && +x <= 65535) return +x;
    const m = /^(\d{1,5})\s*-\s*(\d{1,5})$/.exec(x);
    if (m && +m[1] >= 1 && +m[1] <= +m[2] && +m[2] <= 65535) return `${+m[1]}-${+m[2]}`;
    throw new Error(`Invalid port "${x}": use 443, 80,443, 8000-8100 or *`);
  };
  return s.includes(",") ? s.split(",").map(one) : one(s);
}
// Editable policy fields remember unsaved edits; a policy event (change elsewhere) leaves them alone.
const POLICY_FIELDS = ["#defaultAction", "#askTimeout", "#rawPolicy"];
POLICY_FIELDS.forEach((s) => $(s).addEventListener("input", () => ($(s).dataset.dirty = "1")));
function setField(sel, value, keepEdits) {
  const el = $(sel);
  if (keepEdits && el.dataset.dirty) { el.classList.add("stale"); el.title = "Changed elsewhere since you started editing"; return false; }
  el.value = value; delete el.dataset.dirty; el.classList.remove("stale"); el.title = "";
  return true;
}
// The blocked ranges are rules in the one Destinations table (ADR-0019), not a setting here.
let rawBase = null;  // the policy the raw editor's text was loaded from (JSON)
async function loadPolicy(keepEdits = false) {
  policy = await gw("GET", "/policy");
  setField("#defaultAction", policy.default, keepEdits); setField("#askTimeout", policy.ask_timeout, keepEdits);
  if (setField("#rawPolicy", JSON.stringify(policy, null, 2), keepEdits)) rawBase = JSON.stringify(policy);
  await renderQuick();
}
// PUT /policy replaces every rule. The browser's copy goes stale (other tab, Telegram "Always", approvals),
// so only the raw editor and the hard deny use it, and both start from the policy as it is now.
async function putPolicy(p) { await gw("PUT", "/policy", p); toast("Policy saved"); await loadPolicy(); }
// Mode and timeout only: the rules on the gateway stay untouched.
async function patchPolicy(change) {
  await gw("PATCH", "/policy", change); toast("Mode saved");
  ["#defaultAction", "#askTimeout"].forEach((s) => delete $(s).dataset.dirty);
  await loadPolicy(true);
}
$("#saveMode").onclick = guard(() => patchPolicy({ default: $("#defaultAction").value, ask_timeout: Number($("#askTimeout").value) }));
$("#saveRaw").onclick = guard(async () => {
  let p;
  try { p = JSON.parse($("#rawPolicy").value); } catch (e) { throw new Error(`Invalid JSON: ${e.message}`); }
  const fresh = await gw("GET", "/policy");
  if (JSON.stringify(fresh) !== rawBase) {
    // Changed elsewhere since the text was loaded: saving it now would drop or revive rules. The text is kept;
    // a second click replaces the policy on purpose.
    rawBase = JSON.stringify(fresh);
    const el = $("#rawPolicy"); el.classList.add("stale"); el.title = "Changed elsewhere since you started editing";
    throw new Error("The policy was changed elsewhere since this text was loaded. Reload it, or click Save policy again to overwrite.");
  }
  return putPolicy(p);
});
$("#reloadRaw").onclick = guard(async () => { delete $("#rawPolicy").dataset.dirty; await loadPolicy(true); });
function explainTest(r) {
  // What decided, in the order the gateway checks: the gateway names the deciding rule and its position.
  const lines = [];
  if (r.rule) {
    const rule = r.rule;
    lines.push(`Decided by rule #${r.pos} (${rule.id}): ${rule.action} ${rule.host || rule.cidr} port ${portText(rule.port === undefined ? "*" : rule.port)}` +
      (rule.source && rule.source !== "user" ? ` [${rule.source}]` : "") + ". The first matching rule from the top wins.");
  } else if (r.rule_id === "locked") {
    lines.push("Decided before the list: the tallygate stack's own networks and the gateway's own ports are locked. No rule or grant opens them.");
  } else if (/invalid hostname/.test(r.reason || "")) lines.push("Not a valid host name.");
  else if (/^default/.test(r.reason || "")) lines.push(`No rule matched, so the default decided (${policy ? policy.default : "default"}).`);
  if (r.shadow) {
    lines.push(`Rule ${r.shadow.rule} matches the name, but a name rule cannot open a blocked range: ${r.shadow.address} is inside ${r.shadow.range} (rule ${r.shadow.by}).`,
      `To reach it, add an allow rule for the address ${r.shadow.address} on Destinations: it is added at the top, above the blocked range.`);
  }
  return lines.join("\n");
}
$("#testBtn").onclick = guard(async () => {
  const r = await gw("POST", "/test", { host: $("#testHost").value.trim(), port: +$("#testPort").value || 443 });
  const ips = (r.ips || []).length ? r.ips.join(", ") : "not resolved (decided on the name)";
  $("#testOut").textContent = `${r.action.toUpperCase()} — ${r.reason}\n${explainTest(r)}\nIPs: ${ips}`;
});
function checkMatch(kind, v) {
  if (!v) throw new Error(kind === "host" ? "Host: e.g. pypi.org, *.github.com or *" : "CIDR: e.g. 203.0.113.0/24");
  if (kind === "host" && !/^(\*|(\*\.|\?\*\.)?[A-Za-z0-9*?]([A-Za-z0-9*?-]*[A-Za-z0-9*?])?(\.[A-Za-z0-9*?]([A-Za-z0-9*?-]*[A-Za-z0-9*?])?)*\.?)$/.test(v))
    throw new Error(`Host "${v}" is not valid: use pypi.org, *.github.com or *`);
  if (kind === "host" && /^\*[^.]/.test(v)) throw new Error(`"${v}" would also match look-alikes (e.g. evil${v.slice(1)}); write *.${v.slice(1).replace(/^\./, "")}`);
  if (kind === "cidr" && !/^[0-9a-fA-F:.]+(\/\d{1,3})?$/.test(v)) throw new Error(`CIDR "${v}" is not valid: use 203.0.113.0/24 or 203.0.113.10/32`);
}

/* ---------------- shortcuts (preset files: internet and tool ecosystems) ---------------- */
let presetInfo = null;
const presetRules = (name) => (policy ? policy.rules.filter((r) => r.source === `preset:${name}`) : []);
const TTL_CHOICES = [["", "Until undone"], ["3600", "For 1 h"], ["86400", "For 1 day"]];
function presetExpiry(rules) {
  const exp = rules.map((r) => r.expires).filter(Boolean);
  return exp.length === rules.length && exp.length ? Math.max(...exp) : null;
}
async function applyPreset(name, ttl) {
  const r = await gw("POST", `/presets/${name}`, ttl ? { ttl: +ttl } : {});
  const p = presetInfo.find((x) => x.name === name);
  toast(`${p ? p.title : name} allowed ${r && r.expires ? `for ${fmtLeft(r.expires)}` : "until undone"}`); await loadPolicy();
}
async function undoPreset(name) {
  await gw("DELETE", `/presets/${name}`);
  const p = presetInfo && presetInfo.find((x) => x.name === name);
  toast(`${p ? p.title : name} undone`); await loadPolicy();
}
// The panel is updated in place on every policy event: cards and buttons are built once per preset, so a
// chosen duration, the keyboard focus and an armed button survive changes made elsewhere.
function hideKeepingFocus(el, fallback) {
  if (el.classList.contains("hidden")) return;
  const had = el.contains(document.activeElement);
  el.classList.add("hidden");
  if (had && fallback) fallback.focus();
}
async function renderQuick() {
  if (!presetInfo) presetInfo = await gw("GET", "/presets?details=1");
  // active shortcuts (internet) with their remaining time
  const box = $("#qaActive");
  if (!box.firstElementChild) box.innerHTML = '<h4 class="hidden">Active shortcuts</h4>';
  let anyActive = false;
  for (const p of presetInfo.filter((x) => x.category === "internet")) {
    let row = $(`:scope > .row[data-preset="${CSS.escape(p.name)}"]`, box);
    if (!row) {
      row = document.createElement("div"); row.className = "row hidden"; row.dataset.preset = p.name;
      row.innerHTML = `<b>${esc(p.title)}</b><span class="status warn">active</span><span class="muted left-text"></span>`;
      const b = document.createElement("button"); b.className = "small ghost"; b.textContent = "Undo";
      b.setAttribute("aria-label", `Undo ${p.title}`);
      b.onclick = guard(() => undoPreset(p.name)); row.appendChild(b); box.appendChild(row);
    }
    const on = presetRules(p.name), exp = presetExpiry(on);
    if (on.length) {
      anyActive = true; row.classList.remove("hidden");
      $(".left-text", row).textContent = exp ? `ends in ${fmtLeft(exp)}` : "until undone";
    } else hideKeepingFocus(row, $(`#quick [data-preset="${CSS.escape(p.name)}"]`) || $("#qaStop"));
  }
  $(":scope > h4", box).classList.toggle("hidden", !anyActive);
  // templates
  const tpls = $("#qaTemplates");
  for (const p of presetInfo.filter((x) => x.category === "template")) {
    let el = $(`:scope > .tpl[data-preset="${CSS.escape(p.name)}"]`, tpls);
    if (!el) {
      el = document.createElement("div"); el.className = "tpl"; el.dataset.preset = p.name;
      el.innerHTML = `<div class="row-between"><b>${esc(p.title)}</b><span class="status ok state hidden"></span></div>
        <p class="meta">${esc(p.description)}</p>
        <p class="meta"><code>${p.rules.map((r) => esc(r.host || r.cidr) + (r.port && r.port !== "*" ? ":" + esc(portText(r.port)) : "")).join("</code> <code>")}</code></p>
        <div class="btns"><select aria-label="Duration for ${esc(p.title)}">${TTL_CHOICES.map(([v, t]) => `<option value="${v}">${t}</option>`).join("")}</select></div>`;
      const apply = document.createElement("button"); apply.className = "small secondary apply";
      apply.onclick = guard(() => applyPreset(p.name, $("select", el).value));
      const undo = document.createElement("button"); undo.className = "small ghost undo hidden"; undo.textContent = "Undo";
      undo.setAttribute("aria-label", `Undo ${p.title}`);
      undo.onclick = guard(() => undoPreset(p.name));
      $(".btns", el).append(apply, undo); tpls.appendChild(el);
    }
    const on = presetRules(p.name), exp = presetExpiry(on);
    const apply = $(".apply", el), state = $(".state", el);
    apply.textContent = on.length ? `Allow ${p.title} again` : `Allow ${p.title}`;
    state.textContent = on.length ? `active${exp ? ` · ends in ${fmtLeft(exp)}` : ""}` : "";
    state.classList.toggle("hidden", !on.length);
    if (on.length) $(".undo", el).classList.remove("hidden");
    else hideKeepingFocus($(".undo", el), apply);  // Undo done: focus goes to Allow on the same card
  }
}
$$("#quick [data-preset]").forEach((b) => (b.onclick = guard(() => applyPreset(b.dataset.preset, b.dataset.ttl))));
const STOP_STEPS = {
  suspend_auto_approval: "Automatic grant approval suspended", revoke_grants: "Active grants revoked",
  deny_pending: "Waiting connections denied", deny_grant_requests: "Grant requests denied",
  remove_internet_presets: "Internet shortcuts removed", end_learning: "Learning mode ended", mode_deny: "Unknown destinations blocked",
};
function showStopResult(r) {
  const box = $("#qaStopResult"); box.classList.remove("hidden");
  box.innerHTML = `<b>${r.ok ? "Emergency stop complete" : "Emergency stop incomplete: check the failed steps"}</b><ul>${r.steps.map((s) => {
    const n = ["revoked", "denied", "removed"].map((k) => s[k]).find(Array.isArray);
    return `<li><span class="status ${s.ok ? "ok" : "bad"}">${s.ok ? "done" : "failed"}</span> ${esc(STOP_STEPS[s.step] || s.step)}${n ? ` (${n.length})` : ""}` +
      `${(s.errors || []).length ? `: ${esc(s.errors.join("; "))}` : ""}</li>`;
  }).join("")}</ul>`;
}
$("#qaStop").onclick = confirmClick($("#qaStop"), "Revoke all grants, deny everything pending, undo the internet shortcuts and block everything unknown?", async () => {
  const r = await gw("POST", "/emergency-stop", {});
  showStopResult(r); toast(r.ok ? "Emergency stop: unknown destinations are blocked" : "Emergency stop incomplete", !r.ok);
  await Promise.allSettled([loadPolicy(true), loadGrants(), loadPending()]);
});
// Local network (#198, ADR-0019): a short form that creates a grant for one device directly, with the host as
// given. A target that is an IP is an address and may be local; one that is only a name cannot open a blocked
// range - the gateway refuses it with the address to use instead, and that explanation is shown under the form.
function lanError(msg) {
  const box = $("#qaLanError"); box.textContent = msg || ""; box.classList.toggle("hidden", !msg);
}
$("#qlKind").onchange = () => {
  const tcp = $("#qlKind").value === "tcp";  // raw TCP cannot be limited to reading
  $("#qlAccess").options[0].disabled = tcp; if (tcp) $("#qlAccess").value = "full";
};
$("#qaLanForm").onsubmit = guard(async (e) => {
  e.preventDefault();
  const name = $("#qlName").value.trim(), kind = $("#qlKind").value, full = $("#qlAccess").value === "full" || kind === "tcp";
  if (!/^[a-z0-9][a-z0-9_-]{0,47}$/.test(name)) throw new Error("Name: lower case letters, digits, - and _");
  if (grants.defs.some((d) => d.name === name)) throw new Error(`A grant named ${name} exists already: edit it on the Grants tab`);
  const target = { scheme: kind, host: $("#qlHost").value.trim(), port: Number($("#qlPort").value) };
  if (kind !== "tcp") target.paths = ["/*"];
  const levels = kind === "tcp" ? ["write"] : full ? ["read", "write"] : ["read"];
  lanError("");
  try {
    await gw("PUT", `/destinations/grant/${encodeURIComponent(name)}`, {
      description: "Device on the local network", levels, approval: Object.fromEntries(levels.map((l) => [l, "ask"])),
      default_ttl: $("#qlDur").value, max_ttl: $("#qlDur").value, targets: [target] });
  } catch (err) {
    lanError(err.message);  // e.g. the name resolves into a blocked range: says which address to enter instead
    throw err;
  }
  toast(`Grant ${name} created`); e.target.reset(); await loadGrants();
});

/* ---------------- grants ---------------- */
let grants = { defs: [], active: [], requests: [], missing_secrets: {} };
const fmtLeft = (exp) => { const s = Math.max(0, Math.round(exp - Date.now() / 1000)); return s > 5400 ? `${Math.round(s / 3600)} h` : s > 90 ? `${Math.round(s / 60)} min` : `${s} s`; };
async function loadGrants() {
  grants = await gw("GET", "/grants");
  renderGrantRequests(); renderGrants();
}
function grantTargets(d) {
  return d.targets.map((t) => `<code>${esc(t.scheme)}://${esc(t.host)}:${esc(t.port)}${t.paths && t.paths.join(",") !== "/*" ? esc(" " + t.paths.join(",")) : ""}</code>${t.address ? ` <span class="muted">at ${esc(t.address)}</span>` : ""}${t.local ? ' <span class="tag">local</span>' : ""}`).join("<br>");
}
function renderGrantRequests() {
  syncCards($("#grantReqList"), grants.requests, grantRequestCard);
  $("#grantReqBox").classList.toggle("hidden", !$("#grantReqList").children.length);
  updateBadges(); tickCountdowns();
}
function grantRequestCard(r) {
  const d = grants.defs.find((x) => x.name === r.name) || { targets: [], levels: [], description: "" };
  const el = document.createElement("div"); el.className = "pending grantreq";
  el.innerHTML = `<div class="dest"><span class="tag">grant</span> ${esc(r.name)} <span class="tag">${esc(r.level)}</span> for ${esc(r.ttl_label)}</div>
    <div class="meta">${esc(d.description)}</div><div class="meta">${grantTargets(d)}</div>
    <div class="meta claim"><span class="claim-badge">claimed by the agent — unverified</span>
      <span class="claim-reason">${esc(r.reason || "(no reason given)")}</span></div>
    <div class="meta"><span class="countdown" data-exp="${Number(r.expires)}"></span></div><div class="btns"></div>`;
  const btn = (label, decision, cls = "") => {
    const b = document.createElement("button"); b.textContent = label; if (cls) b.className = cls; b.dataset.decision = decision;
    b.onclick = decide(el, async () => { await gw("POST", `/grant-requests/${r.id}/decide`, { decision }); await loadGrants(); });
    $(".btns", el).appendChild(b);
  };
  btn(`Allow ${r.level} for ${r.ttl_label}`, "approve");
  if (r.level === "write" && d.levels.includes("read")) btn("Allow read-only", "read", "secondary");
  btn("Deny", "deny", "secondary");
  return el;
}
function renderGrants() {
  const act = $("#activeGrants"); act.innerHTML = "";
  const sus = grants.auto_suspended;
  $("#autoSuspended").classList.toggle("hidden", !sus);
  if (sus) $("#autoSuspended").textContent = `Automatic approval is suspended since the emergency stop${sus.since ? " at " + fmtDate(sus.since) : ""}: every grant request needs you. Change the mode under Settings to resume it.`;
  $("#activeEmpty").classList.toggle("hidden", grants.active.length > 0);
  for (const a of grants.active) {
    const el = document.createElement("div"); el.className = "card row-between";
    el.innerHTML = `<div><b>${esc(a.name)}</b> <span class="tag">${esc(a.level)}</span> <span class="status ok">active</span>
      <span class="muted">· ends in <span class="left" data-exp="${Number(a.expires)}">${fmtLeft(a.expires)}</span> · by ${esc(a.approved_by)}${a.reason ? ` · “${esc(a.reason)}”` : ""}</span></div>`;
    const b = document.createElement("button"); b.textContent = "Revoke"; b.className = "small ghost danger";
    b.setAttribute("aria-label", `Revoke grant ${a.name}`);
    b.onclick = confirmClick(b, `Revoke grant ${a.name}? The agent loses this access at once.`, async () => {
      await gw("DELETE", `/active-grants/${a.id}`); toast(`Grant ${a.name} revoked`); await loadGrants();
    });
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
      ${missing.length ? `<div class="alert warn">Missing secret(s): ${esc(missing.join(", "))}. Save them under Secrets below.</div>` : ""}`;
    const btns = $(".btns", el);
    for (const lvl of d.levels) {
      const b = document.createElement("button"); b.className = "small ghost"; b.textContent = `Activate ${lvl}`;
      b.setAttribute("aria-label", `Activate ${lvl} for grant ${d.name}`);
      b.onclick = guard(async () => { await gw("POST", `/grants/${d.name}/activate`, { level: lvl }); toast(`Grant ${d.name} activated: ${lvl} for ${d.default_ttl}`); await loadGrants(); });
      btns.appendChild(b);
    }
    if (d.source === "ui") {
      const e = document.createElement("button"); e.className = "small ghost"; e.textContent = "Edit"; e.setAttribute("aria-label", `Edit grant ${d.name}`); e.onclick = () => openGrantEditor(d); btns.appendChild(e);
      const x = document.createElement("button"); x.className = "small ghost danger"; x.textContent = "Delete";
      x.setAttribute("aria-label", `Delete grant ${d.name}`);
      x.onclick = confirmClick(x, `Delete grant ${d.name}?`, async () => { await gw("DELETE", `/destinations/grant/${d.name}`); toast(`Grant ${d.name} deleted`); await loadGrants(); });
      btns.appendChild(x);
    }
    defs.appendChild(el);
  }
  if (!grants.defs.length) defs.innerHTML = '<p class="empty">No grants defined yet. Create the first one below.</p>';
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
  row.innerHTML = `<select class="t-scheme" aria-label="Scheme"><option>https</option><option>http</option><option>tcp</option></select>
    <input class="t-host" aria-label="Host" placeholder="ha.lan or 192.168.1.5"><input class="t-port" type="number" min="1" max="65535" aria-label="Port">
    <input class="t-paths" aria-label="Paths" placeholder="Paths, e.g. /api/*">
    <input class="t-address" aria-label="Fixed IP (optional)" placeholder="Fixed IP (optional)"><input class="t-fp" aria-label="SHA-256 certificate fingerprint (optional)" placeholder="SHA-256 cert fingerprint (optional)">
    <button class="small ghost t-del" aria-label="Remove target">Remove</button>`;
  $(".t-scheme", row).value = t.scheme; $(".t-host", row).value = t.host; $(".t-port", row).value = t.port;
  $(".t-paths", row).value = (t.paths || ["/*"]).join(", ");
  $(".t-address", row).value = t.address || ""; $(".t-fp", row).value = t.tls_fingerprint || "";
  $(".t-del", row).onclick = () => row.remove();
  return row;
}
// The simple form (#121): address, type, access, duration, local network. It writes into the controls under
// "Advanced", which are what is saved; changes made there are shown back in the simple form.
const GE_PORTS = { https: 443, http: 80 };
function parseGrantAddress(value) {
  let v = value.trim(), scheme = null, path = null;
  const m = v.match(/^([a-z][a-z0-9+.-]*):\/\/(.*)$/i);
  if (m) { scheme = m[1].toLowerCase(); v = m[2]; }
  const slash = v.indexOf("/");
  if (slash >= 0) { path = v.slice(slash).split(/[?#]/)[0]; v = v.slice(0, slash); }
  let host = v, port = null;
  const bracket = v.match(/^\[([^\]]+)\](?::(\d+))?$/);  // [IPv6]:port
  if (bracket) { host = bracket[1]; port = bracket[2]; } else if (v.indexOf(":") > 0 && v.indexOf(":") === v.lastIndexOf(":")) {
    host = v.slice(0, v.indexOf(":")); port = v.slice(v.indexOf(":") + 1);
  }
  return { scheme, host: host.toLowerCase(), port: port ? Number(port) : null, path };
}
function grantSimpleToAdvanced() {
  const a = parseGrantAddress($("#geAddr").value);
  if (a.scheme) $("#geKind").value = a.scheme in GE_PORTS ? a.scheme : "tcp";  // ssh://, postgres://, ...
  const kind = $("#geKind").value;
  if (!$("#geTargets .target-row")) $("#geTargets").appendChild(targetRow());
  const row = $("#geTargets .target-row");
  $(".t-scheme", row).value = kind; $(".t-host", row).value = a.host;
  $(".t-port", row).value = a.port || GE_PORTS[kind] || (a.scheme === "ssh" ? 22 : "");
  if (kind !== "tcp" && a.path && a.path !== "/") $(".t-paths", row).value = a.path.endsWith("/") ? `${a.path}*` : `${a.path}, ${a.path}/*`;
  if (kind === "tcp") $("#geAccess").value = "full";  // no protocol visibility: read-only cannot be enforced
  $("#geAccess").options[0].disabled = kind === "tcp";
  const full = $("#geAccess").value === "full";
  $("#geRead").checked = kind !== "tcp"; $("#geWrite").checked = full;
  $("#geAccessHint").textContent = kind === "tcp" ? "Raw TCP passes through as-is, so it cannot be limited to reading."
    : full ? "Full access: every request method — the agent can change things. You can still approve read-only each time."
      : "Read-only: GET, HEAD and OPTIONS only — the agent can look but not change anything.";
  $("#geTtl").value = $("#geDur").value; $("#geMaxTtl").value = $("#geDur").value;
}
function grantAdvancedToSimple() {
  const rows = $$("#geTargets .target-row"), row = rows[0];
  const kind = row ? $(".t-scheme", row).value : "https";
  $("#geKind").value = kind;
  const host = row ? $(".t-host", row).value.trim() : "", port = row ? $(".t-port", row).value : "";
  $("#geAddr").value = host ? `${host.includes(":") ? `[${host}]` : host}${port ? `:${port}` : ""}` : "";
  $("#geAccess").options[0].disabled = kind === "tcp";
  $("#geAccess").value = $("#geWrite").checked ? "full" : "read";
  const dur = $("#geTtl").value.trim();
  if (dur && ![...$("#geDur").options].some((o) => o.value === dur)) $("#geDur").add(new Option(dur, dur));
  if (dur) $("#geDur").value = dur;
  const special = rows.length > 1 || $("#geApprRead").value === "auto" || $("#geApprWrite").value === "auto"
    || $("#geTtl").value.trim() !== $("#geMaxTtl").value.trim()
    || rows.some((r) => $(".t-address", r).value.trim() || $(".t-fp", r).value.trim()
      || ($(".t-scheme", r).value !== "tcp" && $(".t-paths", r).value.trim() !== "/*"));
  $("#geSimpleNote").classList.toggle("hidden", !special);
  return special;
}
["#geAddr", "#geKind", "#geAccess", "#geDur"].forEach((id) => { $(id).oninput = grantSimpleToAdvanced; $(id).onchange = grantSimpleToAdvanced; });
$("#geAdvanced").addEventListener("change", grantAdvancedToSimple);
$("#geAdvanced").addEventListener("click", (e) => { if (e.target.closest(".t-del, #geAddTarget")) setTimeout(grantAdvancedToSimple); });

function openGrantEditor(d) {
  const ed = $("#grantEditor"); ed.classList.remove("hidden");
  $("#geTitle").textContent = d ? `Edit grant ${d.name}` : "Create grant";
  $("#geName").value = d ? d.name : ""; $("#geName").disabled = !!d;
  $("#geDesc").value = d ? d.description : "";
  $("#geRead").checked = d ? d.levels.includes("read") : true; $("#geWrite").checked = d ? d.levels.includes("write") : false;
  $("#geApprRead").value = d?.approval?.read || "ask"; $("#geApprWrite").value = d?.approval?.write || "ask";
  $("#geTtl").value = d ? d.default_ttl : "1h"; $("#geMaxTtl").value = d ? d.max_ttl : "4h";
  $("#geTargets").innerHTML = ""; (d ? d.targets : [undefined]).forEach((t) => $("#geTargets").appendChild(targetRow(t)));
  if (!d) { $("#geAddr").value = ""; $("#geKind").value = "https"; $("#geAccess").value = "read"; $("#geDur").value = "1h"; grantSimpleToAdvanced(); }
  $("#geAdvanced").open = grantAdvancedToSimple();  // open "Advanced" when the grant uses more than the simple form shows
  ed.scrollIntoView({ behavior: "smooth" });
}
$("#grantNew").onclick = () => openGrantEditor(null);
$("#geAddTarget").onclick = () => $("#geTargets").appendChild(targetRow());
$("#geCancel").onclick = () => $("#grantEditor").classList.add("hidden");
$("#geSave").onclick = guard(async () => {
  const name = $("#geName").value.trim();
  const levels = [["read", "#geRead"], ["write", "#geWrite"]].filter(([, id]) => $(id).checked).map(([l]) => l);
  const approval = {}; if (levels.includes("read")) approval.read = $("#geApprRead").value; if (levels.includes("write")) approval.write = $("#geApprWrite").value;
  const targets = $$("#geTargets .target-row").map((r) => {
    const t = { scheme: $(".t-scheme", r).value, host: $(".t-host", r).value.trim(), port: Number($(".t-port", r).value) };
    if (t.scheme !== "tcp") t.paths = $(".t-paths", r).value.split(",").map((x) => x.trim()).filter(Boolean);
    if ($(".t-address", r).value.trim()) t.address = $(".t-address", r).value.trim();
    if ($(".t-fp", r).value.trim()) t.tls_fingerprint = $(".t-fp", r).value.trim();
    return t;
  });
  const body = { description: $("#geDesc").value.trim(), levels, approval, default_ttl: $("#geTtl").value.trim(), max_ttl: $("#geMaxTtl").value.trim(), targets };
  await gw("PUT", `/destinations/grant/${encodeURIComponent(name)}`, body);
  $("#grantEditor").classList.add("hidden"); toast(`Grant ${name} saved`); await loadGrants();
});

async function loadSecrets() {
  const sec = await gw("GET", "/secrets"); const list = $("#secretList"); list.innerHTML = "";
  for (const n of sec.names) {
    const row = document.createElement("div"); row.className = "row-between";
    row.innerHTML = `<code>${esc(n)}</code>`;
    const b = document.createElement("button"); b.className = "small ghost danger"; b.textContent = "Delete";
    b.setAttribute("aria-label", `Delete secret ${n}`);
    b.onclick = confirmClick(b, `Delete secret ${n}? Grants that inject it stop working until it is saved again.`, async () => {
      await gw("PUT", `/secrets/${n}`, { value: "" }); toast(`Secret ${n} deleted`); await loadSecrets();
    });
    row.appendChild(b); list.appendChild(row);
  }
  if (!sec.names.length) list.innerHTML = '<p class="empty">No secrets saved yet. Add one with the form below.</p>';
}
$("#secSave").onclick = guard(async () => {
  const name = $("#secName").value.trim(), value = $("#secValue").value;
  if (!name || !value) return;
  await gw("PUT", `/secrets/${encodeURIComponent(name)}`, { value });
  $("#secName").value = ""; $("#secValue").value = ""; toast(`Secret ${name} saved`); await loadSecrets(); await loadGrants();
});

/* ---------------- console ---------------- */
// Which console is open is a state, so it is a select, not a row of buttons with a "selected" look.
const TERM_TEXT = {
  rc: "rc: the Remote Control server (answer its prompts here)", bash: "bash: a shell in the agent",
  claude: "claude: interactive Claude Code",
};
function openTerm(name) {
  showTab("console"); $("#termFrame").src = `/term/${encodeURIComponent(name)}/`;
  const sel = $("#termSelect"); if (sel) sel.value = name;
}

/* ---------------- live stream ---------------- */
let streamOpened = false;
// Connection state in words as well as colour.
function setConn(ok) { $("#conn").classList.toggle("ok", ok); $("#connText").textContent = ok ? "live" : "reconnecting"; }
// After every (re)connect, reload what may have changed during the gap (sleep, network change, gateway
// restart): otherwise asks and grant requests from the gap stay invisible until they are auto-denied.
function connectStream() {
  const es = new EventSource("/api/stream");
  es.onopen = () => {
    setConn(true);
    if (streamOpened) {
      loadPending().catch(() => {}); loadGrants().catch(() => {});
      if (policy) loadPolicy(true).catch(() => {});  // rule changes during the gap
      if (logLoaded) loadLog().catch(() => {});
      document.dispatchEvent(new CustomEvent("tg:reconnected"));
    }
    streamOpened = true;
  };
  es.onerror = () => {
    setConn(false);
    if (es.readyState !== EventSource.CLOSED) return;  // the browser retries by itself
    // Closed for good (e.g. 401 after the session ended): api() sends us to the login page on 401.
    setTimeout(() => api("GET", "/api/meta").then(connectStream, connectStream), 3000);
  };
  es.onmessage = (m) => {
    const ev = JSON.parse(m.data);
    window.dispatchEvent(new CustomEvent("tg:event", { detail: ev }));  // for feature scripts (overview.js, ...)
    document.dispatchEvent(new CustomEvent("tg:event", { detail: ev }));  // hook for the feature scripts
    if (ev.type === "event") addLogRow(ev.event);
    if (ev.type === "ask" || ev.type === "resolved") loadPending().catch(() => {});
    if (ev.type === "ask" && document.hidden && Notification?.permission === "granted") new Notification("tallygate: approval needed", { body: `${ev.pending.host}:${ev.pending.port}` });
    if (ev.type === "policy" && !$("#tab-destinations").classList.contains("hidden")) loadPolicy(true).catch(() => {});
    if (["grant_request", "grant_resolved", "grants"].includes(ev.type)) loadGrants().catch(() => {});
    if (ev.type === "grant_request" && document.hidden && Notification?.permission === "granted") new Notification("tallygate: grant requested", { body: `${ev.request.name} (${ev.request.level})` });
  };
}

/* ---------------- init ---------------- */
(async () => {
  const meta = await api("GET", "/api/meta");
  const terms = meta.terminals || [];
  $("#termButtons").innerHTML = terms.length
    ? `<label class="inline">Connect to <select id="termSelect"><option value="">Choose a console…</option>${terms.map((n) =>
      `<option value="${esc(n)}">${esc(TERM_TEXT[n] || n)}</option>`).join("")}</select></label>`
    : '<p class="empty">No console is available: the agent reported none.</p>';
  if (terms.length) $("#termSelect").onchange = (e) => { if (e.target.value) openTerm(e.target.value); };
  await loadPending().catch((e) => toast(e.message, true));
  await loadGrants().catch((e) => toast(e.message, true));
  connectStream();
  showTab(location.hash.slice(1) || "overview");
})();
