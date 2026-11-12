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
function showTab(name) {
  $$("main > section").forEach((s) => s.classList.toggle("hidden", s.id !== "tab-" + name));
  $$("#tabs button").forEach((b) => {
    const on = b.dataset.tab === name;
    b.classList.toggle("active", on); b.setAttribute("aria-selected", String(on)); b.tabIndex = on ? 0 : -1;
  });
  history.replaceState(null, "", "#" + name);
  if (name === "rules") guard(loadPolicy)();
  if (name === "grants") { guard(loadGrants)(); guard(loadSecrets)(); }
  if (name === "setup") guard(loadSetup)();
  if (name === "log" && !logLoaded) guard(loadLog)();
}
$$("#tabs button").forEach((b) => b.addEventListener("click", () => showTab(b.dataset.tab)));
$("#tabs").addEventListener("keydown", (e) => {  // arrow keys move between tabs (WAI-ARIA tabs pattern)
  const tabs = $$("#tabs button"), i = tabs.indexOf(document.activeElement);
  if (i < 0 || !["ArrowLeft", "ArrowRight", "Home", "End"].includes(e.key)) return;
  const j = e.key === "Home" ? 0 : e.key === "End" ? tabs.length - 1 : (i + (e.key === "ArrowRight" ? 1 : -1) + tabs.length) % tabs.length;
  e.preventDefault(); tabs[j].focus(); showTab(tabs[j].dataset.tab);
});

/* ---------------- approvals ---------------- */
const SCOPES = [["once", "Allow 2 min", ""], ["hour", "Allow 1 h", ""], ["always", "Always (host)", ""],
  ["domain", "Always (*.domain)", ""], ["deny", "Deny", "secondary"], ["deny_always", "Block forever", "danger"]];
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
    ${p.domain && p.domain !== p.host ? `<div class="meta">domain <b>${esc(p.domain)}</b></div>` : ""}
    ${p.idn ? `<div class="meta warn">⚠ internationalised (punycode) name – check for look-alikes</div>` : ""}
    <div class="meta">${esc(p.proto)} · IPs ${esc((p.ips || []).join(", ") || "not resolved yet")} · attempts ${esc(p.attempts)} ·
    <span class="countdown" data-exp="${Number(p.expires)}"></span></div><div class="btns"></div>`;
  for (const [scope, label, cls] of SCOPES) {
    if (scope === "domain" && !p.domain) continue;  // no registrable domain (IP, public suffix)
    const b = document.createElement("button"); if (cls) b.className = cls;
    b.textContent = scope === "domain" ? `Always (*.${p.domain})` : label;
    b.onclick = decide(el, async () => { await gw("POST", `/pending/${p.id}/decide`, { scope }); await loadPending(); });
    $(".btns", el).appendChild(b);
  }
  document.dispatchEvent(new CustomEvent("tg:card", { detail: { el, item: p, kind: "ask" } }));  // feature scripts
  return el;
}
function tickCountdowns() {
  const now = Date.now() / 1000;
  $$(".countdown").forEach((c) => { const s = Math.max(0, Math.round(c.dataset.exp - now)); c.textContent = `auto-deny in ${s}s`; });
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
  const q = older && oldestId !== null ? `?limit=200&before=${oldestId}` : "?limit=200";
  const rows = await gw("GET", "/events" + q);
  rows.forEach((e) => addLogRow(e, !older));  // "Load older" may grow the table beyond 2000
  logLoaded = true;
  if (older && !rows.length) toast("No older events");
}
["#logFilter", "#logHideDns", "#logOnlyBlocked"].forEach((s) => $(s).addEventListener("input", () => $$("#logBody tr").forEach(applyLogFilter)));
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
const POLICY_FIELDS = ["#defaultAction", "#askTimeout", "#hardDeny", "#rawPolicy"];
POLICY_FIELDS.forEach((s) => $(s).addEventListener("input", () => ($(s).dataset.dirty = "1")));
function setField(sel, value, keepEdits) {
  const el = $(sel);
  if (keepEdits && el.dataset.dirty) { el.classList.add("stale"); el.title = "Changed elsewhere since you started editing"; return false; }
  el.value = value; delete el.dataset.dirty; el.classList.remove("stale"); el.title = "";
  return true;
}
let rawBase = null;  // the policy the raw editor's text was loaded from (JSON)
async function loadPolicy(keepEdits = false) {
  policy = await gw("GET", "/policy");
  setField("#defaultAction", policy.default, keepEdits); setField("#askTimeout", policy.ask_timeout, keepEdits);
  $("#hardDenyFloor").textContent = (policy.hard_deny_floor || []).join("  ");
  setField("#hardDeny", policy.hard_deny.join("\n"), keepEdits);
  if (setField("#rawPolicy", JSON.stringify(policy, null, 2), keepEdits)) rawBase = JSON.stringify(policy);
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
$("#saveHard").onclick = guard(async () => {
  const fresh = await gw("GET", "/policy");
  return putPolicy({ ...fresh, hard_deny: $("#hardDeny").value.split(/\s+/).filter(Boolean) });
});
$("#saveRaw").onclick = guard(async () => {
  let p;
  try { p = JSON.parse($("#rawPolicy").value); } catch (e) { throw new Error(`Invalid JSON: ${e.message}`); }
  const fresh = await gw("GET", "/policy");
  if (JSON.stringify(fresh) !== rawBase) {
    // Changed elsewhere since the text was loaded: saving it now would drop or revive rules. The text is kept;
    // a second click replaces the policy on purpose.
    rawBase = JSON.stringify(fresh);
    const el = $("#rawPolicy"); el.classList.add("stale"); el.title = "Changed elsewhere since you started editing";
    throw new Error("The policy was changed elsewhere since this text was loaded. Reload it, or click Replace policy again to overwrite.");
  }
  return putPolicy(p);
});
$("#reloadRaw").onclick = guard(async () => { delete $("#rawPolicy").dataset.dirty; await loadPolicy(true); });
$("#nrAdd").onclick = guard(async () => {
  checkMatch($("#nrKind").value, $("#nrMatch").value.trim());
  const rule = { action: $("#nrAction").value, [$("#nrKind").value]: $("#nrMatch").value.trim(), port: parsePort($("#nrPort").value) };
  if ($("#nrNote").value) rule.note = $("#nrNote").value;
  if (+$("#nrTtl").value > 0) rule.expires = Date.now() / 1000 + +$("#nrTtl").value;
  await gw("POST", "/rules", rule); $("#nrMatch").value = ""; await loadPolicy();
});
function explainTest(r) {
  // What decided, in the order the gateway checks (docs/rules.md#how-a-connection-is-decided).
  const idx = r.rule_id && policy ? policy.rules.findIndex((x) => x.id === r.rule_id) : -1;
  if (idx >= 0) {
    const rule = policy.rules[idx];
    return `Decided by rule #${idx + 1}: ${rule.action} ${rule.host || rule.cidr} port ${portText(rule.port)}` +
      (rule.source && rule.source !== "user" ? ` [${rule.source}]` : "") + " (the first matching rule from the top wins).";
  }
  if (r.rule_id === "hard_deny" || /hard-deny/.test(r.reason || ""))
    return "Decided by the hard deny: local network, Docker host or metadata addresses are never reachable. Use a grant for one device.";
  if (/invalid hostname/.test(r.reason || "")) return "Not a valid host name.";
  if (/^default/.test(r.reason || "")) return `No rule matched, so the mode decided (${policy ? policy.default : "default"}).`;
  return "";
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

/* ---------------- quick actions and templates ---------------- */
let presetInfo = null;
const presetRules = (name) => (policy ? policy.rules.filter((r) => r.source === `preset:${name}`) : []);
const TTL_CHOICES = [["", "until undone"], ["3600", "for 1 h"], ["86400", "for 1 day"]];
function presetExpiry(rules) {
  const exp = rules.map((r) => r.expires).filter(Boolean);
  return exp.length === rules.length && exp.length ? Math.max(...exp) : null;
}
async function applyPreset(name, ttl) {
  const r = await gw("POST", `/presets/${name}`, ttl ? { ttl: +ttl } : {});
  const p = presetInfo.find((x) => x.name === name);
  toast(`${p ? p.title : name} allowed ${r && r.expires ? `for ${fmtLeft(r.expires)}` : "until undone"}`); await loadPolicy();
}
async function undoPreset(name) { await gw("DELETE", `/presets/${name}`); toast("Undone"); await loadPolicy(); }
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
  $$("#quick [data-mode]").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.mode === policy.default)));
  // active shortcuts (internet) with their remaining time
  const box = $("#qaActive");
  if (!box.firstElementChild) box.innerHTML = '<h4 class="hidden">Active</h4>';
  let anyActive = false;
  for (const p of presetInfo.filter((x) => x.category === "internet")) {
    let row = $(`:scope > .row[data-preset="${CSS.escape(p.name)}"]`, box);
    if (!row) {
      row = document.createElement("div"); row.className = "row hidden"; row.dataset.preset = p.name;
      row.innerHTML = `<span class="tag warn">${esc(p.title)}</span><span class="muted left-text"></span>`;
      const b = document.createElement("button"); b.className = "small secondary"; b.textContent = "Undo";
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
      el.innerHTML = `<div class="row-between"><b>${esc(p.title)}</b><span class="tag state hidden"></span></div>
        <p class="meta">${esc(p.description)}</p>
        <p class="meta"><code>${p.rules.map((r) => esc(r.host || r.cidr) + (r.port && r.port !== "*" ? ":" + esc(portText(r.port)) : "")).join("</code> <code>")}</code></p>
        <div class="btns"><select aria-label="Duration for ${esc(p.title)}">${TTL_CHOICES.map(([v, t]) => `<option value="${v}">${t}</option>`).join("")}</select></div>`;
      const apply = document.createElement("button"); apply.className = "small apply";
      apply.onclick = guard(() => applyPreset(p.name, $("select", el).value));
      const undo = document.createElement("button"); undo.className = "small secondary undo hidden"; undo.textContent = "Undo";
      undo.setAttribute("aria-label", `Undo ${p.title}`);
      undo.onclick = guard(() => undoPreset(p.name));
      $(".btns", el).append(apply, undo); tpls.appendChild(el);
    }
    const on = presetRules(p.name), exp = presetExpiry(on);
    const apply = $(".apply", el), state = $(".state", el);
    apply.textContent = on.length ? "Apply again" : "Apply";
    apply.setAttribute("aria-label", on.length ? `Apply ${p.title} again` : `Apply ${p.title}`);
    state.textContent = on.length ? `active${exp ? `, ends in ${fmtLeft(exp)}` : ""}` : "";
    state.classList.toggle("hidden", !on.length);
    if (on.length) $(".undo", el).classList.remove("hidden");
    else hideKeepingFocus($(".undo", el), apply);  // Undo done: focus goes to Apply on the same card
  }
}
$$("#quick [data-preset]").forEach((b) => (b.onclick = guard(() => applyPreset(b.dataset.preset, b.dataset.ttl))));
$$("#quick [data-mode]").forEach((b) => {
  const set = () => patchPolicy({ default: b.dataset.mode });
  b.onclick = b.dataset.mode === "allow"
    ? confirmClick(b, "Allow every unknown public destination? The local network stays blocked; everything is still logged.", set)
    : guard(set);
});
const STOP_STEPS = {
  suspend_auto_approval: "Automatic grant approval suspended", revoke_grants: "Active grants revoked",
  deny_pending: "Waiting connections denied", deny_grant_requests: "Grant requests denied",
  remove_internet_presets: "Internet shortcuts removed", mode_deny: "Unknown destinations blocked",
};
function showStopResult(r) {
  const box = $("#qaStopResult"); box.classList.remove("hidden");
  box.innerHTML = `<b>${r.ok ? "Emergency stop complete" : "Emergency stop incomplete: check the failed steps"}</b><ul>${r.steps.map((s) => {
    const n = ["revoked", "denied", "removed"].map((k) => s[k]).find(Array.isArray);
    return `<li class="${s.ok ? "ok" : "bad"}">${s.ok ? "✔" : "✖"} ${esc(STOP_STEPS[s.step] || s.step)}${n ? ` (${n.length})` : ""}` +
      `${(s.errors || []).length ? `: ${esc(s.errors.join("; "))}` : ""}</li>`;
  }).join("")}</ul>`;
}
$("#qaStop").onclick = confirmClick($("#qaStop"), "Revoke all grants, deny everything pending, undo the internet shortcuts and block everything unknown?", async () => {
  const r = await gw("POST", "/emergency-stop", {});
  showStopResult(r); toast(r.ok ? "Emergency stop: unknown destinations are blocked" : "Emergency stop incomplete", !r.ok);
  await Promise.allSettled([loadPolicy(true), loadGrants(), loadPending()]);
});
$("#qaLan").onclick = guard(async () => {
  const g = await gw("GET", "/grants");
  const help = $("#qaLanHelp");
  if (!(g.lan_allow_ui || []).length) {
    help.innerHTML = `Grants created in the UI may only reach local addresses inside <code>grants_lan_allow</code>, which is
      empty. Add your home network to the gateway config and restart the gateway, e.g.
      <pre>grants_lan_allow: [192.168.1.0/24]</pre> (see <i>Configuration</i> in the docs), or define the grant in the
      config file itself.`;
    help.classList.remove("hidden"); return;
  }
  help.classList.add("hidden");
  showTab("grants");
  openGrantEditor(null);
  $("#geTargets").innerHTML = "";
  $("#geTargets").appendChild(targetRow({ scheme: "http", host: "", port: 80, lan: true }));
  $("#geDesc").value = "Device on the local network";
  toast(`Local targets must be inside ${g.lan_allow_ui.join(", ")}`);
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
  syncCards($("#grantReqList"), grants.requests, grantRequestCard);
  $("#grantReqBox").classList.toggle("hidden", !$("#grantReqList").children.length);
  updateBadges(); tickCountdowns();
}
function grantRequestCard(r) {
  const d = grants.defs.find((x) => x.name === r.name) || { targets: [], levels: [], description: "" };
  const el = document.createElement("div"); el.className = "pending grantreq";
  el.innerHTML = `<div class="dest">🔑 ${esc(r.name)} <span class="tag ${r.level === "write" ? "warn" : ""}">${esc(r.level)}</span> for ${esc(r.ttl_label)}</div>
    <div class="meta">${esc(d.description)}</div><div class="meta">${grantTargets(d)}</div>
    <div class="meta">Agent's reason: <i>${esc(r.reason || "(none given)")}</i></div>
    <div class="meta"><span class="countdown" data-exp="${Number(r.expires)}"></span></div><div class="btns"></div>`;
  const btn = (label, decision, cls = "") => {
    const b = document.createElement("button"); b.textContent = label; if (cls) b.className = cls;
    b.onclick = decide(el, async () => { await gw("POST", `/grant-requests/${r.id}/decide`, { decision }); await loadGrants(); });
    $(".btns", el).appendChild(b);
  };
  btn(`Approve ${r.level} (${r.ttl_label})`, "approve");
  if (r.level === "write" && d.levels.includes("read")) btn("Approve read-only", "read", "secondary");
  btn("Deny", "deny", "danger");
  return el;
}
function renderGrants() {
  const act = $("#activeGrants"); act.innerHTML = "";
  const sus = grants.auto_suspended;
  $("#autoSuspended").classList.toggle("hidden", !sus);
  if (sus) $("#autoSuspended").textContent = `Automatic approval is suspended since the emergency stop${sus.since ? " at " + fmtDate(sus.since) : ""}: every grant request needs you. Change the mode in the Rules tab to resume it.`;
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
      x.setAttribute("aria-label", `Delete grant ${d.name}`);
      x.onclick = confirmClick(x, `Delete grant ${d.name}?`, async () => { await gw("DELETE", `/grants/${d.name}`); await loadGrants(); });
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
  row.innerHTML = `<select class="t-scheme" aria-label="Scheme"><option>https</option><option>http</option><option>tcp</option></select>
    <input class="t-host" aria-label="Host" placeholder="ha.lan or 192.168.1.5"><input class="t-port" type="number" min="1" max="65535" aria-label="Port">
    <input class="t-paths" aria-label="Paths" placeholder="paths, e.g. /api/*"><label><input type="checkbox" class="t-lan"> LAN</label>
    <input class="t-address" aria-label="Fixed IP (optional)" placeholder="fixed IP (optional)"><input class="t-fp" aria-label="SHA-256 certificate fingerprint (optional)" placeholder="SHA-256 cert fingerprint (optional)">
    <button class="small secondary t-del" aria-label="Remove target">✕</button>`;
  $(".t-scheme", row).value = t.scheme; $(".t-host", row).value = t.host; $(".t-port", row).value = t.port;
  $(".t-paths", row).value = (t.paths || ["/*"]).join(", "); $(".t-lan", row).checked = !!t.lan;
  $(".t-address", row).value = t.address || ""; $(".t-fp", row).value = t.tls_fingerprint || "";
  $(".t-del", row).onclick = () => row.remove();
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
    if ($(".t-lan", r).checked) t.lan = true;
    if ($(".t-address", r).value.trim()) t.address = $(".t-address", r).value.trim();
    if ($(".t-fp", r).value.trim()) t.tls_fingerprint = $(".t-fp", r).value.trim();
    return t;
  });
  const body = { description: $("#geDesc").value.trim(), levels, approval, default_ttl: $("#geTtl").value.trim(), max_ttl: $("#geMaxTtl").value.trim(), targets };
  await gw("PUT", `/grants/${encodeURIComponent(name)}`, body);
  $("#grantEditor").classList.add("hidden"); toast(`Grant ${name} saved`); await loadGrants();
});

async function loadSecrets() {
  const sec = await gw("GET", "/secrets"); const list = $("#secretList"); list.innerHTML = "";
  for (const n of sec.names) {
    const row = document.createElement("div"); row.className = "row-between";
    row.innerHTML = `<code>${esc(n)}</code>`;
    const b = document.createElement("button"); b.className = "small danger"; b.textContent = "Remove";
    b.setAttribute("aria-label", `Remove secret ${n}`);
    b.onclick = confirmClick(b, `Remove secret ${n}?`, async () => { await gw("PUT", `/secrets/${n}`, { value: "" }); await loadSecrets(); });
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
    const repos = (info.github_repos || []).length ? ` · GitHub only for <code>${esc(info.github_repos.join(", "))}</code>` : "";
    setStatus("st-gw", `${info.ca_pem ? "✔ CA exported" : "✖ CA missing"} · injection for <code>${esc(info.inject_hosts.join(", ") || "none")}</code>${repos} · pending ${info.pending}`, info.ca_pem ? "ok" : "bad");
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
  const CHANNELS = { telegram: "Telegram", matrix: "Matrix", webpush: "Web Push", ntfy: "ntfy", gotify: "Gotify", pushover: "Pushover" };
  $("#notifyStatus").textContent = Object.entries(CHANNELS).filter(([k]) => k in meta.notify)
    .map(([k, n]) => `${n}: ${meta.notify[k] ? "on" : "off"}`).join(" · ") + " (chat and push services: configured via environment)";
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
$$(".wizard [data-term]").forEach((b) => (b.onclick = () => openTerm(b.dataset.term)));
$$("pre.copy").forEach((p) => (p.onclick = () => navigator.clipboard.writeText(p.textContent).then(() => toast("Copied"))));

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
    document.dispatchEvent(new CustomEvent("tg:event", { detail: ev }));  // for the feature scripts
    if (ev.type === "event") addLogRow(ev.event);
    if (ev.type === "ask" || ev.type === "resolved") loadPending().catch(() => {});
    if (ev.type === "ask" && document.hidden && Notification?.permission === "granted") new Notification("tallygate: approval needed", { body: `${ev.pending.host}:${ev.pending.port}` });
    if (ev.type === "policy" && !$("#tab-rules").classList.contains("hidden")) loadPolicy(true).catch(() => {});
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
  await loadPending().catch((e) => toast(e.message, true));
  await loadGrants().catch((e) => toast(e.message, true));
  connectStream();
  showTab(location.hash.slice(1) || "approvals");
})();
