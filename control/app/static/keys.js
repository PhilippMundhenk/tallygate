"use strict";
/* Keyboard shortcuts, compact approval list and sound (#79).
   Keys (on the Approvals tab): j / k select the next / previous request, a Allow once / 2 min (approve a grant request),
   h allow 1 h, d deny, ? shows the keys (anywhere). Single-key shortcuts can be switched off (WCAG 2.1.4). Settings
   are kept in this browser only (localStorage). */
const KEY_SETTINGS = { keys: true, compact: false, sound: false };
const keyStore = {
  get(k) { try { const v = localStorage.getItem("tallygate." + k); return v === null ? KEY_SETTINGS[k] : v === "1"; } catch { return KEY_SETTINGS[k]; } },
  set(k, v) { try { localStorage.setItem("tallygate." + k, v ? "1" : "0"); } catch { /* private mode: not kept */ } },
};
const KEYS = [["j", "next request"], ["k", "previous request"], ["a", "Allow once / 2 min (grant request: approve)"],
  ["h", "allow 1 h"], ["d", "deny"], ["?", "show these keys"], ["Esc", "close this list"]];

(() => {
  const opts = $("#approvalOpts");
  const box = (id, label, help) => `<label title="${esc(help)}"><input type="checkbox" id="${id}"> ${esc(label)}</label>`;
  opts.innerHTML = box("optKeys", "Keyboard shortcuts", "j/k select, a/h/d decide, ? lists the keys")
    + box("optCompact", "Compact list", "One line per connection request")
    + box("optSound", "Sound", "A short tone when a request arrives while this tab is in the background")
    + '<button id="keysBtn" class="small secondary" aria-haspopup="dialog">Keys (?)</button>';
  const dlg = document.createElement("dialog"); dlg.id = "keysHelp"; dlg.setAttribute("aria-labelledby", "keysTitle");
  dlg.innerHTML = `<h3 id="keysTitle">Keyboard shortcuts</h3><dl class="fieldhelp">${KEYS.map(([k, t]) => `<dt><kbd>${esc(k)}</kbd></dt><dd>${esc(t)}</dd>`).join("")}</dl>
    <p class="hint">On the Approvals tab, outside text fields. a, h and d act on the selected request; without a
      selection they select the first one. Switch them off with <i>Keyboard shortcuts</i>.</p>
    <form method="dialog"><button>Close</button></form>`;
  document.body.appendChild(dlg);
  for (const [id, k] of [["#optKeys", "keys"], ["#optCompact", "compact"], ["#optSound", "sound"]]) {
    $(id).checked = keyStore.get(k);
    $(id).addEventListener("change", () => { keyStore.set(k, $(id).checked); applyKeyOpts(); if (k === "sound" && $(id).checked) beep(); });
  }
  $("#keysBtn").onclick = () => dlg.showModal();
  applyKeyOpts();
})();

function applyKeyOpts() { $("#tab-approvals").classList.toggle("compact", $("#optCompact").checked); }

/* ---- selection ---- */
const cards = () => $$("#grantReqList > .pending:not(.gone):not(.busy), #pendingList > .pending:not(.gone):not(.busy)");
let selectedId = null;
function select(el) {
  $$(".pending.kbd-sel").forEach((c) => c.classList.remove("kbd-sel"));
  selectedId = el ? el.dataset.id : null;
  if (!el) return;
  el.classList.add("kbd-sel"); el.tabIndex = -1; el.focus({ preventScroll: true });
  el.scrollIntoView({ block: "nearest" });
}
// Cards are rebuilt when their request changes (app.js syncCards): keep the selection on the same request.
const keepSelection = new MutationObserver(() => {
  const el = selectedId && cards().find((c) => c.dataset.id === selectedId);
  if (el && !el.classList.contains("kbd-sel")) { el.classList.add("kbd-sel"); el.tabIndex = -1; }
});
["#grantReqList", "#pendingList"].forEach((s) => keepSelection.observe($(s), { childList: true }));
function move(step) {
  const list = cards(); if (!list.length) return;
  const i = list.findIndex((c) => c.dataset.id === selectedId);
  select(list[i < 0 ? (step > 0 ? 0 : list.length - 1) : Math.min(list.length - 1, Math.max(0, i + step))]);
}
function act(key) {
  const list = cards(), i = list.findIndex((c) => c.dataset.id === selectedId);
  if (i < 0) {
    if (list.length) { select(list[0]); toast(`Selected the first request: press ${key} again to decide`); } else toast("Nothing waiting");
    return;
  }
  const el = list[i], grant = el.classList.contains("grantreq");
  const sel = grant ? { a: '[data-decision="approve"]', d: '[data-decision="deny"]' }[key]
    : { a: '[data-scope="once"]', h: '[data-scope="hour"]', d: '[data-scope="deny"]' }[key];
  const btn = sel && $(sel, el);
  if (!btn) { toast(`"${key}" does not apply to a grant request: use a or d`, true); return; }
  const next = list[i + 1] || list[i - 1] || null;
  btn.click();
  select(next);
}

document.addEventListener("keydown", (e) => {
  if (!$("#optKeys").checked || e.defaultPrevented || e.ctrlKey || e.metaKey || e.altKey) return;
  const t = e.target;
  if (t.closest && t.closest("input:not([type=checkbox]):not([type=radio]), textarea, select, [contenteditable], dialog")) return;
  if (e.key === "?") { e.preventDefault(); $("#keysHelp").showModal(); return; }
  if ($("#tab-approvals").classList.contains("hidden") || !"jkahd".includes(e.key) || e.key.length !== 1) return;
  e.preventDefault();
  if (e.key === "j") move(1); else if (e.key === "k") move(-1); else act(e.key);
});

/* ---- sound ---- */
let audioCtx = null;
function beep() {
  try {
    audioCtx = audioCtx || new (window.AudioContext || window.webkitAudioContext)();
    if (audioCtx.state === "suspended") audioCtx.resume();
    const o = audioCtx.createOscillator(), g = audioCtx.createGain(), now = audioCtx.currentTime;
    o.frequency.value = 880; g.gain.setValueAtTime(0.0001, now);
    g.gain.exponentialRampToValueAtTime(0.2, now + 0.02); g.gain.exponentialRampToValueAtTime(0.0001, now + 0.35);
    o.connect(g).connect(audioCtx.destination); o.start(now); o.stop(now + 0.4);
  } catch { /* no audio in this browser */ }
}
window.addEventListener("tg:event", (e) => {
  if ($("#optSound").checked && document.hidden && ["ask", "grant_request"].includes(e.detail.type)) beep();
});
