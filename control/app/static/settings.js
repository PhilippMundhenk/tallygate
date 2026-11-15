"use strict";
/* Behaviour settings the UI owns (ADR-0015): GET /settings shows the values, defaults and which need a
   restart; PATCH /settings saves them. Trust-critical settings stay file-only and are not shown here.
   Uses app.js helpers: $, esc, gw, toast, guard. */
(() => {
  const box = $("#settingsBox"), card = $("#settingsCard");
  if (!box || !card) return;
  const LABELS = {
    log_keep_days: "Log retention (days)",
    log_max_events: "Log size cap (events)",
    learning_ports: "Learning ports",
    learning_max_minutes: "Learning session limit (minutes)",
    rule_stale_days: "Rule unused after (days)",
    suggest_min_approvals: "Suggest a rule after (approvals)",
    suggest_window_days: "Suggestion window (days)",
    grant_request_timeout: "Grant request timeout (s)",
    grant_max_pending: "Maximum waiting grant requests",
    policy_history_keep: "Policy versions kept",
    max_pending: "Maximum waiting connection requests",
  };
  let model = null;

  function render() {
    const restart = new Set(model.restart_keys);
    const rows = Object.keys(LABELS).map((k) => {
      const v = model.values[k];
      const val = k === "learning_ports" ? (Array.isArray(v) ? v.join(", ") : v) : v;
      const note = restart.has(k) ? ' <span class="tag">restart</span>' : "";
      const def = model.defaults[k];
      const defTxt = k === "learning_ports" ? [].concat(def).join(", ") : def;
      return `<label>${esc(LABELS[k])}${note}
        <input class="s-field" data-key="${k}" value="${esc(String(val))}" aria-label="${esc(LABELS[k])}">
        <small class="muted">Default ${esc(String(defTxt))}</small></label>`;
    }).join("");
    box.innerHTML = `<div class="grid2">${rows}</div><div class="row"><button id="settingsSave">Save settings</button>
      <span id="settingsMsg" class="muted" role="status"></span></div>`;
    $("#settingsSave").onclick = guard(save);
  }

  async function save() {
    const changes = {};
    for (const el of box.querySelectorAll(".s-field")) {
      const k = el.dataset.key, raw = el.value.trim();
      if (k === "learning_ports") changes[k] = raw.split(",").map((x) => x.trim()).filter(Boolean).map(Number);
      else changes[k] = Number(raw);
    }
    const res = await gw("PATCH", "/settings", changes);
    model = res; render();
    const r = res.restart_needed || [];
    toast(r.length ? `Settings saved. Restart the gateway for: ${r.join(", ")}` : "Settings saved");
  }

  async function load() {
    const m = await gw("GET", "/settings");
    if (!m || !m.values) return;  // an older gateway without the route
    model = m; render();
  }
  card.addEventListener("toggle", () => { if (card.open) load().catch(() => {}); });
})();
