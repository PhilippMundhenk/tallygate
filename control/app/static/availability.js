"use strict";
/* Availability (#73): away mode, quiet hours and what was refused meanwhile. Uses $, gw, esc, guard, toast and
   fmtDate from app.js; refreshed by the "tg:event" events app.js dispatches for every gateway stream message. */
(() => {
  const box = document.getElementById("availability");
  if (!box) return;
  const DAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];
  const AWAY_FOR = [["", "until I'm back"], ["3600", "for 1 h"], ["14400", "for 4 h"], ["morning", "until 08:00"]];
  const clock = (ts) => new Date(ts * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  let state = null;

  box.innerHTML = `<div class="row-between"><div><h2 class="inline-h">Availability</h2> <span class="tag" id="avState" role="status"></span></div>
      <div class="btns"><select id="avFor" aria-label="How long you are away">${AWAY_FOR.map(([v, t]) => `<option value="${v}">${t}</option>`).join("")}</select>
      <button id="avToggle" class="small"></button></div></div>
    <p class="hint">While you are away or in quiet hours, nothing waits for you: new destinations and grant requests that
      need your approval are refused at once, and the agent is told why. Nothing is allowed automatically. What was
      refused is listed here and sent as one digest when you are back.</p>
    <details id="avQuiet"><summary>Quiet hours: <span id="avQuietText"></span></summary>
      <div class="row wrap">
        <label class="check inline-check"><input type="checkbox" id="avQOn"> quiet hours on</label>
        <label class="inline">from <input type="time" id="avQStart" value="22:00"></label>
        <label class="inline">to <input type="time" id="avQEnd" value="07:00"></label>
      </div>
      <fieldset class="days"><legend>Starting on</legend>${DAYS.map((d) => `<label><input type="checkbox" value="${d}" checked> ${d}</label>`).join("")}</fieldset>
      <p class="hint" id="avZone"></p>
      <button id="avQSave" class="small">Save quiet hours</button>
    </details>
    <div id="avMissed" class="hidden"><h3>Refused while you were away <span id="avMissedN" class="badge"></span></h3>
      <div id="avMissedList"></div><button id="avMissedClear" class="small secondary">Dismiss all</button></div>`;

  // A small marker next to the brand, so the state is visible on every tab.
  const brand = document.querySelector("header .brand");
  const marker = document.createElement("span");
  marker.className = "tag warn hidden"; marker.id = "avMarker";
  if (brand) brand.after(marker);

  function awayUntil() {
    const v = $("#avFor").value;
    if (!v) return null;
    if (v === "morning") {
      const d = new Date(); d.setHours(8, 0, 0, 0);
      if (d <= new Date()) d.setDate(d.getDate() + 1);
      return Math.floor(d.getTime() / 1000);
    }
    return Math.floor(Date.now() / 1000) + Number(v);
  }

  function quietText(q) {
    if (!q) return "off";
    const days = q.days.length === 7 ? "every day" : q.days.join(", ");
    return `${q.start}–${q.end}, starting ${days}`;
  }

  function render(s) {
    state = s;
    const label = s.mode === "away" ? `away${s.until ? " until " + clock(s.until) : ""}`
      : s.mode === "quiet" ? `quiet hours until ${clock(s.until)}` : "available";
    const st = $("#avState"); st.textContent = label; st.classList.toggle("warn", s.mode !== "available");
    marker.textContent = label; marker.classList.toggle("hidden", s.mode === "available");
    const away = s.mode === "away";
    const t = $("#avToggle"); t.textContent = away ? "I'm back" : "I'm away"; t.classList.toggle("secondary", away);
    $("#avFor").classList.toggle("hidden", away);
    $("#avQuietText").textContent = quietText(s.quiet_hours) + (s.quiet_source === "config" && s.quiet_hours ? " (from the gateway config)" : "");
    if (!$("#avQuiet").dataset.dirty) {
      const q = s.quiet_hours;
      $("#avQOn").checked = !!q;
      if (q) {
        $("#avQStart").value = q.start; $("#avQEnd").value = q.end;
        $$("#avQuiet .days input").forEach((c) => (c.checked = q.days.includes(c.value)));
      }
    }
    $("#avZone").textContent = `Times are in the gateway's time zone (${s.quiet_zone}); set TZ on the gateway container to change it.`;
    const missed = s.missed || [];
    const more = s.missed_dropped || 0;
    $("#avMissed").classList.toggle("hidden", !missed.length && !more);
    $("#avMissedN").textContent = String(missed.length + more);
    const list = $("#avMissedList"); list.innerHTML = "";
    for (const m of missed) {
      const row = document.createElement("div"); row.className = "row-between missed-row";
      const what = m.kind === "grant" ? `grant ${m.host}` : `${m.host}:${m.port}`;
      row.innerHTML = `<div><code>${esc(what)}</code> <span class="muted">${m.count > 1 ? `×${esc(m.count)} · ` : ""}last ${esc(fmtDate(m.last))}</span></div>`;
      if (m.kind === "conn") {
        const b = document.createElement("button"); b.className = "small"; b.textContent = "Allow 1 h";
        b.setAttribute("aria-label", `Allow ${what} for 1 hour`);
        b.onclick = guard(async () => {
          await gw("POST", "/rules", { action: "allow", host: m.host, port: m.port, expires: Date.now() / 1000 + 3600, note: "refused while away" });
          toast(`${what} allowed for 1 h`); row.remove();
        });
        row.appendChild(b);
      } else {
        const n = document.createElement("span"); n.className = "muted"; n.textContent = "the agent can request it again";
        row.appendChild(n);
      }
      list.appendChild(row);
    }
    if (more) {
      const p = document.createElement("p"); p.className = "muted"; p.textContent = `… and ${more} more (see the log)`;
      list.appendChild(p);
    }
  }

  async function load() { render(await gw("GET", "/availability")); }

  $("#avToggle").onclick = guard(async () => {
    const body = state && state.mode === "away" ? { away: false } : { away: true, away_until: awayUntil() };
    render(await gw("PATCH", "/availability", body));
    toast(body.away ? "Away: requests that need you are refused" : "Welcome back");
  });
  $("#avQuiet").addEventListener("input", () => ($("#avQuiet").dataset.dirty = "1"));
  $("#avQSave").onclick = guard(async () => {
    let q = null;
    if ($("#avQOn").checked) {
      const days = $$("#avQuiet .days input").filter((c) => c.checked).map((c) => c.value);
      if (!days.length) throw new Error("Pick at least one day");
      q = { start: $("#avQStart").value, end: $("#avQEnd").value, days };
    }
    delete $("#avQuiet").dataset.dirty;
    render(await gw("PATCH", "/availability", { quiet_hours: q }));
    toast(q ? `Quiet hours ${q.start}–${q.end}` : "Quiet hours off");
  });
  $("#avMissedClear").onclick = guard(async () => render(await gw("DELETE", "/availability/missed")));

  let soon = null;  // refused requests arrive as log events: reload at most every 2 s
  const later = () => { if (!soon) soon = setTimeout(() => { soon = null; load().catch(() => {}); }, 2000); };
  document.addEventListener("tg:event", (e) => {
    const ev = e.detail || {};
    if (ev.type === "availability" || ev.type === "digest") load().catch(() => {});
    else if (ev.type === "event" && state && state.mode !== "available" && /refused without asking/.test(ev.event?.reason || "")) later();
  });
  document.addEventListener("tg:reconnected", () => load().catch(() => {}));
  setInterval(() => { if (state && state.until && state.until <= Date.now() / 1000) load().catch(() => {}); }, 15000);
  load().catch((e) => toast(e.message, true));
})();
