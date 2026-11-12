"use strict";
/* Context for decisions (#74): what the agent said it was doing when it asked. Written by the agent, so it is
   escaped, labelled as a claim and never styled as a fact. Uses esc from app.js. */
document.addEventListener("tg:card", (e) => {
  const { el, item } = e.detail || {};
  const ctx = (item && Array.isArray(item.context)) ? item.context : [];
  if (!el || !ctx.length || el.querySelector(".agent-ctx")) return;
  const ago = (ts) => { const s = Math.max(0, Math.round(Number(item.created) - Number(ts))); return s < 2 ? "just before" : `${s} s before`; };
  const box = document.createElement("div"); box.className = "agent-ctx";
  box.innerHTML = `<div class="meta">Agent's recent activity <span class="tag">claimed by the agent, unverified</span></div><ul>${ctx.map((c) => {
    const what = c.kind === "note" ? `<i>note:</i> ${esc(c.note || c.text)}`
      : `${c.tool ? `<b>${esc(c.tool)}</b> ` : ""}<code>${esc(c.text || "")}</code>${c.note ? ` <span class="muted">– ${esc(c.note)}</span>` : ""}`;
    return `<li>${what} <span class="muted">(${esc(ago(c.ts))})</span></li>`;
  }).join("")}</ul>`;
  const btns = el.querySelector(".btns");
  el.insertBefore(box, btns);
});
