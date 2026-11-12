"use strict";
/* tallygate service worker (#72): shows Web Push notifications and sends their buttons back.
   A button carries a single-use action token minted for this device and this request; the server checks it.
   No caching: the UI always comes from the server. */

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (e) => e.waitUntil(self.clients.claim()));

self.addEventListener("push", (event) => {
  let m = {};
  try { m = event.data ? event.data.json() : {}; } catch (_) { m = { body: event.data ? event.data.text() : "" }; }
  const opts = {
    body: String(m.body || ""),
    tag: String(m.tag || "tallygate"),
    icon: "/static/icon-192.png",
    badge: "/static/icon-192.png",
    data: { url: m.url || "/#approvals", tokens: m.tokens || {} },
    actions: Array.isArray(m.actions) ? m.actions.slice(0, 2) : [],
    renotify: !m.silent,
    silent: !!m.silent,
    requireInteraction: !!(m.actions && m.actions.length),
  };
  event.waitUntil(self.registration.showNotification(String(m.title || "tallygate"), opts));
});

async function act(note, action) {
  const token = (note.data && note.data.tokens || {})[action];
  if (!token) return openUi(note);
  let msg;
  try {
    const r = await fetch("/api/push/act", {
      method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-Tallygate": "1" },
      body: JSON.stringify({ token }),
    });
    const data = await r.json().catch(() => ({}));
    msg = r.ok ? (action === "deny" ? "Denied" : action === "once" ? "Allowed for 2 min" : "Approved")
      : `Not applied: ${data.error || "HTTP " + r.status}`;
  } catch (e) {
    msg = "Not applied: tallygate is not reachable";
  }
  await self.registration.showNotification("tallygate", { body: msg, tag: note.tag, silent: true, icon: "/static/icon-192.png" });
}

async function openUi(note) {
  const url = new URL((note.data && note.data.url) || "/#approvals", self.location.origin).href;
  const wins = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
  for (const w of wins) {
    if (new URL(w.url).origin === self.location.origin) { await w.focus(); if ("navigate" in w) await w.navigate(url); return; }
  }
  await self.clients.openWindow(url);
}

self.addEventListener("notificationclick", (event) => {
  const note = event.notification;
  note.close();
  event.waitUntil(event.action ? act(note, event.action) : openUi(note));
});
