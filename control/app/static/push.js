"use strict";
/* Phone approvals without a chat bot (#72): service worker, Web Push subscription and the device list.
   Uses $, api, esc, guard, toast and fmtDate from app.js. Needs a secure context (HTTPS or localhost);
   on plain HTTP it explains that instead of failing. */
(() => {
  const box = document.getElementById("pushSetup");
  const secure = window.isSecureContext && "serviceWorker" in navigator;
  // Register the worker on every page load: it shows the notifications and handles their buttons.
  if (secure) navigator.serviceWorker.register("/sw.js", { scope: "/" }).catch(() => {});
  if (!box) return;
  const supported = secure && "PushManager" in window && "Notification" in window;

  box.innerHTML = `<h4>Phone approvals (Web Push)</h4>
    <p class="hint">Install tallygate on your phone (browser menu → <i>Add to Home screen</i> / <i>Install app</i>) and turn
      on notifications here. Each request arrives with <b>Allow once</b> and <b>Deny</b> buttons; tapping the
      notification opens the approvals. No chat bot needed.</p>
    <p id="pushUnsupported" class="meta warn hidden" role="note"></p>
    <div class="row wrap" id="pushControls">
      <label class="inline">This device <input id="pushLabel" maxlength="40" placeholder="e.g. phone" autocomplete="off"></label>
      <button id="pushOn" class="secondary">Turn on notifications on this device</button>
      <button id="pushTest" class="small secondary">Send a test</button>
    </div>
    <div id="pushDevices"></div>`;

  const unsupported = (text) => {
    const el = $("#pushUnsupported"); el.textContent = text; el.classList.remove("hidden");
    $("#pushControls").classList.add("hidden");
  };

  async function load() {
    const st = await api("GET", "/api/push");
    const list = $("#pushDevices"); list.innerHTML = "";
    if (!st.enabled) return unsupported("Web Push is off: the control data volume is not writable (see the control log).");
    for (const d of st.subscriptions) {
      const row = document.createElement("div"); row.className = "row-between push-device";
      row.innerHTML = `<span><b>${esc(d.label)}</b> <span class="muted">${esc(d.service || "")} · since ${esc(fmtDate(d.created))}</span></span>`;
      const b = document.createElement("button"); b.className = "small danger"; b.textContent = "Remove";
      b.setAttribute("aria-label", `Stop notifications to ${d.label}`);
      b.onclick = guard(async () => { await api("DELETE", `/api/push/${encodeURIComponent(d.id)}`); await load(); });
      row.appendChild(b); list.appendChild(row);
    }
    if (!st.subscriptions.length) list.innerHTML = '<p class="muted">No device receives push notifications yet.</p>';
    $("#pushTest").classList.toggle("hidden", !st.subscriptions.length);
    return st;
  }

  const keyBytes = (b64) => {
    const raw = atob(b64.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (b64.length % 4)) % 4));
    return Uint8Array.from(raw, (c) => c.charCodeAt(0));
  };

  $("#pushOn").onclick = guard(async () => {
    const st = await api("GET", "/api/push");
    if (!st.enabled) return load();
    if ((await Notification.requestPermission()) !== "granted") throw new Error("Notifications are blocked for this site in the browser settings");
    const reg = await navigator.serviceWorker.ready;
    const old = await reg.pushManager.getSubscription();
    // A subscription made with another server key (e.g. after the control volume was reset) cannot work.
    if (old) await old.unsubscribe();
    const sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: keyBytes(st.public_key) });
    const label = $("#pushLabel").value.trim() || (/Mobi|Android/.test(navigator.userAgent) ? "phone" : "browser");
    await api("POST", "/api/push/subscribe", { subscription: sub.toJSON(), label });
    toast(`Notifications on for ${label}`); await load();
  });
  $("#pushTest").onclick = guard(async () => {
    const r = await api("POST", "/api/push/test", {});
    toast(`Test sent to ${r.delivered} device(s)`);
  });

  if (!secure) {
    unsupported("Phone notifications need HTTPS: open the UI through your TLS reverse proxy (or on localhost). " +
      "Telegram, Matrix, ntfy, Gotify and Pushover work either way.");
    load().catch(() => {});
  } else if (!supported) {
    unsupported("This browser does not support Web Push. On iPhone, add tallygate to the Home Screen first (iOS 16.4+).");
    load().catch(() => {});
  } else load().catch((e) => toast(e.message, true));
})();
