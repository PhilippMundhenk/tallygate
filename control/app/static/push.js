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
    <p class="hint">Approve from your phone without a chat bot: install tallygate there and add the device here.</p>
    <details class="help"><summary>How do phone approvals work?</summary>
      <p>Install tallygate on your phone (browser menu → <i>Add to Home screen</i> / <i>Install app</i>), open it
        and use <i>Add this device</i>. Each connection request arrives with the buttons chosen under
        <i>Notification buttons</i> above, now <b class="notify-actions-text">Allow once, Deny</b>. A device shows
        the first ones it has room for (two on most phones); tapping the notification opens the approvals.</p></details>
    <p id="pushUnsupported" class="alert warn hidden" role="note"></p>
    <div class="row wrap" id="pushControls">
      <label class="inline">This device <input id="pushLabel" maxlength="40" placeholder="e.g. phone" autocomplete="off"></label>
      <button id="pushOn" class="secondary">Add this device</button>
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
      const b = document.createElement("button"); b.className = "small ghost danger"; b.textContent = "Remove";
      b.setAttribute("aria-label", `Remove device ${d.label}`);
      b.onclick = confirmClick(b, `Remove device ${d.label}? It stops receiving notifications.`, async () => {
        await api("DELETE", `/api/push/${encodeURIComponent(d.id)}`); toast(`Device ${d.label} removed`); await load();
      });
      row.appendChild(b); list.appendChild(row);
    }
    if (!st.subscriptions.length) list.innerHTML = '<p class="empty">No device receives push notifications yet. Add this one above.</p>';
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
    toast(`Device ${label} added`); await load();
    // Refresh the Setup channel list so the Web Push row (and its Test button) reflects the new device.
    if (typeof tabHooks !== "undefined" && tabHooks.setup) tabHooks.setup().catch(() => {});
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
