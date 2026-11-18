"use strict";
/* No connection from the gateway (#218): a warning on Overview and on the Log tab while the gateway's own lookups
   and connections fail, so that an outage of the host's network is not mistaken for a policy decision. The state
   comes from the gateway (GET /info, and "connectivity" stream messages as "tg:event"); it holds times, counts and
   kinds only, never a host name. The text is set with textContent. Uses `gw` from app.js. */
(function () {
  const banners = ["#netBanner", "#netBannerLog"].map((s) => $(s)).filter(Boolean);
  let net = { down: false };
  function ago(secs) {
    const m = Math.max(1, Math.round(secs / 60));
    return m >= 120 ? `${(m / 60).toFixed(1)} h` : `${m} min`;
  }
  function netText(state, now) {
    const since = new Date(state.since * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    return `No connection from the gateway since ${since} (${ago(now - state.since)}): lookups and connections fail. ` +
      "This is a problem of the host's network, not a policy decision.";
  }
  function render() {
    const down = net.down && Number.isFinite(net.since);
    for (const b of banners) {
      b.classList.toggle("hidden", !down);
      b.textContent = down ? netText(net, Date.now() / 1000) : "";
    }
  }
  async function load() { net = (await gw("GET", "/info")).connectivity || { down: false }; render(); }
  document.addEventListener("tg:event", (e) => {
    if (e.detail.type !== "connectivity") return;
    net = e.detail; render();
  });
  setInterval(() => { if (!document.hidden) load().catch(() => {}); }, 30000);  // keeps the minutes current, too
  load().catch(() => {});
})();
