"use strict";
/* Versions in one place and the update notice (#81). Control asks GitHub's releases API (cached, can be switched
   off with UPDATE_CHECK=0); the agent has no auto-updater, so new Claude Code versions come with tallygate releases. */
let versionInfo = null;
async function loadVersions() {
  versionInfo = await api("GET", "/api/version");
  renderVersions();
}
function renderVersions() {
  const v = versionInfo; if (!v) return;
  const notice = $("#updateNotice");
  notice.hidden = !v.update_available;
  if (v.update_available) {
    notice.textContent = `Update: ${v.latest.version}`;
    notice.setAttribute("aria-label", `tallygate ${v.latest.version} is available. Show versions`);
  }
  const latest = v.check === "off" ? "update check switched off (<code>UPDATE_CHECK=0</code>)"
    : v.check === "error" ? `<span class="warn">${esc(v.error)}</span>`
    : `${esc(v.latest.version)}${v.latest.published ? ` <span class="muted">(${esc(v.latest.published.slice(0, 10))})</span>` : ""}`;
  const state = v.update_available ? `<p class="warn"><b>tallygate ${esc(v.latest.version)} is available.</b> Read the
      <a href="${esc(v.changelog)}" target="_blank" rel="noopener noreferrer">changelog</a> (and its <i>Upgrading</i> notes), then on the Docker host:</p>
      <pre class="copy" tabindex="0" role="button" aria-label="Copy the upgrade command" title="Click to copy">${esc(v.upgrade)}</pre>
      <p><a href="${esc(v.latest.url)}" target="_blank" rel="noopener noreferrer">Release notes</a></p>`
    : v.update_available === false ? '<p class="ok">✔ Up to date.</p>' : "";
  $("#ovVersions").className = "";
  $("#ovVersions").innerHTML = `<dl class="ov-dl">
      <dt>tallygate</dt><dd>${esc(v.tallygate || "unknown (development build?)")}</dd>
      <dt>Claude Code</dt><dd>${esc(v.claude_code || "unknown")} <span class="muted">· updated with tallygate releases</span></dd>
      <dt>Latest release</dt><dd>${latest}</dd></dl>${state}`;
  const pre = $("#ovVersions pre.copy");
  if (pre) {
    const copy = () => navigator.clipboard.writeText(pre.textContent).then(() => toast("Copied"), () => toast("Copy it by hand", true));
    pre.onclick = copy; pre.onkeydown = (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); copy(); } };
  }
}
$("#updateNotice").onclick = () => { showTab("overview"); $("#ovVersionsCard").scrollIntoView({ behavior: "smooth" }); };
loadVersions().catch(() => {});
setInterval(() => loadVersions().catch(() => {}), 6 * 3600 * 1000);
