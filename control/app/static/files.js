"use strict";
/* Workspace files (#76): browse /workspace, upload into the open folder, download files. Control checks every
   path and relays to the agent's status server; downloads are attachments (application/octet-stream), so
   nothing from the workspace is rendered on this origin. Names come from the agent: always escaped. */
const fileState = { path: "", maxUpload: 0 };
const fileUrl = (base, path, extra = "") => `${base}?path=${encodeURIComponent(path)}${extra}`;
const joinPath = (dir, name) => (dir ? `${dir}/${name}` : name);

async function loadFiles(path = fileState.path) {
  const r = await api("GET", fileUrl("/api/files", path));
  fileState.path = r.path; fileState.maxUpload = r.max_upload;
  $("#fileHint").textContent = `Up to ${fmtBytes(r.max_upload)} per file (FILES_MAX_UPLOAD); downloads up to ${fmtBytes(r.max_download)}.`;
  const parts = r.path ? r.path.split("/") : [];
  $("#fileCrumbs").innerHTML = [`<button class="small secondary" data-dir="">workspace</button>`]
    .concat(parts.map((p, i) => `<span aria-hidden="true">/</span><button class="small secondary" data-dir="${esc(parts.slice(0, i + 1).join("/"))}"${i === parts.length - 1 ? ' aria-current="page"' : ""}>${esc(p)}</button>`))
    .join("");
  const rows = [];
  if (r.path) rows.push(`<tr><td colspan="4"><button class="link" data-dir="${esc(parts.slice(0, -1).join("/"))}">⬑ up</button></td></tr>`);
  for (const e of r.entries) {
    const p = joinPath(r.path, e.name);
    const name = e.type === "dir" ? `<button class="link" data-dir="${esc(p)}">📁 ${esc(e.name)}/</button>`
      : e.type === "link" ? `${esc(e.name)} <span class="muted">(link)</span>` : esc(e.name);
    const action = e.type === "file" ? (e.size > r.max_download ? '<span class="muted">too large</span>'
      : `<a class="dl" href="${esc(fileUrl("/api/files/download", p))}" download="${esc(e.name)}" aria-label="Download ${esc(e.name)}">Download</a>`) : "";
    rows.push(`<tr><td>${name}</td><td>${e.type === "file" ? esc(fmtBytes(e.size)) : ""}</td><td>${esc(fmtDate(e.mtime))}</td><td>${action}</td></tr>`);
  }
  if (!r.entries.length) rows.push('<tr><td colspan="4" class="muted">This folder is empty.</td></tr>');
  $("#fileBody").innerHTML = rows.join("");
  $("#fileTruncated").classList.toggle("hidden", !r.truncated);
}
tabHooks.files = () => loadFiles();

$("#tab-files").addEventListener("click", (e) => {
  const b = e.target.closest("[data-dir]");
  if (b) guard(async () => { await loadFiles(b.dataset.dir); ($("#fileCrumbs [aria-current]") || $("#fileCrumbs button")).focus(); })();
});

async function uploadOne(file, overwrite) {
  if (file.size > fileState.maxUpload) throw new Error(`${file.name}: larger than ${fmtBytes(fileState.maxUpload)}`);
  const r = await fetch(fileUrl("/api/files", joinPath(fileState.path, file.name), overwrite ? "&overwrite=1" : ""), {
    method: "PUT", body: file, credentials: "same-origin",
    headers: { "X-Tallygate": "1", "Content-Type": "application/octet-stream" },
  });
  if (r.status === 401) { location.href = "/login"; throw new Error("login required"); }
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(`${file.name}: ${data.error || `HTTP ${r.status}`}`);
}
$("#fileForm").addEventListener("submit", guard(async (e) => {
  e.preventDefault();
  const files = [...$("#fileInput").files];
  if (!files.length) throw new Error("Choose one or more files first");
  const btn = $("#fileUpload"), status = $("#fileStatus"), done = [], failed = [];
  btn.disabled = true;
  try {
    for (const [i, f] of files.entries()) {
      status.className = "status"; status.textContent = `Uploading ${i + 1} of ${files.length}: ${f.name}…`;
      try { await uploadOne(f, $("#fileOverwrite").checked); done.push(f.name); } catch (err) { failed.push(err.message); }
    }
  } finally { btn.disabled = false; }
  status.className = "status " + (failed.length ? "bad" : "ok");
  status.textContent = (done.length ? `✔ Uploaded ${done.length}: ${done.join(", ")}. ` : "") + (failed.length ? `✖ ${failed.join("; ")}` : "");
  $("#fileInput").value = "";
  await loadFiles();
}));
