"""Workspace files (#76) end to end: browser API → control → the real agent/status.py on a temporary
workspace."""

from __future__ import annotations

import urllib.request

from .test_setup_wizard import login


def put(ui, path: str, data: bytes, query: str = "", csrf: bool = True):
    headers = {"Content-Type": "application/octet-stream"}
    if csrf:
        headers["X-Tallygate"] = "1"
    req = urllib.request.Request(
        f"{ui.base}/api/files?path={urllib.parse.quote(path)}{query}", data=data, method="PUT", headers=headers
    )
    try:
        with ui.opener.open(req, timeout=20) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def test_upload_list_download(agent_control, fake_agent):
    ui = login(agent_control["base"])
    ws = fake_agent["workspace"]
    (ws / "results").mkdir(exist_ok=True)
    assert put(ui, "results/spec.md", b"# spec\n")[0] == 200
    assert (ws / "results" / "spec.md").read_bytes() == b"# spec\n"
    assert put(ui, "results/spec.md", b"again")[0] == 409  # no silent overwrite
    assert put(ui, "results/spec.md", b"again", "&overwrite=1")[0] == 200
    assert put(ui, "results/x.md", b"x", csrf=False)[0] == 403
    listing = ui.call("GET", "/api/files?path=results")[1]
    assert {k: listing["entries"][0][k] for k in ("name", "type", "size")} == {
        "name": "spec.md",
        "type": "file",
        "size": 5,
    }
    status, body, headers = ui.call("GET", "/api/files/download?path=results/spec.md")
    assert status == 200 and body == b"again"
    assert headers["Content-Disposition"].startswith('attachment; filename="spec.md"')
    assert headers["Content-Type"] == "application/octet-stream"
    assert headers["Content-Security-Policy"] == "sandbox; default-src 'none'"


def test_no_way_out_of_the_workspace(agent_control, fake_agent, tmp_path):
    ui = login(agent_control["base"])
    ws = fake_agent["workspace"]
    secret = tmp_path / "secret.txt"
    secret.write_text("outside")
    (ws / "escape").symlink_to(secret)
    (ws / "escape-dir").symlink_to(tmp_path)
    for path in ("../secret.txt", "/etc/passwd", "a/../../x"):
        assert ui.call("GET", f"/api/files/download?path={urllib.parse.quote(path)}")[0] == 400
    for url in (
        "/api/files/download?path=escape",
        "/api/files?path=escape-dir",
        "/api/files/download?path=escape-dir/secret.txt",
    ):
        status, data, _ = ui.call("GET", url)
        assert status == 403 and data["error"] == "outside the workspace", url
    assert put(ui, "escape-dir/new.txt", b"x")[0] == 403
    assert put(ui, "escape", b"x", "&overwrite=1")[0] == 409  # never written through a link
    assert secret.read_text() == "outside" and not (tmp_path / "new.txt").exists()
    entries = {e["name"]: e["type"] for e in ui.call("GET", "/api/files")[1]["entries"]}
    assert entries["escape"] == "link" and entries["escape-dir"] == "link"


def test_files_tab_is_served(agent_control):
    ui = login(agent_control["base"])
    page = ui.call("GET", "/")[1]
    assert b'data-tab="files"' in page and b'src="/static/files.js"' in page
