"""Workspace files (#76) end to end: browser API → control → the real agent/status.py on a temporary
workspace."""

from __future__ import annotations

import json
import urllib.request
from http.server import BaseHTTPRequestHandler

from .conftest import start_echo
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


def delete(ui, path: str, csrf: bool = True):
    req = urllib.request.Request(
        f"{ui.base}/api/files?path={urllib.parse.quote(path)}",
        method="DELETE",
        headers={"X-Tallygate": "1"} if csrf else {},
    )
    try:
        with ui.opener.open(req, timeout=20) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_delete_files_and_folders(agent_control, fake_agent, tmp_path):
    """#199: a file, a folder with everything in it, a link (never its target); nothing outside, never the root."""
    ui = login(agent_control["base"])
    ws = fake_agent["workspace"]
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("outside")
    (ws / "trash" / "deep").mkdir(parents=True)
    (ws / "trash" / "deep" / "a.txt").write_text("a")
    (ws / "trash" / "link-out").symlink_to(outside)
    (ws / "old.txt").write_text("old")
    (ws / "del-escape").symlink_to(outside)
    assert delete(ui, "old.txt", csrf=False)[0] == 403 and (ws / "old.txt").exists()
    assert delete(ui, "old.txt") == (200, {"path": "old.txt", "type": "file"})
    assert not (ws / "old.txt").exists()
    assert delete(ui, "old.txt") == (404, {"error": "no such file or folder"})
    for path in ("", "../outside", "/etc/passwd", "trash/../.."):
        assert delete(ui, path) == (400, {"error": "invalid path"}), path
    assert delete(ui, "del-escape/secret.txt") == (403, {"error": "outside the workspace"})
    assert delete(ui, "del-escape") == (200, {"path": "del-escape", "type": "file"})  # the link, not its target
    assert delete(ui, "trash") == (200, {"path": "trash", "type": "dir"})
    assert not (ws / "trash").exists() and not (ws / "del-escape").is_symlink() and ws.is_dir()
    assert (outside / "secret.txt").read_text() == "outside"
    names = {e["name"] for e in ui.call("GET", "/api/files")[1]["entries"]}
    assert not names & {"old.txt", "trash", "del-escape"}


def test_files_tab_is_served(agent_control):
    ui = login(agent_control["base"])
    page = ui.call("GET", "/")[1]
    assert b'data-tab="files"' in page and b'src="/static/files.js"' in page


def test_a_redirecting_agent_cannot_send_control_elsewhere(control_with):
    """#230: an agent that replaced its status server answers every call with a redirect to a host only the
    control plane can reach. The real control process follows none of them: the other host sees no request,
    the browser gets 502 with a fixed text."""
    outside: list[str] = []

    class Outside(BaseHTTPRequestHandler):
        def _any(self):
            outside.append(f"{self.command} {self.path}")
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")

        do_GET = do_POST = do_PUT = do_DELETE = _any

        def log_message(self, *args):
            pass

    asked: list[str] = []

    class HostileAgent(BaseHTTPRequestHandler):
        def _any(self):
            asked.append(f"{self.command} {self.path.split('?')[0]}")
            self.send_response(307 if self.command in ("POST", "PUT", "DELETE") else 302)
            self.send_header("Location", f"http://127.0.0.1:{outside_port}/exfil?data=WORKSPACE-DATA")
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()

        do_GET = do_POST = do_PUT = do_DELETE = _any

        def log_message(self, *args):
            pass

    outside_port = start_echo(handler=Outside)
    ui = login(control_with(AGENT_STATUS_PORT=start_echo(handler=HostileAgent)))
    fixed = {"error": "the agent answered with a redirect, which is never followed"}
    for method, path, body in (
        ("GET", "/api/agent/status", None),
        ("POST", "/api/agent/setup/git-identity", {"name": "Alex Example", "email": "alex@example.org"}),
        ("GET", "/api/files?path=", None),
        ("GET", "/api/files/download?path=notes.txt", None),
    ):
        status, data, _ = ui.call(method, path, body)
        assert (status, data) == (502, fixed), (method, path)
    status, raw = put(ui, "upload.bin", b"x" * 4096)
    assert (status, json.loads(raw)) == (502, fixed)
    assert delete(ui, "notes.txt") == (502, fixed)
    status, version, _ = ui.call("GET", "/api/version")
    assert status == 200 and version["claude_code"] is None
    assert asked == [
        "GET /status",
        "POST /setup/git-identity",
        "GET /files",
        "GET /files/download",
        "PUT /files",
        "DELETE /files",
        "GET /status",
    ]
    assert outside == []
