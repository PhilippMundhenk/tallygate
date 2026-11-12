"""Versions and update notice (#81) end to end: the gateway reports VERSION, control asks a (mock) GitHub
releases API through its own network and can be told not to."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar

import pytest

from .conftest import ROOT
from .test_setup_wizard import login


class Releases(BaseHTTPRequestHandler):
    calls: ClassVar[list[str]] = []

    def do_GET(self):
        Releases.calls.append(self.path)
        body = json.dumps({"tag_name": "v99.0.0", "published_at": "2099-01-01T00:00:00Z"}).encode()
        self.send_response(200 if self.path == "/repos/PhilippMundhenk/tallygate/releases/latest" else 404)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def github():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Releases)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def test_versions_in_one_place_and_the_update_notice(control_with, fake_agent, github):
    ui = login(control_with(GITHUB_API_URL=github, AGENT_STATUS_PORT=fake_agent["port"]))
    v = ui.call("GET", "/api/version")[1]
    assert v["tallygate"] == Path(ROOT / "VERSION").read_text().strip()
    assert v["claude_code"] == "2.1.304" and v["check"] == "ok" and v["update_available"] is True
    assert v["latest"] == {
        "version": "99.0.0",
        "url": "https://github.com/PhilippMundhenk/tallygate/releases/tag/v99.0.0",
        "published": "2099-01-01T00:00:00Z",
    }
    ui.call("GET", "/api/version")
    assert Releases.calls.count("/repos/PhilippMundhenk/tallygate/releases/latest") == 1  # cached
    page = ui.call("GET", "/")[1]
    assert b'id="updateNotice"' in page and b'src="/static/update.js"' in page


def test_update_check_can_be_switched_off(control_with, github):
    before = len(Releases.calls)
    ui = login(control_with(GITHUB_API_URL=github, UPDATE_CHECK="0"))
    v = ui.call("GET", "/api/version")[1]
    assert v["check"] == "off" and v["latest"] is None and v["update_available"] is None
    assert len(Releases.calls) == before  # GitHub was not asked
