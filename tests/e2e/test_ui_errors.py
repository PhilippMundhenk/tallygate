"""Web UI API robustness (#23): errors come back as {"error": ...} with 400/502, never as a bare 500,
and the session cookie is SameSite=Lax while the CSRF checks still hold."""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from .conftest import CONTROL_PASSWORD, free_port
from .helpers import Api


class NotJson(BaseHTTPRequestHandler):
    def _reply(self):
        if self.headers.get("Content-Length"):
            self.rfile.read(int(self.headers["Content-Length"]))
        body = b"<html>502 Bad Gateway</html>"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_PUT = do_POST = _reply

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def not_json():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), NotJson)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def login(base: str) -> Api:
    a = Api(base, csrf_header="X-Tallygate")
    status, _, headers = a.call("POST", "/login", form={"password": CONTROL_PASSWORD})
    assert status == 302
    a.set_cookie = headers.get("Set-Cookie", "")
    return a


def raw(a: Api, method: str, path: str, data: bytes):
    """A request with a body that is not valid JSON."""
    import urllib.error
    import urllib.request

    req = urllib.request.Request(
        a.base + path, data=data, method=method, headers={"Content-Type": "application/json", "X-Tallygate": "1"}
    )
    try:
        with a.opener.open(req, timeout=10) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def test_session_cookie_is_samesite_lax_and_csrf_still_holds(control):
    a = login(control["base"])
    assert "SameSite=Lax" in a.set_cookie and "HttpOnly" in a.set_cookie
    # Lax lets a link from a notification arrive logged in; state changes still need header + origin
    assert a.call("GET", "/api/meta")[0] == 200
    evil = {"Origin": "https://evil.example"}
    assert a.call("POST", "/api/gw/test", {"host": "x.org"}, headers=evil)[0] == 403
    assert a.call("POST", "/logout", headers=evil)[0] == 403
    no_header = Api(a.base)
    no_header.opener = a.opener
    assert no_header.call("PUT", "/api/gw/secrets/x", {"value": "y"})[0] == 403


def test_invalid_json_body_is_400(control):
    a = login(control["base"])
    status, body = raw(a, "POST", "/api/gw/test", b"{not json")
    assert status == 400 and b'"error"' in body
    status, body = raw(a, "POST", "/api/github/check", b"[")
    assert status == 400 and b'"error"' in body
    status, data, _ = a.call("POST", "/api/github/check", ["not", "an", "object"])
    assert status == 400 and "error" in data


def test_non_json_gateway_reply_is_502(control_with, not_json):
    a = login(control_with(GW_URL=not_json))
    status, data, _ = a.call("GET", "/api/gw/policy")
    assert status == 502 and data == {"error": "invalid response from the gateway"}


def test_github_unreachable_or_garbled_is_502(control_with, not_json):
    a = login(control_with(GITHUB_API_URL=f"http://127.0.0.1:{free_port()}"))
    status, data, _ = a.call("POST", "/api/github/check", {"token": "github_pat_x"})
    assert status == 502 and data["error"].startswith("GitHub unreachable")
    b = login(control_with(GITHUB_API_URL=not_json))
    status, data, _ = b.call("POST", "/api/github/check", {"token": "github_pat_x"})
    assert status == 502 and data == {"error": "invalid response from GitHub"}
