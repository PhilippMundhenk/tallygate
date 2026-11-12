"""Reverse/auth proxy trust (#19): forwarded and auth headers count only from the proxy's own address,
and, with TRUST_PROXY_SECRET, only together with the shared secret.

127.0.0.2 plays the proxy container with its fixed `mgmt` address; 127.0.0.1 plays every other process
on the Docker host (what the published port looks like from inside control).
"""

from __future__ import annotations

import http.client
import subprocess
import sys
import urllib.parse

from .conftest import API_TOKEN, ROOT, clean_env, free_port

PROXY = "127.0.0.2"
SECRET = "proxy-secret-proxy-secret"


def request(base: str, method: str, path: str, source: str = "127.0.0.1", headers: dict | None = None, body=None):
    u = urllib.parse.urlsplit(base)
    conn = http.client.HTTPConnection(u.hostname, u.port, timeout=10, source_address=(source, 0))
    try:
        conn.request(method, path, body=body, headers=headers or {})
        r = conn.getresponse()
        r.read()
        return r.status, dict(r.getheaders())
    finally:
        conn.close()


def test_auth_header_is_trusted_only_from_the_proxy_address(control_with):
    base = control_with(TRUST_PROXY_AUTH_HEADER="Remote-User", TRUSTED_PROXIES=f"{PROXY}/32")
    assert request(base, "GET", "/api/meta", PROXY, {"Remote-User": "alice"})[0] == 200
    # any other local process: the header is ignored
    assert request(base, "GET", "/api/meta", "127.0.0.1", {"Remote-User": "alice"})[0] == 401
    assert request(base, "GET", "/api/meta", PROXY)[0] == 401  # the proxy did not authenticate anyone


def test_proxy_secret_is_required_with_the_auth_header(control_with):
    base = control_with(TRUST_PROXY_AUTH_HEADER="Remote-User", TRUSTED_PROXIES=f"{PROXY}/32", TRUST_PROXY_SECRET=SECRET)
    ok = {"Remote-User": "alice", "X-Tallygate-Proxy-Secret": SECRET}
    assert request(base, "GET", "/api/meta", PROXY, ok)[0] == 200
    assert request(base, "GET", "/api/meta", PROXY, {"Remote-User": "alice"})[0] == 401
    wrong = {"Remote-User": "alice", "X-Tallygate-Proxy-Secret": SECRET[:-1] + "x"}
    assert request(base, "GET", "/api/meta", PROXY, wrong)[0] == 401
    assert request(base, "GET", "/api/meta", "127.0.0.1", ok)[0] == 401  # right secret, wrong peer


def test_forwarded_headers_need_the_proxy_secret(control_with):
    """X-Forwarded-Host/-Proto feed the origin check: without the secret they are ignored."""
    base = control_with(TRUST_FORWARDED_FOR="1", TRUSTED_PROXIES=f"{PROXY}/32", TRUST_PROXY_SECRET=SECRET)
    fwd = {
        "X-Forwarded-Host": "ui.example",
        "X-Forwarded-Proto": "https",
        "Origin": "https://ui.example",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    body = "password=nope"
    # believed: origin matches the forwarded host, so the login is processed (wrong password -> redirect)
    status, headers = request(base, "POST", "/login", PROXY, {**fwd, "X-Tallygate-Proxy-Secret": SECRET}, body)
    assert status == 302 and "failed=1" in headers["Location"]
    # without the secret the forwarded host is not believed and the origin does not match
    assert request(base, "POST", "/login", PROXY, fwd, body)[0] == 403


def test_short_proxy_secret_is_refused():
    r = subprocess.run(
        [sys.executable, "-m", "app.main"],
        cwd=ROOT / "control",
        env=clean_env(
            PYTHONPATH=ROOT / "control",
            CONTROL_BIND_HOST="127.0.0.1",
            CONTROL_PORT=free_port(),
            GW_API_TOKEN=API_TOKEN,
            SESSION_SECRET="e2e",
            TTYD_CREDENTIAL="agent:x",
            CONTROL_PASSWORD="x",
            TRUSTED_PROXIES=f"{PROXY}/32",
            TRUST_PROXY_SECRET="short",
        ),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert r.returncode != 0 and "TRUST_PROXY_SECRET must be at least 16 characters" in r.stderr
