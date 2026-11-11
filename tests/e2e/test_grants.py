"""Grants end to end: agent request API -> human decision -> enforcement on real connections."""

import json
import time

import pytest

from .helpers import connect_tunnel, proxy_request, tls_request

pytestmark = pytest.mark.usefixtures("gateway")


def agent(gw, method, path, body=None):
    return gw["agent"].call(method, path, body)


def last_event(gw, host):
    _, evs, _ = gw["api"].call("GET", "/events?limit=30")
    return next(e for e in evs if e.get("host") == host)


def request_and_approve(gw, name, level="write", decision="approve"):
    status, r, _ = agent(gw, "POST", f"/v1/grants/{name}/request", {"level": level, "reason": "e2e"})
    assert status in (200, 202), r
    if r["status"] == "pending":
        gw["api"].call("POST", f"/grant-requests/{r['id']}/decide", {"decision": decision, "by": "e2e"})
    return r


def revoke(gw, name):
    _, g, _ = gw["api"].call("GET", "/grants")
    for a in g["active"]:
        if a["name"] == name:
            gw["api"].call("DELETE", f"/active-grants/{a['id']}?by=e2e")


def test_catalog_shows_grants_but_no_secrets(gateway):
    status, cat, _ = agent(gateway, "GET", "/v1/grants")
    names = {g["name"] for g in cat["grants"]}
    assert status == 200 and {"svc", "sec", "lanhttp", "raw"} <= names
    assert "grant_token" not in json.dumps(cat) and "Bearer" not in json.dumps(cat)
    assert agent(gateway, "POST", "/v1/grants/nope/request", {"level": "read"})[0] == 404
    assert agent(gateway, "POST", "/v1/grants/svc/request", {"level": "admin"})[0] == 400


def test_inactive_grant_blocks_with_hint(gateway, upstream):
    status, _ = proxy_request(gateway["ports"]["http"], f"svc.test:{upstream['http']}", "/api/x")
    assert status in (502, 403)
    assert "available via grant svc" in last_event(gateway, "svc.test")["reason"]


def test_read_level_allows_only_safe_methods_paths_and_host(gateway, upstream):
    r = request_and_approve(gateway, "svc", "read")  # read is auto-approved
    assert r["status"] == "approved"
    hp = f"svc.test:{upstream['http']}"
    p = gateway["ports"]["http"]
    status, body = proxy_request(p, hp, "/api/states")
    assert status == 200 and json.loads(body)["method"] == "GET"
    assert proxy_request(p, hp, "/api/services/light", "POST")[0] == 403
    assert proxy_request(p, hp, "/config")[0] == 403
    for evil in ("/api/../config", "/api/%2e%2e/config", "/api//x", "/api/x%2fy"):
        assert proxy_request(p, hp, evil)[0] == 403, evil
    assert proxy_request(p, hp, "/api/x", headers={"Host": "other.test"})[0] == 403
    assert proxy_request(p, hp, "/api/ws", headers={"Connection": "Upgrade", "Upgrade": "websocket"})[0] == 403
    assert "read-only" in last_event(gateway, "svc.test")["reason"]


def test_write_level_needs_a_human_and_can_be_downgraded(gateway, upstream):
    status, r, _ = agent(
        gateway, "POST", "/v1/grants/svc/request", {"level": "write", "ttl": "2h", "reason": "toggle light"}
    )
    assert status == 202 and r["status"] == "pending"
    _, g, _ = gateway["api"].call("GET", "/grants")
    req = next(x for x in g["requests"] if x["id"] == r["id"])
    assert req["reason"] == "toggle light" and req["ttl"] == 7200
    gateway["api"].call("POST", f"/grant-requests/{r['id']}/decide", {"decision": "read", "by": "e2e"})
    _, r2, _ = agent(gateway, "GET", f"/v1/requests/{r['id']}")
    assert r2["status"] == "approved" and r2["granted_level"] == "read"
    hp = f"svc.test:{upstream['http']}"
    assert proxy_request(gateway["ports"]["http"], hp, "/api/x", "POST")[0] == 403
    request_and_approve(gateway, "svc", "write")
    status, body = proxy_request(gateway["ports"]["http"], hp, "/api/x", "POST")
    assert status == 200 and json.loads(body)["method"] == "POST"
    revoke(gateway, "svc")
    assert proxy_request(gateway["ports"]["http"], hp, "/api/x")[0] in (403, 502)


def test_agent_can_long_poll_and_denial_is_reported(gateway):
    _, r, _ = agent(gateway, "POST", "/v1/grants/raw/request", {"level": "write", "reason": "x"})
    t0 = time.time()
    import threading

    threading.Timer(
        1, lambda: gateway["api"].call("POST", f"/grant-requests/{r['id']}/decide", {"decision": "deny", "by": "e2e"})
    ).start()
    _, r2, _ = agent(gateway, "GET", f"/v1/requests/{r['id']}?wait=10")
    assert r2["status"] == "denied" and 0.5 < time.time() - t0 < 8


def test_https_grant_injects_credentials_and_cuts_non_http(gateway, upstream):
    gateway["api"].call("PUT", "/secrets/grant_token", {"value": "tok-123"})
    request_and_approve(gateway, "sec", "write")
    target = f"sec.test:{upstream['https']}"
    status, body = tls_request(
        gateway["ports"]["http"],
        target,
        "sec.test",
        gateway["ca"],
        "POST",
        "/x",
        {"Authorization": "agent-own", "Cookie": "a=b"},
    )
    assert status == 200 and json.loads(body)["auth"] == "Bearer tok-123"
    # raw bytes instead of TLS/HTTP must not be passed through to an HTTP grant target
    raw, line = connect_tunnel(gateway["ports"]["http"], target)
    assert " 200" in line
    raw.sendall(b"\x00\x01SSH-2.0-not-http\r\n\r\n")
    raw.settimeout(5)
    try:
        data = raw.recv(100)
    except OSError:
        data = b""
    raw.close()
    assert not data.startswith(b"HTTP/1.1 200")
    time.sleep(0.5)
    assert "non-HTTP traffic to an HTTP grant target" in last_event(gateway, "sec.test")["reason"]
    revoke(gateway, "sec")


def test_lan_grant_exempts_exact_target_from_hard_deny(gateway, upstream):
    hp = f"lanecho.test:{upstream['lan']}"
    status, _ = proxy_request(gateway["ports"]["http"], hp, "/")
    assert status in (403, 502) and "available via grant" in last_event(gateway, "lanecho.test")["reason"]
    request_and_approve(gateway, "nolan", "write")  # same target without lan: true -> still hard-denied
    assert proxy_request(gateway["ports"]["http"], hp, "/")[0] in (403, 502)
    assert "hard-deny" in last_event(gateway, "lanecho.test")["reason"]
    revoke(gateway, "nolan")
    request_and_approve(gateway, "lanhttp", "write")
    status, body = proxy_request(gateway["ports"]["http"], hp, "/")
    assert status == 200 and json.loads(body)["path"] == "/"
    revoke(gateway, "lanhttp")


def test_pinned_fingerprint_replaces_ca_and_hostname_checks(gateway, upstream):
    request_and_approve(gateway, "pinned", "read")
    status, _ = tls_request(gateway["ports"]["http"], f"pin.test:{upstream['https']}", "pin.test", gateway["ca"])
    assert status == 200  # the upstream cert does not even name pin.test - the pin is what counts
    request_and_approve(gateway, "badpin", "read")
    status, _ = tls_request(gateway["ports"]["http"], f"badpin.test:{upstream['https']}", "badpin.test", gateway["ca"])
    assert status != 200


def test_tcp_grant_passes_raw_traffic(gateway, upstream):
    request_and_approve(gateway, "raw", "write")
    raw, line = connect_tunnel(gateway["ports"]["http"], f"raw.test:{upstream['http2']}")
    assert " 200" in line
    raw.sendall(b"GET /raw HTTP/1.1\r\nHost: anything\r\nConnection: close\r\n\r\n")
    raw.settimeout(5)
    data = b""
    while chunk := raw.recv(4096):
        data += chunk
    raw.close()
    # passed through untouched: the Host header is not checked and the echo answers directly
    assert data.startswith(b"HTTP/1.0 200") and b'"host": "anything"' in data
    revoke(gateway, "raw")


def test_ui_defined_grants_are_validated(gateway):
    api = gateway["api"]
    ok = {"targets": [{"host": "cam.test", "port": 80, "scheme": "http"}], "levels": ["read"]}
    assert api.call("PUT", "/grants/cam", ok)[0] == 200
    lan_out = {"targets": [{"host": "cam.test", "port": 80, "scheme": "http", "lan": True, "address": "10.1.2.3"}]}
    assert api.call("PUT", "/grants/cam2", lan_out)[0] == 400
    assert api.call("PUT", "/grants/svc", ok)[0] == 400  # config grants are read-only
    assert api.call("DELETE", "/grants/svc")[0] == 400
    _, g, _ = api.call("GET", "/grants")
    assert {d["name"]: d["source"] for d in g["defs"]}["cam"] == "ui"
    assert api.call("DELETE", "/grants/cam")[0] == 200


def test_cli_lists_requests_and_waits(gateway):
    import subprocess
    import sys
    import threading
    from pathlib import Path

    cli = Path(__file__).resolve().parents[2] / "agent" / "tallygate-cli.py"
    env = {"TALLYGATE_URL": gateway["agent"].base, "PATH": "/usr/bin:/bin"}

    def run(*args):
        return subprocess.run([sys.executable, str(cli), *args], env=env, capture_output=True, text=True, timeout=60)

    out = run("grants")
    assert out.returncode == 0 and "svc" in out.stdout and "http://svc.test" in out.stdout
    out = run("request", "svc", "--reason", "read states")  # read is auto-approved
    assert out.returncode == 0 and "granted: svc (read)" in out.stdout

    def approve_soon():
        for _ in range(50):
            _, g, _ = gateway["api"].call("GET", "/grants")
            reqs = [r for r in g["requests"] if r["name"] == "svc" and r["level"] == "write"]
            if reqs:
                gateway["api"].call(
                    "POST", f"/grant-requests/{reqs[0]['id']}/decide", {"decision": "read", "by": "e2e"}
                )
                return
            time.sleep(0.2)

    threading.Thread(target=approve_soon, daemon=True).start()
    out = run("request", "svc", "--write", "--ttl", "10m", "--reason", "toggle")
    assert out.returncode == 0 and "granted only" not in out.stdout and "were granted read only" in out.stdout
    assert run("request", "nope", "--reason", "x").returncode == 2
    revoke(gateway, "svc")


def test_grants_never_narrow_what_rules_allow(gateway, upstream):
    """gh.test is allowed by a host rule; an active read-only grant on it must not block writes."""
    api = gateway["api"]
    api.call("PUT", "/grants/ghread", {"targets": [{"host": "gh.test", "port": upstream["https"]}], "levels": ["read"]})
    api.call("POST", "/grants/ghread/activate", {"level": "read", "by": "e2e"})
    status, body = tls_request(
        gateway["ports"]["http"], f"gh.test:{upstream['https']}", "gh.test", gateway["ca"], "POST", "/w"
    )
    assert status == 200 and json.loads(body)["method"] == "POST"
    api.call("DELETE", "/grants/ghread")
