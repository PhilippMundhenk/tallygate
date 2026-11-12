"""#14: grant enforcement gaps (plain HTTP to https targets, LAN grants vs allowing rules, re-approval,
credential stripping on inject hosts)."""

from __future__ import annotations

import json
import ssl

from .helpers import connect_tunnel, proxy_request, tls_request


def grant_gateway(make_gateway, grants: dict, rules=(), floor=("203.0.113.7/32",), **config):
    return make_gateway(
        {"hard_deny_floor": list(floor), "grants_never": ["169.254.0.0/16"], "grants": grants, **config},
        {"default": "ask", "ask_timeout": 5, "rules": list(rules)},
        GW_TEST_FLOOR_REPLACE="1",
        GW_TEST_STATIC_HOSTS="h8.test=127.0.0.1,lanecho.test=127.0.0.2,other.test=127.0.0.1,gh.test=127.0.0.1",
    )


def request_grant(gw, name, level):
    status, r, _ = gw["agent"].call("POST", f"/v1/grants/{name}/request", {"level": level, "reason": "e2e"})
    assert status == 200 and r["status"] == "approved", r


def test_plain_http_to_an_https_grant_target_is_refused(make_gateway, upstream):
    port = upstream["http"]  # declared https, but the port speaks plain HTTP
    target = {"host": "h8.test", "port": port, "scheme": "https", "paths": ["/api/*"]}
    gw = grant_gateway(make_gateway, {"h8": {"targets": [target], "levels": ["read"], "approval": "auto"}})
    request_grant(gw, "h8", "read")
    status, body = proxy_request(gw["ports"]["http"], f"h8.test:{port}", "/admin/delete-all", "DELETE")
    assert status == 403 and b"plain HTTP to an https grant target" in body


def test_lan_grant_works_while_a_rule_allows_the_name(make_gateway, upstream):
    """With e.g. the `open` preset active the grant was skipped, and the connection was then hard-denied."""
    port = upstream["lan"]
    target = {"host": "lanecho.test", "port": port, "scheme": "http", "lan": True}
    gw = grant_gateway(
        make_gateway,
        {"lan": {"targets": [target], "levels": ["read"], "approval": "auto"}},
        rules=[{"id": "open", "action": "allow", "host": "*", "port": port}],
        floor=["127.0.0.2/32"],
    )
    assert proxy_request(gw["ports"]["http"], f"lanecho.test:{port}", "/")[0] == 502  # hard deny
    request_grant(gw, "lan", "read")
    status, body = proxy_request(gw["ports"]["http"], f"lanecho.test:{port}", "/")
    assert status == 200 and json.loads(body)["path"] == "/"
    assert proxy_request(gw["ports"]["http"], f"lanecho.test:{port}", "/", "POST")[0] == 403  # read-only


def _send(sock, host, path) -> int:
    """One keep-alive request; reads exactly one response."""
    sock.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
    data = b""
    while b"\r\n\r\n" not in data:
        data += sock.recv(65536)
    head, _, body = data.partition(b"\r\n\r\n")
    length = int(next(h.split(b":")[1] for h in head.split(b"\r\n") if h.lower().startswith(b"content-length")))
    while len(body) < length:
        body += sock.recv(65536)
    return int(head.split()[1])


def test_reapproval_keeps_open_connections(make_gateway, upstream):
    """Re-approving/upgrading replaced the grant id, so open keep-alive connections got "expired or revoked"."""
    port = upstream["keepalive_tls"]
    target = {"host": "other.test", "port": port, "scheme": "https"}
    gw = grant_gateway(make_gateway, {"ka": {"targets": [target], "levels": ["read", "write"], "approval": "auto"}})
    request_grant(gw, "ka", "read")
    raw, line = connect_tunnel(gw["ports"]["http"], f"other.test:{port}")
    assert " 200" in line
    with ssl.create_default_context(cafile=gw["ca"]).wrap_socket(raw, server_hostname="other.test") as s:
        assert _send(s, "other.test", "/one") == 200
        request_grant(gw, "ka", "write")  # upgrade while the connection is open
        assert _send(s, "other.test", "/two") == 200


def test_agent_credentials_are_stripped_on_inject_hosts_reached_through_a_grant(make_gateway, upstream):
    port = upstream["https"]
    target = {"host": "gh.test", "port": port, "scheme": "https"}
    gw = grant_gateway(
        make_gateway,
        {"ghg": {"targets": [target], "levels": ["write"], "approval": "auto"}},
        inject=[{"host": "gh.test", "header": "Authorization", "value": "Bearer ${github_token}"}],
    )
    request_grant(gw, "ghg", "write")
    hdr = {"Authorization": "token AGENT", "Cookie": "user_session=agent"}
    status, body = tls_request(gw["ports"]["http"], f"gh.test:{port}", "gh.test", gw["ca"], headers=hdr)
    assert status == 200 and json.loads(body)["auth"] is None
