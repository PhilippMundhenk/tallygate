"""#56: request bodies over stream_large_bodies (1 MB) are streamed upstream right after the request headers.
The per-request checks must therefore run on the headers, before anything leaves the gateway."""

from __future__ import annotations

import contextlib
import json
import socket
import ssl

import pytest

from .helpers import TIMEOUT, connect_tunnel

BIG = 2_000_000  # over stream_large_bodies=1m


def _exchange(sock, method: str, host: str, path: str, headers: dict | None = None, chunked: bool = False) -> bytes:
    """Send one request with a large body; returns whatever came back (the gateway may cut the connection)."""
    body = b"x" * BIG
    hdrs = {"Host": host, "Connection": "close", **(headers or {})}
    if chunked:
        hdrs["Transfer-Encoding"] = "chunked"
        body = f"{BIG:x}\r\n".encode() + body + b"\r\n0\r\n\r\n"
    else:
        hdrs["Content-Length"] = str(BIG)
    head = f"{method} {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in hdrs.items()) + "\r\n"
    data = b""
    with contextlib.suppress(OSError):
        sock.sendall(head.encode() + body)
    with contextlib.suppress(OSError):
        while chunk := sock.recv(65536):
            data += chunk
    return data


def _tls(gw: dict, target: str, sni: str):
    raw, line = connect_tunnel(gw["ports"]["http"], target)
    assert " 200" in line
    return ssl.create_default_context(cafile=gw["ca"]).wrap_socket(raw, server_hostname=sni)


def _denied(gw: dict, reason: str) -> bool:
    _, events, _ = gw["api"].call("GET", "/events?limit=20")
    return any(e["action"] == "deny" and e["reason"].startswith(reason) for e in events)


@pytest.mark.parametrize("chunked", [False, True])
def test_large_put_to_a_readonly_host_never_reaches_the_upstream(gateway, upstream, chunked):
    with _tls(gateway, f"ro.test:{upstream['https']}", "ro.test") as s:
        data = _exchange(s, "PUT", "ro.test", "/big", chunked=chunked)
    assert not data.startswith(b"HTTP/1.1 200") and b'"method"' not in data  # the echo never answered
    assert _denied(gateway, "read-only host: PUT /big")


def test_large_body_to_an_inject_host_carries_no_agent_credentials(gateway, upstream):
    gateway["api"].call("PUT", "/secrets/github_token", {"value": "ghp_E2E"})
    with _tls(gateway, f"gh.test:{upstream['https']}", "gh.test") as s:
        data = _exchange(s, "POST", "gh.test", "/upload", {"Authorization": "token AGENT", "Cookie": "s=agent"})
    assert data.split(b" ", 2)[1] == b"200"
    assert json.loads(data.partition(b"\r\n\r\n")[2])["auth"] == "Bearer ghp_E2E"  # stripped, then injected


def test_large_write_on_a_read_grant_is_refused(make_gateway, upstream):
    port = upstream["http"]
    target = {"host": "big.test", "port": port, "scheme": "http", "paths": ["/api/*"]}
    gw = make_gateway(
        {
            "hard_deny_floor": ["203.0.113.7/32"],
            "grants": {"big": {"targets": [target], "levels": ["read"], "approval": "auto"}},
        },
        {"default": "deny"},
        GW_TEST_FLOOR_REPLACE="1",
        GW_TEST_STATIC_HOSTS="big.test=127.0.0.1",
    )
    status, r, _ = gw["agent"].call("POST", "/v1/grants/big/request", {"level": "read", "reason": "e2e"})
    assert status == 200 and r["status"] == "approved", r
    for method, path, reason in (("POST", "/api/x", "grant big is read-only"), ("GET", "/admin", "path not covered")):
        with socket.create_connection(("127.0.0.1", gw["ports"]["http"]), timeout=TIMEOUT) as s:
            data = _exchange(s, method, f"big.test:{port}", f"http://big.test:{port}{path}")
        assert not data.startswith(b"HTTP/1.1 200") and b'"method"' not in data
        assert _denied(gw, reason)
