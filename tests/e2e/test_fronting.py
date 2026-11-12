"""#57: the TLS SNI and the HTTP Host must name the checked destination. On a shared CDN or virtual-host
server they pick the site, so another name would reach a destination nobody checked (domain fronting)."""

from __future__ import annotations

import json
import socket
import ssl

import pytest

from .helpers import TIMEOUT, _read_response, connect_tunnel, proxy_request, tls_request


def _passthrough(proxy_port: int, target: str, sni: str | None, cafile: str | None = None) -> int:
    """CONNECT + TLS with the given SNI, certificate not checked unless `cafile`. Returns the HTTP status,
    or 0 if the TLS handshake was refused."""
    raw, line = connect_tunnel(proxy_port, target)
    assert " 200" in line
    ctx = ssl.create_default_context(cafile=cafile) if cafile else ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if not cafile:
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    try:
        with ctx.wrap_socket(raw, server_hostname=sni) as t:
            t.sendall(f"GET / HTTP/1.1\r\nHost: {sni or target}\r\nConnection: close\r\n\r\n".encode())
            return _read_response(t)[0]
    except (OSError, ssl.SSLError):
        return 0


def _denied(gw: dict, reason: str) -> bool:
    _, events, _ = gw["api"].call("GET", "/events?limit=20")
    return any(e["action"] == "deny" and e["reason"].startswith(reason) for e in events)


# ---------------------------------------------------------------- SNI
def test_tls_passes_through_with_the_checked_sni(gateway, upstream):
    target = f"other.test:{upstream['https']}"
    assert _passthrough(gateway["ports"]["http"], target, "other.test", str(upstream["cert"])) == 200


@pytest.mark.parametrize("sni", ["gh.test", "front.example", None])
def test_tls_with_another_or_no_sni_is_refused(gateway, upstream, sni):
    target = f"other.test:{upstream['https']}"
    assert _passthrough(gateway["ports"]["http"], target, sni) == 0
    assert _denied(gateway, f"TLS SNI {sni or '(none)'} does not match the checked name other.test")


def test_ip_literal_connect(make_gateway, upstream):
    """No SNI is normal for an IP. An SNI name passes only if the rules allow that name by itself."""
    port = upstream["https"]
    gw = make_gateway(
        {"hard_deny_floor": ["203.0.113.7/32"]},
        {
            "default": "deny",
            "rules": [
                {"id": "ip", "action": "allow", "cidr": "127.0.0.1/32", "port": port},
                {"id": "other", "action": "allow", "host": "other.test", "port": port},
            ],
        },
        GW_TEST_FLOOR_REPLACE="1",
    )
    target = f"127.0.0.1:{port}"
    assert _passthrough(gw["ports"]["http"], target, None) == 200
    assert _passthrough(gw["ports"]["http"], target, "other.test") == 200
    assert _passthrough(gw["ports"]["http"], target, "gh.test") == 0
    assert _denied(gw, "TLS SNI gh.test on IP 127.0.0.1 is not allowed by the rules")


# ---------------------------------------------------------------- Host
def test_plain_http_proxy_request_with_another_host_is_refused(gateway, upstream):
    hp = f"127.0.0.1:{upstream['http']}"
    status, body = proxy_request(gateway["ports"]["http"], hp, "/", headers={"Host": "attacker.example"})
    assert status == 403 and b"Host header does not match the checked target" in body
    status, body = proxy_request(gateway["ports"]["http"], hp, "/ok")
    assert status == 200 and json.loads(body)["path"] == "/ok"


def _tunnelled(proxy_port: int, target: str, host: str) -> tuple[int, bytes]:
    raw, line = connect_tunnel(proxy_port, target)
    assert " 200" in line
    with raw:
        raw.sendall(f"GET /t HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
        return _read_response(raw)


def test_plain_http_in_a_connect_tunnel_with_another_host_is_refused(gateway, upstream):
    target = f"127.0.0.1:{upstream['http']}"
    status, body = _tunnelled(gateway["ports"]["http"], target, "attacker.example")
    assert status == 403 and b"Host header does not match" in body
    status, body = _tunnelled(gateway["ports"]["http"], target, target)
    assert status == 200 and json.loads(body)["path"] == "/t"


def test_intercepted_host_with_another_host_header_is_refused(gateway, upstream):
    target = f"gh.test:{upstream['https']}"
    status, body = tls_request(
        gateway["ports"]["http"], target, "gh.test", gateway["ca"], headers={"Host": "other.test"}
    )
    assert status == 403 and b"Host header does not match" in body


def test_socks5_with_another_host_is_refused(gateway, upstream):
    import struct

    s = socket.create_connection(("127.0.0.1", gateway["ports"]["socks"]), timeout=TIMEOUT)
    with s:
        s.sendall(b"\x05\x01\x00")
        assert s.recv(2) == b"\x05\x00"
        s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack(">H", upstream["http"]))
        assert s.recv(10)[1] == 0
        s.sendall(b"GET / HTTP/1.1\r\nHost: attacker.example\r\nConnection: close\r\n\r\n")
        status, body = _read_response(s)
    assert status == 403 and b"Host header does not match" in body
