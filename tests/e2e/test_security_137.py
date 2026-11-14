"""Security review of the ADR-0014 refactor (#137): a request must be checked against the connection's
checked destination, not the host it names for itself; and a CIDR deny wins for IP literals too."""

from __future__ import annotations

import socket

from .helpers import TIMEOUT, _read_response, http_via_proxy, proxy_request


def _absolute_https(proxy_port: int, host_port: str, path: str, method: str = "GET") -> tuple[int, bytes]:
    """An absolute-form `https://` request sent straight to the HTTP proxy port, with no CONNECT."""
    head = (
        f"{method} https://{host_port}{path} HTTP/1.1\r\nHost: {host_port}\r\n"
        "Connection: close\r\nContent-Length: 0\r\n\r\n"
    )
    with socket.create_connection(("127.0.0.1", proxy_port), timeout=TIMEOUT) as s:
        s.sendall(head.encode())
        return _read_response(s)


def test_absolute_form_https_over_the_plain_proxy_is_refused(make_gateway, upstream):
    """#137: an https destination must come through CONNECT, where it is gated and TLS is intercepted or
    bound to the SNI. Sent as an absolute-form proxy request it would be checked against the host it names,
    skipping the grant and credential limits of the real target."""
    port = upstream["https"]  # a real TLS port, so the upstream handshake succeeds and the request is reached
    gw = make_gateway(
        {
            "hard_deny_floor": ["203.0.113.7/32"],
            "inject": [{"host": "gh.test", "value": "Bearer ${t}"}],
            "grants_never": ["169.254.0.0/16"],
            "grants": {"g": {"targets": [{"host": "api.test", "port": port, "paths": ["/api/*"]}], "approval": "auto"}},
        },
        {"default": "allow", "rules": []},
        GW_TEST_FLOOR_REPLACE="1",
        GW_TEST_STATIC_HOSTS="gh.test=127.0.0.1,api.test=127.0.0.1",
    )
    proxy = gw["ports"]["http"]
    for host in (f"gh.test:{port}", f"api.test:{port}"):
        status, body = _absolute_https(proxy, host, "/admin/x", "DELETE")
        assert status == 403 and b"https over the plain proxy must use CONNECT" in body, (host, status, body)
    # plain http to a plain-http host still works (the request names what it is)
    assert http_via_proxy(proxy, f"http://gh.test:{upstream['http']}/ok")[0] == 200


def test_a_cidr_deny_refuses_an_ip_literal_below_a_wildcard_allow(make_gateway, upstream):
    """#137: the #119 "a CIDR deny always wins" holds for IP literals too. A `*` allow (e.g. the open preset)
    must not let the agent reach a denied range by connecting to the IP directly."""
    port = upstream["http"]
    gw = make_gateway(
        {"hard_deny_floor": ["203.0.113.7/32"]},
        {
            "default": "deny",
            "rules": [
                {"id": "web", "action": "allow", "host": "*", "port": port},  # like "Allow web"
                {"id": "ok", "action": "allow", "cidr": "127.0.0.1/32", "port": port},  # a narrower allow on top
                {"id": "net", "action": "deny", "cidr": "127.0.0.0/8"},
            ],
        },
        GW_TEST_FLOOR_REPLACE="1",
    )
    proxy = gw["ports"]["http"]
    status, _ = proxy_request(proxy, f"127.0.0.1:{port}", "/x")
    assert status in (403, 502)  # the CIDR deny wins over the `*` allow and the narrower allow above it
    _, events, _ = gw["api"].call("GET", "/events?limit=10")
    assert any(e.get("reason") == "rule net" and e["action"] == "deny" for e in events)
