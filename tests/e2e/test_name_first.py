"""TG-02 / #10: an approved IP literal must not make the gateway resolve hostnames before deciding on them."""

from __future__ import annotations

import threading
import time

from .conftest import free_port
from .helpers import connect_tunnel


def wait_pending(gw, port, timeout=4.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        match = [p for p in gw["api"].call("GET", "/pending")[1] if p["port"] == port]
        if match:
            return match[0]
        time.sleep(0.1)
    raise AssertionError(f"no pending request for port {port}")


def approve_soon(gw, port, scope):
    threading.Thread(target=connect_tunnel, args=(gw["ports"]["http"], f"127.0.0.1:{port}", 8), daemon=True).start()
    p = wait_pending(gw, port)
    return gw["api"].call("POST", f"/pending/{p['id']}/decide", {"scope": scope, "by": "e2e"})[1]


def test_ip_approval_does_not_resolve_names_before_the_decision(make_gateway, upstream):
    gw = make_gateway(
        {"hard_deny_floor": ["203.0.113.0/24"]},
        {"default": "ask", "ask_timeout": 5, "rules": []},
        GW_TEST_STATIC_HOSTS="probe.test=127.0.0.1,probe2.test=198.51.100.9",
    )
    port = free_port()
    assert approve_soon(gw, port, "always")["rule"]["cidr"] == "127.0.0.1"

    # a pending name is held without being resolved
    threading.Thread(target=connect_tunnel, args=(gw["ports"]["http"], f"probe2.test:{port}", 8), daemon=True).start()
    p = wait_pending(gw, port)
    assert p["host"] == "probe2.test" and p["ips"] == []
    gw["api"].call("POST", f"/pending/{p['id']}/decide", {"scope": "deny", "by": "e2e"})

    # a name resolving to the approved IP is not allowed by that approval: it is asked about (and times out)
    _, line = connect_tunnel(gw["ports"]["http"], f"probe.test:{port}", 10)
    assert " 200" not in line
    events = [e for e in gw["api"].call("GET", "/events?limit=20")[1] if e["host"] == "probe.test"]
    assert events and all(e["ips"] == [] for e in events)
    # an unknown name is not looked up either (it used to cause a real DNS query: "dns failure")
    _, line = connect_tunnel(gw["ports"]["http"], f"tg02-leak.invalid:{port}", 10)
    assert " 200" not in line
    assert not any("dns failure" in e["reason"] for e in gw["api"].call("GET", "/events?limit=50")[1])
