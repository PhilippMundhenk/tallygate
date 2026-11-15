"""TG-02 / #10 under ADR-0019: when a name is decided before it is resolved, and when it cannot be."""

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


def events_for(gw, host):
    return [e for e in gw["api"].call("GET", "/events?limit=100")[1] if e["host"] == host]


def test_names_are_decided_before_they_are_resolved_where_no_address_can_change_the_result(make_gateway, upstream):
    """TG-02 (ADR-0011) under ADR-0019. A name the list denies or still asks about is not resolved - unless an
    address allow rule for that port stands above what decides: then one of its addresses could be allowed by
    that rule, and the name alone cannot say. That is the price of "an address rule decides for the address,
    however it was named" (it re-opens #10 for the ports of such rules, and only for them)."""
    gw = make_gateway(
        {"hard_deny_floor": ["203.0.113.0/24"]},
        {"default": "ask", "ask_timeout": 5, "seeded": [], "rules": []},
        GW_TEST_STATIC_HOSTS="probe.test=127.0.0.1,probe2.test=198.51.100.9,probe3.test=198.51.100.10",
        GW_TEST_FLOOR_REPLACE="1",
    )
    proxy, port, other = gw["ports"]["http"], free_port(), free_port()

    # 1) no address allow rule: a pending name is held without being resolved, an unknown one is not looked up
    threading.Thread(target=connect_tunnel, args=(proxy, f"probe2.test:{port}", 8), daemon=True).start()
    p = wait_pending(gw, port)
    assert p["host"] == "probe2.test" and p["ips"] == []
    gw["api"].call("POST", f"/pending/{p['id']}/decide", {"scope": "deny", "by": "e2e"})
    _, line = connect_tunnel(proxy, f"tg02-leak.invalid:{port}", 10)
    assert " 200" not in line
    assert not any("dns failure" in e["reason"] for e in gw["api"].call("GET", "/events?limit=50")[1])
    assert all(e["ips"] == [] for e in events_for(gw, "tg02-leak.invalid"))

    # 2) approve an IP literal: an address rule for exactly that address and port, at the top
    rule = approve_soon(gw, port, "always")["rule"]
    assert (rule["cidr"], rule["port"]) == ("127.0.0.1/32", port)

    # a name that resolves to the approved address is allowed by that rule (nothing listens there: no tunnel)
    connect_tunnel(proxy, f"probe.test:{port}", 10)
    ev = events_for(gw, "probe.test")[0]
    assert (ev["action"], ev["reason"], ev["ips"]) == ("allow", f"rule {rule['id']} (approved via always)", ["127.0.0.1"])
    # another name on that port is resolved first and then asked about, with its addresses shown
    threading.Thread(target=connect_tunnel, args=(proxy, f"probe3.test:{port}", 8), daemon=True).start()
    p = wait_pending(gw, port)
    assert p["host"] == "probe3.test" and p["ips"] == ["198.51.100.10"]
    gw["api"].call("POST", f"/pending/{p['id']}/decide", {"scope": "deny", "by": "e2e"})
    # ... and an unknown name on that port is looked up now
    connect_tunnel(proxy, f"tg02-leak2.invalid:{port}", 10)
    assert events_for(gw, "tg02-leak2.invalid")[0]["reason"].startswith("dns failure")

    # 3) on every other port nothing changed: held without resolving, never looked up
    threading.Thread(target=connect_tunnel, args=(proxy, f"probe3.test:{other}", 8), daemon=True).start()
    p = wait_pending(gw, other)
    assert p["host"] == "probe3.test" and p["ips"] == []
    gw["api"].call("POST", f"/pending/{p['id']}/decide", {"scope": "deny", "by": "e2e"})
    _, line = connect_tunnel(proxy, f"tg02-leak3.invalid:{other}", 10)
    assert " 200" not in line and all(e["ips"] == [] for e in events_for(gw, "tg02-leak3.invalid"))
    assert not any("dns failure" in e["reason"] for e in events_for(gw, "tg02-leak3.invalid"))
