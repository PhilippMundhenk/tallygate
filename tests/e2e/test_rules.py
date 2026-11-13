"""#13: rule notation cannot be used to slip past a rule."""

from __future__ import annotations

from .helpers import connect_tunnel, http_via_proxy


def test_ipv4_mapped_literal_is_matched_by_cidr_deny(make_gateway, upstream):
    gw = make_gateway(
        {"hard_deny_floor": ["203.0.113.7/32"]},
        {"default": "allow", "rules": [{"id": "d", "action": "deny", "cidr": "127.0.0.1/32"}]},
        GW_TEST_FLOOR_REPLACE="1",
    )
    proxy, port = gw["ports"]["http"], upstream["http"]
    assert http_via_proxy(proxy, f"http://127.0.0.1:{port}/v4")[0] == 502
    assert http_via_proxy(proxy, f"http://[::ffff:127.0.0.1]:{port}/mapped")[0] == 502
    assert " 200" not in connect_tunnel(proxy, f"[::ffff:127.0.0.1]:{port}")[1]


def test_a_cidr_deny_refuses_a_name_below_rules_that_allow_it(make_gateway, upstream):
    """#119: an approval or a shortcut on top of the list must not switch off a CIDR deny further down."""
    port = upstream["http"]
    gw = make_gateway(
        {"hard_deny_floor": ["203.0.113.7/32"]},
        {
            "default": "ask",
            "ask_timeout": 5,
            "rules": [
                {"id": "web", "action": "allow", "host": "*", "port": port},  # like "Allow web for 15 min"
                {"id": "always", "action": "allow", "host": "evil.test", "port": port},  # like "Always allow"
                {"id": "net", "action": "deny", "cidr": "127.0.0.2/32"},
            ],
        },
        GW_TEST_FLOOR_REPLACE="1",
        GW_TEST_STATIC_HOSTS="evil.test=127.0.0.2,fine.test=127.0.0.1",
    )
    proxy = gw["ports"]["http"]
    assert http_via_proxy(proxy, f"http://fine.test:{port}/ok")[0] == 200  # outside the range: allowed as before
    assert http_via_proxy(proxy, f"http://evil.test:{port}/x")[0] == 502
    _, events, _ = gw["api"].call("GET", "/events?limit=10")
    denied = next(e for e in events if e["host"] == "evil.test")
    assert denied["action"] == "deny" and denied["reason"] == "rule net" and denied["ips"] == ["127.0.0.2"]


def test_null_and_garbled_ports_are_rejected(gateway):
    api = gateway["api"]
    for port in (None, [443, None], "https", "443;8443"):
        status, body, _ = api.call("POST", "/rules", {"action": "allow", "host": "p9.test", "port": port})
        assert status == 400 and "invalid port" in body["error"], port
    assert not any(r.get("host") == "p9.test" for r in api.call("GET", "/policy")[1]["rules"])
