"""#11: hard_deny_floor extends the built-in list; API extras are compared with the floor in force."""

from __future__ import annotations

from .helpers import http_via_proxy


def test_configured_floor_extends_the_builtin_list(make_gateway, upstream):
    gw = make_gateway({"hard_deny_floor": ["203.0.113.7/32"]}, {"default": "allow", "rules": []})
    floor = gw["api"].call("GET", "/policy")[1]["hard_deny_floor"]
    assert "203.0.113.7/32" in floor and "127.0.0.0/8" in floor and "169.254.0.0/16" in floor
    proxy = gw["ports"]["http"]
    assert http_via_proxy(proxy, f"http://127.0.0.1:{upstream['http']}/loopback")[0] == 502
    assert http_via_proxy(proxy, f"http://127.0.0.2:{upstream['lan']}/lan")[0] == 502


def test_api_extra_is_compared_with_the_floor_in_force(make_gateway, upstream):
    """A range that is built in but not in the floor in force (test mode) must not be dropped as a duplicate."""
    gw = make_gateway({"hard_deny_floor": ["203.0.113.7/32"]}, {"default": "allow"}, GW_TEST_FLOOR_REPLACE="1")
    proxy, url = gw["ports"]["http"], f"http://127.0.0.1:{upstream['http']}/x"
    assert http_via_proxy(proxy, url)[0] == 200
    _, pol, _ = gw["api"].call("PUT", "/policy", {"default": "allow", "hard_deny": ["127.0.0.0/8", "203.0.113.7/32"]})
    assert pol["hard_deny"] == ["127.0.0.0/8"]  # 203.0.113.7/32 is in the floor already
    assert http_via_proxy(proxy, url)[0] == 502
