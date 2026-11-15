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


def test_floor_open_opens_a_lan_range_but_never_the_stack(make_gateway, upstream):
    """ADR-0017: the admin may open a scope-all floor range from the UI for normal connections, but the
    stack's own networks (grants.internal) stay blocked whatever floor_open says."""
    url = f"http://127.0.0.2:{upstream['lan']}/x"  # 127.0.0.2 plays a LAN host
    # (a) hard-denied out of the box (secure by default), then opened via floor_open
    gw = make_gateway({"hard_deny_floor": ["127.0.0.2/32"]}, {"default": "allow"}, GW_TEST_FLOOR_REPLACE="1")
    proxy = gw["ports"]["http"]
    assert http_via_proxy(proxy, url)[0] == 502
    pol = gw["api"].call("GET", "/policy")[1]
    pol["floor_open"] = ["127.0.0.2/32"]
    gw["api"].call("PUT", "/policy", pol)
    assert gw["api"].call("GET", "/policy")[1]["floor_open"] == ["127.0.0.2/32"]
    assert http_via_proxy(proxy, url)[0] == 200  # opened: the mode (allow) now decides it

    # (b) the same range is also the stack's own network: floor_open can never open it (locked_nets first)
    gw2 = make_gateway(
        {"hard_deny_floor": ["127.0.0.2/32"]},
        {"default": "allow", "floor_open": ["127.0.0.2/32"]},
        GW_TEST_FLOOR_REPLACE="1",
        GW_INTERNAL_NETS="127.0.0.2/32",
    )
    assert http_via_proxy(gw2["ports"]["http"], url)[0] == 502


def test_api_extra_is_compared_with_the_floor_in_force(make_gateway, upstream):
    """A range that is built in but not in the floor in force (test mode) must not be dropped as a duplicate."""
    gw = make_gateway({"hard_deny_floor": ["203.0.113.7/32"]}, {"default": "allow"}, GW_TEST_FLOOR_REPLACE="1")
    proxy, url = gw["ports"]["http"], f"http://127.0.0.1:{upstream['http']}/x"
    assert http_via_proxy(proxy, url)[0] == 200
    _, pol, _ = gw["api"].call("PUT", "/policy", {"default": "allow", "hard_deny": ["127.0.0.0/8", "203.0.113.7/32"]})
    assert pol["hard_deny"] == ["127.0.0.0/8"]  # 203.0.113.7/32 is in the floor already
    assert http_via_proxy(proxy, url)[0] == 502
