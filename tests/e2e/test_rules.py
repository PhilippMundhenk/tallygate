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


def test_null_and_garbled_ports_are_rejected(gateway):
    api = gateway["api"]
    for port in (None, [443, None], "https", "443;8443"):
        status, body, _ = api.call("POST", "/rules", {"action": "allow", "host": "p9.test", "port": port})
        assert status == 400 and "invalid port" in body["error"], port
    assert not any(r.get("host") == "p9.test" for r in api.call("GET", "/policy")[1]["rules"])
