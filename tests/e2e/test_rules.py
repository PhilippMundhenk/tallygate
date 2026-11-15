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
    """#119: an approval or a shortcut on top of the list must not switch off a CIDR deny further down.
    ADR-0019 keeps it: they are name rules, and a name rule never overrides an address deny below it."""
    port = upstream["http"]
    gw = make_gateway(
        {"hard_deny_floor": ["203.0.113.7/32"]},
        {
            "default": "ask",
            "ask_timeout": 5,
            "seeded": [],  # the current form: the rules stay in this order
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
    assert [r["id"] for r in gw["api"].call("GET", "/policy")[1]["rules"]][:3] == ["web", "always", "net"]
    assert http_via_proxy(proxy, f"http://fine.test:{port}/ok")[0] == 200  # outside the range: allowed as before
    assert http_via_proxy(proxy, f"http://evil.test:{port}/x")[0] == 502
    _, events, _ = gw["api"].call("GET", "/events?limit=10")
    denied = next(e for e in events if e["host"] == "evil.test")
    assert denied["action"] == "deny" and denied["ips"] == ["127.0.0.2"]
    assert denied["reason"] == (
        "name allowed by rule web, but it resolves to 127.0.0.2, inside blocked range 127.0.0.2/32 (rule net): "
        "add an allow for the address above that rule"
    )
    # the IP literal: the `*` rule matches it as a name rule would - and the deny below still wins
    assert http_via_proxy(proxy, f"http://127.0.0.2:{upstream['lan']}/x")[0] == 502


def test_a_pre_0019_policy_keeps_its_cidr_denies_winning(make_gateway, upstream):
    """Migration: in an old policy.yaml a CIDR deny won wherever it stood, also over a CIDR allow above it."""
    port = upstream["http"]
    gw = make_gateway(
        {"hard_deny_floor": ["203.0.113.7/32"]},
        {
            "default": "deny",
            "rules": [
                {"id": "lo", "action": "allow", "cidr": "127.0.0.0/8"},
                {"id": "net", "action": "deny", "cidr": "127.0.0.2/32"},
            ],
        },
        GW_TEST_FLOOR_REPLACE="1",
    )
    assert [r["id"] for r in gw["api"].call("GET", "/policy")[1]["rules"]][:2] == ["net", "lo"]
    assert http_via_proxy(gw["ports"]["http"], f"http://127.0.0.1:{port}/ok")[0] == 200
    assert http_via_proxy(gw["ports"]["http"], f"http://127.0.0.2:{upstream['lan']}/x")[0] == 502
    # what the migration did is in the event log the operator reads, and in the gateway's own log
    event = next(e for e in gw["api"].call("GET", "/events?limit=50&kind=admin")[1] if e["action"] == "policy")
    assert "migrated to one ordered rule list (ADR-0019): moved 1 CIDR deny rule(s) to the top: net" in event["reason"]
    gw["proc"].terminate()
    gw["proc"].wait(10)
    log = gw["log"].read_text()
    assert "policy migration: moved 1 CIDR deny rule(s) to the top: net" in log and "kept as *.pre-0019" in log


def test_null_and_garbled_ports_are_rejected(gateway):
    api = gateway["api"]
    for port in (None, [443, None], "https", "443;8443"):
        status, body, _ = api.call(
            "POST", "/destinations", {"access": "allow", "match": {"host": "p9.test", "port": port}}
        )
        assert status == 400 and "invalid port" in body["error"], port
    assert not any(r.get("host") == "p9.test" for r in api.call("GET", "/policy")[1]["rules"])
