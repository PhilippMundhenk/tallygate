"""ADR-0019: the blocked ranges are rules in the one ordered list; only the stack itself is locked.

(Before: #11 `hard_deny_floor` and ADR-0017 `floor_open`. What they protected is kept here in the new model:
a configured range is blocked like the built-in ones, opening a range is an explicit act of the operator, and
nothing opens the stack's own networks.)"""

from __future__ import annotations

from .helpers import http_via_proxy


def rules(gw):
    return gw["api"].call("GET", "/policy")[1]["rules"]


def test_config_never_entries_are_seeded_next_to_the_built_in_blocks(make_gateway, upstream):
    gw = make_gateway({"hard_deny_floor": ["203.0.113.7/32"]}, {"default": "allow", "rules": []})
    by_cidr = {r.get("cidr"): r for r in rules(gw)}
    assert by_cidr["203.0.113.7/32"]["source"] == "config" and by_cidr["203.0.113.7/32"]["action"] == "deny"
    assert by_cidr["127.0.0.0/8"]["source"] == "builtin" and by_cidr["169.254.0.0/16"]["source"] == "builtin"
    assert rules(gw)[-1]["cidr"] == "203.0.113.7/32"  # below the built-in blocks
    proxy = gw["ports"]["http"]
    assert http_via_proxy(proxy, f"http://127.0.0.1:{upstream['http']}/loopback")[0] == 502
    assert http_via_proxy(proxy, f"http://127.0.0.2:{upstream['lan']}/lan")[0] == 502
    assert (gw["data"] / "policy.yaml.pre-0019").exists()  # the policy file was in the old form: migrated, kept


def test_one_address_is_opened_by_an_allow_above_the_block_and_the_stack_never(make_gateway, upstream):
    """The point of ADR-0019: one device (host and port) instead of a whole range - and position decides."""
    lan, port = "127.0.0.2", upstream["lan"]  # 127.0.0.2 plays a LAN host
    url = f"http://{lan}:{port}/x"
    gw = make_gateway(
        {"never": ["127.0.0.2/31"]},
        {"default": "allow"},
        GW_TEST_FLOOR_REPLACE="1",
        GW_TEST_STATIC_HOSTS=f"nas.test={lan}",
    )
    proxy, api = gw["ports"]["http"], gw["api"]
    assert http_via_proxy(proxy, url)[0] == 502  # blocked out of the box
    # a NAME rule does not open it
    assert api.call("POST", "/destinations", {"match": {"host": "nas.test"}, "access": "allow", "id": "n"})[0] == 201
    status, body = http_via_proxy(proxy, f"http://nas.test:{port}/x")
    assert status == 502 and b"name allowed by rule n, but it resolves to 127.0.0.2, inside blocked range 127.0.0.2/31" in body
    model = api.call("GET", "/model")[1]
    shadowed = next(d for d in model["destinations"] if d.get("id") == "n")["shadowed"]
    assert shadowed["count"] == 1 and shadowed["address"] == lan and shadowed["by"] == "block-127.0.0.2_31"
    test = api.call("POST", "/test", {"host": "nas.test", "port": port})[1]
    assert test["action"] == "deny" and test["shadow"]["rule"] == "n" and test["rule"]["cidr"] == "127.0.0.2/31"
    # an ADDRESS rule does: added at the top, for that host and port only
    dest = {"match": {"cidr": f"{lan}/32", "port": port}, "access": "allow", "id": "dev"}
    assert api.call("POST", "/destinations", dest)[0] == 201
    assert http_via_proxy(proxy, url)[0] == 200 and http_via_proxy(proxy, f"http://nas.test:{port}/x")[0] == 200
    assert b"rule block-127.0.0.2_31" in http_via_proxy(proxy, f"http://{lan}:{upstream['closed']}/x")[1]  # other port
    # moved below the block it is never reached, and the model says so
    assert api.call("POST", "/destinations/dev/move", {"before": None})[0] == 200
    assert http_via_proxy(proxy, url)[0] == 502
    model = api.call("GET", "/model")[1]
    assert next(d for d in model["destinations"] if d.get("id") == "dev")["covered_by"] == "block-127.0.0.2_31"
    assert api.call("POST", "/destinations/dev/move", {"before": "block-127.0.0.2_31"})[0] == 200
    assert http_via_proxy(proxy, url)[0] == 200
    # deleting the block opens the whole range (the mode decides); it stays deleted across a policy reload ...
    assert api.call("DELETE", "/destinations/dev")[0] == 200 and http_via_proxy(proxy, url)[0] == 502
    assert api.call("DELETE", "/destinations/block-127.0.0.2_31")[0] == 200
    assert http_via_proxy(proxy, url)[0] == 200
    assert api.call("PUT", "/policy", api.call("GET", "/policy")[1])[0] == 200  # the raw editor's round trip
    assert http_via_proxy(proxy, url)[0] == 200
    # ... until it is restored
    added = api.call("POST", "/destinations/restore-blocks")[1]["added"]
    assert [r["cidr"] for r in added] == ["127.0.0.2/31"] and http_via_proxy(proxy, url)[0] == 502

    # the same address as the stack's own network: locked, whatever the list says
    gw2 = make_gateway(
        {"never": ["127.0.0.2/31"]},
        {
            "default": "allow",
            "seeded": ["127.0.0.2/31"],  # the block "deleted"
            "rules": [{"id": "all", "action": "allow", "cidr": "0.0.0.0/0"}, {"id": "n", "action": "allow", "host": "*"}],
        },
        GW_TEST_FLOOR_REPLACE="1",
        GW_INTERNAL_NETS="127.0.0.2/32",
        GW_TEST_STATIC_HOSTS=f"nas.test={lan}",
    )
    assert [r["id"] for r in rules(gw2)] == ["all", "n"]
    for target in (url, f"http://nas.test:{port}/x"):
        status, body = http_via_proxy(gw2["ports"]["http"], target)
        assert status == 502 and b"locked: 127.0.0.2 belongs to the tallygate stack itself" in body
    locked = gw2["api"].call("GET", "/model")[1]["locked"]
    assert locked[0] == {"range": "127.0.0.2/32", "source": "stack", "reason": "the tallygate stack's own network"}
    assert gw2["api"].call("GET", "/never-reachable")[1] == locked
    assert gw2["api"].call("POST", "/test", {"host": lan, "port": port})[1]["rule_id"] == "locked"


def test_the_gateway_api_is_not_reachable_through_the_proxy(make_gateway, upstream):
    """The gateway's own listeners are locked by address and port, with every block deleted and all allowed."""
    gw = make_gateway(
        {"never": ["203.0.113.7/32"]},
        {"default": "allow", "seeded": ["203.0.113.7/32"], "rules": [{"id": "all", "action": "allow", "cidr": "0.0.0.0/0"}]},
        GW_TEST_FLOOR_REPLACE="1",
    )
    proxy = gw["ports"]["http"]
    for name in ("api", "grants", "http", "socks"):
        status, body = http_via_proxy(proxy, f"http://127.0.0.1:{gw['ports'][name]}/health")
        assert status == 502 and b"is the gateway itself" in body, name
    assert http_via_proxy(proxy, f"http://127.0.0.1:{upstream['http']}/x")[0] == 200  # another port on that address


def test_a_pre_0019_policy_sent_to_the_api_is_migrated(make_gateway, upstream):
    """An old client (or an old export) still sends hard_deny: it becomes a deny rule, never nothing."""
    gw = make_gateway({"hard_deny_floor": ["203.0.113.7/32"]}, {"default": "allow"}, GW_TEST_FLOOR_REPLACE="1")
    proxy, url = gw["ports"]["http"], f"http://127.0.0.1:{upstream['http']}/x"
    assert http_via_proxy(proxy, url)[0] == 200
    old = {"default": "allow", "hard_deny": ["127.0.0.0/8", "203.0.113.7/32"], "floor_open": []}
    status, pol, _ = gw["api"].call("PUT", "/policy", old)
    assert status == 200 and "hard_deny" not in pol and "floor_open" not in pol
    assert [(r["id"], r["cidr"]) for r in pol["rules"]] == [
        ("block-127.0.0.0_8", "127.0.0.0/8"),  # the extra: the operator's own deny rule
        ("block-203.0.113.7_32", "203.0.113.7/32"),  # the config block, seeded once
    ]
    assert http_via_proxy(proxy, url)[0] == 502
