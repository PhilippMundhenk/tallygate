"""Policy writes through the control plane (#60): mode changes never replace rules, and the emergency stop
runs on the gateway, best effort, with a result per step."""

from __future__ import annotations

import time

import pytest

from .conftest import CONTROL_PASSWORD, free_port, start_control
from .helpers import Api, http_via_proxy
from .test_gateway import in_thread

CONFIG = {
    "hard_deny_floor": ["10.0.0.0/8"],  # replaces the built-in floor: the tests use 127.0.0.1 upstreams
    "grant_api_rate": 1000,
    "grants": {
        "auto": {"targets": [{"host": "auto.test", "port": 443}], "approval": "auto"},
        "nas": {"targets": [{"host": "nas.test", "port": 443}], "levels": ["write"]},
    },
}
POLICY = {
    "default": "ask",
    "ask_timeout": 30,
    "rules": [
        {"id": "keep", "action": "allow", "host": "keep.test"},
        {"id": "old", "action": "allow", "host": "old.test"},
    ],
}


@pytest.fixture
def stack(make_gateway, tmp_path):
    gw = make_gateway(CONFIG, POLICY, GW_TEST_FLOOR_REPLACE="1")
    proc, port = start_control(tmp_path, gw, {})
    ui = Api(f"http://127.0.0.1:{port}", csrf_header="X-Tallygate")
    assert ui.call("POST", "/login", form={"password": CONTROL_PASSWORD})[0] == 302
    yield gw, ui
    proc.terminate()
    proc.wait(10)


def rule_ids(policy):
    return [r["id"] for r in policy["rules"]]


def test_mode_change_from_a_stale_copy_cannot_drop_or_revive_rules(stack):
    gw, ui = stack
    _, stale, _ = ui.call("GET", "/api/gw/policy")  # what an open browser tab still holds
    gw["api"].call(
        "POST", "/destinations", {"id": "new", "access": "allow", "match": {"host": "new.test"}}
    )  # Telegram "Always"
    gw["api"].call("DELETE", "/destinations/old")  # e.g. removed in another tab
    assert rule_ids(stale) == ["keep", "old"]
    status, data, _ = ui.call("PATCH", "/api/gw/policy", {"default": "deny"})
    assert status == 200 and data["default"] == "deny" and rule_ids(data) == ["new", "keep"]
    status, data, _ = ui.call("PATCH", "/api/gw/policy", {**stale, "default": "ask"})  # a whole copy is refused
    assert status == 400 and "changes only default and ask_timeout" in data["error"]
    assert ui.call("PATCH", "/api/gw/policy", {"ask_timeout": 2})[0] == 400
    assert ui.call("PATCH", "/api/gw/policy", {"default": "maybe"})[0] == 400
    _, now, _ = gw["api"].call("GET", "/policy")
    assert now["default"] == "deny" and rule_ids(now) == ["new", "keep"]


def test_rule_edit_through_the_control_relay(stack):
    # #141/#122: the UI edits a rule in place through the one /destinations surface.
    gw, ui = stack
    status, data, _ = ui.call(
        "PATCH", "/api/gw/destinations/old", {"access": "deny", "expires": 2000000000, "note": "limited"}
    )
    assert status == 200 and data["id"] == "old"
    assert (data["access"], data["expires"], data["note"]) == ("deny", 2000000000, "limited")
    _, now, _ = gw["api"].call("GET", "/policy")
    old = next(r for r in now["rules"] if r["id"] == "old")
    assert old["action"] == "deny" and old["note"] == "limited"  # persisted on the gateway
    assert ui.call("PATCH", "/api/gw/destinations/missing", {"note": "x"})[0] == 404


def test_model_and_grouping_through_the_control_relay(stack):
    # #122/#142: the Destinations view reads GET /model and groups rules via POST /destinations/group, end to end.
    gw, ui = stack
    status, model, _ = ui.call("GET", "/api/gw/model")
    assert status == 200 and set(model) == {"default", "destinations", "never"}
    hosts = {d["match"].get("host") for d in model["destinations"] if d.get("access")}
    assert {"keep.test", "old.test"} <= hosts

    status, data, _ = ui.call("POST", "/api/gw/destinations/group", {"ids": ["keep", "old"], "group": "test-set"})
    assert status == 200 and {r["id"] for r in data["changed"]} == {"keep", "old"}
    _, policy, _ = gw["api"].call("GET", "/policy")
    assert all(r["group"] == "test-set" for r in policy["rules"] if r["id"] in ("keep", "old"))  # persisted
    _, model2, _ = ui.call("GET", "/api/gw/model")
    assert all(
        d.get("group") == "test-set"
        for d in model2["destinations"]
        if d["match"].get("host") in ("keep.test", "old.test")
    )

    # the Destinations tab adds/removes an on-request destination via PUT/DELETE /grants; it shows in /model
    defn = {
        "description": "shop",
        "levels": ["read", "write"],
        "approval": {"read": "ask", "write": "ask"},
        "targets": [{"host": "shop.test", "port": 443, "scheme": "https", "paths": ["/*"]}],
    }
    assert ui.call("PUT", "/api/gw/destinations/grant/shop", defn)[0] == 200
    _, m3, _ = ui.call("GET", "/api/gw/model")
    req = [d for d in m3["destinations"] if d.get("access") == "request" and d["match"].get("host") == "shop.test"]
    assert req and req[0]["request"]["name"] == "shop" and req[0]["source"] == "ui"
    assert ui.call("DELETE", "/api/gw/destinations/grant/shop")[0] == 200
    _, m4, _ = ui.call("GET", "/api/gw/model")
    assert not any(d["match"].get("host") == "shop.test" for d in m4["destinations"])


def test_destinations_crud_through_the_control_relay(stack):
    # ADR-0014: the Destinations tab uses one CRUD surface (POST/PATCH/DELETE /destinations) end to end.
    gw, ui = stack
    # add an access rule as a destination
    status, d, _ = ui.call("POST", "/api/gw/destinations", {"match": {"host": "shop.test"}, "access": "allow"})
    assert status == 201 and d["access"] == "allow"
    rid = d["id"]
    _, pol, _ = gw["api"].call("GET", "/policy")
    assert any(r["id"] == rid and r["host"] == "shop.test" for r in pol["rules"])
    # edit it through the same surface
    assert ui.call("PATCH", f"/api/gw/destinations/{rid}", {"access": "deny", "note": "n"})[0] == 200
    _, pol2, _ = gw["api"].call("GET", "/policy")
    assert next(r for r in pol2["rules"] if r["id"] == rid)["action"] == "deny"
    # add an on-request destination; it appears in /model as a ui request destination
    req = {
        "match": {"host": "svc2.test", "port": 443},
        "access": "request",
        "scheme": "https",
        "request": {
            "name": "svc2",
            "levels": ["read"],
            "approval": {"read": "ask"},
            "default_ttl": 3600,
            "max_ttl": 14400,
        },
    }
    assert ui.call("POST", "/api/gw/destinations", req)[0] == 201
    _, model, _ = ui.call("GET", "/api/gw/model")
    assert any(x["match"].get("host") == "svc2.test" and x.get("id") == "grant:svc2" for x in model["destinations"])
    # delete both through the surface
    assert ui.call("DELETE", f"/api/gw/destinations/{rid}")[0] == 200
    assert ui.call("DELETE", "/api/gw/destinations/grant:svc2")[0] == 200
    _, model2, _ = ui.call("GET", "/api/gw/model")
    assert not any(x["match"].get("host") in ("shop.test", "svc2.test") for x in model2["destinations"])


def test_behaviour_settings_through_the_control_relay(stack):
    # ADR-0015 (#147): behaviour settings read and written in the UI via the relay.
    _, ui = stack
    status, s, _ = ui.call("GET", "/api/gw/settings")
    assert status == 200 and "rule_stale_days" in s["values"] and "log_keep_days" in s["restart_keys"]
    status, after, _ = ui.call("PATCH", "/api/gw/settings", {"rule_stale_days": 50})
    assert status == 200 and after["values"]["rule_stale_days"] == 50 and after["restart_needed"] == []
    _, s2, _ = ui.call("GET", "/api/gw/settings")
    assert s2["values"]["rule_stale_days"] == 50  # persisted
    assert ui.call("PATCH", "/api/gw/settings", {"inject": []})[0] == 400  # trust-critical stays file-only


def wait_for(fn, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        v = fn()
        if v:
            return v
        time.sleep(0.1)
    raise AssertionError("condition not reached")


def test_emergency_stop_revokes_denies_removes_and_suspends_auto_approval(stack):
    gw, ui = stack
    agent = gw["agent"]
    status, auto, _ = agent.call("POST", "/v1/grants/auto/request", {"reason": "e2e"})
    assert status == 200 and auto["status"] == "approved"
    status, nas, _ = agent.call("POST", "/v1/grants/nas/request", {"level": "write", "reason": "e2e"})
    assert status == 202
    port = free_port()
    t, res = in_thread(http_via_proxy, gw["ports"]["http"], f"http://127.0.0.1:{port}/")
    wait_for(lambda: [p for p in gw["api"].call("GET", "/pending")[1] if p["port"] == port])
    assert ui.call("POST", "/api/gw/presets/internet", {"ttl": 600})[0] == 200

    status, r, _ = ui.call("POST", "/api/gw/emergency-stop", {"by": "spoofed"})
    assert status == 200 and r["ok"], r
    steps = {s["step"]: s for s in r["steps"]}
    assert steps["revoke_grants"]["revoked"] == ["auto"]
    assert steps["deny_pending"]["denied"] == [f"127.0.0.1:{port}"]
    assert steps["deny_grant_requests"]["denied"] == ["nas"]
    assert steps["remove_internet_presets"]["removed"] == ["internet:all"]
    t.join(5)
    assert not t.is_alive() and res["r"][0] != 200  # the waiting connection was refused at once

    _, g, _ = gw["api"].call("GET", "/grants")
    assert g["active"] == [] and g["requests"] == [] and g["auto_suspended"]["by"] == "web:admin"
    _, pol, _ = gw["api"].call("GET", "/policy")
    assert pol["default"] == "deny" and rule_ids(pol) == ["keep", "old"]
    _, evs, _ = gw["api"].call("GET", "/events?limit=20")
    assert any(e["action"] == "emergency-stop" and e["reason"].startswith("emergency stop by web:admin") for e in evs)
    assert agent.call("GET", f"/v1/requests/{nas['id']}")[1]["status"] == "denied"

    # the agent cannot turn its auto grant back on until a human changes the mode
    status, again, _ = agent.call("POST", "/v1/grants/auto/request", {"reason": "again"})
    assert status == 202 and again["status"] == "pending"
    assert ui.call("PATCH", "/api/gw/policy", {"default": "ask"})[0] == 200
    assert gw["api"].call("GET", "/grants")[1]["auto_suspended"] is None
    status, later, _ = agent.call("POST", "/v1/grants/auto/request", {"level": "read", "reason": "later"})
    assert later["status"] in ("approved", "pending")  # the earlier request may still be pending (deduplicated)
