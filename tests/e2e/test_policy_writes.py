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
    gw["api"].call("POST", "/rules", {"id": "new", "action": "allow", "host": "new.test"})  # e.g. Telegram "Always"
    gw["api"].call("DELETE", "/rules/old")  # e.g. removed in another tab
    assert rule_ids(stale) == ["keep", "old"]
    status, data, _ = ui.call("PATCH", "/api/gw/policy", {"default": "deny"})
    assert status == 200 and data["default"] == "deny" and rule_ids(data) == ["new", "keep"]
    status, data, _ = ui.call("PATCH", "/api/gw/policy", {**stale, "default": "ask"})  # a whole copy is refused
    assert status == 400 and "changes only default and ask_timeout" in data["error"]
    assert ui.call("PATCH", "/api/gw/policy", {"ask_timeout": 2})[0] == 400
    assert ui.call("PATCH", "/api/gw/policy", {"default": "maybe"})[0] == 400
    _, now, _ = gw["api"].call("GET", "/policy")
    assert now["default"] == "deny" and rule_ids(now) == ["new", "keep"]


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
