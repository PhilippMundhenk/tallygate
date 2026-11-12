"""Rule hit counters, unused rules and suggestions through the real gateway and control plane (#70)."""

from __future__ import annotations

import time

import pytest

from .conftest import CONTROL_PASSWORD, start_control
from .helpers import Api, http_via_proxy
from .test_gateway import in_thread


@pytest.fixture
def stack(make_gateway, tmp_path, upstream):
    config = {"hard_deny_floor": ["10.0.0.0/8"], "suggest_min_approvals": 1, "rule_stale_days": 1}
    policy = {
        "default": "ask",
        "ask_timeout": 20,
        "rules": [
            {"id": "echo", "action": "allow", "host": "echo.test", "port": upstream["http"]},
            {"id": "never", "action": "allow", "host": "never.test"},
            {"id": "blocked", "action": "deny", "host": "blocked.test"},
        ],
    }
    gw = make_gateway(
        config, policy, GW_TEST_FLOOR_REPLACE="1", GW_TEST_STATIC_HOSTS="echo.test=127.0.0.1,sug.test=127.0.0.1"
    )
    proc, port = start_control(tmp_path, gw, {})
    ui = Api(f"http://127.0.0.1:{port}", csrf_header="X-Tallygate")
    assert ui.call("POST", "/login", form={"password": CONTROL_PASSWORD})[0] == 302
    yield gw, ui
    proc.terminate()
    proc.wait(10)


def stats(ui):
    return {r["id"]: r for r in ui.call("GET", "/api/gw/rules/stats")[1]["rules"]}


def test_allowed_and_denied_connections_count_for_their_rule(stack, upstream):
    gw, ui = stack
    proxy = gw["ports"]["http"]
    for _ in range(2):
        assert http_via_proxy(proxy, f"http://echo.test:{upstream['http']}/")[0] == 200
    assert http_via_proxy(proxy, "http://blocked.test/")[0] in (502, 403)
    s = stats(ui)
    assert s["echo"]["hits"] >= 1 and s["echo"]["last"] and s["blocked"]["hits"] == 1
    assert s["never"]["hits"] == 0 and s["never"]["last"] is None and not s["never"]["stale"]  # seen just now


def test_a_temporary_approval_becomes_a_suggestion_and_a_permanent_rule(stack, upstream):
    gw, ui = stack
    url = f"http://sug.test:{upstream['http']}/"
    t, _ = in_thread(http_via_proxy, gw["ports"]["http"], url)
    deadline, pending = time.time() + 5, []
    while not pending and time.time() < deadline:
        pending = ui.call("GET", "/api/gw/pending")[1]
        time.sleep(0.1)
    assert ui.call("POST", f"/api/gw/pending/{pending[0]['id']}/decide", {"scope": "once"})[0] == 200
    t.join(10)
    _, sg, _ = ui.call("GET", "/api/gw/suggestions")
    key = f"sug.test:{upstream['http']}"
    assert [s["key"] for s in sg["suggestions"]] == [key] and sg["suggestions"][0]["count"] == 1
    status, rule, _ = ui.call("POST", "/api/gw/suggestions/accept", {"key": key})
    assert status == 201 and rule["host"] == "sug.test" and "expires" not in rule
    assert ui.call("GET", "/api/gw/suggestions")[1]["suggestions"] == []
    _, h, _ = ui.call("GET", "/api/gw/policy/history?limit=1")
    assert h["versions"][0]["by"] == "web:admin" and "suggestion accepted" in h["versions"][0]["what"]


def test_unused_rules_are_offered_and_removed_only_if_still_unused(stack):
    gw, ui = stack
    gw_api = gw["api"]
    s = stats(ui)
    assert not any(r["stale"] for r in s.values())  # rule_stale_days 1: nothing is a day old yet
    status, r, _ = ui.call("POST", "/api/gw/rules/cleanup", {"ids": ["never"]})
    assert status == 200 and r == {"removed": [], "kept": ["never"]}
    assert "never" in [x["id"] for x in gw_api.call("GET", "/policy")[1]["rules"]]
