"""Learning mode through the real gateway and control plane (#69)."""

from __future__ import annotations

import pytest

from .conftest import CONTROL_PASSWORD, start_control
from .helpers import Api, http_via_proxy


@pytest.fixture
def stack(make_gateway, tmp_path, upstream):
    config = {"hard_deny_floor": ["10.0.0.0/8", "192.168.0.0/16"], "learning_ports": [upstream["http"], 443]}
    policy = {"default": "deny", "rules": [{"id": "no", "action": "deny", "host": "no.learn.test"}]}
    gw = make_gateway(
        config,
        policy,
        GW_TEST_FLOOR_REPLACE="1",
        GW_TEST_STATIC_HOSTS="a.learn.test=127.0.0.1,b.learn.test=127.0.0.1,no.learn.test=127.0.0.1,lan.learn.test=192.168.7.7",
    )
    proc, port = start_control(tmp_path, gw, {})
    ui = Api(f"http://127.0.0.1:{port}", csrf_header="X-Tallygate")
    assert ui.call("POST", "/login", form={"password": CONTROL_PASSWORD})[0] == 302
    yield gw, ui
    proc.terminate()
    proc.wait(10)


def test_learn_then_save_the_rules(stack, upstream):
    gw, ui = stack
    proxy, port = gw["ports"]["http"], upstream["http"]
    url = f"http://a.learn.test:{port}/"
    assert http_via_proxy(proxy, url)[0] != 200  # mode deny
    status, st, _ = ui.call("POST", "/api/gw/learning", {"minutes": 10, "ports": [port]})
    assert status == 201 and st["active"]["by"] == "web:admin"
    assert http_via_proxy(proxy, url)[0] == 200
    assert http_via_proxy(proxy, f"http://b.learn.test:{port}/")[0] == 200
    assert http_via_proxy(proxy, f"http://no.learn.test:{port}/")[0] != 200  # deny rule
    assert http_via_proxy(proxy, f"http://lan.learn.test:{port}/")[0] != 200  # hard deny after resolving
    _, ev, _ = ui.call("GET", "/api/gw/events?kind=conn&limit=10")
    reasons = {e["host"]: e["reason"] for e in reversed(ev)}  # the newest per host
    assert reasons["a.learn.test"] == "learning mode" and reasons["no.learn.test"].startswith("rule no")
    assert reasons["lan.learn.test"].startswith("hard-deny")
    sid = st["active"]["id"]
    assert ui.call("DELETE", "/api/gw/learning")[1]["active"] is None
    assert http_via_proxy(proxy, url)[0] != 200  # over: the mode decides again
    _, s, _ = ui.call("GET", f"/api/gw/learning/{sid}")
    prop = [g["proposal"] for g in s["groups"] if g["proposal"]]
    assert prop == [{"host": "*.learn.test", "port": port}]
    status, r, _ = ui.call("POST", "/api/gw/learning/apply", {"rules": prop})
    assert status == 201 and r["added"][0]["source"] == "learning"
    assert http_via_proxy(proxy, url)[0] == 200
    assert http_via_proxy(proxy, f"http://no.learn.test:{port}/")[0] != 200  # the deny rule stays above it
    _, h, _ = ui.call("GET", "/api/gw/policy/history?limit=1")
    assert h["versions"][0]["by"] == "web:admin"
