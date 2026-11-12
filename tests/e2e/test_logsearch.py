"""Log search, destinations and the per-destination view through the control plane (#80)."""

from __future__ import annotations

import time

import pytest

from .conftest import CONTROL_PASSWORD, start_control
from .helpers import Api, http_via_proxy


@pytest.fixture
def stack(make_gateway, tmp_path, upstream):
    policy = {
        "default": "deny",
        "rules": [
            {"id": "echo", "action": "allow", "host": "*.echo.test", "port": upstream["http"]},
            {"id": "nope", "action": "deny", "host": "nope.test"},
        ],
    }
    gw = make_gateway(
        {"hard_deny_floor": ["10.0.0.0/8"]},
        policy,
        GW_TEST_FLOOR_REPLACE="1",
        GW_TEST_STATIC_HOSTS="a.echo.test=127.0.0.1,b.echo.test=127.0.0.1",
    )
    proc, port = start_control(tmp_path, gw, {})
    ui = Api(f"http://127.0.0.1:{port}", csrf_header="X-Tallygate")
    assert ui.call("POST", "/login", form={"password": CONTROL_PASSWORD})[0] == 302
    yield gw, ui
    proc.terminate()
    proc.wait(10)


def test_search_destinations_and_detail(stack, upstream):
    gw, ui = stack
    start = time.time() - 1
    proxy, port = gw["ports"]["http"], upstream["http"]
    assert http_via_proxy(proxy, f"http://a.echo.test:{port}/")[0] == 200
    assert http_via_proxy(proxy, f"http://b.echo.test:{port}/")[0] == 200
    http_via_proxy(proxy, "http://nope.test/")
    _, ev, _ = ui.call("GET", f"/api/gw/events?host=*.echo.test&kind=conn&since={start}")
    assert {e["host"] for e in ev} == {"a.echo.test", "b.echo.test"} and all(e["action"] == "allow" for e in ev)
    _, ev, _ = ui.call("GET", "/api/gw/events?kind=conn&action=deny")
    assert [e["host"] for e in ev] == ["nope.test"]
    assert ui.call("GET", f"/api/gw/events?until={start}&kind=conn")[1] == []
    assert ui.call("GET", "/api/gw/events?kind=bogus")[0] == 400
    _, dests, _ = ui.call("GET", f"/api/gw/destinations?since={start}&new=1")
    assert {(d["host"], d["new"]) for d in dests} == {("a.echo.test", True), ("b.echo.test", True), ("nope.test", True)}
    _, d, _ = ui.call("GET", f"/api/gw/destinations/detail?host=a.echo.test&port={port}")
    assert (
        d["decision"]["rule"]["id"] == "echo" and d["stats"]["allowed"] == 1 and d["events"][0]["host"] == "a.echo.test"
    )
    _, d, _ = ui.call("GET", "/api/gw/destinations/detail?host=nope.test&port=80")
    assert d["decision"]["action"] == "deny" and d["stats"]["denied"] == 1
