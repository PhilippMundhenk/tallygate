"""Notification channels are independent (#22): one chat API failing or hanging does not stop or delay
the prompt on the other one."""

from __future__ import annotations

import time

import pytest

from .conftest import start_echo
from .helpers import http_via_proxy

BOTH = {
    "TELEGRAM_BOT_TOKEN": "t",
    "TELEGRAM_CHAT_ID": "777",
    "TELEGRAM_ALLOWED_USER_IDS": "4242",
    "MATRIX_ACCESS_TOKEN": "m",
    "MATRIX_ROOM_ID": "!room:hs",
    "MATRIX_ALLOWED_USERS": "@me:hs",
}


@pytest.fixture
def outage(mockbots):
    yield mockbots.fail
    mockbots.fail.clear()


def _both(control_with, mockbots):
    control_with(TELEGRAM_API_BASE=mockbots.base, MATRIX_HOMESERVER=mockbots.base, **BOTH)


def _reasons(gateway, port):
    return [e["reason"] for e in gateway["api"].call("GET", "/events?limit=20")[1] if e["port"] == port]


@pytest.mark.parametrize("kind", ["error", "slow"])
def test_matrix_delivers_while_telegram_is_down(gateway, mockbots, control_with, outage, kind):
    outage["telegram"] = kind
    mockbots.plan = {"matrix": {"actions": [("@me:hs", "text", "hour {n}")]}}
    _both(control_with, mockbots)
    port = start_echo()
    t0 = time.time()
    status, _ = http_via_proxy(gateway["ports"]["http"], f"http://127.0.0.1:{port}/")
    assert status == 200 and time.time() - t0 < 4  # approved on Matrix, not held until the timeout
    assert "hour by matrix:@me:hs" in _reasons(gateway, port)


def test_telegram_delivers_while_matrix_is_down(gateway, mockbots, control_with, outage):
    outage["matrix"] = "error"
    mockbots.plan = {"telegram": {"scope_label": "Allow 1 h", "user_id": 4242, "chat_id": 777}}
    _both(control_with, mockbots)
    port = start_echo()
    status, _ = http_via_proxy(gateway["ports"]["http"], f"http://127.0.0.1:{port}/")
    assert status == 200
    assert "hour by telegram:tester" in _reasons(gateway, port)
    time.sleep(0.5)
    assert any("allow (hour, by telegram:tester)" in m for m in mockbots.messages("tg.editMessageText"))


def test_grant_request_reaches_matrix_while_telegram_fails(gateway, mockbots, control_with, outage):
    outage["telegram"] = "error"
    mockbots.plan = {"matrix": {"actions": [("@me:hs", "text", "approve {n}")]}}
    _both(control_with, mockbots)
    time.sleep(1)  # control subscribes to the gateway stream
    _, r, _ = gateway["agent"].call("POST", "/v1/grants/svc/request", {"level": "write", "reason": "status"})
    _, r2, _ = gateway["agent"].call("GET", f"/v1/requests/{r['id']}?wait=10")
    assert r2["status"] == "approved"
    _, g, _ = gateway["api"].call("GET", "/grants")
    assert next(a for a in g["active"] if a["name"] == "svc")["approved_by"] == "matrix:@me:hs"
    for a in g["active"]:
        if a["name"] == "svc":
            gateway["api"].call("DELETE", f"/active-grants/{a['id']}")
