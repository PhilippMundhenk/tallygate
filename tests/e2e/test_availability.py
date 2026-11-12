"""Away mode, quiet hours and the digest end to end (#73): real gateway and control, mock chat APIs.

Each test gets its own gateway, so away mode never leaks into the shared one."""

from __future__ import annotations

import time

import pytest

from .conftest import CONTROL_PASSWORD, start_control, start_echo
from .helpers import Api, http_via_proxy
from .test_gateway import in_thread

POLICY = {"default": "ask", "ask_timeout": 20}
CONFIG = {
    "hard_deny_floor": ["10.0.0.0/8"],
    "grant_api_rate": 1000,
    "digest_minutes": 0,
    "grants": {"w": {"targets": [{"host": "w.test", "port": 443}], "levels": ["write"]}},
}
TG = {"TELEGRAM_BOT_TOKEN": "t", "TELEGRAM_CHAT_ID": "777", "TELEGRAM_ALLOWED_USER_IDS": "4242"}


@pytest.fixture
def gw(make_gateway):
    return make_gateway(CONFIG, POLICY, GW_TEST_FLOOR_REPLACE="1")


def events(gw, n=20):
    return gw["api"].call("GET", f"/events?limit={n}")[1]


def test_away_refuses_at_once_with_a_message_and_lists_what_was_missed(gw):
    status, av, _ = gw["api"].call("PATCH", "/availability", {"away": True, "by": "e2e"})
    assert status == 200 and av["mode"] == "away" and av["away"]["by"] == "e2e"
    port = start_echo()
    t0 = time.time()
    status, _ = http_via_proxy(gw["ports"]["http"], f"http://127.0.0.1:{port}/")
    assert status in (502, 403) and time.time() - t0 < 3  # not held for the 20 s approval timeout
    reason = next(e["reason"] for e in events(gw) if e.get("port") == port)
    assert "operator away" in reason and "refused without asking" in reason
    status, r, _ = gw["agent"].call("POST", "/v1/grants/w/request", {"level": "write", "reason": "x"})
    assert status == 503 and r["status"] == "denied" and "operator away" in r["error"]
    _, cat, _ = gw["agent"].call("GET", "/v1/grants")
    assert cat["operator"]["state"] == "away" and "operator away" in cat["operator"]["message"]
    _, av, _ = gw["api"].call("GET", "/availability")
    assert {(m["kind"], m["host"]) for m in av["missed"]} == {("conn", "127.0.0.1"), ("grant", "w")}
    assert gw["api"].call("GET", "/pending")[1] == []
    _, av, _ = gw["api"].call("DELETE", "/availability/missed")
    assert av["missed"] == []
    _, av, _ = gw["api"].call("PATCH", "/availability", {"away": False, "by": "e2e"})
    assert av["mode"] == "available"
    assert any(e["reason"] == "back by e2e" for e in events(gw) if e["kind"] == "admin")


def test_going_away_denies_held_connections(gw):
    port = start_echo()
    t, res = in_thread(http_via_proxy, gw["ports"]["http"], f"http://127.0.0.1:{port}/")
    for _ in range(50):
        if gw["api"].call("GET", "/pending")[1]:
            break
        time.sleep(0.1)
    until = time.time() + 3600
    _, av, _ = gw["api"].call("PATCH", "/availability", {"away_until": until, "by": "e2e"})
    assert av["mode"] == "away" and av["until"] == int(until)
    t.join(5)
    assert not t.is_alive() and res["r"][0] in (502, 403)
    assert any(m["port"] == port for m in av["missed"])


def test_quiet_hours_from_the_api(gw):
    now = time.localtime()
    start = f"{now.tm_hour:02d}:{now.tm_min:02d}"
    end = f"{(now.tm_hour + 2) % 24:02d}:{now.tm_min:02d}"
    _, av, _ = gw["api"].call("PATCH", "/availability", {"quiet_hours": {"start": start, "end": end}, "by": "e2e"})
    assert av["mode"] == "quiet" and av["quiet_source"] == "ui" and av["message"].startswith("quiet hours until")
    port = start_echo()
    status, _ = http_via_proxy(gw["ports"]["http"], f"http://127.0.0.1:{port}/")
    assert status in (502, 403)
    assert "quiet hours" in next(e["reason"] for e in events(gw) if e.get("port") == port)
    _, av, _ = gw["api"].call("PATCH", "/availability", {"quiet_hours": None, "by": "e2e"})
    assert av["mode"] == "available" and av["quiet_hours"] is None


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"by": "x"},
        [1],
        {"away": "yes"},
        {"away_until": "tomorrow"},
        {"away_until": 1},
        {"quiet_hours": {"start": "25:00", "end": "07:00"}},
        {"default": "allow"},
    ],
)
def test_invalid_changes_are_refused(gw, body):
    status, r, _ = gw["api"].call("PATCH", "/availability", body)
    assert status == 400 and "error" in r
    assert gw["api"].call("GET", "/availability")[1]["mode"] == "available"


def test_digest_reaches_telegram_when_the_operator_is_back(gw, mockbots, tmp_path):
    mockbots.plan = {}
    proc, port = start_control(tmp_path, gw, {"TELEGRAM_API_BASE": mockbots.base, **TG})
    try:
        ui = Api(f"http://127.0.0.1:{port}", csrf_header="X-Tallygate")
        ui.call("POST", "/login", form={"password": CONTROL_PASSWORD})
        status, av, _ = ui.call("PATCH", "/api/gw/availability", {"away": True, "by": "spoofed"})
        assert status == 200 and av["away"]["by"] == "web:admin"  # attribution set by control
        echo = start_echo()
        http_via_proxy(gw["ports"]["http"], f"http://127.0.0.1:{echo}/")
        http_via_proxy(gw["ports"]["http"], f"http://127.0.0.1:{echo}/")
        assert ui.call("GET", "/api/gw/availability")[1]["missed"][0]["count"] == 2
        before = len(mockbots.messages("tg.send"))
        ui.call("PATCH", "/api/gw/availability", {"away": False})
        deadline = time.time() + 5
        while len(mockbots.messages("tg.send")) == before and time.time() < deadline:
            time.sleep(0.1)
        digest = mockbots.messages("tg.send")[-1]
        assert "digest (away ended)" in digest and f"127.0.0.1:{echo} ×2" in digest
        assert ui.call("DELETE", "/api/gw/availability/missed")[0] == 200
    finally:
        proc.terminate()
        proc.wait(10)


def test_invalid_quiet_hours_in_the_config_stop_the_gateway(make_gateway):
    g = make_gateway({"quiet_hours": {"start": "late", "end": "07:00"}}, POLICY, wait=False)
    assert g["proc"].wait(30) != 0
    assert "quiet_hours" in g["log"].read_text()


def test_state_survives_a_restart(make_gateway, tmp_path):
    g = make_gateway(CONFIG, POLICY, GW_TEST_FLOOR_REPLACE="1")
    g["api"].call("PATCH", "/availability", {"away": True})
    g["proc"].terminate()
    g["proc"].wait(10)
    assert "away:" in (g["data"] / "availability.yaml").read_text()
