"""Notification channels configured in the web UI (#201, ADR-0018), against the real control process, the
real gateway and the mock bot APIs: a channel saved in the UI works at once (no restart), its token is
never given back, it is refused without its allowed users, and removing it switches it off again."""

from __future__ import annotations

import json
import stat
import time

import pytest

pytest.importorskip("aiohttp", reason="needs aiohttp (pip install -r control/requirements.txt)")

from .conftest import CONTROL_PASSWORD, free_port, start_echo
from .helpers import Api, http_via_proxy

TOKEN = "424242:" + "e2e-Secret_token-" * 2
TELEGRAM = {"bot_token": TOKEN, "chat_id": "777", "allowed_user_ids": "4242"}


def login(base: str) -> Api:
    api = Api(base, csrf_header="X-Tallygate")
    api.call("POST", "/login", form={"password": CONTROL_PASSWORD})
    return api


def channel(api: Api, name: str) -> dict:
    _, data, _ = api.call("GET", "/api/notify/config")
    return next(c for c in data["channels"] if c["channel"] == name)


def test_telegram_configured_in_the_ui_approves_without_a_restart(gateway, mockbots, control_with, tmp_path):
    mockbots.plan = {"telegram": {"scope_label": "Allow host permanently", "user_id": 4242, "chat_id": 777}}
    data = tmp_path / "control-data"
    base = control_with(TELEGRAM_API_BASE=mockbots.base, CONTROL_DATA=data)  # no Telegram in the environment
    ui = login(base)
    assert ui.call("GET", "/api/meta")[1]["notify"]["telegram"] is False
    assert channel(ui, "telegram")["source"] == "unset"

    # blocking paths: no session, no CSRF header, no allowlist (ADR-0010)
    assert Api(base, csrf_header="X-Tallygate").call("PUT", "/api/notify/config/telegram", TELEGRAM)[0] == 401
    assert ui.call("PUT", "/api/notify/config/telegram", TELEGRAM, headers={"X-Tallygate": ""})[0] == 403
    status, err, _ = ui.call("PUT", "/api/notify/config/telegram", {"bot_token": TOKEN, "chat_id": "777"})
    assert status == 400 and "Allowed user ids are required" in err["error"]
    assert ui.call("GET", "/api/meta")[1]["notify"]["telegram"] is False and not (data / "notify.json").exists()

    status, saved, _ = ui.call("PUT", "/api/notify/config/telegram", TELEGRAM)
    assert status == 200 and saved["changed"] == ["bot_token", "chat_id", "allowed_user_ids"]
    tg = channel(ui, "telegram")
    assert tg["active"] is True and tg["source"] == "ui" and tg["override"] is True
    token = next(f for f in tg["fields"] if f["name"] == "bot_token")
    assert token["set"] is True and token["source"] == "ui" and "value" not in token
    for text in (json.dumps(saved), json.dumps(ui.call("GET", "/api/notify/config")[1])):
        assert TOKEN not in text  # write-only
    assert stat.S_IMODE((data / "notify.json").stat().st_mode) == 0o600

    # it works at once: a held connection is released by the Telegram button, through the new poll loop
    port = start_echo()
    t0 = time.time()
    status, body = http_via_proxy(gateway["ports"]["http"], f"http://127.0.0.1:{port}/ui-tg")
    assert status == 200 and json.loads(body)["path"] == "/ui-tg" and time.time() - t0 < 4
    events = [e for e in gateway["api"].call("GET", "/events?limit=20")[1] if e["port"] == port]
    assert any(e["reason"] == "always by telegram:tester" for e in events)

    # the Test button goes through the same sender
    before = len(mockbots.messages("tg.send"))
    mockbots.plan = {}
    assert ui.call("POST", "/api/notify/test", {"channel": "telegram"})[0] == 200
    assert "tallygate test" in mockbots.messages("tg.send")[before]

    # nothing of it reached the log
    log = "".join(p.read_text() for p in tmp_path.glob("control-*.log"))
    assert "telegram saved by admin" in log and TOKEN not in log

    # removing the override: nothing in the environment, so Telegram is off and nobody is asked there
    status, removed, _ = ui.call("DELETE", "/api/notify/config/telegram")
    assert status == 200 and removed["removed"] is True and not (data / "notify.json").read_text().count("bot_token")
    assert ui.call("GET", "/api/meta")[1]["notify"]["telegram"] is False
    sent = len(mockbots.messages("tg.send"))
    closed = free_port()
    assert http_via_proxy(gateway["ports"]["http"], f"http://127.0.0.1:{closed}/")[0] == 502  # timed out: denied
    assert len(mockbots.messages("tg.send")) == sent


def test_ntfy_from_the_ui_survives_a_restart_and_its_token_stays_with_its_server(mockbots, control_with, tmp_path):
    data = tmp_path / "control-data"
    ui = login(control_with(CONTROL_DATA=data, NTFY_URL=f"{mockbots.base}/ntfy/from-env"))
    assert channel(ui, "ntfy")["source"] == "environment"

    url = f"{mockbots.base}/ntfy/from-ui"
    assert ui.call("PUT", "/api/notify/config/ntfy", {"url": url, "token": "ui-ntfy-secret"})[0] == 200
    assert ui.call("POST", "/api/notify/test", {"channel": "ntfy"})[0] == 200
    headers, body = mockbots.got("ntfy")[-1]
    assert headers["Authorization"] == "Bearer ui-ntfy-secret" and b"tallygate test" in body
    assert "ui-ntfy-secret" not in json.dumps(ui.call("GET", "/api/notify/config")[1])

    # the UI value wins over the environment; pointing the stored token elsewhere needs the token again
    status, err, _ = ui.call("PUT", "/api/notify/config/ntfy", {"url": "http://127.0.0.1:9/ntfy/elsewhere"})
    assert status == 400 and "enter the access token again" in err["error"]
    assert channel(ui, "ntfy")["fields"][0]["value"] == url
    assert ui.call("PUT", "/api/notify/config/ntfy", {"url": "javascript:alert(1)"})[0] == 400

    # a second control process on the same data volume starts with what the UI saved
    again = login(control_with(CONTROL_DATA=data, NTFY_URL=f"{mockbots.base}/ntfy/from-env"))
    ntfy = channel(again, "ntfy")
    assert ntfy["active"] is True and ntfy["source"] == "ui" and ntfy["fields"][0]["value"] == url

    # without the override the environment is used again
    assert again.call("DELETE", "/api/notify/config/ntfy")[0] == 200
    ntfy = channel(again, "ntfy")
    assert ntfy["source"] == "environment" and ntfy["fields"][0]["value"].endswith("/ntfy/from-env")


def test_a_channel_url_cannot_point_at_the_stack_or_this_machine(gateway, mockbots, control_with, tmp_path):
    """#240, without the test switch (as in production): the mock services, the gateway API and the agent
    of this test run all listen on loopback, where a channel URL must not point. Neither the UI nor the
    environment gets a request there, and Test tells the browser nothing the service said."""
    mockbots.received.clear()
    api = f"http://127.0.0.1:{gateway['ports']['api']}"
    base = control_with(
        NOTIFY_TEST_ALLOW_LOCAL="",
        CONTROL_DATA=tmp_path / "control-data",
        NTFY_URL=f"{mockbots.base}/ntfy/from-env",
        GOTIFY_URL=f"{api}/policy?x=",
        GOTIFY_TOKEN="g",
    )
    ui = login(base)
    for name in ("ntfy", "gotify"):
        assert channel(ui, name)["active"] is False and channel(ui, name)["reason"].startswith("Off: the URL must not")
        assert ui.call("POST", "/api/notify/test", {"channel": name})[0] == 400
    matrix = {"access_token": "any-bearer", "room_id": "!r:x", "allowed_users": "@a:x"}
    for url, why in (
        (f"{api}/policy?x=", "?query"),  # the gateway's management API, the fixed suffix cut off
        (api, "this machine"),
        (mockbots.base, "this machine"),
        ("http://localhost:8080", "this machine"),
        ("http://169.254.169.254/latest/meta-data", "link-local"),
        ("http://[::1]:8081", "this machine"),
    ):
        status, err, _ = ui.call("PUT", "/api/notify/config/matrix", {"homeserver": url, **matrix})
        assert status == 400 and why in err["error"], (url, err)
        for name, extra in (("ntfy", {}), ("gotify", {"token": "t"})):
            assert ui.call("PUT", f"/api/notify/config/{name}", {"url": url + "/x", **extra})[0] == 400, url
    assert channel(ui, "matrix")["active"] is False
    # a server on the local network is still accepted (nothing listens there: Test fails with a fixed text)
    assert ui.call("PUT", "/api/notify/config/ntfy", {"url": "http://192.0.2.20:9/tallygate"})[0] == 200
    status, err, _ = ui.call("POST", "/api/notify/test", {"channel": "ntfy"})
    assert status == 502 and err["error"] in (
        "ntfy could not be reached: see the control log",
        "ntfy did not answer in time",
    )
    time.sleep(0.5)
    assert mockbots.received == []  # no request reached a service on loopback


def test_the_test_button_reports_the_status_class_only(mockbots, control_with, tmp_path):
    ui = login(control_with(CONTROL_DATA=tmp_path / "control-data"))
    url = f"{mockbots.base}/gotify"
    assert ui.call("PUT", "/api/notify/config/gotify", {"url": url, "token": "gotify-ui-secret"})[0] == 200
    assert ui.call("POST", "/api/notify/test", {"channel": "gotify"})[0] == 200
    mockbots.fail["gotify"] = "error"  # the service answers 500 {"error": "down"}
    try:
        status, err, _ = ui.call("POST", "/api/notify/test", {"channel": "gotify"})
    finally:
        mockbots.fail.pop("gotify", None)
    assert status == 502 and err == {"error": "Gotify answered with an error (HTTP 5xx): see the control log"}
