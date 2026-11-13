"""Human-in-the-loop via Telegram and Matrix (mock APIs): approvals release held connections,
unauthorised users are ignored."""

from __future__ import annotations

import json
import time

import pytest

# Skip, don't error, without the control dependencies: control and the mock bot APIs run on aiohttp.
pytest.importorskip("aiohttp", reason="needs aiohttp (pip install -r control/requirements.txt)")

from .conftest import free_port
from .helpers import http_via_proxy


def _events(gateway, port):
    return [e for e in gateway["api"].call("GET", "/events?limit=20")[1] if e["port"] == port]


def test_telegram_button_approves(gateway, upstream, mockbots, control_with):
    mockbots.plan = {"telegram": {"scope_label": "Always allow", "user_id": 4242, "chat_id": 777}}
    control_with(
        TELEGRAM_API_BASE=mockbots.base,
        TELEGRAM_BOT_TOKEN="t",
        TELEGRAM_CHAT_ID="777",
        TELEGRAM_ALLOWED_USER_IDS="4242",
    )
    # a fresh, real upstream that has no rule yet
    from .conftest import start_echo

    port = start_echo()
    t0 = time.time()
    status, body = http_via_proxy(gateway["ports"]["http"], f"http://127.0.0.1:{port}/tg")
    assert status == 200 and json.loads(body)["path"] == "/tg" and time.time() - t0 < 4
    assert any(e["reason"] == "always by telegram:tester" for e in _events(gateway, port))
    time.sleep(0.5)
    assert any("allow (always, by telegram:tester)" in m for m in mockbots.messages("tg.editMessageText"))


def test_telegram_unauthorised_user_is_rejected(gateway, mockbots, control_with):
    mockbots.plan = {"telegram": {"scope_label": "Always allow", "user_id": 9999, "chat_id": 777}}
    control_with(
        TELEGRAM_API_BASE=mockbots.base,
        TELEGRAM_BOT_TOKEN="t",
        TELEGRAM_CHAT_ID="777",
        TELEGRAM_ALLOWED_USER_IDS="4242",
    )
    port = free_port()
    status, _ = http_via_proxy(gateway["ports"]["http"], f"http://127.0.0.1:{port}/")
    assert status == 502  # timed out -> denied
    assert any(r == "Not authorised" for r in mockbots.messages("tg.answerCallbackQuery"))
    assert not any("telegram" in (e["reason"] or "") for e in _events(gateway, port))


def test_matrix_reaction_denies_and_stranger_is_ignored(gateway, mockbots, control_with):
    mockbots.plan = {"matrix": {"actions": [("@stranger:hs", "reaction", "✅"), ("@me:hs", "reaction", "👎")]}}
    control_with(
        MATRIX_HOMESERVER=mockbots.base,
        MATRIX_ACCESS_TOKEN="m",
        MATRIX_ROOM_ID="!room:hs",
        MATRIX_ALLOWED_USERS="@me:hs",
    )
    port = free_port()
    t0 = time.time()
    status, _ = http_via_proxy(gateway["ports"]["http"], f"http://127.0.0.1:{port}/")
    assert status == 502 and time.time() - t0 < 4  # decided by reaction, not by timeout
    reasons = [e["reason"] for e in _events(gateway, port)]
    assert "deny by matrix:@me:hs" in reasons and not any("stranger" in r for r in reasons)
    assert len(mockbots.messages("mx.reaction")) >= 3  # bot pre-seeds the three first choices


def test_matrix_text_reply_approves(gateway, mockbots, control_with):
    from .conftest import start_echo

    mockbots.plan = {"matrix": {"actions": [("@me:hs", "text", "hour {n}")]}}
    control_with(
        MATRIX_HOMESERVER=mockbots.base,
        MATRIX_ACCESS_TOKEN="m",
        MATRIX_ROOM_ID="!room:hs",
        MATRIX_ALLOWED_USERS="@me:hs",
    )
    port = start_echo()
    status, _ = http_via_proxy(gateway["ports"]["http"], f"http://127.0.0.1:{port}/mx")
    assert status == 200
    assert any(e["reason"] == "hour by matrix:@me:hs" for e in _events(gateway, port))


def test_matrix_refuses_bot_in_allowed_users(gateway, mockbots, control_with):
    mockbots.plan = {"matrix": {"actions": [("@bot:hs", "reaction", "✅")]}}
    control_with(
        MATRIX_HOMESERVER=mockbots.base,
        MATRIX_ACCESS_TOKEN="m",
        MATRIX_ROOM_ID="!room:hs",
        MATRIX_ALLOWED_USERS="@bot:hs",
    )
    port = free_port()
    status, _ = http_via_proxy(gateway["ports"]["http"], f"http://127.0.0.1:{port}/")
    assert status == 502
    assert not any("matrix" in (e["reason"] or "") for e in _events(gateway, port))


def test_telegram_without_allowed_users_is_disabled(mockbots, control_with):
    """TG-06: without TELEGRAM_ALLOWED_USER_IDS any member of a group chat could approve."""
    from .conftest import CONTROL_PASSWORD
    from .helpers import Api

    base = control_with(TELEGRAM_API_BASE=mockbots.base, TELEGRAM_BOT_TOKEN="t", TELEGRAM_CHAT_ID="777")
    a = Api(base, csrf_header="X-Tallygate")
    a.call("POST", "/login", form={"password": CONTROL_PASSWORD})
    _, meta, _ = a.call("GET", "/api/meta")
    assert meta["notify"]["telegram"] is False


def _revoke_all(gateway, name):
    _, g, _ = gateway["api"].call("GET", "/grants")
    for a in g["active"]:
        if a["name"] == name:
            gateway["api"].call("DELETE", f"/active-grants/{a['id']}")


def test_telegram_grant_request_can_be_downgraded_to_read(gateway, mockbots, control_with):
    mockbots.plan = {"telegram": {"scope_label": "📖 Approve read-only", "user_id": 4242, "chat_id": 777}}
    control_with(
        TELEGRAM_API_BASE=mockbots.base,
        TELEGRAM_BOT_TOKEN="t",
        TELEGRAM_CHAT_ID="777",
        TELEGRAM_ALLOWED_USER_IDS="4242",
    )
    time.sleep(1)  # control subscribes to the gateway stream
    _, r, _ = gateway["agent"].call("POST", "/v1/grants/svc/request", {"level": "write", "reason": "dim the lights"})
    _, r2, _ = gateway["agent"].call("GET", f"/v1/requests/{r['id']}?wait=10")
    assert r2["status"] == "approved" and r2["granted_level"] == "read"
    sent = [m for m in mockbots.messages("tg.send") if "Grant request: svc" in m][-1]
    assert "Agent's reason (unverified): dim the lights" in sent
    time.sleep(0.5)
    assert any("read until" in m and "telegram:tester" in m for m in mockbots.messages("tg.editMessageText"))
    _revoke_all(gateway, "svc")


def test_matrix_text_reply_approves_grant(gateway, mockbots, control_with):
    mockbots.plan = {
        "matrix": {"actions": [("@stranger:hs", "text", "approve {n}"), ("@me:hs", "text", "approve {n}")]}
    }
    control_with(
        MATRIX_HOMESERVER=mockbots.base,
        MATRIX_ACCESS_TOKEN="m",
        MATRIX_ROOM_ID="!room:hs",
        MATRIX_ALLOWED_USERS="@me:hs",
    )
    time.sleep(1)
    _, r, _ = gateway["agent"].call("POST", "/v1/grants/sec/request", {"level": "write", "reason": "deploy check"})
    _, r2, _ = gateway["agent"].call("GET", f"/v1/requests/{r['id']}?wait=10")
    assert r2["status"] == "approved" and r2["granted_level"] == "write"
    _, g, _ = gateway["api"].call("GET", "/grants")
    assert next(a for a in g["active"] if a["name"] == "sec")["approved_by"] == "matrix:@me:hs"
    _revoke_all(gateway, "sec")
