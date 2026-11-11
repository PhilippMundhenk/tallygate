"""Human-in-the-loop via Telegram and Matrix (mock APIs): approvals release held connections,
unauthorised users are ignored."""

from __future__ import annotations

import json
import time

from .conftest import free_port
from .helpers import http_via_proxy


def _events(gateway, port):
    return [e for e in gateway["api"].call("GET", "/events?limit=20")[1] if e["port"] == port]


def test_telegram_button_approves(gateway, upstream, mockbots, control_with):
    mockbots.plan = {"telegram": {"scope_label": "Always (host)", "user_id": 4242, "chat_id": 777}}
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
    mockbots.plan = {"telegram": {"scope_label": "Always (host)", "user_id": 9999, "chat_id": 777}}
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
    assert len(mockbots.messages("mx.reaction")) >= 6  # bot pre-seeds the reaction buttons


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
