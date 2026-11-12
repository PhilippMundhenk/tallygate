"""Grant decisions through the bots (#27): deny on Telegram, revoke from Telegram's button and with
Matrix's `revoke N` reply."""

from __future__ import annotations

import time

TELEGRAM = {"TELEGRAM_BOT_TOKEN": "t", "TELEGRAM_CHAT_ID": "777", "TELEGRAM_ALLOWED_USER_IDS": "4242"}
MATRIX = {"MATRIX_ACCESS_TOKEN": "m", "MATRIX_ROOM_ID": "!room:hs", "MATRIX_ALLOWED_USERS": "@me:hs"}


def request_grant(gateway, name: str = "svc", level: str = "write") -> dict:
    time.sleep(1)  # control subscribes to the gateway stream
    _, r, _ = gateway["agent"].call("POST", f"/v1/grants/{name}/request", {"level": level, "reason": "test"})
    _, r2, _ = gateway["agent"].call("GET", f"/v1/requests/{r['id']}?wait=10")
    return r2


def active(gateway, name: str = "svc") -> list[dict]:
    return [a for a in gateway["api"].call("GET", "/grants")[1]["active"] if a["name"] == name]


def wait_until(cond, timeout: float = 8) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if cond():
            return True
        time.sleep(0.2)
    return False


def test_telegram_denies_grant(gateway, mockbots, control_with):
    mockbots.plan = {"telegram": {"scope_label": "⛔ Deny", "user_id": 4242, "chat_id": 777}}
    control_with(TELEGRAM_API_BASE=mockbots.base, **TELEGRAM)
    r = request_grant(gateway)
    assert r["status"] == "denied" and not active(gateway)
    assert wait_until(lambda: any("denied (by telegram:tester)" in m for m in mockbots.messages("tg.editMessageText")))


def test_telegram_revoke_button_ends_the_grant(gateway, mockbots, control_with):
    mockbots.plan = {"telegram": {"scope_label": "✅ Approve", "then": "Revoke", "user_id": 4242, "chat_id": 777}}
    control_with(TELEGRAM_API_BASE=mockbots.base, **TELEGRAM)
    r = request_grant(gateway)
    assert r["status"] == "approved"
    assert wait_until(lambda: not active(gateway))  # the "Revoke" button under the outcome was pressed
    assert wait_until(lambda: "revoked" in mockbots.messages("tg.answerCallbackQuery"))
    assert any("revoked by tester" in m for m in mockbots.messages("tg.editMessageText"))


def test_matrix_revoke_reply_ends_the_grant(gateway, mockbots, control_with):
    mockbots.plan = {
        "matrix": {
            "actions": [
                ("@me:hs", "text", "approve {n}"),
                ("@me:hs", "wait", "2"),  # until the grant is active
                ("@stranger:hs", "text", "revoke {n}"),  # ignored
                ("@me:hs", "text", "revoke {n}"),
            ]
        }
    }
    control_with(MATRIX_HOMESERVER=mockbots.base, **MATRIX)
    r = request_grant(gateway)
    assert r["status"] == "approved"
    assert wait_until(lambda: not active(gateway))
    assert any(m == "Grant revoked by @me:hs" for m in mockbots.messages("mx.msg"))
    assert not any("stranger" in m for m in mockbots.messages("mx.msg"))
