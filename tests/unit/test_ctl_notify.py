"""control/app/notify.py in-process: who may decide, how chat input is parsed, and that failures of one
message or channel never break the notifier. The chat APIs are replaced by a recording fake at the
_tg / _mx level (the HTTP wrappers themselves are exercised by the e2e tests against mock bots)."""

from __future__ import annotations

import asyncio
import logging
import sys
import time
from pathlib import Path

import pytest

pytest.importorskip("aiohttp")
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "control"))

from app import notify

TG = {"TELEGRAM_BOT_TOKEN": "SECRET", "TELEGRAM_CHAT_ID": "777", "TELEGRAM_ALLOWED_USER_IDS": "4242"}
MX = {
    "MATRIX_HOMESERVER": "http://hs",
    "MATRIX_ACCESS_TOKEN": "m",
    "MATRIX_ROOM_ID": "!room:hs",
    "MATRIX_ALLOWED_USERS": "@me:hs",
}


class Chat:
    """Fake Telegram + Matrix: records calls, fails on request, plays scripted getUpdates / sync replies."""

    def __init__(self) -> None:
        self.calls: list[tuple] = []
        self.fail: set[str] = set()  # telegram methods or matrix path fragments that raise
        self.script: list = []  # replies for getUpdates / sync (an exception is raised instead)
        self.whoami: object = {"user_id": "@bot:hs"}
        self.hold: asyncio.Event | None = None  # while set up and not set, reactions hang (slow homeserver)

    def _next(self):
        item = self.script.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item

    async def tg(self, method, **params):
        self.calls.append(("tg", method, params))
        if method in self.fail:
            raise RuntimeError(f"telegram {method}: down")
        if method == "getUpdates":
            return self._next()
        return {"message_id": 41} if method == "sendMessage" else True

    async def mx(self, method, path, body=None, params=None):
        self.calls.append(("mx", method, path, body, params))
        if any(f in path for f in self.fail):
            raise RuntimeError(f"matrix {path}: down")
        if "m.reaction" in path and self.hold is not None:
            await self.hold.wait()
        if path == "/account/whoami":
            if isinstance(self.whoami, BaseException):
                raise self.whoami
            return self.whoami
        if path == "/sync":
            return self._next()
        return {"event_id": f"$e{len(self.calls)}"}

    def sent(self, kind: str, what: str) -> list:
        return [c for c in self.calls if c[0] == kind and what in c[1 + (kind == "mx")]]

    def notices(self) -> list[str]:
        return [c[3]["body"] for c in self.calls if c[0] == "mx" and c[3] and c[3].get("msgtype") == "m.notice"]


class Decisions:
    def __init__(self) -> None:
        self.calls: list[tuple] = []
        self.reply = (200, {"ok": True})

    async def __call__(self, *args):
        self.calls.append(args)
        return self.reply


@pytest.fixture
def make(monkeypatch):
    def _make(env=None, grants=True):
        for k in (*TG, *MX, "PUBLIC_URL"):
            monkeypatch.delenv(k, raising=False)
        for k, v in (env or {}).items():
            monkeypatch.setenv(k, v)
        d, dg, rg = Decisions(), Decisions(), Decisions()
        n = notify.Notifier({}, decide=d, decide_grant=dg if grants else None, revoke_grant=rg if grants else None)
        chat = Chat()
        n._tg, n._mx = chat.tg, chat.mx
        n.chat, n.d, n.dg, n.rg = chat, d, dg, rg
        return n

    return _make


@pytest.fixture
def no_sleep(monkeypatch):
    slept = []

    async def sleep(s):
        slept.append(s)

    monkeypatch.setattr(notify.asyncio, "sleep", sleep)
    return slept


def run(coro):
    return asyncio.run(coro)


def pending(pid="p1", **kw):
    return {"id": pid, "host": "api.example.com", "port": 443, "proto": "https", "expires": time.time() + 60, **kw}


# ---------------------------------------------------------------- texts and configuration
def test_describe_points_out_look_alikes():
    text = notify._describe(pending(host="github.com.evil.example", domain="evil.example", idn=True))
    assert "github.com.evil.example:443 via https (IPs: not resolved yet)" in text
    assert "\nDomain: evil.example" in text and "punycode" in text
    plain = notify._describe(pending(domain="api.example.com", ips=["192.0.2.1"]))
    assert plain == "api.example.com:443 via https (IPs: 192.0.2.1)"


@pytest.mark.parametrize(
    ("env", "channel"),
    [({**MX, "MATRIX_ALLOWED_USERS": " , "}, "matrix"), ({**TG, "TELEGRAM_ALLOWED_USER_IDS": ""}, "telegram")],
)
def test_a_channel_without_allowed_users_is_disabled(make, caplog, env, channel):
    with caplog.at_level(logging.ERROR, logger="notify"):
        n = make(env)
    assert n.describe()[channel] is False
    assert "is required" in caplog.text


def test_full_queue_drops_new_events(make, monkeypatch, caplog):
    monkeypatch.setattr(notify, "QUEUE_SIZE", 2)
    n = make()
    with caplog.at_level(logging.WARNING, logger="notify"):
        for i in range(3):
            n.enqueue({"type": "ask", "n": i})
    assert n.queue.qsize() == 2 and [n.queue.get_nowait()["n"] for _ in range(2)] == [0, 1]
    assert "queue full, dropping ask event" in caplog.text


def test_a_broken_event_is_logged_not_raised(make, caplog):
    n = make()
    with caplog.at_level(logging.WARNING, logger="notify"):
        run(n.handle({"type": "ask"}))  # no "pending"
        run(n.handle({"type": "something new"}))
    assert caplog.text.count("notification failed") == 1


# ---------------------------------------------------------------- short numbers
def test_short_numbers_wrap_and_never_reuse_an_open_one(make):
    n = make()
    old = time.time() - 400
    n.msgs["stale"] = {"short": 5, "text": "t", "expires": old}  # its 'resolved' was missed
    n.short.update({5: "stale", 999: "open-a", 1: "open-b"})
    n._n = 998
    run(n._on_ask(pending()))
    assert n.msgs["p1"]["short"] == 2 and n.short[2] == "p1"  # 999 and 1 are taken
    assert "stale" not in n.msgs and 5 not in n.short
    n.gmsgs["gstale"] = {"short": 7, "expires": old}
    n.short[7] = "g:gstale"
    n.short[3] = "open-c"
    assert n._next_short("g:new") == 4
    assert "gstale" not in n.gmsgs and 7 not in n.short


def test_resolved_without_a_prompt_sends_nothing(make):
    n = make({**TG, **MX})
    run(n._on_resolved({"id": "unknown", "action": "allow"}))
    assert n.chat.calls == []


# ---------------------------------------------------------------- sending
def test_telegram_prompt_carries_the_public_link_and_domain_button(make):
    n = make({**TG, "PUBLIC_URL": "https://tally.example"})
    run(n._on_ask(pending(domain="example.com")))
    ((_, _, params),) = n.chat.sent("tg", "sendMessage")
    assert params["text"].endswith("\nhttps://tally.example") and params["chat_id"] == "777"
    labels = [b["text"] for row in params["reply_markup"]["inline_keyboard"] for b in row]
    assert "Always (*.example.com)" in labels and len(labels) == 6
    assert n.msgs["p1"]["tg"] == 41


def test_telegram_prompt_without_a_domain_has_no_domain_button(make):
    n = make(TG)
    run(n._on_ask(pending()))
    ((_, _, params),) = n.chat.sent("tg", "sendMessage")
    labels = [b["text"] for row in params["reply_markup"]["inline_keyboard"] for b in row]
    assert not any(label.startswith("Always (*.") for label in labels) and len(labels) == 5


@pytest.mark.parametrize("kind", ["ask", "grant"])
def test_reaction_seeding_stops_at_the_first_failure_but_the_prompt_stands(make, kind):
    n = make(MX)
    n.chat.fail.add("m.reaction")

    async def go(prompt):
        await prompt
        await asyncio.gather(*n.tasks)  # seeding runs in the background

    if kind == "ask":
        run(go(n._on_ask(pending())))
        entry = n.msgs["p1"]
    else:
        req = {"id": "r1", "name": "svc", "level": "read", "ttl_label": "1h", "expires": time.time() + 60}
        run(go(n._on_grant_request(req, {"description": "d", "targets": ["http://svc"]})))
        entry = n.gmsgs["r1"]
    assert len(n.chat.sent("mx", "m.reaction")) == 1  # tried once, then gave up
    assert entry["mx"].startswith("$e")  # the prompt itself was sent and is answerable by text


def test_slow_reaction_seeding_does_not_delay_the_next_prompt(make):
    n = make({**TG, **MX})

    async def go():
        n.chat.hold = asyncio.Event()  # the homeserver hangs on reactions
        await n.handle({"type": "ask", "pending": pending("p1")})
        req = {"id": "r1", "name": "svc", "level": "read", "ttl_label": "1h", "expires": time.time() + 60}
        await asyncio.wait_for(n.handle({"type": "grant_request", "request": req, "grant": {}}), 1)
        await asyncio.wait_for(n.handle({"type": "ask", "pending": pending("p2")}), 1)
        assert len(n.chat.sent("tg", "sendMessage")) == 3 and len(n.tasks) == 3  # prompts out, seeding waits
        n.chat.hold.set()
        await asyncio.gather(*n.tasks)
        assert not n.tasks

    run(go())
    keys = [c[3]["m.relates_to"]["key"] for c in n.chat.sent("mx", "m.reaction")]
    assert len(keys) == 6 + 3 + 6


def test_expired_asks_and_grant_requests_are_not_sent(make, caplog):
    n = make({**TG, **MX})
    old = time.time() - 1
    with caplog.at_level(logging.INFO, logger="notify"):
        run(n.handle({"type": "ask", "pending": pending(expires=old)}))
        req = {"id": "r1", "name": "svc", "level": "read", "ttl_label": "1h", "expires": old}
        run(n.handle({"type": "grant_request", "request": req, "grant": {}}))
        run(n.handle({"type": "resolved", "id": "p1", "action": "deny"}))  # no prompt, nothing to update
    assert n.chat.calls == [] and not n.msgs and not n.gmsgs and not n.short
    assert caplog.text.count("expired before it could be sent") == 2


def test_close_cancels_and_awaits_background_work(make):
    n = make(MX)

    async def go():
        n.chat.hold = asyncio.Event()  # never set: seeding would hang until SEND_TIMEOUT
        await n._on_ask(pending())
        (task,) = n.tasks
        await n.close()
        assert task.cancelled() and not n.tasks
        await n.close()  # nothing left: a no-op

    run(go())


# ---------------------------------------------------------------- applying decisions
def test_apply_grant_outcomes(make):
    n = make()
    assert run(n._apply_grant("r1", "revoke", "x")) == "nothing to revoke"  # not active yet
    n.gmsgs["r1"] = {"aid": "a1", "short": 1}
    assert run(n._apply_grant("r1", "revoke", "x")) == "ok" and n.rg.calls == [("a1", "x")]
    n.dg.reply = (409, {"error": "already decided"})
    assert run(n._apply_grant("r1", "approve", "x")) == "already decided"
    n.dg.reply = (500, "<html>")
    assert run(n._apply_grant("r1", "approve", "x")) == "error 500"
    n.dg.reply = (404, {})
    assert run(n._apply_grant("r1", "approve", "x")) == "error 404"
    n.d.reply = (404, {"error": "no such request"})
    assert run(n._apply("p1", "once", "x")) == "no such request"
    n.d.reply = (502, None)
    assert run(n._apply("p1", "once", "x")) == "error 502"


def test_without_grant_callbacks_grants_are_refused(make):
    n = make(grants=False)
    n.gmsgs["r1"] = {"aid": "a1", "short": 1}
    assert run(n._apply_grant("r1", "approve", "x")) == "grants not supported"
    assert run(n._apply_grant("r1", "revoke", "x")) == "nothing to revoke"


# ---------------------------------------------------------------- Telegram callbacks
def cq(update_id, data, uid=4242, chat=777, username="alice", **msg):
    frm = {"id": uid, **({"username": username} if username else {})}
    return {
        "update_id": update_id,
        "callback_query": {"id": f"c{update_id}", "data": data, "from": frm, "message": {"chat": {"id": chat}, **msg}},
    }


def test_telegram_callbacks(make, no_sleep, caplog):
    n = make(TG)
    n.chat.fail.add("editMessageText")  # editing the revoked message fails: the answer still goes out
    n.rg.reply = (200, {})
    n.chat.script = [
        [
            {"update_id": 10},  # not a button press
            cq(11, "d:p1:always", uid=999),  # not an allowed user
            cq(12, "d:p1:always", chat=666),  # allowed user, but another chat
            cq(13, "d:p1:once"),
            cq(14, "g:r1:read", username=None),
            cq(15, "r:a1", message_id=5, text="Grant request ..."),
            cq(16, "x:evil"),  # unknown kind
            cq(17, "d:p1"),  # malformed
        ],
        RuntimeError("POST https://api.telegram.org/botSECRET/getUpdates: timeout"),
        [],
        asyncio.CancelledError(),
    ]

    async def body():
        with pytest.raises(asyncio.CancelledError):
            await n._tg_poll()

    with caplog.at_level(logging.WARNING, logger="notify"):
        run(body())
    answers = [(c[2]["callback_query_id"], c[2]["text"]) for c in n.chat.sent("tg", "answerCallbackQuery")]
    assert answers == [
        ("c11", "Not authorised"),
        ("c12", "Not authorised"),
        ("c13", "ok"),
        ("c14", "ok"),
        ("c15", "revoked"),
    ]
    assert n.d.calls == [("p1", "once", "telegram:alice")]  # only the authorised press was applied
    assert n.dg.calls == [("r1", "read", "telegram:4242")]  # no username: the numeric id
    assert n.rg.calls == [("a1", "telegram:alice")]
    polls = [c[2] for c in n.chat.sent("tg", "getUpdates")]
    assert "offset" not in polls[0] and polls[1]["offset"] == 18 and polls[2]["offset"] == 18
    assert "SECRET" not in caplog.text and "bot<token>/getUpdates" in caplog.text
    assert no_sleep == [5]


def test_telegram_revoke_of_an_ended_grant(make, no_sleep):
    n = make(TG)
    n.rg.reply = (404, {"error": "not active"})
    n.chat.script = [[cq(1, "r:a9", message_id=5, text="t")], asyncio.CancelledError()]

    async def body():
        with pytest.raises(asyncio.CancelledError):
            await n._tg_poll()

    run(body())
    assert [c[2]["text"] for c in n.chat.sent("tg", "answerCallbackQuery")] == ["already ended"]
    (edit,) = n.chat.sent("tg", "editMessageText")
    assert edit[2]["text"] == "t\n→ revoked by alice" and edit[2]["reply_markup"] == {"inline_keyboard": []}


# ---------------------------------------------------------------- Matrix
def test_matrix_bot_account_must_not_be_an_approver(make, caplog):
    n = make({**MX, "MATRIX_ALLOWED_USERS": "@me:hs,@bot:hs"})
    with caplog.at_level(logging.ERROR, logger="notify"):
        run(n._mx_sync())  # returns instead of syncing
    assert "must not be in MATRIX_ALLOWED_USERS" in caplog.text
    assert n.chat.sent("mx", "/sync") == []


def test_matrix_sync_skips_history_survives_errors_and_dispatches(make, no_sleep, caplog):
    n = make(MX)
    n.chat.whoami = RuntimeError("M_UNKNOWN_TOKEN")
    seen = []

    async def on_event(ev):
        seen.append(ev)

    n._mx_event = on_event
    old = {"type": "m.room.message", "sender": "@me:hs", "content": {"body": "allow 1"}}
    new = {"type": "m.room.message", "sender": "@me:hs", "content": {"body": "allow 2"}}
    room = {"rooms": {"join": {"!room:hs": {"timeline": {"events": [new]}}}}}
    n.chat.script = [
        {"next_batch": "s1", "rooms": {"join": {"!room:hs": {"timeline": {"events": [old]}}}}},
        RuntimeError("connection reset"),
        {"next_batch": "s2", **room},
        {"next_batch": "s3"},  # nothing new for our room
        asyncio.CancelledError(),
    ]

    async def body():
        with pytest.raises(asyncio.CancelledError):
            await n._mx_sync()

    with caplog.at_level(logging.WARNING, logger="notify"):
        run(body())
    assert n.mx_self is None and "matrix whoami failed: M_UNKNOWN_TOKEN" in caplog.text
    assert seen == [new]  # history before the start is not replayed
    assert [c[4].get("since") for c in n.chat.sent("mx", "/sync")] == [None, "s1", "s1", "s2", "s3"]
    assert "matrix sync: connection reset" in caplog.text and no_sleep == [5]


def mx_ready(make):
    n = make(MX)
    n.mx_self = "@bot:hs"
    n.msgs["p1"] = {"mx": "$ask", "short": 3, "text": "t"}
    n.gmsgs["r1"] = {"mx": "$grant", "short": 4, "text": "t", "aid": "a1"}
    n.short.update({3: "p1", 4: "g:r1"})
    return n


def text(body, sender="@me:hs"):
    return {"type": "m.room.message", "sender": sender, "content": {"msgtype": "m.text", "body": body}}


def reaction(event_id, key, sender="@me:hs"):
    return {"type": "m.reaction", "sender": sender, "content": {"m.relates_to": {"event_id": event_id, "key": key}}}


def test_matrix_only_allowed_users_decide(make):
    n = mx_ready(make)
    for ev in (
        text("allow 3", "@bot:hs"),
        text("allow 3", "@evil:hs"),
        reaction("$ask", "✅", "@evil:hs"),
        {"type": "m.room.message"},
    ):
        run(n._mx_event(ev))
    assert n.d.calls == [] and n.dg.calls == [] and n.chat.calls == []


def test_matrix_connection_decisions(make):
    n = mx_ready(make)
    run(n._mx_event(reaction("$ask", "👍️")))  # with the emoji variation selector
    run(n._mx_event(reaction("$ask", "⛔")))
    run(n._mx_event(text("  Hour #3 ")))
    run(n._mx_event(text("allow 99")))  # unknown number
    run(n._mx_event(text("allow three")))
    run(n._mx_event(text("please allow 3")))
    run(n._mx_event(reaction("$other", "👍")))  # not one of our prompts
    run(n._mx_event(reaction("$ask", "🎉")))  # not a decision
    assert n.d.calls == [
        ("p1", "once", "matrix:@me:hs"),
        ("p1", "deny_always", "matrix:@me:hs"),
        ("p1", "hour", "matrix:@me:hs"),
    ]
    assert n.chat.calls == []
    n.d.reply = (404, {"error": "already decided"})
    run(n._mx_event(text("deny 3")))
    assert n.chat.notices() == ["Could not apply: already decided"]


def test_matrix_grant_decisions(make):
    n = mx_ready(make)
    run(n._mx_event(reaction("$grant", "📖")))
    run(n._mx_event(text("approve 4")))
    run(n._mx_event(text("allow 4")))  # a grant number is never taken as a connection decision
    run(n._mx_event(text("dance 4")))  # not a grant word: ignored
    run(n._mx_event(reaction("$grant", "🎉")))
    assert n.dg.calls == [
        ("r1", "read", "matrix:@me:hs"),
        ("r1", "approve", "matrix:@me:hs"),
        ("r1", "approve", "matrix:@me:hs"),
    ]
    assert n.d.calls == [] and n.chat.calls == []
    n.dg.reply = (409, {"error": "already decided"})
    run(n._mx_event(text("deny 4")))
    assert n.chat.notices() == ["Could not apply: already decided"]


def test_matrix_revoke_ends_the_grant_and_frees_the_number(make):
    n = mx_ready(make)
    run(n._mx_event(text("revoke 4")))
    assert n.rg.calls == [("a1", "matrix:@me:hs")]
    assert "r1" not in n.gmsgs and 4 not in n.short
    assert n.chat.notices() == ["Grant revoked by @me:hs"]
    run(n._mx_event(text("revoke 4")))  # number is free now: nothing happens
    assert len(n.rg.calls) == 1


# ---------------------------------------------------------------- digest (#73)
def test_digest_text_counts_and_truncates():
    items = [{"kind": "conn", "host": f"h{i}.example", "port": 443, "count": 1} for i in range(3)]
    items[0]["count"] = 4
    items.append({"kind": "grant", "host": "nas", "port": 0, "count": 1})
    text = notify.digest_text({"why": "quiet hours ended", "items": items, "more": 2}, "https://t.example", limit=3)
    assert text.startswith("📋 tallygate digest (quiet hours ended): 6 request(s) refused without asking")
    assert "  h0.example:443 ×4" in text and "grant nas" not in text and "… and 3 more" in text
    assert text.endswith(": https://t.example")
    assert notify.digest_text({"items": [items[3]]}).endswith("(Approvals → Availability).")


def test_digest_goes_to_every_channel(make):
    n = make({**TG, **MX})
    run(n.handle({"type": "digest", "why": "away ended", "items": [{"kind": "grant", "host": "nas", "port": 0}]}))
    ((_, _, params),) = n.chat.sent("tg", "sendMessage")
    assert "grant nas" in params["text"] and "reply_markup" not in params
    assert any("grant nas" in body for body in n.chat.notices())
    quiet = make()
    run(quiet.handle({"type": "digest", "items": []}))  # no channel configured: nothing to send
    assert quiet.chat.calls == []
