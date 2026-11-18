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

from app import notify, notifyconfig

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
    assert "are required" in caplog.text
    assert "required" in {c["channel"]: c for c in n.status()}[channel]["reason"]  # the UI says why it is off


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
    assert labels == [
        "Allow once",
        "Allow host permanently",
        "Deny",
        "More…",
    ]  # the other scopes are behind "More" (#121)
    assert n.msgs["p1"]["tg"] == 41 and n.msgs["p1"]["domain"] == "example.com"
    full = [
        b["text"]
        for row in n._tg_keyboard("p1", pending(domain="example.com"), full=True)["inline_keyboard"]
        for b in row
    ]
    assert full == [
        "Allow once",
        "Allow for 1 h",
        "Allow host permanently",
        "Allow *.example.com permanently",
        "Deny",
        "Deny permanently",
    ]


def test_telegram_prompt_without_a_domain_has_no_domain_button(make):
    n = make(TG)
    run(n._on_ask(pending()))
    ((_, _, params),) = n.chat.sent("tg", "sendMessage")
    labels = [b["text"] for row in params["reply_markup"]["inline_keyboard"] for b in row]
    assert labels == ["Allow once", "Allow host permanently", "Deny", "More…"]
    full = [b["text"] for row in n._tg_keyboard("p1", pending(), full=True)["inline_keyboard"] for b in row]
    assert not any(label.startswith("Allow *.") for label in full) and len(full) == 5


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
    assert len(keys) == 3 + 3 + 3  # two connection prompts (three first choices each) and one grant prompt


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


def test_telegram_more_shows_every_scope_on_the_same_message(make, no_sleep):
    n = make(TG)
    run(n._on_ask(pending(domain="example.com")))
    n.chat.script = [
        [cq(1, "m:p1", message_id=41), cq(2, "m:gone", message_id=7), cq(3, "d:p1:hour", message_id=41)],
        asyncio.CancelledError(),
    ]

    async def body():
        with pytest.raises(asyncio.CancelledError):
            await n._tg_poll()

    run(body())
    (edit,) = n.chat.sent("tg", "editMessageReplyMarkup")  # only for the prompt that is still open
    assert edit[2]["message_id"] == 41 and edit[2]["chat_id"] == "777"
    labels = [b["text"] for row in edit[2]["reply_markup"]["inline_keyboard"] for b in row]
    assert labels == [
        "Allow once",
        "Allow for 1 h",
        "Allow host permanently",
        "Allow *.example.com permanently",
        "Deny",
        "Deny permanently",
    ]
    answers = [c[2]["text"] for c in n.chat.sent("tg", "answerCallbackQuery")]
    assert answers == ["More choices", "already decided", "ok"]
    assert n.d.calls == [("p1", "hour", "telegram:alice")]


def test_matrix_prompt_seeds_the_three_first_choices_and_lists_the_rest(make):
    n = make(MX)

    async def body():
        await n._on_ask(pending(domain="example.com"))
        await asyncio.gather(*n.tasks)

    run(body())
    msg = n.chat.sent("mx", "m.room.message")[0][3]
    assert "React: 👍 Allow once  ✅ Allow host permanently  👎 Deny\n" in msg["body"]
    assert "More: ⏰ Allow for 1 h  🌐 Allow *.example.com permanently  ⛔ Deny permanently\n" in msg["body"]
    assert "More: ⏰ Allow for 1 h" in msg["formatted_body"]
    seeded = [c[3]["m.relates_to"]["key"] for c in n.chat.sent("mx", "m.reaction")]
    assert seeded == ["👍", "✅", "👎"]


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


# ---------------------------------------------------------------- status and test button (#180)
class FakePush:
    def __init__(self, subs) -> None:
        self.subs = subs


def test_status_lists_every_channel_with_a_reason(make):
    n = make({**TG, "NTFY_URL": "http://ntfy"})
    detail = n.status()
    assert [c["channel"] for c in detail] == ["telegram", "matrix", "ntfy", "gotify", "pushover", "webpush"]
    by = {c["channel"]: c for c in detail}
    assert (
        by["telegram"]["configured"]
        and by["telegram"]["source"] == "environment"
        and by["telegram"]["reason"] == "Configured in the environment."
    )
    assert by["telegram"]["configurable"] is False  # no writable store here: environment-only
    assert by["ntfy"]["configured"] is True
    assert by["matrix"]["configured"] is False and "MATRIX_HOMESERVER" in by["matrix"]["reason"]  # names what to set


def test_status_webpush_is_set_up_per_browser(make):
    n = make()  # push is None here
    wp = {c["channel"]: c for c in n.status()}["webpush"]
    assert wp["source"] is None and wp["configurable"] is False
    assert wp["configured"] is False and "not writable" in wp["reason"]
    n.push = FakePush([{"id": "1"}])
    assert {c["channel"]: c for c in n.status()}["webpush"]["configured"] is True
    n.push = FakePush([])
    off = {c["channel"]: c for c in n.status()}["webpush"]
    assert off["configured"] is False and "No device subscribed" in off["reason"]


def test_send_test_rejects_unknown_unconfigured_and_webpush(make):
    n = make(TG)
    with pytest.raises(ValueError, match="unknown channel"):
        run(n.send_test("nope"))
    with pytest.raises(ValueError, match="Web Push"):
        run(n.send_test("webpush"))
    with pytest.raises(ValueError, match="not configured"):
        run(n.send_test("ntfy"))


def test_send_test_telegram_and_matrix_use_the_chat_api(make):
    n = make({**TG, **MX})
    run(n.send_test("telegram"))
    ((_, _, params),) = n.chat.sent("tg", "sendMessage")
    assert params["chat_id"] == "777" and "test" in params["text"].lower() and "reply_markup" not in params
    run(n.send_test("matrix"))
    assert any("test" in body.lower() for body in n.chat.notices())


def test_send_test_posts_to_ntfy_gotify_and_pushover(make):
    n = make(
        {
            "NTFY_URL": "http://ntfy",
            "GOTIFY_URL": "http://g",
            "GOTIFY_TOKEN": "t",
            "PUSHOVER_TOKEN": "a",
            "PUSHOVER_USER": "u",
        }
    )
    posts = []

    async def fake_post(name, url, **kw):
        posts.append((name, url))

    n._post = fake_post
    for channel in ("ntfy", "gotify", "pushover"):
        run(n.send_test(channel))
    assert [name for name, _ in posts] == ["ntfy", "gotify", "pushover"]
    assert posts[1][1] == "http://g/message"


def test_send_test_propagates_a_channel_failure(make):
    n = make(TG)
    n.chat.fail.add("sendMessage")
    with pytest.raises(RuntimeError):
        run(n.send_test("telegram"))


# ---------------------------------------------------------------- configured in the UI, applied live (#201)
UI_TG = {"bot_token": "123456:" + "A" * 30, "chat_id": "555", "allowed_user_ids": "4242"}
UI_MX = {"homeserver": "http://hs2", "access_token": "tok2", "room_id": "!r2:hs2", "allowed_users": "@me:hs2"}


@pytest.fixture
def ui(make, tmp_path):
    """A notifier whose channels can be configured through a writable store, as the web UI does."""

    def _ui(env=None):
        n = make(env)
        n.config = notifyconfig.NotifyConfig(tmp_path / "notify.json")
        n._load()
        return n

    return _ui


def idle_chat(n):
    """Poll loops that wait (as a long poll does) and count how many are running per channel."""
    n.running = {"telegram": 0, "matrix": 0}
    n.started = {"telegram": 0, "matrix": 0}

    def loop(channel):
        async def poll():
            n.started[channel] += 1
            n.running[channel] += 1
            try:
                await asyncio.Event().wait()
            finally:
                n.running[channel] -= 1

        return poll

    n._tg_poll, n._mx_sync = loop("telegram"), loop("matrix")


def test_ui_values_override_the_environment_and_status_names_the_source(ui):
    n = ui(TG)
    assert n.tg_chat == "777" and n.status()[0]["source"] == "environment" and n.status()[0]["configurable"]
    n.config.update("telegram", {"chat_id": "555"})
    run(n.reconfigure())
    by = {c["channel"]: c for c in n.status()}
    assert n.tg_chat == "555" and n.tg_token == "SECRET"  # the token still comes from the environment
    assert by["telegram"]["source"] == "mixed" and "web UI and the environment" in by["telegram"]["reason"]
    n.config.update("telegram", UI_TG)
    run(n.reconfigure())
    assert n.tg_token == UI_TG["bot_token"] and n.status()[0]["reason"] == "Configured in the web UI."
    n.config.remove("telegram")
    run(n.reconfigure())
    assert (n.tg_token, n.tg_chat) == ("SECRET", "777") and n.status()[0]["source"] == "environment"


def test_status_says_how_to_configure_a_channel_that_is_off(ui):
    n = ui()
    by = {c["channel"]: c for c in n.status()}
    assert "Use Configure" in by["ntfy"]["reason"] and "NTFY_URL" in by["ntfy"]["reason"]
    n.config.update("gotify", {"url": "http://g"})  # no token yet
    run(n.reconfigure())
    gotify = {c["channel"]: c for c in n.status()}["gotify"]
    assert gotify["configured"] is False and gotify["reason"].startswith("Incomplete")


def test_reconfigure_restarts_only_the_changed_poll_loop_and_never_duplicates_it(ui):
    n = ui({**TG, **MX})
    idle_chat(n)

    async def body():
        tasks = n.start()
        await asyncio.sleep(0)
        assert len(tasks) == 3 and n.running == {"telegram": 1, "matrix": 1}
        tg, mx = n.polls["telegram"], n.polls["matrix"]
        assert await n.reconfigure() == [] and n.polls == {"telegram": tg, "matrix": mx}  # nothing changed

        n.config.update("ntfy", {"url": "http://ntfy/topic"})  # a channel without a poll loop
        assert await n.reconfigure() == [] and n.polls["telegram"] is tg and n.ntfy_url == "http://ntfy/topic"

        n.config.update("telegram", UI_TG)
        assert await n.reconfigure() == ["telegram"]
        await asyncio.sleep(0)
        assert tg.cancelled() and n.polls["telegram"] is not tg and n.polls["matrix"] is mx
        assert n.running == {"telegram": 1, "matrix": 1} and n.started == {"telegram": 2, "matrix": 1}

        n.config.update("matrix", UI_MX)
        n.config.update("telegram", {"chat_id": "556"})
        both = await asyncio.gather(n.reconfigure(), n.reconfigure())  # two saves at once: still one loop each
        await asyncio.sleep(0)
        assert both == [["telegram", "matrix"], []] and n.running == {"telegram": 1, "matrix": 1}
        assert not n.worker.done()  # the worker (and with it the queue) is never restarted
        polls = list(n.polls.values())
        await n.close()
        assert all(t.cancelled() for t in polls) and n.polls == {} and n.running == {"telegram": 0, "matrix": 0}

    run(body())


def test_reconfigure_starts_and_stops_a_channel_and_keeps_open_prompts(ui):
    n = ui()
    idle_chat(n)

    async def body():
        assert n.start() == [n.worker] and n.polls == {}  # nothing configured: only the worker
        n.config.update("telegram", UI_TG)
        assert await n.reconfigure() == ["telegram"]
        await asyncio.sleep(0)
        assert n.running["telegram"] == 1
        await n.handle({"type": "ask", "pending": pending("p1")})
        assert n.msgs["p1"]["tg"] == 41 and n.chat.sent("tg", "sendMessage")[0][2]["chat_id"] == "555"

        n.config.update("telegram", {"chat_id": "556"})  # the loop restarts, the open prompt stays
        assert await n.reconfigure() == ["telegram"]
        assert n.msgs["p1"]["short"] == 1 and n.short == {1: "p1"}
        await n.handle({"type": "resolved", "id": "p1", "action": "allow", "scope": "once"})
        assert n.chat.sent("tg", "editMessageText")[0][2]["message_id"] == 41

        n.config.remove("telegram")  # no environment to fall back to: the channel and its loop stop
        assert await n.reconfigure() == ["telegram"]
        assert n.polls == {} and n.running["telegram"] == 0 and n.describe()["telegram"] is False
        await n.close()

    run(body())


def test_reconfigure_before_start_starts_no_loop(ui):
    n = ui()
    idle_chat(n)
    n.config.update("matrix", UI_MX)
    assert run(n.reconfigure()) == ["matrix"]
    assert n.polls == {} and n.describe()["matrix"] is True


def test_a_stored_channel_without_allowed_users_stays_off(ui, tmp_path, caplog):
    """The store refuses this, so write the file directly: the notifier is the second line (ADR-0010)."""
    n = ui()
    (tmp_path / "notify.json").write_text(
        '{"version": 1, "channels": {"telegram": {"bot_token": "123456:%s", "chat_id": "5"}}}' % ("A" * 30)
    )
    n.config = notifyconfig.NotifyConfig(tmp_path / "notify.json")
    with caplog.at_level(logging.ERROR, logger="notify"):
        run(n.reconfigure())
    assert n.describe()["telegram"] is False and n.polls == {} and "are required" in caplog.text


def test_redact_strips_channel_tokens(make):
    n = make(TG)  # TELEGRAM_BOT_TOKEN = SECRET
    assert n.redact("boom at https://api.telegram.org/botSECRET/x") == "boom at https://api.telegram.org/bot<token>/x"


# ---------------------------------------------------------------- context (#74)
def test_context_line_only_for_push_and_bounded():
    assert notify.context_line({}) == "" and notify.context_line({"context": []}) == ""
    p = {"context": [{"tool": "Bash", "text": "npm install", "note": "Install deps"}, {"text": "older"}]}
    assert notify.context_line(p) == "\nAgent says (unverified): Bash: npm install – Install deps"
    assert notify.context_line({"context": [{"kind": "note", "note": "n" * 300}]}).endswith(": " + "n" * 160)
    assert "npm" not in notify._describe({**pending(), **p})  # chat services never get it


# ---------------------------------------------------------------- configurable buttons (#212)
ALL_SCOPES = ["once", "hour", "always", "domain", "deny", "deny_always"]


def test_ask_buttons_follow_the_configured_order_and_name_the_domain():
    p = pending(domain="example.com")
    assert notify.ask_buttons(["deny_always", "domain", "once"], p) == [
        ("deny_always", "Deny permanently"),
        ("domain", "Allow *.example.com permanently"),
        ("once", "Allow once"),
    ]
    assert [s for s, _ in notify.ask_buttons(ALL_SCOPES, p, deny_only_for_ip=True)] == ALL_SCOPES  # a name: all


@pytest.mark.parametrize("host", ["github.io", "localhost", "nas"])
def test_the_domain_button_needs_a_registrable_domain(host):
    """The gateway sends domain=None for a public suffix or a single-label name, and would refuse the scope."""
    p = pending(host=host, domain=None)
    assert [s for s, _ in notify.ask_buttons(ALL_SCOPES, p)] == ["once", "hour", "always", "deny", "deny_always"]
    assert notify.ask_buttons(["domain"], p) == [] and notify.ask_buttons(["domain"], pending()) == []


@pytest.mark.parametrize("host", ["192.0.2.7", "10.0.0.1", "2001:db8::1", "[2001:db8::1]", "::ffff:192.0.2.7"])
def test_an_ip_literal_gets_no_allow_button_in_web_push(host):
    p = pending(host=host, domain=None)
    assert notify.is_ip(host)
    assert notify.ask_buttons(ALL_SCOPES, p, deny_only_for_ip=True) == [
        ("deny", "Deny"),
        ("deny_always", "Deny permanently"),
    ]
    assert notify.ask_buttons(["once", "hour", "always", "domain"], p, deny_only_for_ip=True) == []
    # a domain the event claims for an address is not believed either
    assert notify.ask_buttons(["domain"], {**p, "domain": "example.com"}) == []
    # the chat bots authenticate the user and keep what they offered before
    assert [s for s, _ in notify.ask_buttons(ALL_SCOPES, p)] == ["once", "hour", "always", "deny", "deny_always"]


def test_names_that_look_like_addresses_are_names():
    for host in ("192.0.2.7.example.com", "1.example", "deadbeef.example"):
        assert not notify.is_ip(host)
    assert not notify.is_ip("") and not notify.is_ip(None)


class Push:
    """Web Push with real action tokens (app/webpush.py) and one subscribed device; nothing is sent."""

    def __init__(self, tmp_path) -> None:
        pytest.importorskip("cryptography")
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        from app import webpush

        pem = ec.generate_private_key(ec.SECP256R1()).private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
        self.real = webpush.WebPush(pem, tmp_path / "subs.json", "https://tally.example", b"secret")
        self.subs = [{"id": "dev1", "label": "phone"}]
        self.mint, self.redeem = self.real.mint, self.real.redeem


@pytest.fixture
def pushed(ui, tmp_path):
    """A notifier with Web Push only; returns (notifier, the messages it would send)."""

    def _pushed(actions=None):
        n = ui()
        n.push = Push(tmp_path)
        if actions:
            n.config.set_actions(actions)
        sent = []

        async def one(sub, message, ttl, topic):
            sent.append(message)
            return 201

        n._push_one = one
        return n, sent

    return _pushed


def claims(token):
    import base64
    import json

    raw = token.split(".")[0]
    return json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))


def test_web_push_offers_allow_once_and_deny_by_default(pushed):
    n, sent = pushed()
    run(n._on_ask(pending(domain="example.com")))
    (m,) = sent
    assert m["actions"] == [{"action": "once", "title": "Allow once"}, {"action": "deny", "title": "Deny"}]
    assert sorted(m["tokens"]) == ["deny", "once"] and "IP address" not in m["body"]


def test_web_push_offers_the_configured_buttons_in_order_each_with_its_own_token(pushed):
    n, sent = pushed(["domain", "deny_always", "always", "hour"])
    run(n._on_ask(pending(domain="example.com")))
    (m,) = sent
    assert m["actions"] == [
        {"action": "domain", "title": "Allow *.example.com permanently"},
        {"action": "deny_always", "title": "Deny permanently"},
        {"action": "always", "title": "Allow host permanently"},
        {"action": "hour", "title": "Allow for 1 h"},
    ]
    assert list(m["tokens"]) == ["domain", "deny_always", "always", "hour"]  # no token without a button
    for scope, token in m["tokens"].items():
        c = claims(token)
        assert (c["k"], c["i"], c["d"], c["s"]) == ("ask", "p1", scope, "dev1")
    # the tokens are the real ones: each is accepted for its own decision, once, while its button is on
    assert n.push.redeem(m["tokens"]["always"], ask=n.config.actions())["d"] == "always"
    n.config.set_actions(["deny"])
    with pytest.raises(ValueError, match="switched off"):
        n.push.redeem(m["tokens"]["domain"], ask=n.config.actions())


def test_web_push_leaves_out_the_domain_button_without_a_registrable_domain(pushed):
    n, sent = pushed(["domain", "always", "deny"])
    run(n._on_ask(pending(host="github.io", domain=None)))
    (m,) = sent
    assert [a["action"] for a in m["actions"]] == ["always", "deny"] and "domain" not in m["tokens"]


@pytest.mark.parametrize("host", ["192.0.2.7", "2001:db8::1"])
def test_web_push_offers_only_deny_for_an_ip_literal_and_says_so(pushed, host):
    n, sent = pushed(["always", "once", "deny_always", "deny"])
    run(n._on_ask(pending(host=host, domain=None)))
    (m,) = sent
    assert m["actions"] == [
        {"action": "deny_always", "title": "Deny permanently"},
        {"action": "deny", "title": "Deny"},
    ]
    assert sorted(m["tokens"]) == ["deny", "deny_always"]  # no allow token exists for this request
    assert "IP address: it can only be denied from here. To allow it, open tallygate." in m["body"]
    assert m["url"] == "/#approvals"  # tapping the notification opens the approvals


def test_web_push_for_an_ip_literal_with_only_allow_buttons_has_no_button_at_all(pushed):
    n, sent = pushed(["always", "once"])
    run(n._on_ask(pending(host="192.0.2.7", domain=None)))
    (m,) = sent
    assert m["actions"] == [] and m["tokens"] == {} and "IP address" in m["body"]


def test_web_push_for_an_ip_literal_with_the_default_buttons(pushed):
    n, sent = pushed()
    run(n._on_ask(pending(host="192.0.2.7", domain=None)))
    assert [a["action"] for a in sent[0]["actions"]] == ["deny"] and "IP address" in sent[0]["body"]
    n2, sent2 = pushed(["deny", "deny_always"])
    run(n2._on_ask(pending(host="192.0.2.7", domain=None)))
    assert "IP address" not in sent2[0]["body"]  # nothing was withheld


def test_the_agents_claim_stays_marked_whatever_the_buttons_are(pushed):
    n, sent = pushed(["always", "domain"])
    ctx = [{"tool": "Bash", "text": "curl https://api.example.com", "note": "Tap the first button to continue"}]
    run(n._on_ask(pending(domain="example.com", context=ctx)))
    body = sent[0]["body"]
    assert "\nAgent says (unverified): Bash: curl https://api.example.com – Tap the first button" in body
    assert body.index("api.example.com:443") < body.index("Agent says (unverified)")  # the destination comes first
    titles = [a["title"] for a in sent[0]["actions"]]
    assert titles == ["Allow host permanently", "Allow *.example.com permanently"]  # never agent-written text


def test_grant_requests_keep_their_own_buttons(pushed):
    n, sent = pushed(["always", "domain", "deny_always"])
    r = {"id": "r1", "name": "nas", "level": "write", "ttl_label": "1 h", "expires": time.time() + 60, "reason": "x"}
    run(n._on_grant_request(r, {"levels": ["read", "write"], "targets": []}))
    assert [a["action"] for a in sent[0]["actions"]] == ["read", "deny"]  # write still needs the UI or a chat bot
    assert "Agent's reason (unverified): x" in sent[0]["body"]


def test_telegram_and_matrix_show_the_saved_buttons_first(ui):
    n = ui({**TG, **MX})
    n.config.set_actions(["deny_always", "domain", "hour"])

    async def body():
        await n._on_ask(pending(domain="example.com"))
        await asyncio.gather(*n.tasks)

    run(body())
    ((_, _, params),) = n.chat.sent("tg", "sendMessage")
    buttons = [b for row in params["reply_markup"]["inline_keyboard"] for b in row]
    assert [b["text"] for b in buttons] == [
        "Deny permanently",
        "Allow *.example.com permanently",
        "Allow for 1 h",
        "More…",
    ]
    assert [b["callback_data"] for b in buttons] == ["d:p1:deny_always", "d:p1:domain", "d:p1:hour", "m:p1"]
    full = [b["text"] for row in n._tg_keyboard("p1", n.msgs["p1"], full=True)["inline_keyboard"] for b in row]
    assert len(full) == 6 and "More…" not in full  # "More" still shows every scope
    msg = n.chat.sent("mx", "m.room.message")[0][3]
    assert "React: ⛔ Deny permanently  🌐 Allow *.example.com permanently  ⏰ Allow for 1 h\n" in msg["body"]
    assert "More: 👍 Allow once  ✅ Allow host permanently  👎 Deny\n" in msg["body"]
    assert [c[3]["m.relates_to"]["key"] for c in n.chat.sent("mx", "m.reaction")] == ["⛔", "🌐", "⏰"]


def test_telegram_keeps_every_scope_for_an_ip_literal(ui):
    """Telegram and Matrix authenticate the user: for them the setting orders the buttons, nothing more."""
    n = ui(TG)
    n.config.set_actions(["always", "deny"])
    run(n._on_ask(pending(host="192.0.2.7", domain=None)))
    ((_, _, params),) = n.chat.sent("tg", "sendMessage")
    labels = [b["text"] for row in params["reply_markup"]["inline_keyboard"] for b in row]
    assert labels == ["Allow host permanently", "Deny", "More…"]
    full = [b["text"] for row in n._tg_keyboard("p1", n.msgs["p1"], full=True)["inline_keyboard"] for b in row]
    assert full == ["Allow once", "Allow for 1 h", "Allow host permanently", "Deny", "Deny permanently"]


def test_the_largest_push_message_still_fits_one_record(pushed):
    """Four buttons with their tokens, the longest host name and a full agent claim: under the 4096-byte record."""
    import json

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    from app import webpush

    n, sent = pushed(["domain", "always", "deny_always", "hour"])
    host = ".".join(["a" * 63] * 3 + ["b" * 57, "com"])  # 253 characters
    domain = "b" * 57 + ".com"
    ctx = [{"tool": "Bash", "text": "x" * 200, "note": "y" * 200}]
    ips = ["2001:db8:85a3:8d3:1319:8a2e:370:7348"] * 8
    run(n._on_ask(pending(host=host, domain=domain, idn=True, ips=ips, context=ctx)))
    (m,) = sent
    assert len(m["actions"]) == 4 and len(m["tokens"]) == 4
    key = ec.generate_private_key(ec.SECP256R1()).public_key()
    point = key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    payload = json.dumps(m, separators=(",", ":")).encode()
    assert len(payload) < 3000
    webpush.encrypt(payload, webpush.b64u(point), webpush.b64u(b"0123456789abcdef"))  # raises when too large


# ---------------------------------------------------------------- the gateway has no connection (#218)
def test_connectivity_text_is_fixed_and_has_only_a_time():
    start = notify.connectivity_text({"down": True, "since": 1_800_000_000, "host": "<b>evil</b>"})
    assert start.startswith("⚠️ tallygate: no connection from the gateway since ")
    assert "not a policy decision" in start and "evil" not in start
    assert "since ?" in notify.connectivity_text({"down": True, "since": "x"})
    assert notify.connectivity_text({"down": False}) == "✅ tallygate: the gateway has a connection again."


def test_connectivity_goes_out_once_per_change_to_every_channel(make):
    n = make({**TG, **MX})
    run(n.handle({"type": "connectivity", "down": True, "since": 1_800_000_000}))
    run(n.handle({"type": "connectivity", "down": False}))
    texts = [p["text"] for _, _, p in n.chat.sent("tg", "sendMessage")]
    assert len(texts) == 2 and "no connection" in texts[0] and "connection again" in texts[1]
    assert all("reply_markup" not in p for _, _, p in n.chat.sent("tg", "sendMessage"))  # a notice, no buttons
    assert len(n.chat.notices()) == 2
    quiet = make()
    run(quiet.handle({"type": "connectivity", "down": True, "since": 1.0}))
    assert quiet.chat.calls == []
