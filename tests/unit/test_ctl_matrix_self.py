"""Matrix approvals against a homeserver that behaves like a real one (#238): everything the bot sends comes
back in /sync with the bot as sender. The real control app, a fake gateway (World) and this homeserver over
HTTP: the bot never approves its own prompts, also when whoami fails at start and the bot's account is an
allowed user (the reviewer's case), and a real user's reaction still decides once whoami has succeeded."""

from __future__ import annotations

import asyncio
import logging
import time

import pytest

from .test_ctl_main import World, run, started
from .test_ctl_setup import load_main  # noqa: F401 (fixture)

pytest.importorskip("aiohttp")
from aiohttp import test_utils, web

ROOM = "!room:hs"
ASK = {"id": "abc123", "host": "files.example", "port": 443, "proto": "https", "ips": []}
GRANT = {"id": "e7", "name": "nas", "level": "write", "ttl_label": "1 h", "reason": "x"}


class Homeserver:
    def __init__(self, bot: str, whoami_failures: float = 0) -> None:
        self.bot, self.whoami_failures = bot, whoami_failures
        self.events: list[dict] = []
        self.whoami_calls = self.syncs = 0
        self.srv: test_utils.TestServer | None = None

    async def start(self) -> str:
        a = web.Application()
        a.router.add_get("/_matrix/client/v3/account/whoami", self.whoami)
        a.router.add_get("/_matrix/client/v3/sync", self.sync)
        a.router.add_put("/_matrix/client/v3/rooms/{room}/send/{type}/{txn}", self.send)
        self.srv = test_utils.TestServer(a)
        await self.srv.start_server()
        return f"http://127.0.0.1:{self.srv.port}"

    async def whoami(self, _request):
        self.whoami_calls += 1
        if self.whoami_calls <= self.whoami_failures:
            return web.json_response({"errcode": "M_UNKNOWN", "error": "upstream timeout"}, status=502)
        return web.json_response({"user_id": self.bot})

    def add(self, kind: str, sender: str, content: dict) -> str:
        event_id = f"$e{len(self.events) + 1}"
        self.events.append({"type": kind, "sender": sender, "event_id": event_id, "content": content})
        return event_id

    def react(self, sender: str, event_id: str, key: str) -> None:
        self.add("m.reaction", sender, {"m.relates_to": {"rel_type": "m.annotation", "event_id": event_id, "key": key}})

    async def send(self, request):
        return web.json_response({"event_id": self.add(request.match_info["type"], self.bot, await request.json())})

    async def sync(self, request):
        self.syncs += 1
        since = request.query.get("since")
        if since is None:
            return web.json_response({"next_batch": str(len(self.events))})
        for _ in range(40):
            if len(self.events) > int(since):
                break
            await asyncio.sleep(0.05)
        events = self.events[int(since) :]
        timeline = {"timeline": {"events": events}}
        return web.json_response({"next_batch": str(len(self.events)), "rooms": {"join": {ROOM: timeline}}})

    def prompt(self, marker: str) -> str:
        return next(e["event_id"] for e in self.events if marker in e["content"].get("body", ""))


async def until(condition, seconds: float = 5) -> None:
    for _ in range(int(seconds / 0.02)):
        if condition():
            return
        await asyncio.sleep(0.02)
    raise AssertionError("condition not reached")


def ask_events(n) -> None:
    n.enqueue({"type": "ask", "pending": {**ASK, "expires": time.time() + 120}})
    n.enqueue(
        {
            "type": "grant_request",
            "request": {**GRANT, "expires": time.time() + 120},
            "grant": {"targets": [], "levels": ["read", "write"]},
        }
    )


def decisions(world: World) -> list:
    return [s for s in world.seen if "decide" in s[1]]


def matrix_reason(n) -> str:
    return {c["channel"]: c for c in n.status()}["matrix"]["reason"]


@pytest.mark.parametrize("whoami_failures", [0, 2, float("inf")], ids=["whoami-ok", "fails-twice", "fails-forever"])
def test_the_operators_own_account_as_bot_never_approves(load_main, monkeypatch, caplog, whoami_failures):  # noqa: F811
    """`MATRIX_ALLOWED_USERS=@me:hs` with the token of @me:hs. On the unfixed code the 'fails' cases let the
    gateway see `once` for the connection and `approve` for the write grant, by matrix:@me:hs."""
    world, hs = World(), Homeserver("@me:hs", whoami_failures)
    caplog.set_level(logging.INFO, logger="notify")

    async def body():
        base = await hs.start()
        main = load_main(
            MATRIX_HOMESERVER=base, MATRIX_ACCESS_TOKEN="tok", MATRIX_ROOM_ID=ROOM, MATRIX_ALLOWED_USERS="@me:hs"
        )
        monkeypatch.setattr(main.notify, "MX_WHOAMI_BACKOFF", (0.05, 0.1))
        async with started(main, world) as c:
            n = c.app["notifier"]
            await until(lambda: hs.whoami_calls >= 1)
            ask_events(n)
            await until(lambda: len(hs.events) == 8)  # 2 prompts, 3 + 3 pre-seeded reactions, all by @me:hs
            await asyncio.sleep(0.6)  # time for whoami retries and for /sync to hand the echoes back
            reason = matrix_reason(n)
            assert "abc123" in n.msgs and "e7" in n.gmsgs  # both prompts are still open: the UI can answer
        await hs.srv.close()
        return main, reason

    main, reason = run(body())
    assert decisions(world) == []
    if whoami_failures == float("inf"):
        assert reason == main.notify.MX_PAUSED and hs.syncs == 0 and hs.whoami_calls > 3
        assert "must not be in MATRIX_ALLOWED_USERS" not in caplog.text  # not known yet: paused, not refused
    else:
        assert reason == main.notify.MX_SELF_ALLOWED.format(user="@me:hs") and hs.syncs == 0
        assert "bot user @me:hs must not be in MATRIX_ALLOWED_USERS - Matrix approvals disabled" in caplog.text
        assert hs.whoami_calls == whoami_failures + 1


def test_a_real_users_reaction_decides_after_whoami_succeeded_and_nothing_is_replayed(load_main, monkeypatch, caplog):  # noqa: F811
    """A separate bot account, whoami fails at first. A tap during the pause is dropped (the prompt stays
    open), the same user's tap after the pause decides, exactly once; the bot's echoes never do."""
    world, hs = World(), Homeserver("@bot:hs", 3)
    caplog.set_level(logging.INFO, logger="notify")

    async def body():
        base = await hs.start()
        main = load_main(
            MATRIX_HOMESERVER=base, MATRIX_ACCESS_TOKEN="tok", MATRIX_ROOM_ID=ROOM, MATRIX_ALLOWED_USERS="@me:hs"
        )
        monkeypatch.setattr(main.notify, "MX_WHOAMI_BACKOFF", (0.3, 0.3))
        async with started(main, world) as c:
            n = c.app["notifier"]
            await until(lambda: hs.whoami_calls >= 1)
            ask_events(n)
            await until(lambda: len(hs.events) == 8)
            assert n.mx_self is None and matrix_reason(n) == main.notify.MX_PAUSED
            hs.react("@me:hs", hs.prompt("wants to connect"), "✅")  # tapped while approvals are paused
            await until(lambda: n.mx_self == "@bot:hs" and hs.syncs >= 2)
            await asyncio.sleep(0.3)
            assert decisions(world) == [] and "abc123" in n.msgs  # dropped, not replayed; still open
            assert matrix_reason(n) == "Configured in the environment."
            hs.react("@me:hs", hs.prompt("wants to connect"), "👍")
            hs.react("@me:hs", hs.prompt("Grant request"), "📖")
            await until(lambda: len(decisions(world)) == 2)
            await asyncio.sleep(0.3)
        await hs.srv.close()

    run(body())
    assert decisions(world) == [
        ("POST", "/gw/pending/abc123/decide", {}, {"scope": "once", "by": "matrix:@me:hs"}),
        ("POST", "/gw/grant-requests/e7/decide", {}, {"decision": "read", "by": "matrix:@me:hs"}),
    ]
    assert "matrix: bot account verified (@bot:hs), approvals resume" in caplog.text
