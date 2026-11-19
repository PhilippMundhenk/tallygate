"""Nothing but the gateway route a caller named is ever requested (#239, #244). The ids in a gateway API path
come from a chat (Telegram callback data), from a push token or from the browser; with ".." or "?" in one,
"decide this prompt" or "delete this destination" would become another gateway call. Three layers, each
tested on its own: the chat input is validated (tests/unit/test_ctl_notify.py), the relay's allow-list
accepts no id that is "." or ".." or starts with a dot, and gw() refuses such a path and sends the path
it was given byte for byte."""

from __future__ import annotations

import asyncio
import logging

import pytest

from .test_ctl_main import CSRF, World, load, run, started  # noqa: F401 (fixture)

pytest.importorskip("aiohttp")
import yarl
from aiohttp import test_utils, web


async def raw(client, method: str, target: str) -> int:
    """One request with the target exactly as written (a client library would normalise ".." itself)."""
    port = client.server.port
    jar = client.session.cookie_jar.filter_cookies(yarl.URL(f"http://127.0.0.1:{port}/"))
    head = (
        f"{method} {target} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nCookie: tallygate_session="
        f"{jar['tallygate_session'].value}\r\nX-Tallygate: 1\r\nContent-Type: application/json\r\n"
        "Content-Length: 2\r\nConnection: close\r\n\r\n{}"
    )
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(head.encode())
    await writer.drain()
    status = int((await asyncio.wait_for(reader.read(65536), 5)).split(b" ", 2)[1])
    writer.close()
    return status


# ---------------------------------------------------------------- the relay's allow-list (#244)
@pytest.mark.parametrize(
    "method,target",
    [
        ("DELETE", "/api/gw/destinations/.."),  # was the gateway's DELETE /
        ("PATCH", "/api/gw/destinations/.."),
        ("POST", "/api/gw/destinations/../move"),  # was POST /move
        ("DELETE", "/api/gw/destinations/%2e%2e"),
        ("DELETE", "/api/gw/destinations/%2E%2e"),
        ("POST", "/api/gw/destinations/%2e%2e/move"),
        ("DELETE", "/api/gw/destinations/."),
        ("POST", "/api/gw/destinations/./move"),
        ("DELETE", "/api/gw/destinations/..."),
        ("DELETE", "/api/gw/destinations/.hidden"),
        ("DELETE", "/api/gw/destinations/a..b"),
        ("DELETE", "/api/gw/destinations/ab.."),
        ("DELETE", "/api/gw/destinations/-ab"),
        ("DELETE", "/api/gw/destinations/:ab"),
        ("DELETE", "/api/gw/destinations/_ab"),
        ("DELETE", "/api/gw/destinations/ab%2fcd"),
        ("DELETE", "/api/gw/destinations/ab%3fx"),
        ("DELETE", "/api/gw/destinations/ab%23x"),
        ("DELETE", "/api/gw/destinations/ab%20x"),
    ],
)
def test_the_relay_accepts_no_id_that_steps_out_of_its_route(load, method, target):  # noqa: F811
    main, world = load(), World()

    async def body():
        async with started(main, world) as c:
            assert await raw(c, method, target) == 404

    run(body())
    assert world.seen == []


def test_the_relay_still_passes_every_real_destination_id_unchanged(load):  # noqa: F811
    main, world = load(), World()
    ids = ["ab12cd34", "grant:svc-1", "grant:a.b_c", "A1", "0"]

    async def body():
        async with started(main, world) as c:
            for i in ids:
                assert await raw(c, "DELETE", f"/api/gw/destinations/{i}") == 200
                assert await raw(c, "POST", f"/api/gw/destinations/{i}/move") == 200
            assert await raw(c, "PATCH", "/api/gw/destinations/grant%3Asvc-1") == 200  # an encoded colon
            r = await c.get("/api/gw/events", params={"q": "a b&c=d", "limit": "5"})
            assert r.status == 200
            r = await c.delete("/api/gw/active-grants/abc123?by=spoofed", headers=CSRF)
            assert r.status == 200

    run(body())
    seen = [(m, p) for m, p, _, _ in world.seen]
    assert seen[:-3] == [
        x for i in ids for x in (("DELETE", f"/gw/destinations/{i}"), ("POST", f"/gw/destinations/{i}/move"))
    ]
    assert seen[-3] == ("PATCH", "/gw/destinations/grant:svc-1")
    assert world.seen[-2] == ("GET", "/gw/events", {"q": "a b&c=d", "limit": "5"}, None)  # the query survives
    assert world.seen[-1] == ("DELETE", "/gw/active-grants/abc123", {"by": "web:admin"}, None)


# ---------------------------------------------------------------- gw() itself (defence in depth)
BAD_PATHS = [
    "/pending/../emergency-stop",
    "/pending/..",
    "/..",
    "/pending/ab12/decide?scope=always",
    "/pending/ab12?x=/decide",
    "/pending/ab12#/decide",
    "/pending/ab%2e%2e/decide",
    "/pending/ab 12/decide",
    "/pending/ab\n12",
    "/pending//decide",
    "/pending/",
    "pending/ab12/decide",
    "",
    "/",
    "@other-host/x",
    "/pending/é",
    None,
]


@pytest.mark.parametrize("path", BAD_PATHS)
def test_gw_refuses_a_path_it_would_not_send_as_written(load, path):  # noqa: F811
    main, world = load(), World()

    async def body():
        async with started(main, world) as c:
            with pytest.raises(main.GatewayPath, match="gateway path refused"):
                await main.gw(c.server.app, "POST", path, {"scope": "once"})

    run(body())
    assert world.seen == []


def test_gw_sends_the_path_as_written_and_the_query_from_params(load):  # noqa: F811
    main = load()
    main.GW_URL = "http://egress-gw:8081"
    assert str(main.gw_url("/pending/ab12/decide")) == "http://egress-gw:8081/pending/ab12/decide"
    assert (
        str(main.gw_url("/destinations/grant:a.b_c-d/move")) == "http://egress-gw:8081/destinations/grant:a.b_c-d/move"
    )
    url = main.gw_url("/active-grants/ab12", {"by": "telegram:a&b=c d?#/../x"})
    assert url.path == "/active-grants/ab12" and dict(url.query) == {"by": "telegram:a&b=c d?#/../x"}
    assert url.raw_query_string.count("&") == 0 and "#" not in str(url) and ".." in url.raw_query_string
    assert issubclass(main.GatewayPath, ValueError)  # callers that expect a bad gateway answer catch it too


def test_a_refused_gateway_path_is_a_404_for_the_browser_not_a_request(load, monkeypatch):  # noqa: F811
    """Should the allow-list ever let through what gw() refuses, the answer is "not allowed", not a call."""
    main, world = load(), World()
    monkeypatch.setattr(main, "GW_ALLOW", [("POST", r"/pending/.*")])

    async def body():
        async with started(main, world) as c:
            assert await raw(c, "POST", "/api/gw/pending/../emergency-stop") == 404
            assert await raw(c, "POST", "/api/gw/pending/ab12/decide") == 200

    run(body())
    assert [(m, p) for m, p, _, _ in world.seen] == [("POST", "/gw/pending/ab12/decide")]


# ---------------------------------------------------------------- Telegram, through the real app (#239)
class Telegram:
    """A Bot API that hands out the given updates once and records what the bot sends back."""

    def __init__(self, updates: list[dict]) -> None:
        self.updates = [updates]
        self.calls: list[tuple[str, dict]] = []

    async def handle(self, request):
        method = request.match_info["method"]
        self.calls.append((method, await request.json()))
        if method == "getUpdates":
            if self.updates:
                return web.json_response({"ok": True, "result": self.updates.pop()})
            await asyncio.sleep(30)
        return web.json_response({"ok": True, "result": {"message_id": 1}})


def press(update_id: int, data: str) -> dict:
    message = {"message_id": 5, "chat": {"id": 7}, "text": "t"}
    query = {"id": f"q{update_id}", "from": {"id": 42, "username": "op"}, "message": message, "data": data}
    return {"update_id": update_id, "callback_query": query}


def test_telegram_callback_data_never_names_another_gateway_route(load, caplog):  # noqa: F811
    """The reviewer's reproduction: an allowed user in the right chat sends callback data that is no button
    of the bot. Before the fix the gateway saw POST /emergency-stop?x=/decide and DELETE
    /policy/history/3/restore?by=telegram:op."""
    world = World()
    telegram = Telegram(
        [
            press(1, "d:../../gw/emergency-stop?x=:once"),
            press(2, "r:../policy/history/3/restore"),
            press(3, "g:../presets/open:approve"),
            press(4, "d:ab12:../../presets/open"),
            press(5, "d:ab12:once"),  # the bot's own buttons still work
            press(6, "g:cd34:read"),
            press(7, "r:ef56"),
        ]
    )

    async def body():
        a = web.Application()
        a.router.add_post("/bot{token}/{method}", telegram.handle)
        srv = test_utils.TestServer(a)
        await srv.start_server()
        main = load(
            TELEGRAM_BOT_TOKEN="123456:ABCDEFGHIJKLMNOP",
            TELEGRAM_CHAT_ID="7",
            TELEGRAM_ALLOWED_USER_IDS="42",
            TELEGRAM_API_BASE=f"http://127.0.0.1:{srv.port}",
        )
        try:
            async with started(main, world):
                for _ in range(100):
                    if sum(1 for m, _ in telegram.calls if m == "answerCallbackQuery") == 3:
                        break
                    await asyncio.sleep(0.05)
        finally:
            await srv.close()

    with caplog.at_level(logging.WARNING, logger="notify"):
        run(body())
    assert world.seen == [
        ("POST", "/gw/pending/ab12/decide", {}, {"scope": "once", "by": "telegram:op"}),
        ("POST", "/gw/grant-requests/cd34/decide", {}, {"decision": "read", "by": "telegram:op"}),
        ("DELETE", "/gw/active-grants/ef56", {"by": "telegram:op"}, None),
    ]
    answered = [b["callback_query_id"] for m, b in telegram.calls if m == "answerCallbackQuery"]
    assert answered == ["q5", "q6", "q7"]  # the four others got no answer at all
    assert caplog.text.count("dropped: not a button of this bot") == 4
