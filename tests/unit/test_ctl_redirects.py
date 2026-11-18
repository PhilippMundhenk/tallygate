"""control never follows a redirect (#230): a hostile agent that answers control's calls with a redirect must
not be able to make control fetch a URL of its choosing (control has a route to the LAN and the internet,
the agent only to the gateway). The same holds for the gateway, GitHub and the notification services, and the
clients for the agent and the gateway connect to nothing but that one peer."""

from __future__ import annotations

import asyncio
import logging

import pytest

from .test_ctl_main import CSRF, World, console, free_port, run, started
from .test_ctl_setup import load_main  # noqa: F401 (fixture)

pytest.importorskip("aiohttp")
import aiohttp
from aiohttp import WSMsgType, test_utils, web

from app import notify

CODES = (301, 302, 303, 307, 308)
FIXED = {
    "agent": {"error": "the agent answered with a redirect, which is never followed"},
    "gateway": {"error": "the gateway answered with a redirect, which is never followed"},
}


class Outside:
    """A host the agent has no route to (a LAN device, cloud metadata, a server on the internet). It records
    every request; after each test it must have seen none."""

    def __init__(self) -> None:
        self.seen: list[tuple[str, str]] = []
        self.srv: test_utils.TestServer | None = None

    async def start(self) -> str:
        a = web.Application(client_max_size=10**7)
        a.router.add_route("*", "/{tail:.*}", self.handle)
        self.srv = test_utils.TestServer(a)
        await self.srv.start_server()
        return f"http://127.0.0.1:{self.srv.port}"

    async def handle(self, request):
        self.seen.append((request.method, request.path_qs))
        await request.read()
        return web.json_response({"claude_version": "9.9.9", "ok": True, "entries": []})


class Redirector:
    """Stands for the agent's status server and ttyd (or the gateway, GitHub, a notification service) under
    the attacker's control: every request, whatever the method and path, is answered with `code` and a
    Location on the outside host, with data in the URL."""

    def __init__(self, code: int, target: str = "") -> None:
        self.code, self.target = code, target
        self.asked: list[tuple[str, str]] = []
        self.srv: test_utils.TestServer | None = None

    async def start(self) -> int:
        a = web.Application(client_max_size=10**7)
        a.router.add_route("*", "/{tail:.*}", self.handle)
        self.srv = test_utils.TestServer(a)
        await self.srv.start_server()
        return self.srv.port

    async def handle(self, request):
        self.asked.append((request.method, request.path))
        location = f"{self.target}/exfil?via={request.method}&data=WORKSPACE-DATA"
        # a body as well: nothing of it may reach the browser
        return web.json_response(
            {"error": "LEAK", "claude_version": "6.6.6"}, status=self.code, headers={"Location": location}
        )


@pytest.fixture
def stage():
    """An outside host and a redirecting peer for one test; both are closed afterwards."""
    made: list = []

    async def _stage(code: int):
        outside = Outside()
        peer = Redirector(code, await outside.start())
        port = await peer.start()
        made.extend((outside, peer))
        return outside, peer, port

    yield _stage


async def close(*servers) -> None:
    for s in servers:
        await s.srv.close()


AGENT_CALLS = [
    ("GET", "/api/agent/status", None),
    ("GET", "/api/agent/selftest", None),
    ("GET", "/api/agent/setup/claude-login", None),
    ("POST", "/api/agent/setup/claude-login", {}),
    ("POST", "/api/agent/setup/claude-code", {"code": "abc"}),
    ("GET", "/api/agent/setup/git-identity", None),
    ("POST", "/api/agent/setup/git-identity", {"name": "Alex Example", "email": "alex@example.org"}),
    ("POST", "/api/agent/setup/remote-control", {}),
    ("GET", "/api/files?path=", None),
    ("GET", "/api/files/download?path=notes.txt", None),
    ("DELETE", "/api/files?path=notes.txt", None),
]


@pytest.mark.parametrize("code", CODES)
def test_a_redirecting_agent_gets_502_and_control_fetches_nothing(load_main, stage, code, caplog):  # noqa: F811
    main = load_main()
    caplog.set_level(logging.WARNING, logger="control")

    async def body():
        outside, agent, port = await stage(code)
        async with started(main, World()) as c:
            main.AGENT_STATUS_PORT, main.TERMINALS = port, {"bash": port}
            for method, path, payload in AGENT_CALLS:
                r = await c.request(method, path, json=payload, headers=CSRF)
                assert (r.status, await r.json()) == (502, FIXED["agent"]), (method, path)
            r = await c.put("/api/files?path=upload.bin", data=b"x" * 5000, headers=CSRF)
            assert (r.status, await r.json()) == (502, FIXED["agent"])
            r = await c.get("/api/version")  # the version card just has no Claude Code version
            assert r.status == 200 and (await r.json())["claude_code"] is None
            ws = await console(c)  # the ttyd relay: the WebSocket handshake is not followed either
            await ws.send_str("{}")
            assert (await asyncio.wait_for(ws.receive(), 5)).type in (WSMsgType.CLOSE, WSMsgType.CLOSED)
        await close(outside, agent)
        return outside, agent

    outside, agent = run(body())
    assert outside.seen == []  # the point: control made no request of the agent's choosing
    assert len(agent.asked) == len(AGENT_CALLS) + 3  # every call did reach the (hostile) agent, once
    assert "the agent answered with a redirect: not followed" in caplog.text
    assert "exfil" not in caplog.text and "LEAK" not in caplog.text


@pytest.mark.parametrize("code", [300, 304, 305, 399])
def test_any_other_3xx_from_the_agent_is_a_502_with_the_fixed_text(load_main, stage, code):  # noqa: F811
    """aiohttp would not follow these, but their bodies are the agent's: nothing of them is passed on."""
    main = load_main()

    async def body():
        outside, agent, port = await stage(code)
        async with started(main, World()) as c:
            main.AGENT_STATUS_PORT = port
            for method, path in (
                ("GET", "/api/agent/status"),
                ("GET", "/api/files?path="),
                ("DELETE", "/api/files?path=a"),
            ):
                r = await c.request(method, path, headers=CSRF)
                assert (r.status, await r.json()) == (502, FIXED["agent"])
            r = await c.get("/api/files/download?path=a")
            assert (r.status, await r.json()) == (502, FIXED["agent"])
        await close(outside, agent)
        return outside.seen

    assert run(body()) == []


def test_a_redirect_to_the_agent_itself_is_not_followed_either(load_main):  # noqa: F811
    """No exception for 'same host': the rule is that control makes exactly the request it built."""
    main = load_main()
    world = World()

    async def body():
        agent = Redirector(302)
        port = await agent.start()
        async with started(main, world) as c:
            agent.target = f"http://127.0.0.1:{main.AGENT_STATUS_PORT}/status?"  # the honest status server
            main.AGENT_STATUS_PORT = port
            r = await c.get("/api/agent/status")
            assert (r.status, await r.json()) == (502, FIXED["agent"])
        await agent.srv.close()
        return agent.asked

    assert run(body()) == [("GET", "/status")]


@pytest.mark.parametrize("code", CODES)
def test_a_redirecting_gateway_gets_502_and_control_fetches_nothing(load_main, stage, code, caplog):  # noqa: F811
    main = load_main()
    caplog.set_level(logging.WARNING, logger="control")

    async def body():
        outside, gateway, port = await stage(code)
        world = World()
        async with started(main, world) as c:
            main.GW_URL = f"http://127.0.0.1:{port}"
            for method, path, payload in (
                ("GET", "/api/gw/info", None),
                ("GET", "/api/gw/policy", None),
                ("POST", "/api/gw/pending/abc123/decide", {"scope": "once"}),
                ("POST", "/api/gw/emergency-stop", {}),
            ):
                r = await c.request(method, path, json=payload, headers=CSRF)
                assert (r.status, await r.json()) == (502, FIXED["gateway"]), (method, path)
            r = await c.get("/api/version")
            assert r.status == 200 and (await r.json())["tallygate"] is None
            r = await c.get("/api/stream")  # the event stream relay ends without a byte from elsewhere
            assert r.status == 200 and await asyncio.wait_for(r.read(), 5) == b""
            # a token that GitHub accepts cannot be stored: the gateway's redirect is an error, not a place to go
            r = await c.post("/api/github/check", json={"token": "good", "store": True}, headers=CSRF)
            assert (
                r.status == 502 and "answered with a redirect, which control never follows" in (await r.json())["error"]
            )
            # decisions from the notification channels use the same client
            with pytest.raises(main.UpstreamRedirect):
                await c.app["notifier"].decide("abc123", "once", "telegram:1")
            await main.asyncio.sleep(0)
        await close(outside, gateway)
        return outside.seen

    assert run(body()) == []
    assert "exfil" not in caplog.text and "LEAK" not in caplog.text


def test_the_gateway_subscription_retries_after_a_redirect(load_main, stage, monkeypatch, caplog):  # noqa: F811
    main = load_main()
    caplog.set_level(logging.WARNING, logger="control")

    async def body():
        outside, gateway, port = await stage(307)
        main.GW_URL = f"http://127.0.0.1:{port}"
        app = {"gw": main._client(main._gateway_peers)}
        task = asyncio.create_task(main.watch_gateway(app))
        for _ in range(100):
            if gateway.asked:
                break
            await asyncio.sleep(0.02)
        await asyncio.sleep(0.05)
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        await app["gw"].close()
        await close(outside, gateway)
        return outside.seen, gateway.asked

    seen, asked = run(body())
    assert seen == [] and asked == [("GET", "/stream")]
    assert "gateway stream: answered with a redirect, which control never follows (retrying)" in caplog.text


@pytest.mark.parametrize("code", CODES)
def test_github_redirects_are_not_followed(load_main, stage, code):  # noqa: F811
    main = load_main()

    async def body():
        outside, github, port = await stage(code)
        async with started(main, World()) as c:
            main.GITHUB_API = f"http://127.0.0.1:{port}"
            r = await c.post("/api/github/check", json={"token": "good"}, headers=CSRF)
            assert r.status == 502
            assert (await r.json())[
                "error"
            ] == "GitHub unreachable: answered with a redirect, which control never follows"
            got = await (await c.get("/api/version")).json()
            assert got["check"] == "error" and "redirect" in got["error"] and got["latest"] is None
        await close(outside, github)
        return outside.seen

    assert run(body()) == []


class FakePush:
    def __init__(self, url: str) -> None:
        self.url = url

    def request(self, sub, message, ttl, topic):
        return self.url, b"encrypted", {"TTL": str(ttl)}


@pytest.mark.parametrize("code", CODES)
def test_notification_services_are_not_followed(load_main, stage, monkeypatch, code):  # noqa: F811
    """ntfy, Gotify, Pushover, Telegram, Matrix and Web Push: the configured URL is the final URL. A redirect
    is a failed delivery (shown as such in the channel's status), never a second request with the message,
    the token or the Authorization header to another place."""
    main = load_main()

    async def body():
        outside, service, port = await stage(code)
        base = f"http://127.0.0.1:{port}"
        for k, v in {
            "NTFY_URL": f"{base}/topic",
            "NTFY_TOKEN": "ntfy-secret",
            "GOTIFY_URL": base,
            "GOTIFY_TOKEN": "gotify-secret",
            "PUSHOVER_TOKEN": "a",
            "PUSHOVER_USER": "u",
            "PUSHOVER_API_BASE": base,
            "TELEGRAM_BOT_TOKEN": "tg-secret",
            "TELEGRAM_CHAT_ID": "1",
            "TELEGRAM_ALLOWED_USER_IDS": "1",
            "TELEGRAM_API_BASE": base,
            "MATRIX_HOMESERVER": base,
            "MATRIX_ACCESS_TOKEN": "mx-secret",
            "MATRIX_ROOM_ID": "!room:hs",
            "MATRIX_ALLOWED_USERS": "@alex:hs",
        }.items():
            monkeypatch.setenv(k, v)
        http = main._client()
        n = notify.Notifier({"http": http}, decide=None)
        for channel in ("ntfy", "gotify", "pushover"):
            with pytest.raises(main.UpstreamRedirect):
                await n.send_test(channel)
        with pytest.raises(main.UpstreamRedirect):
            await n._tg("sendMessage", chat_id="1", text="x")
        with pytest.raises(main.UpstreamRedirect):
            await n._mx("GET", "/account/whoami")
        n.push = FakePush(f"{base}/push/abc")
        with pytest.raises(main.UpstreamRedirect):
            await n._push_one({"id": "s1"}, {"title": "t"}, 60, None)
        await http.close()
        await close(outside, service)
        return outside.seen, len(service.asked)

    seen, asked = run(body())
    assert seen == [] and asked == 6


def test_the_agent_and_gateway_clients_connect_to_their_peer_only(load_main, stage):  # noqa: F811
    """Second line of defence, independent of the redirect rule: even a request built for another place by a
    future bug is refused before a name is resolved or a socket is opened."""
    main = load_main()

    async def body():
        outside, _peer, _port = await stage(302)
        elsewhere = f"http://127.0.0.1:{outside.srv.port}/x"
        async with started(main, World()) as c:
            app = c.app
            for name in ("agent", "gw"):
                for url in (elsewhere, f"http://localhost:{outside.srv.port}/x", "http://name.invalid/x"):
                    with pytest.raises(main.PinnedPeer, match="one configured peer only"):
                        await app[name].get(url)
                with pytest.raises(main.PinnedPeer):
                    await app[name].ws_connect(elsewhere.replace("http", "ws"))
            # the real peers still answer
            assert (await main.agent_call(app, "GET", "status"))[0] == 200
            assert (await main.gw(app, "GET", "/info"))[0] == 200
            # the general client (GitHub, notification services) may go anywhere, but keeps no cookies
            async with app["http"].get(elsewhere) as r:
                assert r.status == 200
            assert isinstance(app["http"].cookie_jar, aiohttp.DummyCookieJar)
        await close(outside, _peer)
        return outside.seen

    assert run(body()) == [("GET", "/x")]


def test_peers_follow_the_configuration(load_main):  # noqa: F811
    main = load_main()
    main.AGENT_HOST, main.AGENT_STATUS_PORT, main.TERMINALS = "Agent", 7680, {"rc": 7681, "bash": 7682}
    assert main._agent_peers() == {("agent", 7680), ("agent", 7681), ("agent", 7682)}
    main.AGENT_HOST = "[fd00::10]"
    assert ("fd00::10", 7680) in main._agent_peers()
    for url, peer in (
        ("http://egress-gw:8081", ("egress-gw", 8081)),
        ("http://GW.example", ("gw.example", 80)),
        ("https://gw.example", ("gw.example", 443)),
    ):
        main.GW_URL = url
        assert main._gateway_peers() == {peer}


def test_a_refused_redirect_leaves_no_open_connection(load_main, stage):  # noqa: F811
    main = load_main()

    async def body():
        outside, peer, port = await stage(302)
        main.AGENT_HOST, main.AGENT_STATUS_PORT, main.TERMINALS = "127.0.0.1", port, {}
        session = main._client(main._agent_peers)
        for _ in range(3):
            with pytest.raises(main.UpstreamRedirect):
                await session.get(f"http://127.0.0.1:{port}/status")
        open_now = len(session.connector._acquired)
        await session.close()
        await close(outside, peer)
        return open_now, free_port() > 0

    assert run(body()) == (0, True)
