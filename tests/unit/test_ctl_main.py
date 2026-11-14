"""control/app/main.py in-process (aiohttp test server) against one fake "world" that plays the gateway
API (/gw), GitHub (/gh), the agent's status server and its ttyd. Covers the error paths and security
decisions the e2e tests cannot provoke with the real gateway and ttyd."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import importlib
import json
import logging
import socket
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

aiohttp = pytest.importorskip("aiohttp")
from aiohttp import WSMsgType, test_utils, web  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "control"))

PW = "unit-password"
ENV = {
    "GW_API_TOKEN": "gw-token-" * 4,
    "SESSION_SECRET": "unit",
    "TTYD_CREDENTIAL": "agent:ttyd-secret",
    "CONTROL_PASSWORD": PW,
    "COOKIE_SECURE": "0",
    "TERMINALS": "bash:1",
}
CLEARED = (
    "CONTROL_PASSWORD_HASH",
    "TRUST_PROXY_AUTH_HEADER",
    "TRUST_FORWARDED_FOR",
    "TRUSTED_PROXIES",
    "TRUST_PROXY_SECRET",
    "PUBLIC_URL",
    "CONTROL_BIND_HOST",
    "TELEGRAM_BOT_TOKEN",
    "MATRIX_HOMESERVER",
)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def load(monkeypatch, tmp_path):
    """Import app.main afresh with the given environment (module-level settings are read at import)."""

    def _load(**env):
        for v in CLEARED:
            monkeypatch.delenv(v, raising=False)
        for k, v in {**ENV, "CONTROL_DATA": str(tmp_path / "data"), **env}.items():
            monkeypatch.setenv(k, v)
        import app.bootstrap
        import app.main

        importlib.reload(app.bootstrap)
        return importlib.reload(app.main)

    return _load


class World:
    def __init__(self) -> None:
        self.seen: list[tuple[str, str, dict, object]] = []
        self.by: list[str | None] = []  # X-Tallygate-By of every relayed gateway call
        self.agent: dict[str, tuple[int, bytes]] = {"status": (200, b'{"claude_version": "2.0.0"}')}
        self.stream: tuple[int, bytes] = (200, b"")
        self.ttyd_frames: list = []  # sent to the browser (via control) right after the handshake
        self.ttyd_got: list = []
        self.ttyd_auth = None

    def app(self) -> web.Application:
        a = web.Application()
        a.router.add_get("/gw/stream", self.gw_stream)
        a.router.add_route("*", "/gw/{tail:.*}", self.gw)
        a.router.add_get("/gh/user", self.github)
        a.router.add_get("/term/bash/ws", self.ttyd)
        a.router.add_route("*", "/setup/{what}", self.agent_setup)
        a.router.add_get("/{what}", self.agent_status)
        return a

    async def gw(self, request):
        body = await request.json() if request.can_read_body else None
        self.seen.append((request.method, request.path, dict(request.query), body))
        self.by.append(request.headers.get("X-Tallygate-By"))
        return web.json_response({"ok": True})

    async def gw_stream(self, _request):
        status, body = self.stream
        return web.Response(status=status, body=body)

    async def github(self, request):
        token = request.headers["Authorization"].removeprefix("Bearer ")
        if token == "good":
            return web.json_response(
                {"login": "octo"},
                headers={"X-OAuth-Scopes": "repo", "github-authentication-token-expiration": "2027-01-01"},
            )
        if token == "list":
            return web.json_response([])
        return web.json_response({"message": "Bad credentials"}, status=401)

    async def agent_status(self, request):
        status, raw = self.agent.get(request.match_info["what"], (404, b"{}"))
        return web.Response(status=status, body=raw)

    async def agent_setup(self, request):
        body = await request.json() if request.can_read_body else None
        self.seen.append((request.method, request.path, {}, body))
        status, raw = self.agent.get("setup/" + request.match_info["what"], (404, b"{}"))
        return web.Response(status=status, body=raw)

    async def ttyd(self, request):
        ws = web.WebSocketResponse(protocols=("tty",), max_msg_size=0)
        await ws.prepare(request)
        self.ttyd_auth = request.headers.get("Authorization")
        self.ttyd_got.append((await ws.receive()).data)  # handshake
        for frame in self.ttyd_frames:
            await (ws.send_str(frame) if isinstance(frame, str) else ws.send_bytes(frame))
        async for msg in ws:
            self.ttyd_got.append(msg.data)
        return ws


@contextlib.asynccontextmanager
async def started(main, world: World | None = None, login: bool = True):
    srv = None
    main.GW_URL = f"http://127.0.0.1:{free_port()}"  # no gateway unless the world plays it
    if world:
        srv = test_utils.TestServer(world.app())
        await srv.start_server()
        base = str(srv.make_url("")).rstrip("/")
        main.GW_URL, main.GITHUB_API = base + "/gw", base + "/gh"
        main.AGENT_HOST, main.AGENT_STATUS_PORT, main.TERMINALS = "127.0.0.1", srv.port, {"bash": srv.port}
    client = test_utils.TestClient(test_utils.TestServer(main.build_app()))
    await client.start_server()
    try:
        if login:
            r = await client.post("/login", data={"password": PW})
            assert r.status == 200 and str(r.url).endswith("/")
        yield client
    finally:
        await client.close()
        if srv:
            await srv.close()


CSRF = {"X-Tallygate": "1"}


def run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------- trust decisions (no server)
def req(remote, **headers):
    return SimpleNamespace(remote=remote, headers=headers)


def test_unparsable_peer_is_never_a_trusted_proxy(load):
    main = load(TRUSTED_PROXIES="0.0.0.0/0", TRUST_FORWARDED_FOR="1")
    assert main._peer_trusted(req("10.1.2.3"))
    for remote in (None, "", "unix-socket", "300.1.1.1"):
        assert not main._peer_trusted(req(remote))


def test_client_ip_takes_the_hop_the_trusted_proxy_appended(load):
    main = load(TRUSTED_PROXIES="10.0.0.0/8", TRUST_FORWARDED_FOR="1")
    # the client controls everything left of what our proxy appended
    assert main.client_ip(req("10.0.0.2", **{"X-Forwarded-For": "1.2.3.4, 203.0.113.9"})) == "203.0.113.9"
    assert main.client_ip(req("192.0.2.1", **{"X-Forwarded-For": "1.2.3.4"})) == "192.0.2.1"  # untrusted peer
    assert main.client_ip(req(None)) == "?"


def test_forwarded_for_without_trusted_proxies_warns_and_is_ignored(load, caplog):
    main = load(TRUST_FORWARDED_FOR="1")
    with caplog.at_level(logging.WARNING, logger="control"):
        main.build_app()
    assert "TRUSTED_PROXIES is empty" in caplog.text
    assert main.client_ip(req("10.0.0.2", **{"X-Forwarded-For": "1.2.3.4"})) == "10.0.0.2"


def test_proxy_auth_header_requires_trusted_proxies(load):
    main = load(TRUST_PROXY_AUTH_HEADER="Remote-User")
    with pytest.raises(SystemExit, match="requires TRUSTED_PROXIES"):
        main.build_app()


def test_public_url_defines_the_expected_origin(load):
    main = load(PUBLIC_URL="https://Tally.Example:8443/ui/")
    r = SimpleNamespace(headers={"Origin": "https://tally.example:8443"}, host="127.0.0.1:8080", scheme="http")
    assert main._same_origin(r)  # the Host header is not what counts behind a proxy
    r.headers["Origin"] = "http://127.0.0.1:8080"
    assert not main._same_origin(r)


def test_main_refuses_to_listen_without_a_bind_address(load, monkeypatch):
    main = load()
    with pytest.raises(SystemExit, match="CONTROL_BIND_HOST must be set"):
        main.main()
    seen = {}
    monkeypatch.setattr(main.web, "run_app", lambda app, **kw: seen.update(kw))
    monkeypatch.setenv("CONTROL_BIND_HOST", "172.31.0.5")
    monkeypatch.setenv("CONTROL_PORT", "8099")
    main.main()
    assert seen == {"host": "172.31.0.5", "port": 8099, "access_log": None}


# ---------------------------------------------------------------- login and sessions
def test_login_page_and_expired_sessions_are_pruned(load):
    main = load()

    async def body():
        async with started(main, login=False) as c:
            r = await c.get("/login")
            assert r.status == 200 and "password" in (await r.text())
            assert (
                r.headers["Cache-Control"] == "no-store"
                and "default-src 'none'" in r.headers["Content-Security-Policy"]
            )
            now = time.time()
            main._sessions["old"] = {"user": "admin", "exp": now - 1, "seen": now}
            main._sessions["idle"] = {"user": "admin", "exp": now + 999, "seen": now - main.SESSION_IDLE - 1}
            main._sessions["live"] = {"user": "admin", "exp": now + 999, "seen": now, "pw": main.password_fingerprint()}
            assert (await c.post("/login", data={"password": PW})).status == 200
            assert "old" not in main._sessions and "idle" not in main._sessions and "live" in main._sessions

    run(body())


def test_changing_the_stored_password_ends_existing_sessions(load, tmp_path, monkeypatch):
    main = load(CONTROL_PASSWORD="")  # the zero-config case: the hash lives in the control volume
    monkeypatch.delenv("CONTROL_PASSWORD")
    import app.bootstrap

    app.bootstrap._write(app.bootstrap.PASSWORD_FILE, app.bootstrap.hash_password(PW, log2n=4))

    async def body():
        async with started(main, World()) as c:
            assert (await c.get("/api/meta")).status == 200
            fp = main.password_fingerprint()
            app.bootstrap._write(app.bootstrap.PASSWORD_FILE, app.bootstrap.hash_password("a new password!", log2n=4))
            assert main.password_fingerprint() != fp
            assert (await c.get("/api/meta")).status == 401  # the session from the old password is gone
            assert not main._sessions
            r = await c.post("/login", data={"password": PW})
            assert str(r.url).endswith("/login?failed=1")
            r = await c.post("/login", data={"password": "a new password!"})
            assert r.status == 200 and str(r.url).endswith("/")
            assert (await c.get("/api/meta")).status == 200

    run(body())


def test_the_fingerprint_follows_the_password_source(load, monkeypatch):
    main = load()
    main.SESSION_SECRET = b"s"
    plain = main.password_fingerprint()
    monkeypatch.setenv("CONTROL_PASSWORD", "another-password")
    assert main.password_fingerprint() != plain
    monkeypatch.setenv("CONTROL_PASSWORD_HASH", "scrypt:16:00:11")
    by_hash = main.password_fingerprint()
    assert by_hash != plain
    assert "scrypt" not in by_hash and len(by_hash) == 64  # a digest, not the hash itself


def test_failure_tracking_stays_bounded_under_address_spraying(load):
    # the per-IP lockout (and thus its memory) only applies with trusted per-client addresses (#101)
    main = load(TRUST_FORWARDED_FOR="1", TRUSTED_PROXIES="127.0.0.1/32")

    async def body():
        async with started(main, login=False) as c:
            main._login_failures.update({f"198.51.100.{i}": [time.time() - 10_000 + i] for i in range(10_001)})
            r = await c.post("/login", data={"password": "wrong"}, allow_redirects=False)
            assert r.status == 302 and r.headers["Location"] == "/login?failed=1"
            assert len(main._login_failures) == 10_002 - 5_000
            assert "198.51.100.0" not in main._login_failures  # oldest dropped
            assert "198.51.100.10000" in main._login_failures and "127.0.0.1" in main._login_failures

    run(body())


def test_handler_errors_become_a_generic_500(load, monkeypatch):
    main = load()

    async def boom(_request):
        raise RuntimeError("secret detail")

    monkeypatch.setattr(main, "api_meta", boom)
    monkeypatch.setattr(main, "index", boom)

    async def body():
        async with started(main, login=False) as c:
            assert (await c.post("/login", data={"password": PW}, allow_redirects=False)).status == 302
            r = await c.get("/api/meta")
            assert r.status == 500 and await r.json() == {"error": "internal error (see the control log)"}
            r = await c.get("/")  # pages: aiohttp's own 500, no details either
            assert r.status == 500 and "secret detail" not in await r.text()

    run(body())


# ---------------------------------------------------------------- gateway relay
def test_revoking_a_grant_is_attributed_to_the_session_user(load):
    main = load()
    world = World()

    async def body():
        async with started(main, world) as c:
            r = await c.delete("/api/gw/active-grants/abc123?by=spoofed", headers=CSRF)
            assert r.status == 200
            r = await c.post("/api/gw/grants/svc/activate", json={"level": "read", "by": "spoofed"}, headers=CSRF)
            assert r.status == 200

    run(body())
    assert world.seen == [
        ("DELETE", "/gw/active-grants/abc123", {"by": "web:admin"}, None),
        ("POST", "/gw/grants/svc/activate", {}, {"level": "read", "by": "web:admin"}),
    ]


def test_mode_patch_and_emergency_stop_are_relayed_and_attributed(load):
    main = load()
    world = World()

    async def body():
        async with started(main, world) as c:
            assert (await c.patch("/api/gw/policy", json={"default": "deny"}, headers=CSRF)).status == 200
            r = await c.post("/api/gw/emergency-stop", json={"by": "spoofed", "skip": ["revoke"]}, headers=CSRF)
            assert r.status == 200
            assert (await c.post("/api/gw/emergency-stop", headers=CSRF)).status == 200  # no body
            assert (await c.patch("/api/gw/rules/x", json={"note": "n"}, headers=CSRF)).status == 200  # #141: relayed
            assert (await c.put("/api/gw/rules/x", json={}, headers=CSRF)).status == 404  # but only PATCH, not PUT

    run(body())
    assert world.seen == [
        ("PATCH", "/gw/policy", {}, {"default": "deny"}),
        ("POST", "/gw/emergency-stop", {}, {"by": "web:admin"}),
        ("POST", "/gw/emergency-stop", {}, {"by": "web:admin"}),
        ("PATCH", "/gw/rules/x", {}, {"note": "n"}),  # not attributed: rules carry no `by`
    ]


def test_policy_history_routes_are_relayed_with_the_session_user(load):
    main = load()
    world = World()

    async def body():
        async with started(main, world) as c:
            for method, path in [
                ("GET", "/api/gw/policy/history?limit=5"),
                ("GET", "/api/gw/policy/history/3"),
                ("GET", "/api/gw/policy/diff?from=1&to=current"),
                ("POST", "/api/gw/policy/history/3/restore"),
                ("GET", "/api/gw/policy/export"),
                ("POST", "/api/gw/policy/import"),
            ]:
                assert (await c.request(method, path, headers=CSRF)).status == 200, path
            assert (await c.post("/api/gw/policy/history/x/restore", headers=CSRF)).status == 404

    run(body())
    assert [s[1] for s in world.seen] == [
        "/gw/policy/history",
        "/gw/policy/history/3",
        "/gw/policy/diff",
        "/gw/policy/history/3/restore",
        "/gw/policy/export",
        "/gw/policy/import",
    ]
    assert world.seen[2][2] == {"from": "1", "to": "current"} and set(world.by) == {"web:admin"}


def test_attribution_header_is_printable_ascii(load):
    main = load()
    world = World()

    async def body():
        async with started(main, world) as c:
            assert (await c.get("/api/gw/policy")).status == 200
            await main.gw(c.server.app, "GET", "/policy", by="web:josé\nx")

    run(body())
    assert world.by == ["web:admin", "web:jos??x"]


def test_gateway_down(load):
    main = load()

    async def body():
        async with started(main, World()) as c:
            main.GW_URL = f"http://127.0.0.1:{free_port()}"
            r = await c.get("/api/gw/policy")
            assert r.status == 502 and (await r.json())["error"].startswith("gateway unreachable")
            r = await c.get("/api/stream")  # ends at once instead of hanging
            assert r.status == 200 and await r.read() == b""
            r = await c.post("/api/github/check", json={"token": "good", "store": True}, headers=CSRF)
            assert r.status == 502
            assert (await r.json())["error"].startswith("token valid, but storing it in the gateway failed")

    run(body())


def test_gateway_event_stream_errors_are_retried(load, caplog):
    main = load()
    world = World()
    world.stream = (500, b"")

    async def body():
        with caplog.at_level(logging.WARNING, logger="control"):
            async with started(main, world, login=False):
                await asyncio.sleep(0.3)
                assert "gateway stream: status 500 (retrying)" in caplog.text
                world.stream = (200, b"data: {not json\n")
                await asyncio.sleep(3.3)
                assert "gateway stream: Expecting property name" in caplog.text

    run(body())


# ---------------------------------------------------------------- GitHub token check
def test_github_check(load):
    main = load()
    world = World()

    async def body():
        async with started(main, world) as c:

            async def check(payload):
                r = await c.post("/api/github/check", json=payload, headers=CSRF)
                return r.status, await r.json()

            assert await check({"token": "  "}) == (400, {"error": "token missing"})
            assert await check(["good"]) == (400, {"error": "expected a JSON object"})
            assert await check({"token": "bad"}) == (200, {"ok": False, "status": 401, "message": "Bad credentials"})
            assert await check({"token": "list"}) == (502, {"error": "invalid response from GitHub"})
            status, info = await check({"token": "good"})
            assert (status, info) == (200, {"ok": True, "login": "octo", "scopes": "repo", "expires": "2027-01-01"})
            assert world.seen == []  # not stored unless asked
            status, info = await check({"token": "good", "store": True})
            assert status == 200 and info["stored"] is True and "good" not in json.dumps(info)

    run(body())
    assert world.seen == [("PUT", "/gw/secrets/github_token", {}, {"value": "good"})]


# ---------------------------------------------------------------- agent status
@pytest.mark.parametrize(
    ("reply", "status", "error"),
    [
        ((200, b'{"claude_version": "2.0.0"}'), 200, None),
        ((200, b'{"results": "' + b"a" * 300_000 + b'"}'), 200, None),  # more than one read, within the cap
        ((500, b'{"error": "boom"}'), 502, None),  # passed on, but marked as a failure
        ((200, b"[1, 2]"), 502, "agent unreachable or invalid response: not an object"),
        ((200, b"<html>"), 502, "agent unreachable or invalid response"),
        ((200, b'{"x": "' + b"a" * (1024 * 1024) + b'"}'), 502, "agent response too large"),
    ],
)
def test_agent_status_is_size_limited_and_validated(load, reply, status, error):
    main = load()
    world = World()
    world.agent["status"] = reply

    async def body():
        async with started(main, world) as c:
            r = await c.get("/api/agent/status")
            return r.status, await r.json()

    got_status, data = run(body())
    assert got_status == status
    if error:
        assert data["error"].startswith(error)
    else:
        assert data == json.loads(reply[1])


def test_agent_status_only_known_endpoints_and_unreachable(load):
    main = load()

    async def body():
        async with started(main, World()) as c:
            assert (await c.get("/api/agent/env")).status == 404  # never relays other agent paths
            main.AGENT_STATUS_PORT = free_port()
            r = await c.get("/api/agent/selftest")
            assert r.status == 502 and "agent unreachable" in (await r.json())["error"]

    run(body())


# ---------------------------------------------------------------- web console relay
async def console(c, **kw):
    origin = str(c.make_url("")).rstrip("/")
    return await c.ws_connect("/term/bash/ws", protocols=("tty",), headers={"Origin": origin}, **kw)


def test_console_filters_both_directions_and_adds_the_credential(load):
    main = load()
    world = World()
    world.ttyd_frames = ["0hello", b"1title", b"2prefs", b"0world"]

    async def body():
        async with started(main, world) as c:
            ws = await console(c)
            await ws.send_str("not json")  # handshake: bad size -> defaults
            for frame in (b"0ls\r", b"2evil", b"1{}", b"9x"):
                await ws.send_bytes(frame)
            got = [await asyncio.wait_for(ws.receive(), 5) for _ in range(2)]
            await asyncio.sleep(0.3)  # let the relay forward the browser's frames
            await ws.close()
            return [m.data for m in got]

    assert run(body()) == [b"0hello", b"0world"]  # output only: title/preferences dropped
    hello = json.loads(world.ttyd_got[0])
    token = base64.b64encode(b"agent:ttyd-secret").decode()  # the test credential, as ttyd expects it
    assert hello == {"AuthToken": token, "columns": 80, "rows": 24}
    assert world.ttyd_auth == f"Basic {token}"
    assert b"2evil" not in world.ttyd_got and b"9x" not in world.ttyd_got
    assert b"0ls\r" in world.ttyd_got and b"1{}" in world.ttyd_got


def test_console_closes_on_an_oversized_agent_frame(load):
    main = load()
    world = World()
    world.ttyd_frames = [b"0before", b"0" + b"x" * (1024 * 1024 + 1)]

    async def body():
        async with started(main, world) as c:
            ws = await console(c)
            await ws.send_str('{"columns": 100, "rows": 30}')
            await ws.send_bytes(b"0a")
            first = await asyncio.wait_for(ws.receive(), 5)
            nxt = await asyncio.wait_for(ws.receive(), 5)
            return first, nxt

    first, nxt = run(body())
    assert first.data == b"0before"
    assert nxt.type in (WSMsgType.CLOSE, WSMsgType.CLOSED)  # the huge frame never reaches the browser
    assert json.loads(world.ttyd_got[0])["columns"] == 100


def test_console_closes_on_an_oversized_browser_frame(load):
    main = load()
    world = World()

    async def body():
        async with started(main, world) as c:
            ws = await console(c)
            await ws.send_str("{}")
            await ws.send_bytes(b"0" + b"x" * (64 * 1024 + 1))
            msg = await asyncio.wait_for(ws.receive(), 5)
            await asyncio.sleep(0.2)
            return msg

    assert run(body()).type in (WSMsgType.CLOSE, WSMsgType.CLOSED)
    assert all(len(f) < 1000 for f in world.ttyd_got)  # nothing big was forwarded


def test_console_unknown_terminal_and_agent_down(load):
    main = load()

    async def body():
        async with started(main, World()) as c:
            origin = str(c.make_url("")).rstrip("/")
            with pytest.raises(aiohttp.WSServerHandshakeError) as e:
                await c.ws_connect("/term/root/ws", protocols=("tty",), headers={"Origin": origin})
            assert e.value.status == 404
            main.TERMINALS = {"bash": free_port()}  # ttyd not running
            ws = await console(c)
            msg = await asyncio.wait_for(ws.receive(), 5)
            return msg.type

    assert run(body()) in (WSMsgType.CLOSE, WSMsgType.CLOSED)
