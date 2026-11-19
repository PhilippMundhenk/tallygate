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
    "SESSION_SECRET": "unit-session-secret-" * 2,
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
webpush_removed = "this device was removed from tallygate: open tallygate to decide"
webpush_restarted = "tallygate was restarted since this notification: open tallygate to decide"


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


def test_notify_test_routes_to_one_channel_and_reports_failures(load):
    main = load()

    async def body():
        async with started(main, World()) as c:
            n = c.app["notifier"]
            calls = []

            async def tg(method, **params):
                calls.append((method, params))

            n._tg, n.tg_token, n.tg_chat = tg, "t", "9"  # mark Telegram configured for describe()
            r = await c.post("/api/notify/test", json={"channel": "telegram"}, headers=CSRF)
            assert r.status == 200 and (await r.json())["channel"] == "telegram" and calls
            assert (await c.post("/api/notify/test", json={"channel": "ntfy"}, headers=CSRF)).status == 400  # off
            assert (await c.post("/api/notify/test", json={"channel": "bogus"}, headers=CSRF)).status == 400
            assert (await c.post("/api/notify/test", json={}, headers=CSRF)).status == 400  # no channel

            async def boom(method, **params):
                raise RuntimeError("telegram sendMessage: upstream is down")

            n._tg = boom
            r = await c.post("/api/notify/test", json={"channel": "telegram"}, headers=CSRF)
            assert r.status == 502 and "down" in (await r.json())["error"]

    run(body())


def test_meta_carries_per_channel_notification_status(load):
    main = load()

    async def body():
        async with started(main, World()) as c:
            meta = await (await c.get("/api/meta")).json()
            assert "notify" in meta and isinstance(meta["notify_status"], list)
            assert {c["channel"] for c in meta["notify_status"]} == {
                "telegram",
                "matrix",
                "ntfy",
                "gotify",
                "pushover",
                "webpush",
            }

    run(body())


# ---------------------------------------------------------------- notification channels in the UI (#201)
TG_TOKEN = "123456:" + "S" * 30
NOTIFY_ENV = (
    "TELEGRAM_CHAT_ID",
    "TELEGRAM_ALLOWED_USER_IDS",
    "MATRIX_ACCESS_TOKEN",
    "MATRIX_ROOM_ID",
    "MATRIX_ALLOWED_USERS",
    "NTFY_URL",
    "NTFY_TOKEN",
    "GOTIFY_URL",
    "GOTIFY_TOKEN",
    "PUSHOVER_TOKEN",
    "PUSHOVER_USER",
)


@pytest.fixture
def notify_env(monkeypatch):
    for k in NOTIFY_ENV:
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("TELEGRAM_API_BASE", "http://127.0.0.1:1")  # never the real Telegram


def idle_polls(n):
    """Replace the chat poll loops by ones that only wait, and count how many run at a time."""
    n.running = {"telegram": 0, "matrix": 0}

    def loop(channel):
        async def poll():
            n.running[channel] += 1
            try:
                await asyncio.Event().wait()
            finally:
                n.running[channel] -= 1

        return poll

    n._tg_poll, n._mx_sync = loop("telegram"), loop("matrix")


def test_notify_config_needs_a_session_and_the_csrf_header(load, notify_env):
    main = load()

    async def body():
        async with started(main, World(), login=False) as c:
            assert (await c.get("/api/notify/config")).status == 401
            assert (await c.put("/api/notify/config/ntfy", json={"url": "http://n/t"}, headers=CSRF)).status == 401
            assert (await c.delete("/api/notify/config/ntfy", headers=CSRF)).status == 401
        async with started(main, World()) as c:
            assert (await c.put("/api/notify/config/ntfy", json={"url": "http://n/t"})).status == 403
            assert (await c.delete("/api/notify/config/ntfy")).status == 403
            cross = {**CSRF, "Origin": "http://evil.example"}
            assert (await c.put("/api/notify/config/ntfy", json={"url": "http://n/t"}, headers=cross)).status == 403
            assert c.app["notifycfg"].overrides == {} and c.app["notifier"].ntfy_url == ""

    run(body())


def test_notify_config_is_saved_applied_live_and_never_returns_secrets(load, notify_env, tmp_path, caplog):
    main = load()
    full = {"bot_token": TG_TOKEN, "chat_id": "555", "allowed_user_ids": "4242"}

    async def body():
        async with started(main, World()) as c:
            n = c.app["notifier"]
            idle_polls(n)
            data = await (await c.get("/api/notify/config")).json()
            assert data["writable"] is True
            assert [x["channel"] for x in data["channels"]] == ["telegram", "matrix", "ntfy", "gotify", "pushover"]
            tg = data["channels"][0]
            assert (tg["label"], tg["active"], tg["source"], tg["override"]) == ("Telegram", False, "unset", False)
            assert "Use Configure" in tg["reason"] and tg["interactive"] is True

            with caplog.at_level(logging.INFO, logger="control"):
                r = await c.put("/api/notify/config/telegram", json=full, headers=CSRF)
            data = await r.json()
            assert r.status == 200 and data["changed"] == ["bot_token", "chat_id", "allowed_user_ids"]
            tg = data["channels"][0]
            assert tg["active"] is True and tg["source"] == "ui" and tg["reason"] == "Configured in the web UI."
            token = next(f for f in tg["fields"] if f["name"] == "bot_token")
            assert token["set"] is True and token["source"] == "ui" and "value" not in token
            assert next(f for f in tg["fields"] if f["name"] == "chat_id")["value"] == "555"
            for text in (json.dumps(data), await (await c.get("/api/notify/config")).text(), caplog.text):
                assert TG_TOKEN not in text
            assert "telegram saved by admin (changed: bot_token, chat_id, allowed_user_ids" in caplog.text
            assert "555" not in caplog.text and "4242" not in caplog.text  # who and what, never the values

            # applied without a restart: the notifier has the values and exactly one poll loop
            await asyncio.sleep(0)
            assert (n.tg_token, n.tg_chat, n.tg_users) == (TG_TOKEN, "555", {"4242"})
            first = n.polls["telegram"]
            assert n.running == {"telegram": 1, "matrix": 0}
            meta = await (await c.get("/api/meta")).json()
            assert meta["notify"]["telegram"] is True and meta["notify_status"][0]["source"] == "ui"
            saved = json.loads((tmp_path / "data" / "notify.json").read_text())
            assert saved["channels"]["telegram"]["bot_token"] == TG_TOKEN
            assert (tmp_path / "data" / "notify.json").stat().st_mode & 0o777 == 0o600

            # an empty secret keeps the stored one; the changed chat restarts the loop, once
            r = await c.put("/api/notify/config/telegram", json={"bot_token": "", "chat_id": "556"}, headers=CSRF)
            assert r.status == 200 and (await r.json())["changed"] == ["chat_id"]
            await asyncio.sleep(0)
            assert n.tg_token == TG_TOKEN and n.tg_chat == "556"
            assert first.cancelled() and n.polls["telegram"] is not first and n.running["telegram"] == 1

            # a channel without a poll loop leaves the Telegram loop alone
            second = n.polls["telegram"]
            r = await c.put("/api/notify/config/ntfy", json={"url": "http://ntfy.test/topic"}, headers=CSRF)
            assert r.status == 200 and n.ntfy_url == "http://ntfy.test/topic" and n.polls["telegram"] is second

            # removing the override: nothing in the environment, so the channel and its loop stop
            with caplog.at_level(logging.INFO, logger="control"):
                r = await c.delete("/api/notify/config/telegram", headers=CSRF)
            data = await r.json()
            assert r.status == 200 and data["removed"] is True and data["channels"][0]["active"] is False
            assert n.polls == {} and n.running["telegram"] == 0 and second.cancelled()
            assert "UI override of telegram removed by admin" in caplog.text
            r = await c.delete("/api/notify/config/telegram", headers=CSRF)
            assert r.status == 200 and (await r.json())["removed"] is False  # nothing left to remove

    run(body())


def test_notify_config_removal_falls_back_to_the_environment(load, notify_env, monkeypatch):
    monkeypatch.setenv("NTFY_URL", "http://env.test/topic")
    main = load()

    async def body():
        async with started(main, World()) as c:
            n = c.app["notifier"]
            r = await c.put("/api/notify/config/ntfy", json={"url": "http://ui.test/topic"}, headers=CSRF)
            ntfy = (await r.json())["channels"][2]
            assert n.ntfy_url == "http://ui.test/topic" and ntfy["source"] == "ui" and ntfy["active"] is True
            ntfy = (await (await c.delete("/api/notify/config/ntfy", headers=CSRF)).json())["channels"][2]
            assert n.ntfy_url == "http://env.test/topic" and ntfy["source"] == "environment"

    run(body())


def test_notify_config_refuses_bad_input_and_interactive_channels_without_allowed_users(load, notify_env):
    main = load()

    async def body():
        async with started(main, World()) as c:
            n = c.app["notifier"]
            idle_polls(n)

            async def put(channel, **kw):
                r = await c.put(f"/api/notify/config/{channel}", headers=CSRF, **kw)
                return r.status, (await r.json()).get("error", "")

            assert await put("bogus", json={}) == (400, "unknown channel")
            assert await put("webpush", json={}) == (400, "unknown channel")
            assert await put("ntfy", data="{not json") == (400, "invalid JSON body")
            assert await put("ntfy", json=["x"]) == (400, "expected a JSON object of field values")
            assert await put("ntfy") == (400, "expected a JSON object of field values")
            assert (await put("ntfy", json={"url": "file:///etc/passwd"}))[0] == 400
            assert (await put("ntfy", json={"url": 7}))[0] == 400
            status, error = await put("telegram", json={"bot_token": TG_TOKEN, "chat_id": "5"})
            assert status == 400 and "Allowed user ids are required" in error  # ADR-0010
            mx = {"homeserver": "http://hs.test", "access_token": "t", "room_id": "!r:hs.test"}
            status, error = await put("matrix", json=mx)
            assert status == 400 and "Allowed users are required" in error
            assert (await c.delete("/api/notify/config/bogus", headers=CSRF)).status == 400
            assert c.app["notifycfg"].overrides == {} and n.polls == {} and not any(n.describe().values())

    run(body())


def test_notify_config_on_an_unwritable_volume_is_environment_only(load, notify_env, monkeypatch):
    monkeypatch.setenv("GOTIFY_URL", "http://g.test")
    monkeypatch.setenv("GOTIFY_TOKEN", "env-app-token")
    main = load()

    async def body():
        async with started(main, World()) as c:
            c.app["notifycfg"].writable = False  # as when /data is a read-only mount
            data = await (await c.get("/api/notify/config")).json()
            gotify = data["channels"][3]
            assert data["writable"] is False and gotify["active"] is True and gotify["source"] == "environment"
            assert "env-app-token" not in json.dumps(data)
            r = await c.put("/api/notify/config/ntfy", json={"url": "http://n.test/t"}, headers=CSRF)
            assert r.status == 503 and "not writable" in (await r.json())["error"]
            status = {x["channel"]: x for x in (await (await c.get("/api/meta")).json())["notify_status"]}
            assert status["gotify"]["configurable"] is False and "environment" in status["ntfy"]["reason"]

            def boom(_channel):
                raise main.notifyconfig.ReadOnlyError("could not write the notification config (disk full)")

            c.app["notifycfg"].remove = boom
            r = await c.delete("/api/notify/config/gotify", headers=CSRF)
            assert r.status == 503 and "disk full" in (await r.json())["error"]

    run(body())


def test_mode_patch_and_emergency_stop_are_relayed_and_attributed(load):
    main = load()
    world = World()

    async def body():
        async with started(main, world) as c:
            assert (await c.patch("/api/gw/policy", json={"default": "deny"}, headers=CSRF)).status == 200
            r = await c.post("/api/gw/emergency-stop", json={"by": "spoofed", "skip": ["revoke"]}, headers=CSRF)
            assert r.status == 200
            assert (await c.post("/api/gw/emergency-stop", headers=CSRF)).status == 200  # no body
            assert (await c.patch("/api/gw/destinations/x", json={"note": "n"}, headers=CSRF)).status == 200  # relayed
            assert (await c.patch("/api/gw/rules/x", json={}, headers=CSRF)).status == 404  # old /rules CRUD is gone

    run(body())
    assert world.seen == [
        ("PATCH", "/gw/policy", {}, {"default": "deny"}),
        ("POST", "/gw/emergency-stop", {}, {"by": "web:admin"}),
        ("POST", "/gw/emergency-stop", {}, {"by": "web:admin"}),
        ("PATCH", "/gw/destinations/x", {}, {"note": "n"}),  # the one CRUD surface; not attributed
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
        ((200, b'{"git_name": "' + b"a" * 300_000 + b'"}'), 200, {"git_name": "a" * 200}),  # several reads; cut
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
    if isinstance(error, str):
        assert data["error"].startswith(error)
    else:
        assert data == (error or json.loads(reply[1]))


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


# ---------------------------------------------------------------- notification buttons (#212)
class Deciding(World):
    """A gateway that answers a decision with the rule it installed, like the real one."""

    def __init__(self) -> None:
        super().__init__()
        self.status = 200

    async def gw(self, request):
        body = await request.json() if request.can_read_body else None
        self.seen.append((request.method, request.path, dict(request.query), body))
        if self.status != 200:
            return web.json_response({"error": "no such pending request"}, status=self.status)
        if "/grant-requests/" in request.path:
            return web.json_response({"ok": True})
        allow = body["scope"] in ("once", "hour", "always", "domain")
        host = "*.example.com" if body["scope"] == "domain" else "api.example.com"
        return web.json_response({"rule": {"id": "r1", "action": "allow" if allow else "deny", "host": host}})


def test_notification_buttons_setting_needs_a_session_and_the_csrf_header(load, notify_env):
    main = load()

    async def body():
        async with started(main, login=False) as c:
            assert (await c.put("/api/notify/actions", json={"actions": ["always"]}, headers=CSRF)).status == 401
            assert (await c.delete("/api/notify/actions", headers=CSRF)).status == 401
        async with started(main) as c:
            assert (await c.put("/api/notify/actions", json={"actions": ["always"]})).status == 403
            assert (await c.delete("/api/notify/actions")).status == 403
            evil = {**CSRF, "Origin": "https://evil.example"}
            assert (await c.put("/api/notify/actions", json={"actions": ["always"]}, headers=evil)).status == 403
            assert c.app["notifycfg"].actions() == ("once", "deny")

    run(body())


def test_notification_buttons_are_saved_validated_and_reset(load, notify_env, tmp_path, caplog):
    main = load()

    async def body():
        async with started(main) as c:
            data = await (await c.get("/api/notify/config")).json()
            assert data["actions"]["value"] == ["once", "deny"] and data["actions"]["custom"] is False
            assert data["actions"]["max"] == 4 and len(data["actions"]["choices"]) == 6
            with caplog.at_level(logging.INFO, logger="control"):
                r = await c.put("/api/notify/actions", json={"actions": ["deny_always", "always"]}, headers=CSRF)
            data = await r.json()
            assert r.status == 200 and data["ok"] is True and "channels" in data
            assert data["actions"]["value"] == ["deny_always", "always"] and data["actions"]["custom"] is True
            assert "notification buttons: deny_always, always saved by admin" in caplog.text
            stored = json.loads((tmp_path / "data" / "notify.json").read_text())
            assert stored["ask_actions"] == ["deny_always", "always"]
            for bad in (
                {"actions": ["always", "bogus"]},
                {"actions": ["allow"]},
                {"actions": []},
                {"actions": ["once", "hour", "always", "domain", "deny"]},
                {"actions": ["deny", "deny"]},
                {"actions": "always"},
                {},
                ["always"],
            ):
                r = await c.put("/api/notify/actions", json=bad, headers=CSRF)
                assert r.status == 400 and (await r.json())["error"].startswith("actions: "), bad
            r = await c.put(
                "/api/notify/actions", data=b"{not json", headers={**CSRF, "Content-Type": "application/json"}
            )
            assert r.status == 400
            assert c.app["notifycfg"].actions() == ("deny_always", "always")  # a refused request changes nothing
            r = await c.delete("/api/notify/actions", headers=CSRF)
            data = await r.json()
            assert r.status == 200 and data["removed"] is True and data["actions"]["value"] == ["once", "deny"]
            assert (await (await c.delete("/api/notify/actions", headers=CSRF)).json())["removed"] is False
            c.app["notifycfg"].writable = False
            r = await c.put("/api/notify/actions", json={"actions": ["always"]}, headers=CSRF)
            assert r.status == 503 and "not writable" in (await r.json())["error"]
            c.app["notifycfg"].ask_actions = ["deny"]
            assert (await c.delete("/api/notify/actions", headers=CSRF)).status == 503

    run(body())


def test_a_notification_button_decides_exactly_what_its_token_says(load, notify_env):
    main = load()

    async def body():
        world = Deciding()
        async with started(main, world, login=False) as c:  # no session: like a phone after it expired
            push, cfg = c.app["webpush"], c.app["notifycfg"]
            push.subs.append({"id": "dev1", "label": "phone", "endpoint": "https://fcm.googleapis.com/x"})
            exp = time.time() + 60

            origin = {**CSRF, "Origin": f"http://127.0.0.1:{c.server.port}"}  # as the service worker sends it

            async def act(token, **extra):
                r = await c.post("/api/push/act", json={"token": token, **extra}, headers=origin)
                return r.status, await r.json()

            # a Deny token with everything a client could add to ask for more: it still only denies
            deny = push.mint("ask", "abc123", "deny", "dev1", exp)
            status, data = await act(deny, scope="always", decision="always", action="always", d="always", ttl=99999)
            assert status == 200 and data == {
                "ok": True,
                "decision": "deny",
                "message": "Denied api.example.com for 2 min",
            }
            assert world.seen == [("POST", "/gw/pending/abc123/decide", {}, {"scope": "deny", "by": "push:phone"})]
            assert (await act(deny))[1] == {"error": "this action was already used"}

            # a permanent allow is refused while its button is not switched on, and the gateway is not asked
            always = push.mint("ask", "abc123", "always", "dev1", exp)
            domain = push.mint("ask", "abc123", "domain", "dev1", exp)
            status, data = await act(always)
            assert status == 403 and "switched off" in data["error"] and len(world.seen) == 1
            # no CSRF header, a foreign origin, or no Origin at all (#241): refused before the token is looked at
            for headers in ({}, {"Origin": origin["Origin"]}, {**CSRF, "Origin": "https://evil.example"}, CSRF):
                r = await c.post("/api/push/act", json={"token": always}, headers=headers)
                assert r.status == 403 and await r.json() == {"error": "csrf check failed"}
            r = await c.post("/api/push/act", json={"token": always}, headers={**CSRF, "Origin": "null"})
            assert r.status == 403

            cfg.set_actions(["always", "domain", "deny_always", "hour"])
            status, data = await act(always)
            assert status == 200 and data["message"] == "Allowed api.example.com permanently"
            assert world.seen[-1][3] == {"scope": "always", "by": "push:phone"}
            assert (await act(always))[0] == 403  # replay
            status, data = await act(domain)
            assert (status, data["decision"], data["message"]) == (200, "domain", "Allowed *.example.com permanently")
            hour = push.mint("ask", "abc123", "hour", "dev1", exp)
            assert (await act(hour))[1]["message"] == "Allowed api.example.com for 1 h"
            block = push.mint("ask", "abc123", "deny_always", "dev1", exp)
            assert (await act(block))[1]["message"] == "Denied api.example.com permanently"

            # switching a button off ends the buttons that were already sent
            late = push.mint("ask", "abc123", "always", "dev1", exp)
            cfg.set_actions(["deny"])
            assert (await act(late))[0] == 403
            cfg.reset_actions()
            once = push.mint("ask", "abc123", "once", "dev1", exp)
            assert (await act(once))[1]["message"] == "Allowed api.example.com for 2 min"

            # a signed token for a request id that is not one is refused, as before
            assert (await act(push.mint("ask", "../policy", "deny", "dev1", exp)))[0] == 403
            assert (await act("forged.token"))[1] == {"error": "invalid action"}
            assert (await act(None))[0] == 403 and (
                await c.post("/api/push/act", json=[1], headers=origin)
            ).status == 403

            # grants: their own decisions and texts
            status, data = await act(push.mint("grant", "ab12", "read", "dev1", exp))
            assert status == 200 and data["message"] == "Approved"
            assert world.seen[-1] == (
                "POST",
                "/gw/grant-requests/ab12/decide",
                {},
                {"decision": "read", "by": "push:phone"},
            )
            assert (await act(push.mint("grant", "ab12", "deny", "dev1", exp)))[1]["message"] == "Denied"

            # a removed device's buttons are dead at once (#241): the reviewer's reproduction, through the app
            push.subs.append({"id": "dev2", "label": "lost phone", "endpoint": "https://fcm.googleapis.com/y"})
            lost = [
                push.mint("ask", "abc123", "once", "dev2", exp),
                push.mint("grant", "abc124", "approve", "dev2", exp),
            ]
            seen = len(world.seen)
            assert push.remove("dev2")
            for token in lost:
                status, data = await act(token)
                assert status == 403 and data == {"error": webpush_removed}
            # ... and after a restart of control no button from before works, used or not
            push.subs.append({"id": "dev2", "label": "lost phone", "endpoint": "https://fcm.googleapis.com/y"})
            spent = push.mint("ask", "abc123", "deny", "dev1", exp)
            assert (await act(spent))[0] == 200
            seen += 1
            push.used.clear()
            push.boot = "0badc0de"  # what a new process would have: another boot id, no memory of used tokens
            for token in (spent, *lost):
                status, data = await act(token)
                assert status == 403 and data == {"error": webpush_restarted}
            assert len(world.seen) == seen  # the gateway was not asked once

            # the gateway no longer knows the request, or cannot be reached
            world.status = 404
            status, data = await act(push.mint("ask", "abc123", "deny", "dev1", exp))
            assert status == 409 and data["error"] == "already decided or expired"
            main.GW_URL = "http://127.0.0.1:1"
            assert (await act(push.mint("ask", "abc123", "deny", "dev1", exp)))[0] == 502

    run(body())


def test_done_text_survives_an_unexpected_gateway_answer(load):
    main = load()
    assert main._done_text("ask", "always", None) == "Allowed permanently"
    assert main._done_text("ask", "deny", {"rule": "x"}) == "Denied for 2 min"
    assert main._done_text("ask", "always", {"rule": {"cidr": "192.0.2.7/32"}}) == "Allowed 192.0.2.7/32 permanently"
    assert main._done_text("ask", "once", {"rule": {"host": "a\nb.example"}}) == "Allowed ab.example for 2 min"
