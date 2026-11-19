"""Hardening of the control plane after the v0.4.0 review: the idle timeout (#242), the agent's answers
(#243), the files the login page may load without a session (#245) and the smaller points of #246. Each
section starts with the reviewer's reproduction."""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import stat
import subprocess
import time
from pathlib import Path

import pytest

from .test_ctl_files import FilesWorld
from .test_ctl_main import CSRF, PW, World, console, load, run, started  # noqa: F401 (fixture)

pytest.importorskip("aiohttp")
import yarl

STATIC = Path(__file__).resolve().parents[2] / "control" / "app" / "static"
POLL = {"X-Tallygate-Poll": "1"}


def session(main):
    (s,) = main._sessions.values()
    return s


async def raw(client, request: bytes) -> tuple[int, bytes]:
    """One request, byte for byte (a client library would normalise the path and refuse odd headers)."""
    reader, writer = await asyncio.open_connection("127.0.0.1", client.server.port)
    writer.write(request)
    await writer.drain()
    data = await asyncio.wait_for(reader.read(200_000), 5)
    writer.close()
    return int(data.split(b" ", 2)[1]), data


def cookie(client) -> str:
    jar = client.session.cookie_jar.filter_cookies(yarl.URL(f"http://127.0.0.1:{client.server.port}/"))
    return jar["tallygate_session"].value


# ---------------------------------------------------------------- #242: the idle timeout
def test_background_polls_do_not_keep_an_idle_session_alive(load):  # noqa: F811
    """The reviewer's reproduction: a poll every few hundred ms kept the session alive for ever. With the
    header the page's own requests carry, the session ends SESSION_IDLE after the last real activity."""
    main = load(SESSION_IDLE="1")

    async def body():
        async with started(main, World()) as c:
            deadline = time.time() + 1.6
            statuses = []
            while time.time() < deadline:
                statuses.append((await c.get("/api/gw/info", headers=POLL)).status)
                await asyncio.sleep(0.2)
            assert statuses[0] == 200 and statuses[-1] == 401  # answered while the session lived, then not
            assert (await c.get("/api/meta")).status == 401  # and it is gone for good

    run(body())


def test_a_request_without_the_header_is_activity(load):  # noqa: F811
    main = load(SESSION_IDLE="1")

    async def body():
        async with started(main, World()) as c:
            for _ in range(8):  # 1.6 s of use: every request pushes the idle timeout back
                assert (await c.get("/api/gw/info")).status == 200
                await asyncio.sleep(0.2)

    run(body())


def test_what_counts_as_activity(load):  # noqa: F811
    main, world = load(), World()

    async def body():
        async with started(main, world) as c:
            s = session(main)

            async def touched(make) -> bool:
                s["seen"] = mark = time.time() - 60
                r = await make()
                if hasattr(r, "release"):
                    r.release()
                return s["seen"] != mark

            assert await touched(lambda: c.get("/api/meta"))
            assert await touched(lambda: c.get("/"))
            assert await touched(lambda: c.post("/api/gw/emergency-stop", headers=CSRF))
            assert await touched(lambda: c.get("/api/meta", headers={"X-Tallygate-Poll": "0"}))  # only "1" marks
            assert not await touched(lambda: c.get("/api/meta", headers=POLL))
            assert not await touched(lambda: c.get("/api/agent/status", headers=POLL))
            assert not await touched(lambda: c.post("/api/gw/emergency-stop", headers={**CSRF, **POLL}))
            assert not await touched(lambda: c.get("/api/stream"))  # the browser re-opens it by itself

            # the console: neither the (re)connect nor a frame counts; xterm also sends by itself, e.g.
            # answers to queries the agent prints, and the agent can drop the connection to force a reconnect
            s["seen"] = mark = time.time() - 60
            ws = await console(c)
            await ws.send_str(json.dumps({"columns": 80, "rows": 24}))
            await ws.send_bytes(b"0ls\n")
            for _ in range(50):
                if len(world.ttyd_got) >= 2:
                    break
                await asyncio.sleep(0.02)
            assert world.ttyd_got[-1] == b"0ls\n" and s["seen"] == mark
            await ws.close()

    run(body())


def test_a_poll_still_needs_a_session_and_the_csrf_header(load):  # noqa: F811
    """The header only says "do not count this": it authenticates nothing and exempts from nothing."""
    main, world = load(), World()

    async def body():
        async with started(main, world, login=False) as c:
            assert (await c.get("/api/meta", headers=POLL)).status == 401
            r = await c.post("/login", data={"password": PW})
            assert r.status == 200
            assert (await c.post("/api/gw/emergency-stop", headers=POLL)).status == 403  # no X-Tallygate
            evil = {**CSRF, **POLL, "Origin": "https://evil.example"}
            assert (await c.post("/api/gw/emergency-stop", headers=evil)).status == 403

    run(body())
    assert world.seen == []


def test_the_pages_own_requests_carry_the_header():
    app, term = (STATIC / "app.js").read_text(), (STATIC / "term.js").read_text()
    assert 'headers["X-Tallygate-Poll"] = "1"' in app and "if (userActive()) lastCounted = Date.now(); else" in app
    assert "e.isTrusted" in app and "e.isTrusted" in term
    assert 'fetch("/api/meta", { credentials: "same-origin", headers: { "X-Tallygate-Poll": "1" } })' in term
    # every request of the main page goes through api(): no fetch() beside it could forget the header
    for name in ("connectivity.js", "overview.js", "availability.js", "learning.js", "update.js", "wizard.js"):
        assert "fetch(" not in (STATIC / name).read_text(), name


NODE = shutil.which("node")
API_HARNESS = r"""
const fs = require("fs");
let now = 1e6; Date.now = () => now;
const listeners = {}, sent = [];
globalThis.window = { addEventListener: (t, f) => { listeners[t] = f; } };
globalThis.document = { querySelector: () => null, querySelectorAll: () => [], addEventListener() {} };
globalThis.location = { href: "" };
globalThis.fetch = async (path, o) => { sent.push([path, o.headers["X-Tallygate-Poll"] || ""]);
  return { status: 200, ok: true, json: async () => ({}) }; };
const src = fs.readFileSync(process.argv[2], "utf8");
const head = src.slice(0, src.indexOf("const gw = "));
(async () => {
  const api = new Function(head + "; return api;")();
  await api("GET", "/api/gw/info");                       // a timer fires, nobody at the keyboard
  listeners.keydown({ isTrusted: false });                 // a synthetic event is not the user
  await api("GET", "/api/gw/info");
  listeners.pointerdown({ isTrusted: true });              // a click: one ping, and requests count
  await new Promise((r) => setTimeout(r, 5));
  await api("POST", "/api/gw/policy", {});
  listeners.keydown({ isTrusted: true });                  // active again within a minute: no second ping
  now += 11000;                                            // 11 s later the 30 s timer fires
  await api("GET", "/api/gw/info");
  now += 60000; listeners.wheel({ isTrusted: true });      // reading and scrolling a minute later: a ping
  await new Promise((r) => setTimeout(r, 5));
  console.log(JSON.stringify(sent));
})();
"""


@pytest.mark.skipif(NODE is None, reason="needs node to run the UI's request helper")
def test_api_marks_requests_made_without_user_input(tmp_path):
    harness = tmp_path / "harness.js"
    harness.write_text(API_HARNESS)
    out = subprocess.run([NODE, str(harness), str(STATIC / "app.js")], capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, out.stderr
    assert json.loads(out.stdout) == [
        ["/api/gw/info", "1"],
        ["/api/gw/info", "1"],
        ["/api/meta", ""],
        ["/api/gw/policy", ""],
        ["/api/gw/info", "1"],
        ["/api/meta", ""],
    ]


# ---------------------------------------------------------------- #243: the agent's answers
def test_deeply_nested_json_from_the_agent_is_a_502_not_a_500(load, caplog):  # noqa: F811
    """The reviewer's reproduction: RecursionError in json.loads was caught by nobody."""
    main, world = load(), World()
    world.agent["status"] = (200, b"[" * 200_000 + b"]" * 200_000)
    world.agent["selftest"] = (200, b'{"results":' + b"[" * 200_000 + b"]" * 200_000 + b"}")

    async def body():
        async with started(main, world) as c:
            for what in ("status", "selftest"):
                r = await c.get(f"/api/agent/{what}")
                assert r.status == 502
                assert await r.json() == {"error": "agent unreachable or invalid response: nested too deeply"}
            r = await c.get("/api/version")
            assert r.status == 200 and (await r.json())["claude_code"] is None

    run(body())
    assert "Traceback" not in caplog.text


def test_the_agents_status_reaches_the_ui_in_the_fixed_schema(load):  # noqa: F811
    main, world = load(), World()
    hostile = {
        "claude_version": 1,  # .replace() on it stopped the Setup tab before the notification settings
        "claude_logged_in": "yes",
        "git_name": "n" * 5000,
        "remote_control_prompt": ["x"],
        "workspace_disk": {"total": "a lot", "used": 1, "free": 2},
        "home_disk": None,
        "surprise": {"deep": [1, 2, 3]},
        "time": 1.5,
    }
    world.agent["status"] = (200, json.dumps(hostile).encode())
    world.agent["setup/claude-login"] = (
        200,
        json.dumps({"state": "waiting_code", "url": "https://evil.example/oauth/authorize", "x": 1}).encode(),
    )
    world.agent["setup/git-identity"] = (409, json.dumps({"error": 5, "detail": "x"}).encode())

    async def body():
        async with started(main, world) as c:
            r = await c.get("/api/agent/status")
            assert r.status == 200 and await r.json() == {
                "git_name": "n" * 200,
                "workspace_disk": {"used": 1, "free": 2},
                "home_disk": None,
                "time": 1.5,
            }
            r = await c.get("/api/agent/setup/claude-login")
            assert await r.json() == {"state": "waiting_code", "url": ""}  # and the link filter still applies
            r = await c.post("/api/agent/setup/git-identity", json={}, headers=CSRF)
            assert r.status == 409 and await r.json() == {}  # the agent's refusal, without its odd fields

    run(body())


def test_the_ui_does_not_call_string_methods_on_agent_values():
    wizard, overview = (STATIC / "wizard.js").read_text(), (STATIC / "overview.js").read_text()
    assert "claude_version.replace(" not in wizard and "String(st.v.claude_version).replace(" in wizard
    assert "token_expires.replace(" not in overview and "String(ov.gh.token_expires).replace(" in overview
    assert "Array.isArray(r.results)" in wizard


# ---------------------------------------------------------------- #245: files served without a session
@pytest.mark.parametrize(
    "path",
    [
        "/static/login/../index.html",
        "/static/login/../app.js",
        "/static/login%2f..%2fwizard.js",
        "/static/login%2F..%2Fapp.js",
        "/static/loginx",
        "/static/login",
        "/static/login.js.map",
        "/static/login.html/../app.js",
        "/static/app.js",
        "/static/index.html",
    ],
)
def test_only_the_login_pages_own_files_are_served_without_a_session(load, path):  # noqa: F811
    main = load()

    async def body():
        async with started(main, login=False) as c:
            status, data = await raw(c, f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n".encode())
            assert status == 302 and b"Location: /login" in data and b"use strict" not in data
            for ok in ("/static/login.html", "/static/login.js", "/static/logo.svg", "/static/favicon.svg", "/login"):
                status, _ = await raw(c, f"GET {ok} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n".encode())
                assert status == 200, ok

    run(body())


def test_the_login_page_loads_nothing_but_its_exempt_files(load):  # noqa: F811
    main = load()
    import re

    html = (STATIC / "login.html").read_text()
    wanted = set(re.findall(r'(?:src|href)="(/[^"#?]+)', html))
    assert wanted and wanted <= main.LOGIN_FILES | set(main.PUBLIC_FILES), wanted - main.LOGIN_FILES


# ---------------------------------------------------------------- #246: the smaller points
def test_a_non_ascii_session_cookie_is_a_401_not_a_500(load, caplog):  # noqa: F811
    main = load()

    async def body():
        async with started(main, login=False) as c:
            for value in ("a.é".encode(), "é.a".encode(), b"a.\xff\xfe", b"a." + "ü".encode("latin-1")):
                head = b"GET /api/meta HTTP/1.1\r\nHost: 127.0.0.1\r\nCookie: tallygate_session=" + value
                status, data = await raw(c, head + b"\r\nConnection: close\r\n\r\n")
                assert status == 401 and b"login required" in data
                head = b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nCookie: tallygate_session=" + value
                assert (await raw(c, head + b"\r\nConnection: close\r\n\r\n"))[0] == 302

    run(body())
    assert "Traceback" not in caplog.text and "TypeError" not in caplog.text


def test_a_valid_cookie_still_works_and_a_wrong_signature_does_not(load):  # noqa: F811
    main = load()

    async def body():
        async with started(main) as c:
            good = cookie(c)

            async def meta(value: str) -> int:
                head = f"GET /api/meta HTTP/1.1\r\nHost: 127.0.0.1\r\nCookie: tallygate_session={value}\r\n"
                return (await raw(c, (head + "Connection: close\r\n\r\n").encode()))[0]

            assert await meta(good) == 200
            sid, sig = good.split(".")
            assert await meta(f"{sid}.{sig[:-1]}{'0' if sig[-1] != '0' else '1'}") == 401
            assert await meta(sid) == 401 and await meta(f".{sig}") == 401

    run(body())


def login_as(c, host: str, origin: str | None = None, pw: str = "wrong"):
    headers = {"Host": host, **({"Origin": origin} if origin else {})}
    return c.post("/login", data={"password": pw}, headers=headers, allow_redirects=False)


def test_allowed_hosts_refuses_every_other_host_name(load):  # noqa: F811
    """The reviewer's reproduction: a login POST whose Host and Origin are both the attacker's name (DNS
    rebinding) was processed. With ALLOWED_HOSTS it is refused before the password is looked at."""
    main = load(ALLOWED_HOSTS="tallygate.lan, Server.Local.")

    async def body():
        async with started(main, login=False) as c:
            r = await login_as(c, "evil.example:8080", "http://evil.example:8080")
            assert r.status == 421 and "ALLOWED_HOSTS" in await r.text()
            assert main._login_failures == {}  # no password check happened
            for path in ("/", "/login", "/api/meta", "/static/login.js", "/sw.js"):
                assert (await c.get(path, headers={"Host": "evil.example"}, allow_redirects=False)).status == 421
            # the names in the list (any port, any case), an address and localhost are served
            for host in (
                "tallygate.lan",
                "TALLYGATE.LAN:8080",
                "server.local:8443",
                "127.0.0.1:8080",
                "192.168.1.5",
                "[::1]:8080",
                "[fd00::5]",
                "localhost:8080",
            ):
                r = await login_as(c, host, f"http://{host}".lower())
                assert r.status == 302 and r.headers["Location"] == "/login?failed=1", host
            for host in (
                "tallygate.lan.evil.example",
                "evil-tallygate.lan",
                "localhost.evil.example",
                "127.0.0.1.evil.example",
            ):
                assert (await login_as(c, host)).status == 421, host
            r = await login_as(c, "tallygate.lan:8080", "http://tallygate.lan:8080", PW)
            assert r.status == 302 and r.headers["Location"] == "/"

    run(body())


def test_allowed_hosts_also_takes_public_url_and_a_trusted_forwarded_host(load):  # noqa: F811
    main = load(
        ALLOWED_HOSTS="other.example",
        PUBLIC_URL="https://tally.example.org",
        TRUST_FORWARDED_FOR="1",
        TRUSTED_PROXIES="127.0.0.1/32",
    )

    async def body():
        async with started(main, login=False) as c:
            assert (await c.get("/login", headers={"Host": "tally.example.org"})).status == 200
            assert (await c.get("/login", headers={"Host": "other.example"})).status == 200
            assert (await c.get("/login", headers={"Host": "evil.example"})).status == 421
            # behind the trusted proxy the browser's name is in X-Forwarded-Host, the Host may be internal
            fwd = {"Host": "control:8080", "X-Forwarded-Host": "tally.example.org"}
            assert (await c.get("/login", headers=fwd)).status == 200
            fwd = {"Host": "tally.example.org", "X-Forwarded-Host": "evil.example"}
            assert (await c.get("/login", headers=fwd)).status == 421

    run(body())


def test_without_allowed_hosts_every_host_is_served_and_setup_says_so(load):  # noqa: F811
    """The default stays as it was (a name like server.local must keep working without configuration);
    the Setup tab names the risk and the two settings."""
    main = load()

    async def checks(c, host):
        r = await c.get("/api/setup/checks", params={"origin": f"http://{host}"}, headers={"Host": host})
        return {x["id"]: x for x in (await r.json())["checks"]}

    async def body():
        async with started(main) as c:
            r = await login_as(c, "server.local:8080", "http://server.local:8080")
            assert r.status == 302  # processed, as before
            got = await checks(c, "server.local:8080")
            assert got["hosts"]["state"] == "warn" and "ALLOWED_HOSTS=server.local" in got["hosts"]["detail"]
            assert "DNS rebinding" in got["hosts"]["detail"] and "PUBLIC_URL" in got["hosts"]["detail"]
            for host in ("127.0.0.1:8080", "localhost:8080", "[::1]:8080", "192.168.1.5:8080"):
                assert "hosts" not in await checks(c, host), host  # an address cannot be re-pointed

    run(body())
    main = load(ALLOWED_HOSTS="server.local")

    async def listed():
        async with started(main) as c:
            got = await checks(c, "server.local:8080")
            assert got["hosts"]["state"] == "ok" and "server.local" in got["hosts"]["detail"]

    run(listed())
    main = load(PUBLIC_URL="http://server.local:8080", ALLOWED_HOSTS="")

    async def with_public_url():
        async with started(main, login=False) as c:
            # PUBLIC_URL alone already refuses the rebinding login: its Origin is not the public one
            assert (await login_as(c, "evil.example:8080", "http://evil.example:8080")).status == 403

    run(with_public_url())


@pytest.mark.parametrize(
    "site,status",
    [
        ("cross-site", 403),
        ("same-site", 403),
        ("CROSS-SITE", 403),
        ("bogus", 403),
        ("", 403),
        ("same-origin", 200),
        ("none", 200),
        ("Same-Origin", 200),
        (None, 200),
    ],
)
def test_a_download_starts_from_the_ui_only(load, site, status):  # noqa: F811
    main, world = load(), FilesWorld()

    async def body():
        async with started(main, world) as c:
            headers = {} if site is None else {"Sec-Fetch-Site": site, "Sec-Fetch-Mode": "navigate"}
            r = await c.get("/api/files/download", params={"path": "notes.txt"}, headers=headers)
            assert r.status == status
            if status == 403:
                assert await r.json() == {"error": "downloads start from the tallygate UI only"}
            else:
                assert await r.read() == b"file-bytes"

    run(body())
    assert bool(world.seen) == (status == 200)  # a refused download does not reach the agent


def test_secret_files_are_private_from_the_moment_they_exist(load, tmp_path, monkeypatch):  # noqa: F811
    """They were written with the default umask and tightened afterwards. Here the umask allows everything
    and the later chmod does nothing: the file must still never be readable by others."""
    import app.bootstrap as bootstrap

    old = os.umask(0)
    try:
        monkeypatch.setattr(os, "fchmod", lambda *_a: None)
        monkeypatch.setattr(Path, "chmod", lambda *_a, **_k: None)
        target = tmp_path / "data" / "session-secret"
        leftover = tmp_path / "data" / "session-secret.tmp"
        leftover.parent.mkdir()
        leftover.write_text("an earlier run died here")
        os.chmod(leftover, 0o666)  # noqa: S103 (the point of the test)
        bootstrap._write(target, "s3cret")
        assert target.read_text() == "s3cret" and stat.S_IMODE(target.stat().st_mode) == 0o600
        assert not leftover.exists()
    finally:
        os.umask(old)
    monkeypatch.undo()
    old = os.umask(0o077)
    try:  # the one file that is shared on purpose keeps its mode, whatever the umask
        bootstrap._write(tmp_path / "data" / "credential", "agent:x", 0o644)
        assert stat.S_IMODE((tmp_path / "data" / "credential").stat().st_mode) == 0o644
    finally:
        os.umask(old)


def test_stored_secrets_and_push_subscriptions_are_0600(load, tmp_path):  # noqa: F811
    old = os.umask(0)
    try:
        main = load(SESSION_SECRET="", CONTROL_PASSWORD="")

        async def body():
            async with started(main, login=False) as c:
                push = c.app["webpush"]
                push.subs.append({"id": "d", "endpoint": "https://fcm.googleapis.com/x", "p256dh": "k", "auth": "a"})
                push._save()

        run(body())
    finally:
        os.umask(old)
    data = tmp_path / "data"
    for name in ("session-secret", "password-hash", "vapid-private.pem", "push-subscriptions.json"):
        assert stat.S_IMODE((data / name).stat().st_mode) == 0o600, name
    assert not list(data.glob("*.tmp"))


@pytest.mark.parametrize("secret", ["s", "unit", "a" * 31])
def test_a_short_session_secret_stops_the_start(load, secret):  # noqa: F811
    main = load(SESSION_SECRET=secret)
    with pytest.raises(SystemExit, match="SESSION_SECRET must be at least 32 characters"):
        main.build_app()


def test_a_long_enough_or_no_session_secret_starts(load, tmp_path):  # noqa: F811
    main = load(SESSION_SECRET="a" * 32)
    main.build_app()
    assert main.SESSION_SECRET == b"a" * 32
    main = load(SESSION_SECRET="")  # unset: created in the data volume, 64 hex characters
    main.build_app()
    assert (
        len(main.SESSION_SECRET) == 64
        and (tmp_path / "data" / "session-secret").read_bytes().strip() == main.SESSION_SECRET
    )


@pytest.mark.parametrize(
    "env,secure",
    [
        ({"COOKIE_SECURE": "auto", "PUBLIC_URL": "https://tally.example.org"}, True),  # TLS proxy, headers not trusted
        ({"COOKIE_SECURE": "auto", "PUBLIC_URL": "HTTPS://tally.example.org"}, True),
        ({"COOKIE_SECURE": "auto", "PUBLIC_URL": "http://tally.example.org"}, False),
        ({"COOKIE_SECURE": "auto"}, False),
        ({"COOKIE_SECURE": "0", "PUBLIC_URL": "https://tally.example.org"}, False),  # an explicit choice wins
        ({"COOKIE_SECURE": "1"}, True),
    ],
)
def test_cookie_secure_auto_follows_public_url(load, env, secure):  # noqa: F811
    main = load(**env)

    async def body():
        async with started(main, login=False) as c:
            origin = main.PUBLIC_URL.lower() or f"http://127.0.0.1:{c.server.port}"
            r = await c.post("/login", data={"password": PW}, headers={"Origin": origin}, allow_redirects=False)
            assert r.status == 302 and r.headers["Location"] == "/"
            (set_cookie,) = r.headers.getall("Set-Cookie")
            assert ("Secure" in set_cookie) is secure and "HttpOnly" in set_cookie

    run(body())


def test_telegram_chat_id_must_be_numeric(load, monkeypatch, caplog):  # noqa: F811
    from app import notify, notifyconfig

    chat = next(f for f in notifyconfig.CHANNELS["telegram"] if f.name == "chat_id")
    for good in ("777", "-1001234567890"):
        assert notifyconfig.validate(chat, good) == good
    for bad in ("@channelname", "@my_channel", "channel", "-", "12a", ""):
        with pytest.raises(notifyconfig.ConfigError, match=r"numeric chat id .* not @channelname"):
            notifyconfig.validate(chat, bad)

    # from the environment: the channel is off and says why, instead of answering every button "Not authorised"
    for k, v in {"TELEGRAM_BOT_TOKEN": "123456:ABCDEFGHIJKLMNOP", "TELEGRAM_ALLOWED_USER_IDS": "42"}.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "@channelname")
    n = notify.Notifier({}, decide=None)
    status = {s["channel"]: s for s in n.status()}["telegram"]
    assert status["configured"] is False
    assert status["reason"] == "Off: the chat id must be numeric (e.g. -1001234567890), not a @name."
    assert "TELEGRAM_CHAT_ID must be the numeric chat id" in caplog.text
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "-1001234567890")
    assert {s["channel"]: s for s in notify.Notifier({}, decide=None).status()}["telegram"]["configured"] is True


def test_keyboard_shortcuts_ignore_a_held_key():
    keys = (STATIC / "keys.js").read_text()
    handler = keys[keys.index('document.addEventListener("keydown"') :]
    guard = handler[: handler.index("const t = e.target")]
    assert "e.repeat" in guard and "return;" in guard


SW_HARNESS = r"""
const fs = require("fs");
globalThis.self = { location: { origin: "https://tally.example.org" }, addEventListener() {} };
const src = fs.readFileSync(process.argv[2], "utf8");
const uiUrl = new Function(src + "; return uiUrl;")();
console.log(JSON.stringify(JSON.parse(process.argv[3]).map(uiUrl)));
"""
HOME = "https://tally.example.org/#approvals"
SW_CASES = [
    ("/#approvals", HOME),
    ("/#grants", "https://tally.example.org/#grants"),
    ("/?tab=log#x", "https://tally.example.org/?tab=log#x"),
    ("https://evil.example/", HOME),
    ("//evil.example/", HOME),
    ("/\\evil.example/", HOME),
    ("\\\\evil.example", HOME),
    ("javascript:alert(1)", HOME),
    ("data:text/html,x", HOME),
    ("https://tally.example.org.evil.example/", HOME),
    ("https://tally.example.org/#grants", HOME),  # only paths: the server never sends an absolute URL
    ("relative", HOME),
    ("", HOME),
    (None, HOME),
    (7, HOME),
    ({"href": "https://evil.example"}, HOME),
]


@pytest.mark.skipif(NODE is None, reason="needs node to run the service worker's function")
def test_a_notification_only_opens_a_path_of_this_ui(tmp_path):
    harness = tmp_path / "harness.js"
    harness.write_text(SW_HARNESS)
    cases = json.dumps([c for c, _ in SW_CASES])
    out = subprocess.run([NODE, str(harness), str(STATIC / "sw.js"), cases], capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, out.stderr
    assert json.loads(out.stdout) == [want for _, want in SW_CASES]


def test_the_service_worker_navigates_through_the_check_only():
    sw = (STATIC / "sw.js").read_text()
    assert "const url = uiUrl(note.data && note.data.url);" in sw
    assert sw.count("openWindow(") == 1 and sw.count(".navigate(") == 1 and "u.origin === self.location.origin" in sw
