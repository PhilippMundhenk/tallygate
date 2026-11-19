"""Where a notification channel URL may point (#240). The URLs of Matrix, ntfy and Gotify are free text, and
control sends to them from its own place in the network, with a token the writer of the URL chooses. A UI
session (a stolen one too) must not be able to aim that at the stack itself or at this machine, to choose
the path on the server with a "?", or to read the answer through **Test**. Checked three times: when the
URL is saved, when the notifier loads it (environment, older notify.json), and for every address a
connection goes to, also one a name only resolves to."""

from __future__ import annotations

import json
import logging

import pytest

from .test_ctl_main import CSRF, World, load, run, started  # noqa: F401 (fixture)

pytest.importorskip("aiohttp")
import aiohttp
from aiohttp import test_utils, web

from app import notifyconfig

SECRET = "INTERNAL-ONLY-DATA: the database password is hunter2"
GUARD_ON = {"NOTIFY_TEST_ALLOW_LOCAL": ""}  # as in production: loopback and the stack's hosts are refused


class Internal:
    """A service only control can reach (the gateway API, the agent, cloud metadata, this machine)."""

    def __init__(self) -> None:
        self.seen: list[tuple[str, str, str | None]] = []
        self.srv: test_utils.TestServer | None = None

    async def start(self) -> str:
        a = web.Application()
        a.router.add_route("*", "/{tail:.*}", self.handle)
        self.srv = test_utils.TestServer(a)
        await self.srv.start_server()
        return f"http://127.0.0.1:{self.srv.port}"

    async def handle(self, request):
        self.seen.append((request.method, request.path_qs, request.headers.get("Authorization")))
        if request.path.startswith("/open"):
            return web.Response(status=204)
        if request.path.startswith("/_matrix") and request.method == "GET":
            return web.json_response({"user_id": "@bot:hs", "next_batch": "s1"})
        if request.path.startswith("/closed"):
            return web.Response(status=404, text=SECRET)
        return web.json_response({"error": SECRET, "errcode": "M_FORBIDDEN"}, status=403)


@pytest.fixture
def channel_env(monkeypatch):
    for k in ("MATRIX_ACCESS_TOKEN", "MATRIX_ROOM_ID", "MATRIX_ALLOWED_USERS", "NTFY_URL", "NTFY_TOKEN", "GOTIFY_URL"):
        monkeypatch.delenv(k, raising=False)
    for k in ("GOTIFY_TOKEN", "GW_INTERNAL_NETS", "GW_URL", "AGENT_HOST", "CONTROL_BIND_HOST"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("TELEGRAM_API_BASE", "http://127.0.0.1:1")


MATRIX = {"access_token": "attacker-chosen-bearer", "room_id": "!r:x", "allowed_users": "@a:x"}


# ---------------------------------------------------------------- the reviewer's reproduction
def test_a_ui_session_cannot_aim_a_channel_at_the_stack_or_this_machine(load, channel_env):  # noqa: F811
    main, internal = load(**GUARD_ON), Internal()

    async def body():
        base = await internal.start()
        try:
            async with started(main, World()) as c:
                # "?" would cut off the fixed /_matrix/... suffix: the writer of the URL would choose the path
                r = await c.put(
                    "/api/notify/config/matrix",
                    headers=CSRF,
                    json={"homeserver": base + "/secret/latest/meta-data?x=", **MATRIX},
                )
                assert r.status == 400 and "?query" in (await r.json())["error"]
                r = await c.put("/api/notify/config/matrix", headers=CSRF, json={"homeserver": base, **MATRIX})
                assert r.status == 400 and "this machine" in (await r.json())["error"]
                for url in (
                    "http://169.254.169.254/latest/meta-data/",
                    "http://egress-gw:8081/policy",
                    "http://agent:7680/files",
                    "http://localhost:8080/",
                    "http://[::1]/",
                    base + "/open/x",
                ):
                    for channel, extra in (("gotify", {"token": "t"}), ("ntfy", {})):
                        r = await c.put(f"/api/notify/config/{channel}", headers=CSRF, json={"url": url, **extra})
                        assert r.status == 400, url
                        r = await c.post("/api/notify/test", headers=CSRF, json={"channel": channel})
                        assert r.status == 400 and (await r.json())["error"] == "channel not configured"
        finally:
            await internal.srv.close()

    run(body())
    assert internal.seen == []


def test_the_test_button_never_repeats_what_the_other_side_said(load, channel_env, caplog):  # noqa: F811
    """With the test switch the fake service on loopback is a permitted destination, like a server on the LAN
    is in production: the answer of the service still does not reach the browser."""
    main, internal = load(), Internal()

    async def body():
        base = await internal.start()
        try:
            async with started(main, World()) as c:

                async def test(channel):
                    r = await c.post("/api/notify/test", headers=CSRF, json={"channel": channel})
                    return r.status, await r.json()

                r = await c.put("/api/notify/config/matrix", headers=CSRF, json={"homeserver": base, **MATRIX})
                assert r.status == 200
                assert await test("matrix") == (
                    502,
                    {"error": "Matrix answered with an error (HTTP 4xx): see the control log"},
                )
                assert (
                    await c.put("/api/notify/config/ntfy", headers=CSRF, json={"url": base + "/open/t"})
                ).status == 200
                assert await test("ntfy") == (200, {"ok": True, "channel": "ntfy"})
                await c.put("/api/notify/config/ntfy", headers=CSRF, json={"url": base + "/closed"})
                assert await test("ntfy") == (
                    502,
                    {"error": "ntfy answered with an error (HTTP 4xx): see the control log"},
                )
                await c.put(
                    "/api/notify/config/gotify", headers=CSRF, json={"url": base + "/secret", "token": "tok-en"}
                )
                assert await test("gotify") == (
                    502,
                    {"error": "Gotify answered with an error (HTTP 4xx): see the control log"},
                )
                await c.put("/api/notify/config/ntfy", headers=CSRF, json={"url": "http://127.0.0.1:1/x"})
                assert await test("ntfy") == (502, {"error": "ntfy could not be reached: see the control log"})

                async def slow(*_a, **_k):
                    raise TimeoutError

                c.app["notifier"]._ntfy = slow
                assert await test("ntfy") == (502, {"error": "ntfy did not answer in time"})

                async def odd(*_a, **_k):
                    raise RuntimeError(SECRET)

                c.app["notifier"]._ntfy = odd
                assert await test("ntfy") == (502, {"error": "ntfy: failed, see the control log"})
        finally:
            await internal.srv.close()

    with caplog.at_level(logging.WARNING, logger="control"):
        run(body())
    # the operator still finds the detail, in the log; the Gotify token is not in it
    assert SECRET in caplog.text and "notification test through matrix failed" in caplog.text
    assert "gotify: HTTP 403" in caplog.text and "tok-en" not in caplog.text


# ---------------------------------------------------------------- at load: environment and older files
def test_a_refused_url_from_the_environment_or_an_older_file_switches_the_channel_off(
    load,  # noqa: F811
    channel_env,
    tmp_path,
    caplog,
):
    (tmp_path / "data").mkdir()
    stored = {"channels": {"matrix": {"homeserver": "https://matrix.example.org/x?y=", **MATRIX}}}
    (tmp_path / "data" / "notify.json").write_text(json.dumps(stored))
    with caplog.at_level(logging.ERROR, logger="notify"):
        main = load(**GUARD_ON, NTFY_URL="http://127.0.0.1:9/topic", GOTIFY_URL="http://agent:7680", GOTIFY_TOKEN="t")

        async def body():
            async with started(main, World()) as c:
                status = {s["channel"]: s for s in c.app["notifier"].status()}
                assert not any(status[ch]["configured"] for ch in ("matrix", "ntfy", "gotify"))
                assert status["matrix"]["reason"] == "Off: the URL must not contain a ?query or #fragment."
                assert status["ntfy"]["reason"] == f"Off: the URL {notifyconfig.LOCAL_REASON}."
                assert status["gotify"]["reason"] == f"Off: the URL {notifyconfig.STACK_REASON}."
                r = await c.post("/api/notify/test", headers=CSRF, json={"channel": "ntfy"})
                assert r.status == 400
                assert "matrix" not in c.app["notifier"].polls  # and no sync loop polls the refused URL

        run(body())
    assert caplog.text.count("channel off") == 3


def test_lan_and_public_servers_stay_allowed(load, channel_env):  # noqa: F811
    """Self-hosted ntfy, Gotify or Matrix on the local network is a supported setup."""
    main = load(**GUARD_ON, NTFY_URL="http://192.168.1.20:8090/tallygate", GOTIFY_URL="https://gotify.example.org/g")

    async def body():
        async with started(main, World()) as c:
            n = c.app["notifier"]
            assert n.ntfy_url == "http://192.168.1.20:8090/tallygate" and n.gotify_url == "https://gotify.example.org/g"
            for url in (
                "http://10.0.0.5/ntfy/t",
                "http://ntfy.lan/t",
                "https://ntfy.example.org/t",
                "http://[fd00::5]:8080/t",
            ):
                r = await c.put("/api/notify/config/ntfy", headers=CSRF, json={"url": url})
                assert r.status == 200, url

    run(body())


# ---------------------------------------------------------------- at connect: what a name resolves to
class Names:
    """Stands in for DNS: every name resolves to the given addresses."""

    def __init__(self, *addresses: str) -> None:
        self.addresses = addresses
        self.asked: list[str] = []

    async def resolve(self, host, port=0, family=0):
        self.asked.append(host)
        return [
            {"hostname": host, "host": a, "port": port, "family": 10 if ":" in a else 2, "proto": 0, "flags": 0}
            for a in self.addresses
        ]

    async def close(self):
        pass


@pytest.mark.parametrize(
    "addresses",
    [
        ("127.0.0.1",),
        ("203.0.113.7", "127.0.0.1"),  # one good address does not excuse the other
        ("169.254.169.254",),
        ("::1",),
        ("::ffff:127.0.0.1",),
        ("fe80::1",),
        ("0.0.0.0",),
    ],
)
def test_a_name_that_resolves_to_a_refused_address_is_not_connected_to(load, channel_env, addresses):  # noqa: F811
    """DNS rebinding: the URL passes when it is saved, the name later points at this machine."""
    main, internal = load(**GUARD_ON), Internal()

    async def body():
        base = await internal.start()
        port = internal.srv.port
        try:
            async with started(main, World()) as c:
                names = Names(*addresses)
                c.app["notify_http"].connector._resolver._inner = names
                r = await c.put(
                    "/api/notify/config/ntfy", headers=CSRF, json={"url": f"http://ntfy.example.org:{port}/open/t"}
                )
                assert r.status == 200  # nothing wrong with the URL itself
                r = await c.post("/api/notify/test", headers=CSRF, json={"channel": "ntfy"})
                assert r.status == 502
                assert (await r.json())["error"].startswith("destination refused: the URL must not point at")
                assert names.asked == ["ntfy.example.org"]
                # an address literal in the URL of a request is refused before any connection, too
                with pytest.raises(main.RefusedDestination):
                    await c.app["notify_http"].get(base + "/open/direct")
                with pytest.raises(main.RefusedDestination):
                    await c.app["notify_http"].get(f"http://localhost:{port}/open/direct")
        finally:
            await internal.srv.close()

    run(body())
    assert internal.seen == []


def test_the_connection_goes_to_the_address_that_was_checked(load, channel_env):  # noqa: F811
    """Working path, and the proof of the pinning: the request for a name arrives at the address the checked
    lookup returned (here the fake service, permitted by the test switch), with no second lookup."""
    main, internal = load(), Internal()

    async def body():
        await internal.start()
        port = internal.srv.port
        try:
            async with started(main, World()) as c:
                names = Names("127.0.0.1")
                c.app["notify_http"].connector._resolver._inner = names
                await c.put(
                    "/api/notify/config/ntfy", headers=CSRF, json={"url": f"http://ntfy.example.org:{port}/open/t"}
                )
                r = await c.post("/api/notify/test", headers=CSRF, json={"channel": "ntfy"})
                assert r.status == 200 and names.asked == ["ntfy.example.org"]
                names.addresses = ("169.254.169.254",)  # link-local stays refused even with the test switch
                url = f"http://other.example.org:{port}/open/t"
                await c.put("/api/notify/config/ntfy", headers=CSRF, json={"url": url})
                r = await c.post("/api/notify/test", headers=CSRF, json={"channel": "ntfy"})
                assert r.status == 502 and "destination refused" in (await r.json())["error"]
                assert names.asked == ["ntfy.example.org", "other.example.org"]
        finally:
            await internal.srv.close()

    run(body())
    assert [(m, p) for m, p, _ in internal.seen] == [("POST", "/open/t")]


def test_number_notations_of_loopback_are_never_connected_to(load, channel_env):  # noqa: F811
    """ "2130706433" and "0x7f.1" are no IP literals for the URL check, but a system resolver makes 127.0.0.1 of
    them. Whichever layer refuses them (the URL parser, the resolver check), nothing arrives."""
    main, internal = load(**GUARD_ON), Internal()

    async def body():
        await internal.start()
        try:
            async with started(main, World()) as c:
                for host in ("2130706433", "0x7f.1", "localhost."):
                    with pytest.raises((aiohttp.ClientError, OSError)):
                        await c.app["notify_http"].get(f"http://{host}:{internal.srv.port}/open/x")
        finally:
            await internal.srv.close()

    run(body())
    assert internal.seen == []


# ---------------------------------------------------------------- the rules themselves
STACK = {
    "GW_URL": "http://172.31.11.2:8081",
    "AGENT_HOST": "172.31.10.10",
    "CONTROL_BIND_HOST": "172.31.12.3",
    "GW_INTERNAL_NETS": "172.31.10.0/24, 172.31.11.0/24,172.31.12.0/24,fd31::/64,nonsense",
}


@pytest.mark.parametrize(
    "host,reason",
    [
        ("127.0.0.1", "local"),
        ("127.8.9.10", "local"),
        ("[::1]", "local"),
        ("::ffff:127.0.0.1", "local"),
        ("0.0.0.0", "local"),
        ("0.1.2.3", "local"),
        ("::", "local"),
        ("localhost", "local"),
        ("LOCALHOST.", "local"),
        ("a.localhost", "local"),
        ("169.254.169.254", "local"),
        ("169.254.0.1", "local"),
        ("fe80::1", "local"),
        ("224.0.0.1", "local"),
        ("", "local"),
        ("172.31.11.2", "stack"),  # the gateway API
        ("172.31.10.10", "stack"),  # the agent
        ("172.31.12.3", "stack"),  # control itself
        ("172.31.10.2", "stack"),  # another address of the stack: only known through GW_INTERNAL_NETS
        ("::ffff:172.31.11.2", "stack"),
        ("fd31::5", "stack"),
        ("192.168.1.20", None),
        ("10.0.0.5", None),
        ("172.31.13.5", None),  # not in the nets control was given
        ("fd00::5", None),
        ("203.0.113.7", None),
        ("ntfy.example.org", None),
        ("matrix.lan", None),
    ],
)
def test_which_hosts_a_channel_url_may_name(monkeypatch, caplog, host, reason):
    monkeypatch.delenv("NOTIFY_TEST_ALLOW_LOCAL", raising=False)
    for k, v in STACK.items():
        monkeypatch.setenv(k, v)
    expected = {"local": notifyconfig.LOCAL_REASON, "stack": notifyconfig.STACK_REASON, None: None}[reason]
    with caplog.at_level(logging.ERROR, logger="notify"):
        assert notifyconfig.blocked_host(host) == expected
        assert notifyconfig.blocked_address("172.31.10.9") == notifyconfig.STACK_REASON
    assert "'nonsense' is not a network (ignored)" in caplog.text  # a broken entry does not disable the others


def test_stack_names_and_the_defaults(monkeypatch):
    monkeypatch.delenv("NOTIFY_TEST_ALLOW_LOCAL", raising=False)
    for k in STACK:
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(notifyconfig.socket, "gethostname", lambda: "Control-1")
    for host in ("egress-gw", "EGRESS-GW.", "agent", "control-1"):  # the compose service names, and its own
        assert notifyconfig.blocked_host(host) == notifyconfig.STACK_REASON
    monkeypatch.setenv("GW_URL", "https://[fd31::2]:8081")
    monkeypatch.setenv("AGENT_HOST", "agent.internal")
    assert notifyconfig.blocked_host("[fd31::2]") == notifyconfig.STACK_REASON
    assert notifyconfig.blocked_host("agent.internal") == notifyconfig.STACK_REASON
    assert notifyconfig.blocked_host("egress-gw") is None  # no longer where the gateway is
    assert notifyconfig.blocked_address("not-an-address") == notifyconfig.LOCAL_REASON


def test_the_test_switch_opens_loopback_and_the_stack_hosts_only(monkeypatch):
    monkeypatch.setenv("NOTIFY_TEST_ALLOW_LOCAL", "1")
    for k, v in STACK.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setenv("GW_URL", "http://127.0.0.1:8081")
    monkeypatch.setenv("GW_INTERNAL_NETS", "172.31.10.0/24")
    for host in ("127.0.0.1", "localhost", "[::1]", "172.31.12.3"):
        assert notifyconfig.blocked_host(host) is None
    assert notifyconfig.blocked_host("169.254.169.254") == notifyconfig.LOCAL_REASON
    assert notifyconfig.blocked_host("fe80::1") == notifyconfig.LOCAL_REASON
    assert notifyconfig.blocked_host("172.31.10.10") == notifyconfig.STACK_REASON  # the nets are never opened
    monkeypatch.setenv("NOTIFY_TEST_ALLOW_LOCAL", "true")  # only "1" is the switch
    assert notifyconfig.blocked_host("127.0.0.1") == notifyconfig.LOCAL_REASON


@pytest.mark.parametrize(
    "url,problem",
    [
        ("https://ntfy.example.org/t", None),
        ("http://192.168.1.20:8090/t", None),
        ("https://ntfy.example.org/t?auth=x", "must not contain a ?query or #fragment"),
        ("https://ntfy.example.org/t?", "must not contain a ?query or #fragment"),
        ("https://ntfy.example.org/t#x", "must not contain a ?query or #fragment"),
        ("https://ntfy.example.org/t#", "must not contain a ?query or #fragment"),
        ("http://[::1/t", "is not a valid URL"),
        ("http://127.0.0.1/t", notifyconfig.LOCAL_REASON),
        ("http://user:pw@127.0.0.1/t", notifyconfig.LOCAL_REASON),  # userinfo does not hide the host
        ("http://ntfy.example.org@127.0.0.1/t", notifyconfig.LOCAL_REASON),
        ("no-url", notifyconfig.LOCAL_REASON),  # no host at all
    ],
)
def test_destination_problem(monkeypatch, url, problem):
    monkeypatch.delenv("NOTIFY_TEST_ALLOW_LOCAL", raising=False)
    assert notifyconfig.destination_problem(url) == problem


@pytest.mark.parametrize("channel,field", [("matrix", "homeserver"), ("gotify", "url"), ("ntfy", "url")])
@pytest.mark.parametrize(
    "url,what",
    [
        ("https://svc.example.org/base?x=", "?query"),
        ("https://svc.example.org/base?", "?query"),
        ("https://svc.example.org?x=1", "?query"),
        ("https://svc.example.org/base#", "#fragment"),
        ("http://127.0.0.1:8081/policy", "this machine"),
        ("http://[::1]:8081/", "this machine"),
        ("http://169.254.169.254/latest/meta-data", "link-local"),
        ("http://localhost/", "this machine"),
        ("http://egress-gw:8081/policy", "the tallygate stack itself"),
        ("http://agent:7680/files", "the tallygate stack itself"),
    ],
)
def test_validate_refuses_the_url_when_it_is_saved(monkeypatch, channel, field, url, what):
    monkeypatch.delenv("NOTIFY_TEST_ALLOW_LOCAL", raising=False)
    for k in STACK:
        monkeypatch.delenv(k, raising=False)
    spec = next(f for f in notifyconfig.CHANNELS[channel] if f.name == field)
    with pytest.raises(notifyconfig.ConfigError, match=what.replace("?", r"\?")):
        notifyconfig.validate(spec, url)
    assert notifyconfig.validate(spec, "http://192.168.1.20:8008/base") == "http://192.168.1.20:8008/base"
