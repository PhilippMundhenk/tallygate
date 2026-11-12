"""control/app/main.py: relay of the agent's setup actions and the deployment checks of the setup wizard (#75)."""

from __future__ import annotations

import json

import pytest

from .test_ctl_main import CSRF, World, run, started

pytest.importorskip("aiohttp")

URL = "https://claude.com/cai/oauth/authorize?code=true&state=x"


@pytest.mark.parametrize(
    ("url", "ok"),
    [
        (URL, True),
        ("https://claude.ai/oauth/authorize?x=1", True),
        ("https://platform.claude.com/oauth/authorize?x=1", True),
        ("http://claude.com/oauth/authorize?x=1", False),
        ("https://claude.com.evil.example/oauth/authorize?x=1", False),
        ("https://evil.example/oauth/authorize?x=1", False),
        ("https://claude.com:444/oauth/authorize?x=1", False),
        ("https://user:pw@claude.com/oauth/authorize?x=1", False),
        ("https://claude.com/other?x=1", False),
        ('https://claude.com/oauth/authorize?x="><script>', False),
        ("https://claude.com/oauth/authorize?" + "x" * 2100, False),
        (None, False),
        (["https://claude.com/oauth/authorize"], False),
    ],
)
def test_only_anthropic_login_pages_pass(main_mod, url, ok):
    assert main_mod.safe_login_url(url) == (url if ok else "")


@pytest.fixture
def main_mod(load_main):
    return load_main()


@pytest.fixture
def load_main(monkeypatch, tmp_path):
    import importlib
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "control"))
    from .test_ctl_main import CLEARED, ENV

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


def test_setup_actions_are_relayed_with_their_body_and_filtered(load_main):
    main = load_main()
    world = World()
    world.agent["setup/claude-login"] = (200, json.dumps({"state": "waiting_code", "url": URL}).encode())
    world.agent["setup/claude-code"] = (200, json.dumps({"state": "done", "url": "https://evil.example/x"}).encode())
    world.agent["setup/git-identity"] = (400, b'{"error": "the name must not be empty"}')
    world.agent["setup/remote-control"] = (500, b'{"error": "boom"}')

    async def body():
        async with started(main, world) as c:
            r = await c.post("/api/agent/setup/claude-login", headers=CSRF)
            assert r.status == 200 and (await r.json())["url"] == URL
            r = await c.post("/api/agent/setup/claude-code", json={"code": "abc-123456"}, headers=CSRF)
            assert (await r.json()) == {"state": "done", "url": ""}  # not Anthropic's: dropped
            r = await c.post("/api/agent/setup/git-identity", json={"name": ""}, headers=CSRF)
            assert r.status == 400 and (await r.json())["error"] == "the name must not be empty"
            r = await c.post("/api/agent/setup/remote-control", json={}, headers=CSRF)
            assert r.status == 502  # the agent's own failure
            r = await c.post(
                "/api/agent/setup/git-identity", data="[1]", headers={**CSRF, "Content-Type": "application/json"}
            )
            assert r.status == 400 and (await r.json())["error"] == "expected a JSON object"
            r = await c.post("/api/agent/setup/git-identity", data="x" * 5000, headers=CSRF)
            assert r.status == 413
            r = await c.post("/api/agent/status", headers=CSRF)
            assert r.status == 404  # GET only
            r = await c.get("/api/agent/setup/remote-control")
            assert r.status == 404  # POST only
            r = await c.post("/api/agent/setup/claude-login")
            assert r.status == 403  # CSRF header missing

    run(body())
    posts = [(m, p, b) for m, p, _, b in world.seen if p.startswith("/setup/")]
    assert posts[0] == ("POST", "/setup/claude-login", {})  # no body: an empty object
    assert posts[1] == ("POST", "/setup/claude-code", {"code": "abc-123456"})


@pytest.mark.parametrize(
    ("env", "state"),
    [
        ({"TRUST_PROXY_AUTH_HEADER": "Remote-User", "TRUSTED_PROXIES": "10.0.0.0/8"}, "proxy"),
        ({"CONTROL_PASSWORD_HASH": "scrypt:14:00:00"}, "env-hash"),
        ({}, "env-plain"),
    ],
)
def test_password_state(load_main, env, state):
    assert load_main(**env).password_state() == state


def test_password_state_generated_and_changed(load_main, monkeypatch, tmp_path):
    main = load_main()
    monkeypatch.delenv("CONTROL_PASSWORD")
    main.bootstrap.ensure_password()
    assert main.password_state() == "generated"
    main.bootstrap.GENERATED_MARK.unlink()
    assert main.password_state() == "changed"


async def checks(c, origin: str, **headers) -> dict:
    r = await c.get("/api/setup/checks", params={"origin": origin}, headers=headers)
    assert r.status == 200
    return {x["id"]: x for x in (await r.json())["checks"]}


def test_checks_plain_http_cookie_and_proxy(load_main):
    async def body():
        main = load_main(COOKIE_SECURE="auto")
        async with started(main, World()) as c:
            got = await checks(c, "http://127.0.0.1:8080")
            assert got["https"]["title"] == "Local connection" and got["cookie"]["state"] == "ok"
            assert got["proxy"]["state"] == "ok" and got["public_url"]["state"] == "info"
            got = await checks(c, "http://192.0.2.5:8080", **{"X-Forwarded-Proto": "https"})
            assert got["https"]["state"] == "warn" and got["proxy"]["state"] == "warn"
            assert "X-Forwarded-Proto" in got["proxy"]["detail"] and "192.0.2.5:8080" in got["reach"]["detail"]
            got = await checks(c, "not a url")
            assert got["https"]["state"] == "warn" and "same address" not in got["reach"]["detail"]

    run(body())


def test_checks_wrong_cookie_flag_both_ways(load_main):
    async def body(mode, origin, headers):
        # logged in by a (trusted) proxy header: a Secure cookie would not come back over plain HTTP
        main = load_main(
            COOKIE_SECURE=mode,
            TRUST_FORWARDED_FOR="1",
            TRUSTED_PROXIES="127.0.0.1/32",
            TRUST_PROXY_AUTH_HEADER="Remote-User",
        )
        async with started(main, World(), login=False) as c:
            return await checks(c, origin, **headers, **{"Remote-User": "admin"})

    got = run(body("0", "https://tally.example", {"X-Forwarded-Proto": "https"}))
    assert got["cookie"]["state"] == "bad" and "not marked Secure" in got["cookie"]["detail"]
    assert got["https"]["state"] == "ok" and got["proxy"]["state"] == "ok"
    got = run(body("1", "http://192.0.2.5:8080", {}))
    assert got["cookie"]["state"] == "bad" and "not kept over plain HTTP" in got["cookie"]["detail"]
    assert got["proxy"]["state"] == "warn" and "without forwarded headers" in got["proxy"]["detail"]
    got = run(body("1", "http://localhost:8080", {}))
    assert got["cookie"]["state"] == "ok"  # browsers keep Secure cookies on localhost


def test_checks_public_url(load_main):
    async def body():
        main = load_main(PUBLIC_URL="https://Tally.example/ui/")
        async with started(main, World()) as c:
            ok = await checks(c, "https://tally.example")
            bad = await checks(c, "http://192.0.2.5:8080")
            none = await checks(c, "")
            return ok, bad, none

    ok, bad, none = run(body())
    assert ok["public_url"]["state"] == "ok" and bad["public_url"]["state"] == "bad"
    assert "https://tally.example" in bad["public_url"]["detail"] and none["public_url"]["state"] == "ok"
