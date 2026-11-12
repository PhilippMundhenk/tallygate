"""Versions and update notice (#81): control asks GitHub's releases API itself, caches it, can be switched off,
and only passes on what it checked."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from .test_ctl_main import World, run, started
from .test_ctl_setup import load_main  # noqa: F401 (fixture)

pytest.importorskip("aiohttp")
from aiohttp import web

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "gateway"))


class ReleaseWorld(World):
    def __init__(self, release=(200, {"tag_name": "v0.5.0", "published_at": "2026-12-01T10:00:00Z"})) -> None:
        super().__init__()
        self.release = release
        self.release_calls = 0
        self.info = {"version": "0.4.0"}

    def app(self) -> web.Application:
        a = web.Application()
        a.router.add_get("/gh/repos/PhilippMundhenk/tallygate/releases/latest", self.latest)
        a.router.add_get("/gw/info", self.gw_info)
        for r in super().app().router.routes():
            a.router.add_route(r.method, r.resource.canonical, r.handler)
        return a

    async def latest(self, request):
        self.release_calls += 1
        assert request.headers["User-Agent"] == "tallygate-update-check"
        status, body = self.release
        raw = body if isinstance(body, bytes) else json.dumps(body).encode()
        return web.Response(status=status, body=raw)

    async def gw_info(self, _request):
        return web.json_response(self.info)


def version(main, world) -> list[dict]:
    async def body():
        async with started(main, world) as c:
            out = []
            for _ in range(2):
                r = await c.get("/api/version")
                assert r.status == 200
                out.append(await r.json())
            return out

    return run(body())


def test_update_available_with_links_built_by_control(load_main):  # noqa: F811
    main = load_main()
    world = ReleaseWorld()
    world.agent["status"] = (200, b'{"claude_version": "2.1.304 (Claude Code)"}')
    first, second = version(main, world)
    assert first == {
        "tallygate": "0.4.0",
        "claude_code": "2.1.304",
        "changelog": "https://github.com/PhilippMundhenk/tallygate/blob/main/CHANGELOG.md",
        "upgrade": "docker compose pull && docker compose up -d",
        "check": "ok",
        "latest": {
            "version": "0.5.0",
            "url": "https://github.com/PhilippMundhenk/tallygate/releases/tag/v0.5.0",
            "published": "2026-12-01T10:00:00Z",
        },
        "update_available": True,
    }
    assert second == first and world.release_calls == 1  # cached


def test_up_to_date_and_unknown_running_version(load_main):  # noqa: F811
    main = load_main()
    world = ReleaseWorld((200, {"tag_name": "0.4.0", "published_at": "<script>"}))
    got = version(main, world)[0]
    assert got["update_available"] is False and got["latest"]["published"] == ""  # odd text dropped
    main = load_main()
    world = ReleaseWorld()
    world.info = {"version": "dev"}
    world.agent["status"] = (200, b'{"claude_version": "<b>x</b>"}')
    got = version(main, world)[0]
    assert got["tallygate"] is None and got["claude_code"] is None and got["update_available"] is None


@pytest.mark.parametrize(
    ("release", "error"),
    [
        ((403, {"message": "rate limited"}), "GitHub answered 403"),
        ((200, {"tag_name": "latest"}), "no release version"),
        ((200, ["v1.0.0"]), "no release version"),
        ((200, b"not json"), "update check failed"),
        ((200, b'{"tag_name": "v9.9.9", "x": "' + b"a" * 300_000 + b'"}'), "answer too large"),
    ],
)
def test_failed_check_is_reported_and_retried_later(load_main, release, error):  # noqa: F811
    main = load_main()
    world = ReleaseWorld(release)
    first, second = version(main, world)
    assert first["check"] == "error" and error in first["error"] and first["update_available"] is None
    assert second == first and world.release_calls == 1  # failures are cached too (30 min)


def test_cache_expires(load_main, monkeypatch):  # noqa: F811
    main = load_main()
    world = ReleaseWorld()
    monkeypatch.setattr(main, "UPDATE_TTL", -1)
    version(main, world)
    assert world.release_calls == 2


def test_switched_off_and_nothing_reachable(load_main):  # noqa: F811
    main = load_main(UPDATE_CHECK="0")
    world = ReleaseWorld()
    got = version(main, world)[0]
    assert got["check"] == "off" and got["latest"] is None and world.release_calls == 0
    main = load_main(UPDATE_CHECK="1")

    async def body():
        async with started(main, None, login=True) as c:  # no gateway, no agent, no GitHub
            main.GITHUB_API = main.GW_URL
            r = await c.get("/api/version")
            return await r.json()

    got = run(body())
    assert got["tallygate"] is None and got["claude_code"] is None and got["check"] == "error"


def test_gateway_reports_its_version(tmp_path, monkeypatch):
    from egressgw import api

    assert api.version() == (Path(__file__).resolve().parents[2] / "VERSION").read_text().strip()
    monkeypatch.setattr(api, "__file__", str(tmp_path / "pkg" / "api.py"))
    assert api.version() is None
    (tmp_path / "VERSION").write_text("1.2.3\n")
    assert api.version() == "1.2.3"
