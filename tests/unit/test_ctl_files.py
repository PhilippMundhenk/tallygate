"""control/app/main.py workspace files relay (#76): paths checked, agent answers untrusted and size-limited,
downloads as attachments that are never rendered on the UI origin, uploads limited and CSRF-protected."""

from __future__ import annotations

import json

import pytest

from .test_ctl_main import CSRF, World, run, started
from .test_ctl_setup import load_main  # noqa: F401 (fixture)

pytest.importorskip("aiohttp")
from aiohttp import web


class FilesWorld(World):
    def __init__(self) -> None:
        super().__init__()
        self.listing = (200, {"path": "", "entries": [], "truncated": False})
        self.download: tuple | None = (200, b"file-bytes")
        self.uploads: list = []
        self.upload_reply = (200, b'{"path": "x", "size": 3}')

    def app(self) -> web.Application:
        a = web.Application()
        a.router.add_get("/files", self.list)
        a.router.add_get("/files/download", self.get)
        a.router.add_put("/files", self.put)
        for r in super().app().router.routes():
            a.router.add_route(r.method, r.resource.canonical, r.handler)
        return a

    async def list(self, request):
        self.seen.append(("GET", "/files", dict(request.query), None))
        status, body = self.listing
        return web.Response(status=status, body=body if isinstance(body, bytes) else json.dumps(body).encode())

    async def get(self, request):
        self.seen.append(("GET", "/files/download", dict(request.query), None))
        kind, body = self.download
        if kind == "chunked":  # no Content-Length
            resp = web.StreamResponse()
            resp.enable_chunked_encoding()
            await resp.prepare(request)
            await resp.write(body)
            return resp
        if kind == "short":  # announces more than it sends, then hangs up
            resp = web.StreamResponse(headers={"Content-Length": "100000"})
            await resp.prepare(request)
            await resp.write(body)
            request.transport.close()
            return resp
        return web.Response(status=kind, body=body)

    async def put(self, request):
        self.uploads.append((dict(request.query), request.headers.get("Content-Length"), await request.read()))
        status, body = self.upload_reply
        return web.Response(status=status, body=body)


def go(main, world, fn):
    async def body():
        async with started(main, world) as c:
            return await fn(c)

    return run(body())


def test_listing_is_checked_and_sanitised(load_main):  # noqa: F811
    main = load_main(FILES_MAX_UPLOAD="1000", FILES_MAX_DOWNLOAD="2000")
    world = FilesWorld()
    good = {"name": "ok.txt", "type": "file", "size": 3, "mtime": 1.5}
    world.listing = (
        200,
        {
            "truncated": True,
            "entries": [
                good,
                {"name": "d", "type": "dir", "size": 0, "mtime": 2},
                "not a dict",
                {"name": "a/b", "type": "file", "size": 1, "mtime": 1},
                {"name": "..", "type": "dir", "size": 1, "mtime": 1},
                {"name": "", "type": "file", "size": 1, "mtime": 1},
                {"name": "x" * 256, "type": "file", "size": 1, "mtime": 1},
                {"name": "esc\x1b", "type": "file", "size": 1, "mtime": 1},
                {"name": "t", "type": "socket", "size": 1, "mtime": 1},
                {"name": "s", "type": "file", "size": -1, "mtime": 1},
                {"name": "b", "type": "file", "size": True, "mtime": 1},
                {"name": "m", "type": "file", "size": 1, "mtime": "now"},
                {"name": 5, "type": "file", "size": 1, "mtime": 1},
            ],
        },
    )

    async def fn(c):
        r = await c.get("/api/files", params={"path": "/sub//dir/"})
        assert r.status == 400  # absolute
        r = await c.get("/api/files", params={"path": "sub//dir/"})
        return await r.json()

    got = go(main, world, fn)
    assert got == {
        "path": "sub/dir",
        "entries": [good, {"name": "d", "type": "dir", "size": 0, "mtime": 2}],
        "truncated": True,
        "max_upload": 1000,
        "max_download": 2000,
    }
    assert world.seen[-1][2] == {"path": "sub/dir"}


@pytest.mark.parametrize("path", ["../x", "a/../b", "a/./b", "a\\b", "a\nb", "x" * 1025])
def test_paths_are_refused_before_the_agent_is_asked(load_main, path):  # noqa: F811
    main = load_main()
    world = FilesWorld()

    async def fn(c):
        out = []
        for method, url in (("GET", "/api/files"), ("GET", "/api/files/download"), ("PUT", "/api/files")):
            r = await c.request(method, url, params={"path": path}, data=b"x", headers=CSRF)
            out.append((r.status, (await r.json())["error"]))
        return out

    assert go(main, world, fn) == [(400, "invalid path")] * 3
    assert not [s for s in world.seen if s[1].startswith("/files")] and not world.uploads


@pytest.mark.parametrize(
    ("reply", "status", "error"),
    [
        ((404, {"error": "no such folder"}), 404, "no such folder"),
        ((403, {"error": "outside the workspace"}), 403, "outside the workspace"),
        ((500, {"error": "boom"}), 502, "boom"),
        ((200, b"[1]"), 502, "agent unreachable or invalid response"),
        ((200, {"entries": "nope"}), 200, None),
    ],
)
def test_listing_errors(load_main, reply, status, error):  # noqa: F811
    main = load_main()
    world = FilesWorld()
    world.listing = reply

    async def fn(c):
        r = await c.get("/api/files")
        return r.status, await r.json()

    got_status, data = go(main, world, fn)
    assert got_status == status
    if error:
        assert data["error"].startswith(error)
    else:
        assert data["entries"] == []


def test_download_is_an_attachment_never_rendered(load_main):  # noqa: F811
    main = load_main()
    world = FilesWorld()
    world.download = (200, b"<script>alert(1)</script>")

    async def fn(c):
        r = await c.get("/api/files/download", params={"path": "out/Bericht ü.html"})
        return r.status, dict(r.headers), await r.read()

    status, headers, body = go(main, world, fn)
    assert status == 200 and body == b"<script>alert(1)</script>"
    assert headers["Content-Type"] == "application/octet-stream"
    assert headers["Content-Disposition"] == (
        "attachment; filename=\"Bericht__.html\"; filename*=UTF-8''Bericht%20%C3%BC.html"
    )
    assert headers["Content-Security-Policy"] == "sandbox; default-src 'none'"
    assert headers["X-Content-Type-Options"] == "nosniff" and headers["Cache-Control"] == "no-store"
    assert world.seen[-1][2] == {"path": "out/Bericht ü.html"}


@pytest.mark.parametrize(
    ("download", "status", "error"),
    [
        ((404, b'{"error": "no such file"}'), 404, "no such file"),
        ((400, b"not json"), 400, "download failed"),
        ((500, b"[]"), 502, "download failed"),
        (("chunked", b"abc"), 502, "the agent sent no length"),
        ((200, b"x" * 50), 413, "file larger than FILES_MAX_DOWNLOAD (10 bytes)"),
    ],
)
def test_download_errors(load_main, download, status, error):  # noqa: F811
    main = load_main(FILES_MAX_DOWNLOAD="10")
    world = FilesWorld()
    world.download = download

    async def fn(c):
        r = await c.get("/api/files/download", params={"path": "f"})
        return r.status, await r.json()

    assert go(main, world, fn) == (status, {"error": error})


def test_download_needs_a_file_and_an_agent(load_main):  # noqa: F811
    main = load_main()

    async def fn(c):
        r = await c.get("/api/files/download", params={"path": ""})
        assert r.status == 400
        main.AGENT_STATUS_PORT = 1  # nothing listens
        r = await c.get("/api/files/download", params={"path": "f"})
        return r.status, (await r.json())["error"]

    status, error = go(main, FilesWorld(), fn)
    assert status == 502 and error.startswith("agent unreachable")


def test_download_broken_off_by_the_agent(load_main):  # noqa: F811
    main = load_main()
    world = FilesWorld()
    world.download = ("short", b"only a part")

    async def fn(c):
        r = await c.get("/api/files/download", params={"path": "f"})
        assert r.status == 200 and r.headers["Content-Length"] == "100000"
        with pytest.raises(Exception):
            await r.read()

    go(main, world, fn)


def test_upload_is_limited_csrf_checked_and_streamed(load_main):  # noqa: F811
    main = load_main(FILES_MAX_UPLOAD="10")
    world = FilesWorld()

    async def fn(c):
        out = {}
        r = await c.put("/api/files", params={"path": "a.txt"}, data=b"abc")
        out["no csrf"] = r.status
        r = await c.put("/api/files", params={"path": "a.txt"}, data=b"x" * 11, headers=CSRF)
        out["too big"] = (r.status, (await r.json())["error"])

        async def gen():
            yield b"abc"

        r = await c.put("/api/files", params={"path": "a.txt"}, data=gen(), headers=CSRF)  # chunked
        out["chunked"] = r.status
        r = await c.put("/api/files", params={"path": ""}, data=b"abc", headers=CSRF)
        out["no name"] = r.status
        r = await c.put("/api/files", params={"path": "d/a.txt", "overwrite": "1"}, data=b"abc", headers=CSRF)
        out["ok"] = (r.status, await r.json())
        r = await c.put("/api/files", params={"path": "b.txt", "overwrite": "yes"}, data=b"", headers=CSRF)
        out["empty"] = r.status
        world.upload_reply = (409, b'{"error": "a file of this name exists"}')
        r = await c.put("/api/files", params={"path": "a.txt"}, data=b"abc", headers=CSRF)
        out["exists"] = (r.status, await r.json())
        world.upload_reply = (200, b"not json")
        r = await c.put("/api/files", params={"path": "a.txt"}, data=b"abc", headers=CSRF)
        out["bad answer"] = r.status
        world.upload_reply = (200, b"[]")
        r = await c.put("/api/files", params={"path": "a.txt"}, data=b"abc", headers=CSRF)
        out["not an object"] = r.status
        world.upload_reply = (500, b'{"error": "disk full"}')
        r = await c.put("/api/files", params={"path": "a.txt"}, data=b"abc", headers=CSRF)
        out["agent failed"] = (r.status, await r.json())
        return out

    out = go(main, world, fn)
    assert out["no csrf"] == 403 and out["too big"] == (413, "file larger than FILES_MAX_UPLOAD (10 bytes)")
    assert out["chunked"] == 411 and out["no name"] == 400
    assert out["ok"] == (200, {"path": "d/a.txt", "size": 3}) and out["empty"] == 200
    assert out["exists"] == (409, {"error": "a file of this name exists"})
    assert out["bad answer"] == 502 and out["not an object"] == 502
    assert out["agent failed"] == (502, {"error": "disk full"})
    assert world.uploads[0] == ({"path": "d/a.txt", "overwrite": "1"}, "3", b"abc")
    assert world.uploads[1] == ({"path": "b.txt", "overwrite": "0"}, "0", b"")


def test_upload_body_ending_early(load_main):  # noqa: F811
    import asyncio

    main = load_main()
    world = FilesWorld()

    async def fn(c):
        reader, writer = await asyncio.open_connection(c.host, c.port)
        cookie = "; ".join(f"{m.key}={m.value}" for m in c.session.cookie_jar)
        writer.write(
            b"PUT /api/files?path=a.txt HTTP/1.1\r\nHost: x\r\nX-Tallygate: 1\r\nContent-Length: 100\r\n"
            + f"Cookie: {cookie}\r\n\r\n".encode()
            + b"only part"
        )
        await writer.drain()
        writer.write_eof()
        data = await asyncio.wait_for(reader.read(), 10)
        writer.close()
        return data

    data = go(main, world, fn)
    assert b"upload failed" in data or data == b""
    assert not world.uploads or len(world.uploads[-1][2]) < 100
