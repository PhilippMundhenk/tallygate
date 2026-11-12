"""Open connections end with their session (#21): the event stream and the web console are re-checked
periodically (SESSION_RECHECK, 1 s here), and console input is checked before it reaches the agent."""

from __future__ import annotations

import asyncio
import http.client
import json
import time
import urllib.parse
from pathlib import Path

import pytest

from .conftest import CONTROL_PASSWORD, start_control
from .helpers import Api

aiohttp = pytest.importorskip("aiohttp")


@pytest.fixture
def control_at(tmp_path, gateway, ttyd_port):
    procs = []

    def factory(**extra):
        proc, port = start_control(tmp_path, gateway, extra, ttyd_port)
        procs.append(proc)
        return f"http://127.0.0.1:{port}"

    yield factory
    for p in procs:
        p.terminate()
        p.wait(10)


def login(base: str) -> Api:
    a = Api(base, csrf_header="X-Tallygate")
    assert a.call("POST", "/login", form={"password": CONTROL_PASSWORD})[0] == 302
    return a


def cookie(a: Api) -> str:
    return "; ".join(f"{c.name}={c.value}" for c in a.jar)


def logout(a: Api) -> None:
    a.call("POST", "/logout", headers={"Origin": a.base})


def open_stream(a: Api) -> http.client.HTTPResponse:
    u = urllib.parse.urlsplit(a.base)
    conn = http.client.HTTPConnection(u.hostname, u.port, timeout=15)
    conn.request("GET", "/api/stream", headers={"Cookie": cookie(a)})
    r = conn.getresponse()
    assert r.status == 200
    return r


def seconds_until_closed(r: http.client.HTTPResponse) -> float:
    t0 = time.time()
    while r.read1(65536):  # b"" once the server ended the stream
        pass
    return time.time() - t0


def test_event_stream_closes_after_logout(control_at):
    a = login(control_at(SESSION_RECHECK="1"))
    r = open_stream(a)
    logout(a)
    assert seconds_until_closed(r) < 5


def test_event_stream_closes_on_idle_expiry_and_does_not_keep_the_session_alive(control_at):
    a = login(control_at(SESSION_RECHECK="1", SESSION_IDLE="3"))
    r = open_stream(a)
    assert 2 < seconds_until_closed(r) < 8
    assert a.call("GET", "/api/meta")[0] == 401


def _ws(a: Api):
    session = aiohttp.ClientSession(headers={"Cookie": cookie(a)}, trust_env=False)
    url = a.base.replace("http", "ws") + "/term/bash/ws"
    return session, session.ws_connect(url, protocols=("tty",), headers={"Origin": a.base})


def test_passive_console_closes_4401_after_logout(control_at, ttyd_port):
    if not ttyd_port:
        pytest.skip("ttyd not installed")
    a = login(control_at(SESSION_RECHECK="1"))

    async def run():
        session, connect = _ws(a)
        async with session, connect as ws:
            await ws.send_str(json.dumps({"columns": 80, "rows": 24}))
            await asyncio.to_thread(logout, a)
            while True:  # only reads: the server must notice the logout by itself
                msg = await asyncio.wait_for(ws.receive(), 5)
                if msg.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSED):
                    return ws.close_code

    assert asyncio.run(run()) == 4401


def test_console_input_after_logout_never_reaches_the_agent(control_at, ttyd_port, tmp_path):
    if not ttyd_port:
        pytest.skip("ttyd not installed")
    a = login(control_at(SESSION_RECHECK="600"))  # the periodic check must not be what saves us
    marker = Path("/tmp") / f"tg-after-logout-{tmp_path.name}"

    async def run():
        session, connect = _ws(a)
        async with session, connect as ws:
            await ws.send_str(json.dumps({"columns": 80, "rows": 24}))
            await ws.send_bytes(b"0echo ready-$((6*7))\r")
            out = b""
            while b"ready-42" not in out:
                msg = await asyncio.wait_for(ws.receive(), 5)
                out += msg.data if isinstance(msg.data, bytes) else b""
            await asyncio.to_thread(logout, a)
            await ws.send_bytes(f"0touch {marker}\r".encode())
            while True:
                msg = await asyncio.wait_for(ws.receive(), 5)
                if msg.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSED):
                    return ws.close_code

    assert asyncio.run(run()) == 4401
    time.sleep(1)
    assert not marker.exists()
