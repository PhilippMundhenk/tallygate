"""Control auth edge cases (#27): password hash formats, idle and absolute session expiry, and the
console relay dropping browser frames that are not input or resize."""

from __future__ import annotations

import asyncio
import hashlib
import json
import time

import pytest

from .conftest import CONTROL_PASSWORD
from .helpers import Api


def scrypt_hash(pw: str, log2n: int | None) -> str:
    salt = bytes(range(16))
    n = 2 ** (log2n or 14)
    digest = hashlib.scrypt(pw.encode(), salt=salt, n=n, r=8, p=1, maxmem=256 * n * 8 + 1024 * 1024).hex()
    return f"scrypt:{salt.hex()}:{digest}" if log2n is None else f"scrypt:{log2n}:{salt.hex()}:{digest}"


def login(base: str, pw: str = CONTROL_PASSWORD) -> tuple[Api, str]:
    a = Api(base, csrf_header="X-Tallygate")
    status, _, headers = a.call("POST", "/login", form={"password": pw})
    assert status == 302
    return a, headers["Location"]


@pytest.mark.parametrize("log2n", [None, 16], ids=["legacy-n14", "current-n16"])
def test_password_hash_formats(control_with, log2n):
    """The hash wins over CONTROL_PASSWORD; the legacy `scrypt:<salt>:<hash>` (N = 2^14) still works."""
    base = control_with(CONTROL_PASSWORD_HASH=scrypt_hash("hashed-pw", log2n))
    assert login(base, "hashed-pw")[1].endswith("/")
    assert "failed=1" in login(base, CONTROL_PASSWORD)[1]


@pytest.mark.parametrize(
    "bad",
    ["scrypt:zz:yy", "scrypt:16:00ff", "scrypt:x:00ff:00ff", "scrypt:16:not-hex:00ff", "plain-text-not-a-hash"],
)
def test_malformed_password_hash_refuses_login_without_crashing(control_with, bad):
    base = control_with(CONTROL_PASSWORD_HASH=bad)
    for pw in (CONTROL_PASSWORD, "", bad):
        assert "failed=1" in login(base, pw)[1]  # a normal failed login, not a 500
    assert Api(base).call("GET", "/healthz")[0] == 200


def test_idle_expiry_and_activity_keeps_the_session(control_with):
    a, _ = login(control_with(SESSION_IDLE="3"))
    for _ in range(4):  # 6 s of activity, every 1.5 s: longer than the idle timeout
        assert a.call("GET", "/api/meta")[0] == 200
        time.sleep(1.5)
    time.sleep(2.5)
    assert a.call("GET", "/api/meta")[0] == 401
    assert a.call("GET", "/api/meta")[0] == 401  # gone for good, not just once


def test_absolute_expiry_despite_activity(control_with):
    a, _ = login(control_with(SESSION_TTL="3", SESSION_IDLE="3600"))
    t0 = time.time()
    while time.time() - t0 < 2.5:
        assert a.call("GET", "/api/meta")[0] == 200
        time.sleep(0.5)
    time.sleep(1.5)
    assert a.call("GET", "/api/meta")[0] == 401


def test_console_drops_browser_frames_other_than_input_and_resize(control):
    """ttyd's '2' (pause output) must not be relayed: if it were, the echo below would never show up."""
    if not control["ttyd"]:
        pytest.skip("ttyd not installed")
    import aiohttp

    a, _ = login(control["base"])

    async def run():
        cookies = {c.name: c.value for c in a.jar}
        async with aiohttp.ClientSession(cookies=cookies, trust_env=False) as s:
            url = control["base"].replace("http", "ws") + "/term/bash/ws"
            async with s.ws_connect(url, protocols=("tty",), headers={"Origin": control["base"]}) as ws:
                await ws.send_str(json.dumps({"columns": 80, "rows": 24}))
                for frame in (b"2", b'{"AuthToken": "x"}', b"9junk", b""):
                    await ws.send_bytes(frame)
                await ws.send_bytes(b"1" + json.dumps({"columns": 100, "rows": 30}).encode())  # resize passes
                await ws.send_bytes(b"0echo dropped-$((6*7))\r")
                out = b""
                while b"dropped-42" not in out:
                    msg = await asyncio.wait_for(ws.receive(), 5)
                    assert msg.type == aiohttp.WSMsgType.BINARY
                    out += msg.data[1:]
                return out

    assert b"dropped-42" in asyncio.run(run())
