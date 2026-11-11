"""tallygate control plane: web UI, approvals, notifications, web console, setup wizard.

Talks to the gateway API (control network) and to ttyd/status on the agent (agent network).
Never has docker.sock; never holds anything the agent could use to widen its own policy.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import time
from pathlib import Path

import aiohttp
from aiohttp import WSMsgType, web

from app import notify

log = logging.getLogger("control")
logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s: %(message)s")

STATIC = Path(__file__).parent / "static"
GW_URL = os.environ.get("GW_URL", "http://egress-gw:8081").rstrip("/")
GW_TOKEN = os.environ.get("GW_API_TOKEN", "")
AGENT_HOST = os.environ.get("AGENT_HOST", "agent")
AGENT_STATUS_PORT = int(os.environ.get("AGENT_STATUS_PORT", "7680"))
TTYD_AUTH = os.environ.get("TTYD_CREDENTIAL", "")  # user:pass shared with the agent's ttyd
TERMINALS = dict(
    (n, int(p))
    for n, p in (t.split(":") for t in os.environ.get("TERMINALS", "rc:7681,bash:7682,claude:7683").split(","))
)
SESSION_SECRET = (os.environ.get("SESSION_SECRET") or secrets.token_hex(32)).encode()
SESSION_TTL = int(os.environ.get("SESSION_TTL", str(12 * 3600)))
PROXY_AUTH_HEADER = os.environ.get("TRUST_PROXY_AUTH_HEADER", "")  # e.g. Remote-User (only behind a trusted proxy!)
COOKIE = "tallygate_session"

# Gateway API paths the UI may use: (method, regex)
GW_ALLOW = [
    ("GET", r"/policy"),
    ("PUT", r"/policy"),
    ("POST", r"/rules"),
    ("DELETE", r"/rules/[A-Za-z0-9_-]+"),
    ("GET", r"/pending"),
    ("POST", r"/pending/[a-f0-9]+/decide"),
    ("GET", r"/events"),
    ("POST", r"/test"),
    ("GET", r"/presets"),
    ("POST", r"/presets/[A-Za-z_][A-Za-z0-9_]*"),
    ("GET", r"/secrets"),
    ("PUT", r"/secrets/[a-z0-9_]+"),
    ("GET", r"/info"),
]


# ------------------------------------------------------------------ auth
def _sign(payload: str) -> str:
    return hmac.new(SESSION_SECRET, payload.encode(), hashlib.sha256).hexdigest()


def make_session(user: str) -> str:
    payload = f"{user}|{int(time.time()) + SESSION_TTL}"
    return base64.urlsafe_b64encode(f"{payload}|{_sign(payload)}".encode()).decode()


def read_session(request: web.Request) -> str | None:
    if PROXY_AUTH_HEADER and request.headers.get(PROXY_AUTH_HEADER):
        return request.headers[PROXY_AUTH_HEADER][:64]
    raw = request.cookies.get(COOKIE)
    if not raw:
        return None
    try:
        user, exp, sig = base64.urlsafe_b64decode(raw.encode()).decode().rsplit("|", 2)
    except Exception:  # noqa: BLE001
        return None
    if not hmac.compare_digest(sig, _sign(f"{user}|{exp}")) or int(exp) < time.time():
        return None
    return user


def check_password(pw: str) -> bool:
    """CONTROL_PASSWORD_HASH = "scrypt:<salt-hex>:<hash-hex>" (preferred) or CONTROL_PASSWORD (plain)."""
    h = os.environ.get("CONTROL_PASSWORD_HASH", "")
    if h.startswith("scrypt:"):
        _, salt, digest = h.split(":")
        calc = hashlib.scrypt(pw.encode(), salt=bytes.fromhex(salt), n=2**14, r=8, p=1).hex()
        return hmac.compare_digest(calc, digest)
    plain = os.environ.get("CONTROL_PASSWORD", "")
    return bool(plain) and hmac.compare_digest(pw.encode(), plain.encode())


_login_failures: dict[str, list[float]] = {}


@web.middleware
async def security(request: web.Request, handler):
    path = request.path
    if path in ("/login", "/healthz") or path.startswith("/static/login"):
        resp = await handler(request)
    else:
        user = read_session(request)
        if not user:
            if path.startswith("/api/") or path.startswith("/term/"):
                return web.json_response({"error": "login required"}, status=401)
            raise web.HTTPFound("/login")
        request["user"] = user
        # CSRF: state-changing API calls must come from our JS (custom header + same origin)
        state_changing = request.method not in ("GET", "HEAD", "OPTIONS") and path.startswith("/api/")
        if state_changing and (request.headers.get("X-Tallygate") != "1" or not _same_origin(request)):
            return web.json_response({"error": "csrf check failed"}, status=403)
        resp = await handler(request)
    if isinstance(resp, web.StreamResponse) and not resp.prepared:
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        if not path.startswith("/term/"):
            resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
            resp.headers.setdefault(
                "Content-Security-Policy",
                "default-src 'self'; frame-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; connect-src 'self'",
            )
    return resp


def _same_origin(request: web.Request) -> bool:
    origin = request.headers.get("Origin")
    if not origin:
        return True  # non-browser client with session cookie; custom header still required
    host = (
        request.headers.get("X-Forwarded-Host") if os.environ.get("TRUST_FORWARDED_FOR") == "1" else None
    ) or request.host
    return origin.split("://", 1)[-1] == host


# ------------------------------------------------------------------ pages
async def login_page(request: web.Request) -> web.StreamResponse:
    if request.method == "GET":
        return web.FileResponse(STATIC / "login.html")
    ip = request.remote or "?"
    if os.environ.get("TRUST_FORWARDED_FOR") == "1":  # only when a trusted reverse proxy sets it
        ip = request.headers.get("X-Forwarded-For", ip).split(",")[-1].strip()
    now = time.time()
    fails = [t for t in _login_failures.get(ip, []) if now - t < 900]
    if len(fails) >= 10:
        return web.Response(status=429, text="Too many attempts, try again later.")
    form = await request.post()
    if check_password(str(form.get("password", ""))):
        _login_failures.pop(ip, None)
        resp = web.HTTPFound("/")
        resp.set_cookie(
            COOKIE,
            make_session("admin"),
            max_age=SESSION_TTL,
            httponly=True,
            samesite="Strict",
            secure=os.environ.get("COOKIE_SECURE", "1") == "1",
        )
        raise resp
    fails.append(now)
    _login_failures[ip] = fails
    await asyncio.sleep(1)
    raise web.HTTPFound("/login?failed=1")


async def logout(_request: web.Request):
    resp = web.HTTPFound("/login")
    resp.del_cookie(COOKIE)
    raise resp


async def index(_request: web.Request):
    return web.FileResponse(STATIC / "index.html")


async def healthz(_request: web.Request):
    return web.json_response({"ok": True})


# ------------------------------------------------------------------ gateway relay
async def gw(app: web.Application, method: str, path: str, body=None, timeout: float = 15):
    async with app["http"].request(
        method,
        GW_URL + path,
        json=body,
        headers={"Authorization": f"Bearer {GW_TOKEN}"},
        timeout=aiohttp.ClientTimeout(total=timeout),
    ) as r:
        data = await r.json(content_type=None)
        return r.status, data


async def api_gw(request: web.Request):
    sub = "/" + request.match_info["tail"]
    if not any(m == request.method and re.fullmatch(rx, sub) for m, rx in GW_ALLOW):
        return web.json_response({"error": "not allowed"}, status=404)
    body = await request.json() if request.can_read_body else None
    if sub.endswith("/decide") and isinstance(body, dict):
        body["by"] = f"web:{request['user']}"
    qs = ("?" + request.query_string) if request.query_string else ""
    try:
        status, data = await gw(request.app, request.method, sub + qs, body)
    except (TimeoutError, aiohttp.ClientError) as e:
        return web.json_response({"error": f"gateway unreachable: {e}"}, status=502)
    return web.json_response(data, status=status)


async def api_stream(request: web.Request):
    """Relay the gateway's SSE stream to the browser."""
    resp = web.StreamResponse(
        headers={"Content-Type": "text/event-stream", "Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
    )
    await resp.prepare(request)
    try:
        async with request.app["http"].get(
            GW_URL + "/stream",
            headers={"Authorization": f"Bearer {GW_TOKEN}"},
            timeout=aiohttp.ClientTimeout(total=None, sock_read=60),
        ) as up:
            async for chunk in up.content.iter_any():
                await resp.write(chunk)
    except (TimeoutError, aiohttp.ClientError, ConnectionResetError):
        pass
    return resp


async def api_github_check(request: web.Request):
    """Validate the stored-at-gateway token by calling GitHub from the control plane (which has egress).
    The token is sent once from the browser for validation and storage; it is never returned."""
    body = await request.json()
    token = str(body.get("token", "")).strip()
    if not token:
        return web.json_response({"error": "token missing"}, status=400)
    async with request.app["http"].get(
        "https://api.github.com/user",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
        timeout=aiohttp.ClientTimeout(total=15),
    ) as r:
        data = await r.json(content_type=None)
        if r.status != 200:
            return web.json_response({"ok": False, "status": r.status, "message": data.get("message")}, status=200)
        info = {
            "ok": True,
            "login": data.get("login"),
            "scopes": r.headers.get("X-OAuth-Scopes"),
            "expires": r.headers.get("github-authentication-token-expiration"),
        }
    if body.get("store"):
        status, _ = await gw(request.app, "PUT", "/secrets/github_token", {"value": token})
        info["stored"] = status == 200
    return web.json_response(info)


async def api_agent(request: web.Request):
    """Read-only agent status + self-test (served by agent/status.py on the agent network)."""
    what = request.match_info["what"]
    if what not in ("status", "selftest"):
        raise web.HTTPNotFound()
    try:
        async with request.app["http"].get(
            f"http://{AGENT_HOST}:{AGENT_STATUS_PORT}/{what}", timeout=aiohttp.ClientTimeout(total=90)
        ) as r:
            return web.json_response(await r.json(content_type=None), status=r.status)
    except (TimeoutError, aiohttp.ClientError) as e:
        return web.json_response({"error": f"agent unreachable: {e}"}, status=502)


async def api_meta(request: web.Request):
    return web.json_response(
        {
            "user": request["user"],
            "terminals": list(TERMINALS),
            "notify": request.app["notifier"].describe(),
        }
    )


# ------------------------------------------------------------------ ttyd reverse proxy
def _ttyd_headers(request: web.Request) -> dict:
    h = {
        k: v
        for k, v in request.headers.items()
        if k.lower()
        not in (
            "host",
            "cookie",
            "authorization",
            "origin",
            "connection",
            "upgrade",
            "sec-websocket-key",
            "sec-websocket-version",
            "sec-websocket-extensions",
            "sec-websocket-protocol",
            "content-length",
        )
    }
    if TTYD_AUTH:
        h["Authorization"] = "Basic " + base64.b64encode(TTYD_AUTH.encode()).decode()
    return h


async def term_proxy(request: web.Request):
    name = request.match_info["name"]
    if name not in TERMINALS:
        raise web.HTTPNotFound()
    tail = request.match_info.get("tail", "")
    upstream = f"http://{AGENT_HOST}:{TERMINALS[name]}/term/{name}/{tail}"
    if request.query_string:
        upstream += "?" + request.query_string
    if request.headers.get("Upgrade", "").lower() == "websocket":
        if not _same_origin(request) or not request.headers.get("Origin"):
            raise web.HTTPForbidden(text="bad origin")
        ws_client = web.WebSocketResponse(protocols=("tty",), max_msg_size=0, autoping=True)
        await ws_client.prepare(request)
        try:
            async with request.app["http"].ws_connect(
                upstream.replace("http://", "ws://"), protocols=("tty",), headers=_ttyd_headers(request), max_msg_size=0
            ) as ws_up:

                async def pump(src, dst):
                    async for msg in src:
                        if msg.type == WSMsgType.TEXT:
                            await dst.send_str(msg.data)
                        elif msg.type == WSMsgType.BINARY:
                            await dst.send_bytes(msg.data)
                        elif msg.type in (WSMsgType.CLOSE, WSMsgType.ERROR):
                            break

                await asyncio.wait(
                    [asyncio.create_task(pump(ws_client, ws_up)), asyncio.create_task(pump(ws_up, ws_client))],
                    return_when=asyncio.FIRST_COMPLETED,
                )
        except aiohttp.ClientError as e:
            log.warning("terminal %s websocket failed: %s", name, e)
        finally:
            await ws_client.close()
        return ws_client
    try:
        async with request.app["http"].request(
            request.method, upstream, headers=_ttyd_headers(request), data=await request.read(), allow_redirects=False
        ) as r:
            body = await r.read()
            headers = {
                k: v
                for k, v in r.headers.items()
                if k.lower() in ("content-type", "cache-control", "etag", "last-modified", "location")
            }
            return web.Response(status=r.status, body=body, headers=headers)
    except aiohttp.ClientError as e:
        return web.Response(status=502, text=f"terminal '{name}' unreachable: {e}")


# ------------------------------------------------------------------ app
async def on_startup(app: web.Application):
    app["http"] = aiohttp.ClientSession(trust_env=False)
    app["notifier"] = notify.Notifier(
        app, decide=lambda pid, scope, by: gw(app, "POST", f"/pending/{pid}/decide", {"scope": scope, "by": by})
    )
    app["bg"] = [asyncio.create_task(watch_gateway(app)), *app["notifier"].start()]


async def on_cleanup(app: web.Application):
    for t in app["bg"]:
        t.cancel()
    await app["http"].close()


async def watch_gateway(app: web.Application):
    """Single upstream SSE subscription that drives notifications."""
    while True:
        try:
            async with app["http"].get(
                GW_URL + "/stream",
                headers={"Authorization": f"Bearer {GW_TOKEN}"},
                timeout=aiohttp.ClientTimeout(total=None, sock_read=60),
            ) as r:
                if r.status != 200:
                    raise aiohttp.ClientError(f"status {r.status}")
                log.info("subscribed to gateway events")
                async for line in r.content:
                    line = line.decode().strip()
                    if line.startswith("data: "):
                        ev = json.loads(line[6:])
                        if ev.get("type") in ("ask", "resolved"):
                            await app["notifier"].handle(ev)
        except asyncio.CancelledError:
            raise
        except Exception as e:  # noqa: BLE001
            log.warning("gateway stream: %s (retrying)", e)
        await asyncio.sleep(3)


def build_app() -> web.Application:
    if not (os.environ.get("CONTROL_PASSWORD") or os.environ.get("CONTROL_PASSWORD_HASH") or PROXY_AUTH_HEADER):
        raise SystemExit("Set CONTROL_PASSWORD_HASH (or CONTROL_PASSWORD, or TRUST_PROXY_AUTH_HEADER)")
    app = web.Application(middlewares=[security], client_max_size=2 * 1024 * 1024)
    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)
    app.router.add_get("/healthz", healthz)
    app.router.add_route("*", "/login", login_page)
    app.router.add_post("/logout", logout)
    app.router.add_get("/", index)
    app.router.add_get("/api/stream", api_stream)
    app.router.add_get("/api/meta", api_meta)
    app.router.add_post("/api/github/check", api_github_check)
    app.router.add_get("/api/agent/{what}", api_agent)
    app.router.add_route("*", "/api/gw/{tail:.*}", api_gw)
    app.router.add_route("*", "/term/{name}/{tail:.*}", term_proxy)
    app.router.add_static("/static/", STATIC)
    return app


def main():
    web.run_app(
        build_app(),
        host=os.environ.get("CONTROL_BIND_HOST", "0.0.0.0"),
        port=int(os.environ.get("CONTROL_PORT", "8080")),
        access_log=None,
    )


if __name__ == "__main__":
    main()
