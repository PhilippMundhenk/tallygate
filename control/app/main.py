"""tallygate control plane: web UI, approvals, notifications, web console, setup wizard.

Talks to the gateway API (control network) and to ttyd/status on the agent (agent network).
Never has docker.sock; never holds anything the agent could use to widen its own policy.

Everything that comes from the agent (terminal bytes, status JSON) is untrusted: no HTML/JS from
the agent is ever served on this origin, and all agent responses are size-limited.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import secrets
import time
import urllib.parse
from pathlib import Path

import aiohttp
from aiohttp import WSMsgType, web

from app import bootstrap, notify

log = logging.getLogger("control")
logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s: %(message)s")

STATIC = Path(__file__).parent / "static"
GW_URL = os.environ.get("GW_URL", "http://egress-gw:8081").rstrip("/")
GW_TOKEN = ""  # set in build_app() (environment or the gateway's token volume)
AGENT_HOST = os.environ.get("AGENT_HOST", "agent")
AGENT_STATUS_PORT = int(os.environ.get("AGENT_STATUS_PORT", "7680"))
TTYD_AUTH = ""  # user:pass shared with the agent's ttyd; set in build_app()
TERMINALS = dict(
    (n, int(p))
    for n, p in (t.split(":") for t in os.environ.get("TERMINALS", "rc:7681,bash:7682,claude:7683").split(","))
)
SESSION_SECRET = b""  # set in build_app()
SESSION_TTL = int(os.environ.get("SESSION_TTL", str(12 * 3600)))  # absolute lifetime
SESSION_IDLE = int(os.environ.get("SESSION_IDLE", str(2 * 3600)))  # idle timeout
PROXY_AUTH_HEADER = os.environ.get("TRUST_PROXY_AUTH_HEADER", "")  # e.g. Remote-User (only behind a trusted proxy!)
TRUST_FORWARDED = os.environ.get("TRUST_FORWARDED_FOR") == "1"
# Peers whose X-Forwarded-* / auth headers are believed. Required for TRUST_PROXY_AUTH_HEADER.
TRUSTED_PROXIES = [
    ipaddress.ip_network(c.strip(), strict=False) for c in os.environ.get("TRUSTED_PROXIES", "").split(",") if c.strip()
]
PUBLIC_URL = os.environ.get("PUBLIC_URL", "").rstrip("/")
COOKIE = "tallygate_session"
AGENT_MAX_BYTES = 1024 * 1024  # cap on anything read from the agent (status JSON, terminal frames)
BROWSER_MAX_FRAME = 64 * 1024

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
    ("GET", r"/grants"),
    ("PUT", r"/grants/[a-z0-9][a-z0-9_-]{0,47}"),
    ("DELETE", r"/grants/[a-z0-9][a-z0-9_-]{0,47}"),
    ("POST", r"/grants/[a-z0-9][a-z0-9_-]{0,47}/activate"),
    ("DELETE", r"/active-grants/[a-f0-9]+"),
    ("POST", r"/grant-requests/[a-f0-9]+/decide"),
    ("GET", r"/info"),
]


# ------------------------------------------------------------------ auth
def _peer_trusted(request: web.Request) -> bool:
    try:
        peer = ipaddress.ip_address(request.remote or "")
    except ValueError:
        return False
    return any(peer in n for n in TRUSTED_PROXIES)


def client_ip(request: web.Request) -> str:
    if TRUST_FORWARDED and _peer_trusted(request) and request.headers.get("X-Forwarded-For"):
        return request.headers["X-Forwarded-For"].split(",")[-1].strip()
    return request.remote or "?"


def _sign(payload: str) -> str:
    return hmac.new(SESSION_SECRET, payload.encode(), hashlib.sha256).hexdigest()


# Server-side sessions: logout and restarts really end a session; idle + absolute expiry.
_sessions: dict[str, dict] = {}


def make_session(user: str) -> str:
    sid = secrets.token_urlsafe(32)
    now = time.time()
    _sessions[sid] = {"user": user, "exp": now + SESSION_TTL, "seen": now}
    return f"{sid}.{_sign(sid)}"


def _session_id(request: web.Request) -> str | None:
    raw = request.cookies.get(COOKIE, "")
    sid, _, sig = raw.partition(".")
    if not sid or not hmac.compare_digest(sig, _sign(sid)):
        return None
    return sid


def read_session(request: web.Request) -> str | None:
    if PROXY_AUTH_HEADER and _peer_trusted(request) and request.headers.get(PROXY_AUTH_HEADER):
        return request.headers[PROXY_AUTH_HEADER][:64]
    sid = _session_id(request)
    s = _sessions.get(sid) if sid else None
    now = time.time()
    if not s or s["exp"] < now or now - s["seen"] > SESSION_IDLE:
        _sessions.pop(sid, None)
        return None
    s["seen"] = now
    return s["user"]


def _prune_sessions() -> None:
    now = time.time()
    for sid, s in list(_sessions.items()):
        if s["exp"] < now or now - s["seen"] > SESSION_IDLE:
            del _sessions[sid]


def check_password(pw: str) -> bool:
    """CONTROL_PASSWORD_HASH = "scrypt:<log2N>:<salt-hex>:<hash-hex>" (legacy "scrypt:<salt>:<hash>" = N 2^14),
    or CONTROL_PASSWORD (plain, discouraged), or the hash stored in the control volume (zero-config default)."""
    h = os.environ.get("CONTROL_PASSWORD_HASH", "")
    if not h and not os.environ.get("CONTROL_PASSWORD"):
        h = bootstrap.password_hash()  # read per attempt: `python -m app.passwd` applies without a restart
    if h.startswith("scrypt:"):
        parts = h.split(":")
        try:
            log2n, salt, digest = (14, *parts[1:]) if len(parts) == 3 else (int(parts[1]), *parts[2:])
            n = 2 ** int(log2n)
            calc = hashlib.scrypt(
                pw.encode(), salt=bytes.fromhex(salt), n=n, r=8, p=1, maxmem=256 * n * 8 + 1024 * 1024
            ).hex()
        except (ValueError, TypeError):
            log.error("CONTROL_PASSWORD_HASH is malformed")
            return False
        return hmac.compare_digest(calc, digest)
    plain = os.environ.get("CONTROL_PASSWORD", "")
    return bool(plain) and hmac.compare_digest(pw.encode(), plain.encode())


_login_failures: dict[str, list[float]] = {}
_login_lock = asyncio.Lock()  # one password check at a time: caps guessing rate globally, bounds memory
_login_waiting = 0  # requests holding or queued on _login_lock
LOGIN_MAX_BODY = 4096  # a password form is tiny; bigger bodies are refused before they are read
LOGIN_MAX_WAITING = 5  # more queued checks get 429 at once instead of piling up (memory, operator lockout)
LOGIN_MAX_FAILURES = 10  # per client address within LOGIN_WINDOW
LOGIN_WINDOW = 900


def _recent_failures(ip: str, now: float) -> list[float]:
    return [t for t in _login_failures.get(ip, []) if now - t < LOGIN_WINDOW]


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
        if path == "/logout" and not _same_origin(request):
            return web.json_response({"error": "csrf check failed"}, status=403)
        resp = await handler(request)
    if isinstance(resp, web.StreamResponse) and not resp.prepared:
        _security_headers(resp, path)
    return resp


CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
    "connect-src 'self'; frame-src 'self'; frame-ancestors 'self'; base-uri 'none'; form-action 'self'"
)


def _security_headers(resp: web.StreamResponse, path: str) -> None:
    resp.headers.setdefault("Content-Security-Policy", CSP)  # everywhere, incl. the console
    resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "same-origin")  # "no-referrer" makes browsers send Origin: null
    resp.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    resp.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
    resp.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=(), usb=()")
    if path.startswith("/api/") or path in ("/", "/login"):
        resp.headers.setdefault("Cache-Control", "no-store")


def _expected_origin(request: web.Request) -> str:
    if PUBLIC_URL:
        u = urllib.parse.urlsplit(PUBLIC_URL)
        return f"{u.scheme}://{u.netloc}".lower()
    trusted = TRUST_FORWARDED and _peer_trusted(request)
    host = (request.headers.get("X-Forwarded-Host") if trusted else None) or request.host
    scheme = (request.headers.get("X-Forwarded-Proto") if trusted else None) or request.scheme
    return f"{scheme}://{host}".lower()


def _same_origin(request: web.Request) -> bool:
    origin = request.headers.get("Origin")
    if not origin:
        return True  # non-browser client with session cookie; custom header still required
    return origin.lower() == _expected_origin(request)


# ------------------------------------------------------------------ pages
async def login_page(request: web.Request) -> web.StreamResponse:
    global _login_waiting
    if request.method == "GET":
        return web.FileResponse(STATIC / "login.html")
    if not _same_origin(request):
        return web.Response(status=403, text="bad origin")
    if request.content_length is None or request.content_length > LOGIN_MAX_BODY:
        return web.Response(status=413, text="Request too large.")  # also refuses chunked bodies, unread
    ip = client_ip(request)
    too_many = web.Response(status=429, text="Too many attempts, try again later.")
    if len(_recent_failures(ip, time.time())) >= LOGIN_MAX_FAILURES:
        return too_many
    if _login_waiting >= LOGIN_MAX_WAITING:
        return web.Response(status=429, text="Too many login attempts in progress, try again shortly.")
    _login_waiting += 1
    try:
        form = await request.post()
        pw = str(form.get("password", ""))[:1024]
        async with _login_lock:  # serialised + 1 s penalty on failure -> ~1 guess/s globally
            # re-check inside the lock: requests that queued together must not exceed the limit
            now = time.time()
            fails = _recent_failures(ip, now)
            if len(fails) >= LOGIN_MAX_FAILURES:
                return too_many
            ok = await asyncio.get_running_loop().run_in_executor(None, check_password, pw)
            if not ok:
                fails.append(now)
                _login_failures[ip] = fails
                await asyncio.sleep(1)
    finally:
        _login_waiting -= 1
    if ok:
        _login_failures.pop(ip, None)
        _prune_sessions()
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
    if len(_login_failures) > 10_000:  # bounded memory under address-spraying
        for k in sorted(_login_failures, key=lambda k: _login_failures[k][-1])[:5_000]:
            del _login_failures[k]
    log.warning("failed login from %s", ip)
    raise web.HTTPFound("/login?failed=1")


async def logout(request: web.Request):
    sid = _session_id(request)
    if sid:
        _sessions.pop(sid, None)
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
    by = f"web:{request['user']}"
    if (sub.endswith("/decide") or sub.endswith("/activate")) and isinstance(body, dict):
        body["by"] = by  # attribution is set here, never taken from the browser
    qs = ("?" + request.query_string) if request.query_string else ""
    if sub.startswith("/active-grants/"):
        qs = "?" + urllib.parse.urlencode({"by": by})
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
            raw = await r.content.read(AGENT_MAX_BYTES + 1)
            if len(raw) > AGENT_MAX_BYTES:
                return web.json_response({"error": "agent response too large"}, status=502)
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise ValueError("not an object")
            return web.json_response(data, status=200 if r.status == 200 else 502)
    except (TimeoutError, aiohttp.ClientError, ValueError) as e:
        return web.json_response({"error": f"agent unreachable or invalid response: {e}"}, status=502)


async def api_meta(request: web.Request):
    return web.json_response(
        {
            "user": request["user"],
            "terminals": list(TERMINALS),
            "notify": request.app["notifier"].describe(),
        }
    )


# ------------------------------------------------------------------ web console
# The console page and its JS are served from THIS container (static/term.*). Only the ttyd
# WebSocket is relayed, and filtered: the browser may send input/resize, the agent may only send
# terminal output. Agent-supplied HTML (ttyd's own page, redirects, ...) never reaches the browser.
async def term_page(request: web.Request):
    if request.match_info["name"] not in TERMINALS:
        raise web.HTTPNotFound()
    return web.FileResponse(STATIC / "term.html")


def _ttyd_token() -> str:
    return base64.b64encode(TTYD_AUTH.encode()).decode() if TTYD_AUTH else ""


async def term_ws(request: web.Request):
    name = request.match_info["name"]
    if name not in TERMINALS:
        raise web.HTTPNotFound()
    if not request.headers.get("Origin") or not _same_origin(request):
        raise web.HTTPForbidden(text="bad origin")
    upstream = f"ws://{AGENT_HOST}:{TERMINALS[name]}/term/{name}/ws"
    headers = {"Authorization": "Basic " + _ttyd_token()} if TTYD_AUTH else {}
    ws_client = web.WebSocketResponse(protocols=("tty",), max_msg_size=BROWSER_MAX_FRAME, heartbeat=30)
    await ws_client.prepare(request)
    try:
        async with request.app["http"].ws_connect(
            upstream, protocols=("tty",), headers=headers, max_msg_size=AGENT_MAX_BYTES
        ) as ws_up:

            async def browser_to_agent():
                first = True
                async for msg in ws_client:
                    if msg.type not in (WSMsgType.TEXT, WSMsgType.BINARY):
                        break
                    data = msg.data.encode() if msg.type == WSMsgType.TEXT else msg.data
                    if first:  # handshake: size only from the browser, credential from us
                        first = False
                        try:
                            hello = json.loads(data)
                            size = {"columns": int(hello.get("columns", 80)), "rows": int(hello.get("rows", 24))}
                        except (ValueError, TypeError, AttributeError):
                            size = {"columns": 80, "rows": 24}
                        await ws_up.send_str(json.dumps({"AuthToken": _ttyd_token(), **size}))
                    elif data[:1] in (b"0", b"1"):  # input, resize
                        await ws_up.send_bytes(data)
                    if read_session(request) is None:  # session ended (logout/expiry): drop the console
                        await ws_client.close(code=4401, message=b"session expired")
                        break

            async def agent_to_browser():
                async for msg in ws_up:
                    if msg.type not in (WSMsgType.TEXT, WSMsgType.BINARY):
                        break
                    data = msg.data.encode() if msg.type == WSMsgType.TEXT else msg.data
                    if data[:1] == b"0":  # terminal output only; title/preferences are dropped
                        await ws_client.send_bytes(data)

            tasks = [asyncio.create_task(browser_to_agent()), asyncio.create_task(agent_to_browser())]
            _done, rest = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for t in rest:
                t.cancel()
    except (aiohttp.ClientError, TimeoutError) as e:
        log.warning("terminal %s websocket failed: %s", name, e)
    finally:
        await ws_client.close()
    return ws_client


# ------------------------------------------------------------------ app
async def on_startup(app: web.Application):
    app["http"] = aiohttp.ClientSession(trust_env=False)
    app["notifier"] = notify.Notifier(
        app,
        decide_grant=lambda rid, decision, by: gw(
            app, "POST", f"/grant-requests/{rid}/decide", {"decision": decision, "by": by}
        ),
        revoke_grant=lambda aid, by: gw(app, "DELETE", f"/active-grants/{aid}?" + urllib.parse.urlencode({"by": by})),
        decide=lambda pid, scope, by: gw(app, "POST", f"/pending/{pid}/decide", {"scope": scope, "by": by}),
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
                        if ev.get("type") in ("ask", "resolved", "grant_request", "grant_resolved"):
                            await app["notifier"].handle(ev)
        except asyncio.CancelledError:
            raise
        except Exception as e:  # noqa: BLE001
            log.warning("gateway stream: %s (retrying)", e)
        await asyncio.sleep(3)


def build_app() -> web.Application:
    global GW_TOKEN, TTYD_AUTH, SESSION_SECRET
    GW_TOKEN = bootstrap.gw_token()
    TTYD_AUTH = bootstrap.ttyd_credential()
    SESSION_SECRET = bootstrap.session_secret()
    if not PROXY_AUTH_HEADER:
        bootstrap.ensure_password()
    if PROXY_AUTH_HEADER and not TRUSTED_PROXIES:
        raise SystemExit("TRUST_PROXY_AUTH_HEADER requires TRUSTED_PROXIES (CIDRs of your auth proxy)")
    if TRUST_FORWARDED and not TRUSTED_PROXIES:
        log.warning("TRUST_FORWARDED_FOR=1 but TRUSTED_PROXIES is empty: X-Forwarded-* headers are ignored")
    if os.environ.get("CONTROL_PASSWORD") and not os.environ.get("CONTROL_PASSWORD_HASH"):
        log.warning("CONTROL_PASSWORD (plain text) is in use - prefer CONTROL_PASSWORD_HASH")
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
    app.router.add_get("/term/{name}/", term_page)
    app.router.add_get("/term/{name}/ws", term_ws)
    app.router.add_static("/static/", STATIC)
    return app


def main():
    bind = os.environ.get("CONTROL_BIND_HOST")
    if not bind:  # fail closed: never listen on all interfaces (incl. the agent network) by accident
        raise SystemExit("CONTROL_BIND_HOST must be set to the control plane's management IP")
    web.run_app(
        build_app(),
        host=bind,
        port=int(os.environ.get("CONTROL_PORT", "8080")),
        access_log=None,
    )


if __name__ == "__main__":
    main()
