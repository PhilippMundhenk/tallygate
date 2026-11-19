"""tallygate control plane: web UI, approvals, notifications, web console, setup wizard.

Talks to the gateway API (control network) and to ttyd/status on the agent (agent network).
Never has docker.sock; never holds anything the agent could use to widen its own policy.

Everything that comes from the agent (terminal bytes, status JSON) is untrusted: no HTML/JS from
the agent is ever served on this origin, and all agent responses are size-limited.
No outbound call follows a redirect, and the clients for the agent and the gateway connect to that one peer
only (see "outbound HTTP"): control makes exactly the requests it built itself.
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
import yarl
from aiohttp import WSMsgType, web

from app import agentschema, bootstrap, notify, notifyconfig, webpush

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
SESSION_RECHECK = float(os.environ.get("SESSION_RECHECK", "10"))  # open streams/consoles re-check this often (s)
PROXY_AUTH_HEADER = os.environ.get("TRUST_PROXY_AUTH_HEADER", "")  # e.g. Remote-User (only behind a trusted proxy!)
TRUST_FORWARDED = os.environ.get("TRUST_FORWARDED_FOR") == "1"
# Peers whose X-Forwarded-* / auth headers are believed. Required for TRUST_PROXY_AUTH_HEADER.
TRUSTED_PROXIES = [
    ipaddress.ip_network(c.strip(), strict=False) for c in os.environ.get("TRUSTED_PROXIES", "").split(",") if c.strip()
]
# Optional shared secret: when set, the proxy must also send it, or its forwarded/auth headers are ignored.
PROXY_SECRET = os.environ.get("TRUST_PROXY_SECRET", "")
# Host names the UI is served under (optional, #246): comma-separated, without port. See host_allowed().
ALLOWED_HOSTS = frozenset(
    h.strip().lower().rstrip(".") for h in os.environ.get("ALLOWED_HOSTS", "").split(",") if h.strip()
)
SESSION_SECRET_MIN = 32  # characters of a SESSION_SECRET from the environment (the generated one has 64)
PROXY_SECRET_HEADER = "X-Tallygate-Proxy-Secret"  # noqa: S105 (a header name)
PUBLIC_URL = os.environ.get("PUBLIC_URL", "").rstrip("/")
GITHUB_API = os.environ.get("GITHUB_API_URL", "https://api.github.com").rstrip("/")  # tests point it elsewhere
COOKIE = "tallygate_session"
# Served without a session: the PWA manifest and icons are fetched without cookies, and the service worker
# script must load before any login. None of them contains anything but static code and pictures.
PUBLIC_FILES = {
    "/sw.js": ("sw.js", "text/javascript"),
    "/manifest.webmanifest": ("manifest.webmanifest", "application/manifest+json"),
    "/static/icon.svg": ("icon.svg", "image/svg+xml"),
    "/static/icon-192.png": ("icon-192.png", "image/png"),
    "/static/icon-512.png": ("icon-512.png", "image/png"),
}
# Served without a session because the login page needs them: exactly these, never a prefix (#245).
LOGIN_FILES = frozenset(
    {"/login", "/healthz", "/static/logo.svg", "/static/favicon.svg", "/static/login.html", "/static/login.js"}
)
# A request that the page sends by itself (a timer, a reload after a stream event, a reconnect) says so with
# this header and does not count as activity for the idle timeout (#242). So do the two long-lived
# connections, which the browser re-opens on its own.
POLL_HEADER = "X-Tallygate-Poll"
PUSH_ACT = "/api/push/act"  # notification buttons: authenticated by a single-use action token, not a session
AGENT_MAX_BYTES = 1024 * 1024  # cap on anything read from the agent (status JSON, terminal frames)
BROWSER_MAX_FRAME = 64 * 1024

# An id in a relayed path (#244): starts with a letter or digit and has no "..", so it is never "." or ".."
# and cannot step out of the route it stands in ("destinations/.." was the gateway's "/").
GW_ID = r"[A-Za-z0-9](?:[A-Za-z0-9_:-]|\.(?!\.))*"
# Gateway API paths the UI may use: (method, regex)
GW_ALLOW = [
    ("GET", r"/policy"),
    ("PUT", r"/policy"),
    ("PATCH", r"/policy"),
    ("GET", r"/policy/history"),
    ("GET", r"/policy/history/[0-9]+"),
    ("POST", r"/policy/history/[0-9]+/restore"),
    ("GET", r"/policy/diff"),
    ("GET", r"/policy/export"),
    ("POST", r"/policy/import"),
    ("POST", r"/emergency-stop"),
    ("GET", r"/rules/stats"),
    ("POST", r"/rules/cleanup"),
    ("GET", r"/suggestions"),
    ("GET", r"/learning"),
    ("POST", r"/learning"),
    ("DELETE", r"/learning"),
    ("GET", r"/learning/[a-f0-9]+"),
    ("POST", r"/learning/apply"),
    ("POST", r"/suggestions/(accept|dismiss)"),
    ("GET", r"/pending"),
    ("POST", r"/pending/[a-f0-9]+/decide"),
    ("GET", r"/events"),
    ("GET", r"/events/summary"),
    ("GET", r"/destinations"),
    ("GET", r"/destinations/detail"),
    ("POST", r"/destinations"),
    ("POST", r"/destinations/group"),
    ("POST", r"/destinations/restore-blocks"),
    ("POST", rf"/destinations/{GW_ID}/move"),
    ("PATCH", rf"/destinations/{GW_ID}"),
    ("DELETE", rf"/destinations/{GW_ID}"),
    ("PUT", r"/destinations/grant/[a-z0-9][a-z0-9_-]{0,47}"),
    ("DELETE", r"/destinations/grant/[a-z0-9][a-z0-9_-]{0,47}"),
    ("POST", r"/test"),
    ("GET", r"/presets"),
    ("POST", r"/presets/[A-Za-z_][A-Za-z0-9_]*"),
    ("DELETE", r"/presets/[A-Za-z_][A-Za-z0-9_]*"),
    ("GET", r"/secrets"),
    ("PUT", r"/secrets/[a-z0-9_]+"),
    ("GET", r"/grants"),
    ("POST", r"/grants/[a-z0-9][a-z0-9_-]{0,47}/activate"),
    ("DELETE", r"/active-grants/[a-f0-9]+"),
    ("POST", r"/grant-requests/[a-f0-9]+/decide"),
    ("GET", r"/info"),
    ("GET", r"/never-reachable"),
    ("GET", r"/access"),
    ("GET", r"/model"),
    ("GET", r"/settings"),
    ("PATCH", r"/settings"),
    ("GET", r"/availability"),
    ("PATCH", r"/availability"),
    ("DELETE", r"/availability/missed"),
]


# ------------------------------------------------------------------ auth
def _peer_trusted(request: web.Request) -> bool:
    try:
        peer = ipaddress.ip_address(request.remote or "")
    except ValueError:
        return False
    if not any(peer in n for n in TRUSTED_PROXIES):
        return False
    if PROXY_SECRET:  # constant-time: the header value must not leak through timing
        sent = request.headers.get(PROXY_SECRET_HEADER, "")
        return hmac.compare_digest(sent.encode(), PROXY_SECRET.encode())
    return True


def client_ip(request: web.Request) -> str:
    if TRUST_FORWARDED and _peer_trusted(request) and request.headers.get("X-Forwarded-For"):
        return request.headers["X-Forwarded-For"].split(",")[-1].strip()
    return request.remote or "?"


def _sign(payload: str) -> str:
    return hmac.new(SESSION_SECRET, payload.encode(), hashlib.sha256).hexdigest()


# Server-side sessions: logout and restarts really end a session; idle + absolute expiry.
_sessions: dict[str, dict] = {}


def password_fingerprint() -> str:
    """Identifies the password in effect (environment hash or plain password, else the stored hash), without
    keeping it. A session remembers the fingerprint from its login and ends when it changes, so
    `python -m app.passwd` logs out every session opened with the old password."""
    secret = os.environ.get("CONTROL_PASSWORD_HASH") or os.environ.get("CONTROL_PASSWORD") or bootstrap.password_hash()
    return hmac.new(SESSION_SECRET, b"password:" + secret.encode(), hashlib.sha256).hexdigest()


def make_session(user: str, fingerprint: str | None = None) -> str:
    sid = secrets.token_urlsafe(32)
    now = time.time()
    _sessions[sid] = {"user": user, "exp": now + SESSION_TTL, "seen": now, "pw": fingerprint}
    return f"{sid}.{_sign(sid)}"


def _session_id(request: web.Request) -> str | None:
    raw = request.cookies.get(COOKIE, "")
    sid, _, sig = raw.partition(".")
    # A real cookie is ASCII. Anything else is refused here: compare_digest raises TypeError for a str with
    # non-ASCII characters, and encoding undecodable header bytes raises too (a 500 for any visitor, #246).
    if not sid or not raw.isascii() or not hmac.compare_digest(sig.encode(), _sign(sid).encode()):
        return None
    return sid


def background(request: web.Request) -> bool:
    """True for a request the page made without the user doing anything (#242): it authenticates like any
    other, but does not push the idle timeout back. The header is set by the UI's own code (app.js); whoever
    sits at the keyboard can leave it out, so the idle timeout protects an unattended tab, nothing more."""
    if request.headers.get(POLL_HEADER) == "1":
        return True
    path = request.path
    return path == "/api/stream" or (path.startswith("/term/") and path.endswith("/ws"))


def _hostname(host: str) -> str:
    """The name or address of a Host header value, without port and brackets, lower case."""
    host = host.strip().lower()
    if host.startswith("["):
        return host[1:].partition("]")[0]
    return host.rsplit(":", 1)[0] if host.count(":") == 1 else host


def _is_address(name: str) -> bool:
    try:
        ipaddress.ip_address(name)
    except ValueError:
        return False
    return True


def host_allowed(request: web.Request) -> bool:
    """ALLOWED_HOSTS (#246): when set, a request is served only if its Host is one of these names, the
    name in PUBLIC_URL, `localhost` or an IP address. That closes DNS rebinding: a page on the attacker's
    name that is re-pointed at this server still sends the attacker's name as Host. Unset (the default),
    every Host is served as before, and Setup says so when the UI is opened under a name."""
    if not ALLOWED_HOSTS:
        return True
    trusted = TRUST_FORWARDED and _peer_trusted(request)
    name = _hostname((request.headers.get("X-Forwarded-Host") if trusted else None) or request.host or "")
    if name == "localhost" or _is_address(name) or name in ALLOWED_HOSTS:
        return True
    return bool(PUBLIC_URL) and name == (urllib.parse.urlsplit(PUBLIC_URL).hostname or "").lower()


def read_session(request: web.Request, touch: bool = True) -> str | None:
    """The logged-in user, or None. touch=False checks without counting as activity (idle timeout)."""
    if PROXY_AUTH_HEADER and _peer_trusted(request) and request.headers.get(PROXY_AUTH_HEADER):
        return request.headers[PROXY_AUTH_HEADER][:64]
    sid = _session_id(request)
    s = _sessions.get(sid) if sid else None
    now = time.time()
    if not s or s["exp"] < now or now - s["seen"] > SESSION_IDLE or s.get("pw") != password_fingerprint():
        _sessions.pop(sid, None)  # expired, idle, or the password was changed since this login
        return None
    if touch:
        s["seen"] = now
    return s["user"]


async def session_ended(request: web.Request) -> None:
    """Returns once the request's session is gone (logout, idle or absolute expiry) or the browser has
    disconnected. A stream that stays open does not keep its session alive."""
    while True:
        await asyncio.sleep(SESSION_RECHECK)
        if read_session(request, touch=False) is None or request.transport is None or request.transport.is_closing():
            return


async def _first_done(*coros) -> None:
    """Run the coroutines until the first one finishes, then cancel the rest."""
    tasks = [asyncio.ensure_future(c) for c in coros]
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


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
    if h and not h.startswith("scrypt:"):  # fail closed: never fall back to CONTROL_PASSWORD
        log.error("CONTROL_PASSWORD_HASH is malformed")
        return False
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


def _per_ip_lockout() -> bool:
    # The per-address failure lockout only protects when we actually see per-client addresses. Behind a reverse
    # proxy without trusted forwarding, every client shares the proxy's address, so the lockout would let one
    # attacker lock the operator out (#101). Without it, brute force is still capped at ~1 guess/s by the global
    # lock, plus LOGIN_MAX_WAITING for floods.
    return TRUST_FORWARDED and bool(TRUSTED_PROXIES)


@web.middleware
async def security(request: web.Request, handler):
    path = request.path
    if not host_allowed(request):
        return web.Response(status=421, text="this host name is not in ALLOWED_HOSTS\n")
    if path in LOGIN_FILES or path in PUBLIC_FILES:
        resp = await handler(request)
    elif path == PUSH_ACT:
        # No session (a phone's session may have expired), but the CSRF rule of every other API call, and
        # stricter: the Origin header must be there (#241). Only the service worker calls this, and every
        # browser sends Origin with a POST; the action token in the body is the authentication (webpush.py).
        ours = request.headers.get("Origin") and _same_origin(request)
        if request.method != "POST" or request.headers.get("X-Tallygate") != "1" or not ours:
            return web.json_response({"error": "csrf check failed"}, status=403)
        resp = await handler(request)
    else:
        user = read_session(request, touch=not background(request))
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
        try:
            resp = await handler(request)
        except web.HTTPException:
            raise
        except Exception:
            if not path.startswith("/api/"):
                raise
            log.exception("%s %s failed", request.method, path)
            return web.json_response({"error": "internal error (see the control log)"}, status=500)
    if isinstance(resp, web.StreamResponse) and not resp.prepared:
        _security_headers(resp, path)
    return resp


CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
    "connect-src 'self'; frame-src 'self'; frame-ancestors 'self'; base-uri 'none'; form-action 'self'; "
    "manifest-src 'self'; worker-src 'self'"
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
    elif path.startswith("/static/"):
        # revalidate every load so a UI update (new app.js/style.css) is picked up without a hard reload;
        # unchanged files still get a cheap 304 via Last-Modified. Without this the browser's heuristic cache
        # served stale assets and the sidebar/live connection looked broken until a manual reload.
        resp.headers.setdefault("Cache-Control", "no-cache")


def _request_scheme(request: web.Request) -> str:
    """http or https as the browser sees it: X-Forwarded-Proto counts only from a trusted proxy."""
    trusted = TRUST_FORWARDED and _peer_trusted(request)
    return ((request.headers.get("X-Forwarded-Proto") if trusted else None) or request.scheme).lower()


def cookie_secure(request: web.Request) -> bool:
    """COOKIE_SECURE: 1 = always Secure, 0 = never, auto (default) = Secure exactly when the browser uses HTTPS.
    `auto` makes plain HTTP on the LAN work out of the box and keeps the cookie Secure behind a TLS proxy (#97)."""
    mode = os.environ.get("COOKIE_SECURE", "auto").strip().lower()
    if mode in ("1", "true", "yes"):
        return True
    if mode in ("0", "false", "no"):
        return False
    # PUBLIC_URL says how browsers reach the UI: behind a TLS proxy whose X-Forwarded-Proto is not trusted
    # the request itself looks like plain HTTP, and the cookie would go out without Secure (#246)
    return _request_scheme(request) == "https" or PUBLIC_URL.lower().startswith("https://")


def _expected_origin(request: web.Request) -> str:
    if PUBLIC_URL:
        u = urllib.parse.urlsplit(PUBLIC_URL)
        return f"{u.scheme}://{u.netloc}".lower()
    trusted = TRUST_FORWARDED and _peer_trusted(request)
    host = (request.headers.get("X-Forwarded-Host") if trusted else None) or request.host
    return f"{_request_scheme(request)}://{host}".lower()


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
    if _per_ip_lockout() and len(_recent_failures(ip, time.time())) >= LOGIN_MAX_FAILURES:
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
            if _per_ip_lockout() and len(fails) >= LOGIN_MAX_FAILURES:
                return too_many
            # taken before the check: a password change during the check can only end the new session
            fingerprint = password_fingerprint()
            ok = await asyncio.get_running_loop().run_in_executor(None, check_password, pw)
            if not ok:
                if _per_ip_lockout():  # meaningless and unbounded when every client shares one address
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
            make_session("admin", fingerprint),
            max_age=SESSION_TTL,
            httponly=True,
            # Lax, not Strict: the PUBLIC_URL link in a Telegram/Matrix message is a cross-site navigation
            # and must arrive logged in. Cross-site POSTs still carry no cookie, and every state-changing
            # API call additionally needs the X-Tallygate header and a same-origin Origin.
            samesite="Lax",
            secure=cookie_secure(request),
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


async def public_file(request: web.Request):
    name, ctype = PUBLIC_FILES[request.path]
    resp = web.FileResponse(STATIC / name, headers={"Content-Type": ctype, "Cache-Control": "no-cache"})
    if name == "sw.js":
        resp.headers["Service-Worker-Allowed"] = "/"
    return resp


# ------------------------------------------------------------------ Web Push (#72)
def _push(request: web.Request) -> webpush.WebPush:
    push = request.app["webpush"]
    if push is None:
        raise web.HTTPServiceUnavailable(
            text=json.dumps({"error": "Web Push is off: the control data volume is not writable"}),
            content_type="application/json",
        )
    return push


async def api_push(request: web.Request):
    """Web Push status: the VAPID public key for subscribing, and the subscribed devices."""
    push = request.app["webpush"]
    if push is None:
        return web.json_response({"enabled": False, "subscriptions": []})
    return web.json_response(
        {"enabled": True, "public_key": push.public_key, "subscriptions": [push.public(x) for x in push.subs]}
    )


async def api_push_subscribe(request: web.Request):
    push = _push(request)
    body = await json_body(request)
    if not isinstance(body, dict):
        return web.json_response({"error": "expected a JSON object"}, status=400)
    try:
        sub = push.add(body.get("subscription"), str(body.get("label", "")))
    except ValueError as e:
        return web.json_response({"error": str(e)}, status=400)
    log.info("web push: %s subscribed (%s) by %s", sub["label"], sub["service"], request["user"])
    return web.json_response(sub, status=201)


async def api_push_delete(request: web.Request):
    if not _push(request).remove(request.match_info["sid"]):
        return web.json_response({"error": "no such device"}, status=404)
    return web.json_response({"ok": True})


async def api_push_test(request: web.Request):
    push = _push(request)
    if not push.subs:
        return web.json_response({"error": "no device subscribed"}, status=400)
    try:
        n = await request.app["notifier"]._push_all(
            lambda _s: {"title": "tallygate", "body": "Test notification: phone approvals work.", "tag": "test"}, 300
        )
    except RuntimeError as e:
        return web.json_response({"error": str(e)}, status=502)
    return web.json_response({"delivered": n})


async def api_notify_test(request: web.Request):
    """Send a one-off test notification through a single bot channel (#180). Body: {"channel": ...}.
    Web Push is tested separately via /api/push/test (it is subscribed per browser, not configured here).
    400 if the channel is unknown or not configured; 502 if the channel's service rejected the send."""
    body = await json_body(request)
    channel = body.get("channel") if isinstance(body, dict) else None
    notifier = request.app["notifier"]
    label = notify.CHANNEL_LABELS.get(channel, "channel") if isinstance(channel, str) else "channel"
    try:
        await notifier.send_test(channel)
    except ValueError as e:
        return web.json_response({"error": str(e)}, status=400)
    except (aiohttp.ClientError, TimeoutError, RuntimeError) as e:
        # What the other side said never reaches the browser (#240): with a channel URL of its choosing, a
        # UI session could otherwise read answers of servers only control can reach. The UI gets a fixed
        # text and the class of the HTTP status; the detail is in the log, tokens redacted. Telegram is the
        # exception: its host is not a setting, and its description ("chat not found") is the useful part.
        log.warning("notification test through %s failed: %s", channel, notifier.redact(str(e))[:300])
        if isinstance(e, (UpstreamRedirect, RefusedDestination)):
            text = str(e)  # our own fixed texts
        elif isinstance(e, notify.ChannelError):
            text = f"{label} answered with an error (HTTP {e.status // 100}xx): see the control log"
        elif isinstance(e, TimeoutError):
            text = f"{label} did not answer in time"
        elif isinstance(e, aiohttp.ClientError):
            text = f"{label} could not be reached: see the control log"
        else:
            text = notifier.redact(str(e)) if channel == "telegram" else f"{label}: failed, see the control log"
        return web.json_response({"error": text}, status=502)
    log.info("notification test sent through %s by %s", channel, request["user"])
    return web.json_response({"ok": True, "channel": channel})


def _notify_config(app: web.Application) -> dict:
    """The channel settings as the UI may see them: no secret values, only set / source (#201)."""
    data = app["notifycfg"].public()
    status = {c["channel"]: c for c in app["notifier"].status()}
    for c in data["channels"]:
        st = status[c["channel"]]
        c.update(label=st["label"], active=st["configured"], reason=st["reason"])
    data["actions"] = app["notifycfg"].public_actions()  # the buttons of a connection request (#212)
    return data


async def api_notify_config(request: web.Request):
    return web.json_response(_notify_config(request.app))


async def api_notify_config_put(request: web.Request):
    """Save UI settings for one bot channel and apply them at once. Body: {field: value, ...}. A secret
    sent empty keeps the stored one; a non-secret field sent empty falls back to the environment.
    400 for a bad channel/field/value, 503 when the data volume is not writable. Values are never logged."""
    channel = request.match_info["channel"]
    try:
        changed = request.app["notifycfg"].update(channel, await json_body(request))
    except notifyconfig.ConfigError as e:
        return web.json_response({"error": str(e)}, status=400)
    except notifyconfig.ReadOnlyError as e:
        return web.json_response({"error": str(e)}, status=503)
    restarted = await request.app["notifier"].reconfigure()
    log.info(
        "notification config: %s saved by %s (changed: %s; poll loops restarted: %s)",
        channel,
        request["user"],
        ", ".join(changed) or "nothing",
        ", ".join(restarted) or "none",
    )
    return web.json_response({"ok": True, "changed": changed, **_notify_config(request.app)})


async def api_notify_config_delete(request: web.Request):
    """Drop the UI override of one bot channel: it falls back to the environment (or switches off)."""
    channel = request.match_info["channel"]
    try:
        removed = request.app["notifycfg"].remove(channel)
    except notifyconfig.ConfigError as e:
        return web.json_response({"error": str(e)}, status=400)
    except notifyconfig.ReadOnlyError as e:
        return web.json_response({"error": str(e)}, status=503)
    restarted = await request.app["notifier"].reconfigure()
    if removed:
        log.info(
            "notification config: UI override of %s removed by %s (poll loops restarted: %s)",
            channel,
            request["user"],
            ", ".join(restarted) or "none",
        )
    return web.json_response({"ok": True, "removed": removed, **_notify_config(request.app)})


async def api_notify_actions_put(request: web.Request):
    """Choose the buttons of a connection-approval notification (#212). Body: {"actions": ["once", ...]}:
    1 to 4 of the gateway's fixed approval scopes, in the order they are shown. It applies to the next
    request; buttons that were sent before and are no longer chosen stop working (webpush.redeem).
    400 for an unknown action, an empty or too long list or a duplicate; 503 when the data volume is not writable."""
    body = await json_body(request)
    try:
        actions = request.app["notifycfg"].set_actions(body.get("actions") if isinstance(body, dict) else None)
    except notifyconfig.ConfigError as e:
        return web.json_response({"error": str(e)}, status=400)
    except notifyconfig.ReadOnlyError as e:
        return web.json_response({"error": str(e)}, status=503)
    log.info("notification buttons: %s saved by %s", ", ".join(actions), request["user"])
    return web.json_response({"ok": True, **_notify_config(request.app)})


async def api_notify_actions_delete(request: web.Request):
    """Forget the chosen buttons: every channel shows its default again (Web Push: Allow once, Deny)."""
    try:
        removed = request.app["notifycfg"].reset_actions()
    except notifyconfig.ReadOnlyError as e:
        return web.json_response({"error": str(e)}, status=503)
    if removed:
        log.info("notification buttons: back to the default by %s", request["user"])
    return web.json_response({"ok": True, "removed": removed, **_notify_config(request.app)})


def _done_text(kind: str, decision: str, data: object) -> str:
    """What the notification says after its button was applied; names the rule the gateway installed."""
    if kind != "ask":
        return "Denied" if decision == "deny" else "Approved"
    rule = data.get("rule") if isinstance(data, dict) else None
    rule = rule if isinstance(rule, dict) else {}
    what = "".join(c for c in str(rule.get("host") or rule.get("cidr") or "")[:80] if c.isprintable())
    verb = "Allowed" if notifyconfig.ASK_ACTIONS[decision][2] == "allow" else "Denied"
    how = {"once": "for 2 min", "hour": "for 1 h", "deny": "for 2 min"}.get(decision, "permanently")
    return " ".join(x for x in (verb, what, how) if x)


async def api_push_act(request: web.Request):
    """A button in a push notification: {"token": ...}. The token says what to decide (see app/webpush.py):
    nothing else in the request does, and only the buttons that are switched on right now are accepted."""
    push = _push(request)
    body = await json_body(request)
    try:
        claims = push.redeem(
            body.get("token", "") if isinstance(body, dict) else "", ask=request.app["notifycfg"].actions()
        )
    except (ValueError, KeyError, TypeError) as e:
        msg = str(e) if isinstance(e, ValueError) and "invalid" not in str(e) else "invalid action"
        return web.json_response({"error": msg}, status=403)
    if not re.fullmatch(r"[a-f0-9]{1,32}", str(claims["i"])):
        return web.json_response({"error": "invalid action"}, status=403)
    by = f"push:{push.label(claims['s'])}"
    if claims["k"] == "ask":
        path, payload = f"/pending/{claims['i']}/decide", {"scope": claims["d"], "by": by}
    else:
        path, payload = f"/grant-requests/{claims['i']}/decide", {"decision": claims["d"], "by": by}
    try:
        status, data = await gw(request.app, "POST", path, payload)
    except (TimeoutError, aiohttp.ClientError, ValueError) as e:
        return web.json_response({"error": f"gateway unreachable: {e}"}, status=502)
    if status != 200:
        return web.json_response({"error": "already decided or expired"}, status=409)
    log.info("web push action %s %s %s by %s", claims["k"], claims["i"], claims["d"], by)
    message = _done_text(claims["k"], claims["d"], data)
    return web.json_response({"ok": True, "decision": claims["d"], "message": message})


# ------------------------------------------------------------------ outbound HTTP (#230)
# Control never follows a redirect and never accepts one as an answer, whoever sends it: the agent's status
# server and ttyd run as the agent user, so a hostile agent can answer any call with "302 Location: <any
# URL>", and control (on mgmt, with a route to the LAN and the internet) would fetch that URL itself, around
# the gateway. Every client session is made by _client(): a redirect raises UpstreamRedirect before a second
# request is built, for HTTP and WebSocket alike, so a new call site cannot forget it. The sessions for the
# agent and the gateway can in addition connect to nothing but that one peer.
class UpstreamRedirect(aiohttp.ClientError):
    """A 3xx answer. The text is fixed: nothing the other side sent (status, Location, body) is in it."""

    def __init__(self) -> None:
        super().__init__("answered with a redirect, which control never follows")


class PinnedPeer(aiohttp.ClientError):
    def __init__(self) -> None:
        super().__init__("destination refused: this client connects to one configured peer only")


async def _refuse_redirect(_session, _ctx, params) -> None:
    # on_request_redirect: aiohttp is about to follow; on_request_end: a 3xx it would not follow (300, 304, ...)
    if 300 <= params.response.status < 400:
        raise UpstreamRedirect  # aiohttp closes the response; the Location header is never read


class PinnedConnector(aiohttp.TCPConnector):
    """Connects only to the (host, port) pairs `allowed()` returns right now; everything else is refused
    before any name is resolved or any socket is opened."""

    def __init__(self, allowed, **kw) -> None:
        super().__init__(**kw)
        self._allowed = allowed

    async def connect(self, req, traces, timeout):
        if ((req.url.host or "").lower(), req.url.port) not in self._allowed():
            raise PinnedPeer
        return await super().connect(req, traces, timeout)


class RefusedDestination(aiohttp.ClientError):
    def __init__(self, reason: str) -> None:
        super().__init__(f"destination refused: the URL {reason}")


class GuardedResolver(aiohttp.abc.AbstractResolver):
    """Resolves like the default resolver and refuses the name if any of its addresses is one a channel URL
    may not point at. The connector connects to exactly the addresses returned here (no second lookup),
    so a name cannot pass the check with one address and be reached at another (DNS rebinding, #240)."""

    def __init__(self) -> None:
        self._inner = aiohttp.resolver.DefaultResolver()

    async def resolve(self, host: str, port: int = 0, family: int = 0):
        found = await self._inner.resolve(host, port, family)
        for entry in found:
            if reason := notifyconfig.blocked_address(entry["host"]):
                raise RefusedDestination(reason)
        return found

    async def close(self) -> None:
        await self._inner.close()


class GuardedConnector(aiohttp.TCPConnector):
    """For the notification channels whose URL is free text: no connection to this machine, link-local
    addresses or the stack itself, whether the URL says so or its name resolves there. Checked for every
    connection, not only when the URL is saved."""

    def __init__(self, **kw) -> None:
        super().__init__(resolver=GuardedResolver(), **kw)

    async def connect(self, req, traces, timeout):
        if reason := notifyconfig.blocked_host(req.url.host or ""):
            raise RefusedDestination(reason)
        return await super().connect(req, traces, timeout)


def _client(allowed=None, guarded: bool = False) -> aiohttp.ClientSession:
    """The only place a client session is created. `allowed`: the peers it may connect to (None = any host:
    GitHub and the notification services the operator configured). `guarded`: any host except the ones a
    notification channel URL may not point at (notifyconfig.blocked_host)."""
    trace = aiohttp.TraceConfig()
    trace.on_request_redirect.append(_refuse_redirect)
    trace.on_request_end.append(_refuse_redirect)
    return aiohttp.ClientSession(
        trust_env=False,
        trace_configs=[trace],
        connector=PinnedConnector(allowed) if allowed else GuardedConnector() if guarded else None,
        cookie_jar=aiohttp.DummyCookieJar(),  # no call needs cookies: none are kept
    )


def _agent_peers() -> set[tuple[str, int]]:
    return {(AGENT_HOST.lower().strip("[]"), port) for port in (AGENT_STATUS_PORT, *TERMINALS.values())}


def _gateway_peers() -> set[tuple[str, int | None]]:
    u = urllib.parse.urlsplit(GW_URL)
    return {((u.hostname or "").lower(), u.port or (443 if u.scheme == "https" else 80))}


def _redirect_502(who: str) -> web.Response:
    log.warning("%s answered with a redirect: not followed", who)
    return web.json_response({"error": f"{who} answered with a redirect, which is never followed"}, status=502)


# ------------------------------------------------------------------ gateway relay
class GatewayPath(ValueError):
    def __init__(self) -> None:
        super().__init__("gateway path refused")


GW_PATH = re.compile(r"(?:/[A-Za-z0-9_:.-]+)+")


def gw_url(path: str, params=None) -> yarl.URL:
    """The gateway URL for an API path, exactly as written (#244, #239). The path is sent as it is
    (`encoded=True`: nothing is normalised or re-quoted, so "a/../b" could not become "b"), and a path
    with "..", "?" or "#" in it, or any character outside the ones the gateway's routes use, is refused
    outright: whatever a caller interpolated, the request goes to the route the caller named or nowhere.
    A query string is given as `params` and encoded here, never as part of the path."""
    if not isinstance(path, str) or ".." in path or not GW_PATH.fullmatch(path):
        raise GatewayPath
    url = yarl.URL(GW_URL + path, encoded=True)
    return url.with_query(params) if params else url


async def gw(app: web.Application, method: str, path: str, body=None, timeout: float = 15, by: str = "", params=None):
    headers = {"Authorization": f"Bearer {GW_TOKEN}"}
    if by:
        # attribution in the gateway's policy history: printable ASCII only (it travels in a header)
        headers["X-Tallygate-By"] = "".join(c if " " <= c <= "~" else "?" for c in by)[:64]
    async with app["gw"].request(
        method,
        gw_url(path, params),
        json=body,
        headers=headers,
        timeout=aiohttp.ClientTimeout(total=timeout),
    ) as r:
        data = await r.json(content_type=None)
        return r.status, data


async def json_body(request: web.Request):
    """The request's JSON body (None if there is none); 400 with {"error": ...} if it is not JSON."""
    if not request.can_read_body:
        return None
    try:
        return await request.json()
    except ValueError:
        raise web.HTTPBadRequest(
            text=json.dumps({"error": "invalid JSON body"}), content_type="application/json"
        ) from None


async def api_gw(request: web.Request):
    sub = "/" + request.match_info["tail"]
    if not any(m == request.method and re.fullmatch(rx, sub) for m, rx in GW_ALLOW):
        return web.json_response({"error": "not allowed"}, status=404)
    body = await json_body(request)
    by = f"web:{request['user']}"
    if sub == "/emergency-stop":
        body = {}  # nothing to choose: the whole stop always runs
    attributed = sub.endswith("/decide") or sub.endswith("/activate") or sub in ("/emergency-stop", "/availability")
    if attributed and isinstance(body, dict):
        body["by"] = by  # attribution is set here, never taken from the browser
    params = {"by": by} if sub.startswith("/active-grants/") else request.query
    try:
        status, data = await gw(request.app, request.method, sub, body, by=by, params=params)
    except GatewayPath:  # the allow-list lets nothing through that gw() refuses; if it ever does: no request
        return web.json_response({"error": "not allowed"}, status=404)
    except UpstreamRedirect:
        return _redirect_502("the gateway")
    except (TimeoutError, aiohttp.ClientError) as e:
        return web.json_response({"error": f"gateway unreachable: {e}"}, status=502)
    except ValueError:
        return web.json_response({"error": "invalid response from the gateway"}, status=502)
    return web.json_response(data, status=status)


async def api_stream(request: web.Request):
    """Relay the gateway's SSE stream to the browser."""
    resp = web.StreamResponse(
        headers={"Content-Type": "text/event-stream", "Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
    )
    await resp.prepare(request)

    async def relay():
        try:
            async with request.app["gw"].get(
                GW_URL + "/stream",
                headers={"Authorization": f"Bearer {GW_TOKEN}"},
                timeout=aiohttp.ClientTimeout(total=None, sock_read=60),
            ) as up:
                async for chunk in up.content.iter_any():
                    await resp.write(chunk)
        except (TimeoutError, aiohttp.ClientError, ConnectionResetError):
            pass

    await _first_done(relay(), session_ended(request))  # logout/expiry ends the stream
    return resp


async def api_github_check(request: web.Request):
    """Validate the stored-at-gateway token by calling GitHub from the control plane (which has egress).
    The token is sent once from the browser for validation and storage; it is never returned."""
    body = await json_body(request)
    if not isinstance(body, dict):
        return web.json_response({"error": "expected a JSON object"}, status=400)
    token = str(body.get("token", "")).strip()
    if not token:
        return web.json_response({"error": "token missing"}, status=400)
    try:
        async with request.app["http"].get(
            GITHUB_API + "/user",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
            timeout=aiohttp.ClientTimeout(total=15),
        ) as r:
            data = await r.json(content_type=None)
            if not isinstance(data, dict):
                raise ValueError("not an object")
            if r.status != 200:
                return web.json_response({"ok": False, "status": r.status, "message": data.get("message")})
            info = {
                "ok": True,
                "login": data.get("login"),
                "scopes": r.headers.get("X-OAuth-Scopes"),
                "expires": r.headers.get("github-authentication-token-expiration"),
            }
    except (TimeoutError, aiohttp.ClientError) as e:
        return web.json_response({"error": f"GitHub unreachable: {e}"}, status=502)
    except ValueError:
        return web.json_response({"error": "invalid response from GitHub"}, status=502)
    if body.get("store"):
        try:
            status, _ = await gw(request.app, "PUT", "/secrets/github_token", {"value": token})
        except (TimeoutError, aiohttp.ClientError, ValueError) as e:
            return web.json_response({"error": f"token valid, but storing it in the gateway failed: {e}"}, status=502)
        info["stored"] = status == 200
    return web.json_response(info)


# Endpoints of the agent's status server (agent/status.py) the UI may use. The setup actions only do what
# the agent user can do in its own container anyway (start `claude auth login`, set the git identity, give
# Remote Control's consent); control adds the session and CSRF checks and treats every answer as untrusted.
AGENT_ROUTES = {
    ("GET", "status"),
    ("GET", "selftest"),
    ("GET", "setup/claude-login"),
    ("POST", "setup/claude-login"),
    ("POST", "setup/claude-code"),
    ("GET", "setup/git-identity"),
    ("POST", "setup/git-identity"),
    ("POST", "setup/remote-control"),
}
AGENT_SETUP_MAX_BODY = 4096
# The agent reports the login URL it read from `claude auth login`. It is shown as a link, so only Anthropic's
# login pages pass: a compromised agent must not be able to send the operator to a page of its choosing.
LOGIN_URL_HOSTS = {"claude.com", "claude.ai", "platform.claude.com", "console.anthropic.com"}


def safe_login_url(url: object) -> str:
    if not isinstance(url, str) or len(url) > 2048 or any(c in url for c in " \"'<>\\\r\n\t"):
        return ""
    u = urllib.parse.urlsplit(url)
    if u.scheme != "https" or u.hostname not in LOGIN_URL_HOSTS or u.port or u.username or u.password:
        return ""
    return url if u.path.endswith("/oauth/authorize") else ""


async def agent_call(app: web.Application, method: str, what: str, body: dict | None = None) -> tuple[int, dict]:
    """Call the agent's status server; the answer is size-limited and must be a JSON object."""
    async with app["agent"].request(
        method, f"http://{AGENT_HOST}:{AGENT_STATUS_PORT}/{what}", json=body, timeout=aiohttp.ClientTimeout(total=90)
    ) as r:
        raw = b""  # read() returns what has arrived so far: read until the end or the cap
        while len(raw) <= AGENT_MAX_BYTES and (chunk := await r.content.read(AGENT_MAX_BYTES + 1 - len(raw))):
            raw += chunk
        if len(raw) > AGENT_MAX_BYTES:
            raise ValueError("agent response too large")
        try:
            data = json.loads(raw)
        except RecursionError:  # "[[[[..." a few thousand deep: not a ValueError, and no handler expects it
            raise ValueError("nested too deeply") from None
        if not isinstance(data, dict):
            raise ValueError("not an object")
        return r.status, data


async def api_agent(request: web.Request):
    """Agent status, self-test and setup actions (served by agent/status.py on the agent network)."""
    what = request.match_info["what"]
    if (request.method, what) not in AGENT_ROUTES:
        raise web.HTTPNotFound()
    body = None
    if request.method == "POST":
        if (request.content_length or 0) > AGENT_SETUP_MAX_BODY:
            return web.json_response({"error": "request too large"}, status=413)
        body = await json_body(request)
        if body is None:
            body = {}
        if not isinstance(body, dict):
            return web.json_response({"error": "expected a JSON object"}, status=400)
    try:
        status, data = await agent_call(request.app, request.method, what, body)
        data = agentschema.clean(request.method, what, data)  # known keys, expected types, capped (#243)
    except UpstreamRedirect:
        return _redirect_502("the agent")
    except ValueError as e:
        msg = "agent response too large" if "too large" in str(e) else f"agent unreachable or invalid response: {e}"
        return web.json_response({"error": msg}, status=502)
    except (TimeoutError, aiohttp.ClientError) as e:
        return web.json_response({"error": f"agent unreachable or invalid response: {e}"}, status=502)
    if what.startswith("setup/claude-"):
        data["url"] = safe_login_url(data.get("url"))
    if status != 200:  # the agent's own refusals (400/409) are passed on; anything else is a failure
        status = status if status in (400, 409) else 502
    return web.json_response(data, status=status)


LOCAL_HOSTS = ("localhost", "127.0.0.1", "[::1]", "::1")


def password_state() -> str:
    if PROXY_AUTH_HEADER:
        return "proxy"
    if os.environ.get("CONTROL_PASSWORD_HASH"):
        return "env-hash"
    if os.environ.get("CONTROL_PASSWORD"):
        return "env-plain"
    return "generated" if bootstrap.password_generated() else "changed"


async def api_setup_checks(request: web.Request):
    """How this browser reaches the UI: HTTPS, cookie flag, forwarded headers, reverse proxy, PUBLIC_URL.
    The page passes its own origin (`?origin=`), which is compared, never trusted for anything."""
    origin = request.query.get("origin", "")[:300].lower()
    u = urllib.parse.urlsplit(origin)
    browser_scheme, browser_host = u.scheme, (u.hostname or "")
    scheme = _request_scheme(request)
    local = browser_host in LOCAL_HOSTS
    checks = []

    def add(cid: str, state: str, title: str, detail: str) -> None:
        checks.append({"id": cid, "state": state, "title": title, "detail": detail})

    if scheme == "https":
        add("https", "ok", "Encrypted", "The browser reaches the UI over HTTPS.")
    elif local:
        add("https", "ok", "Local connection", "Plain HTTP on this machine (or through an SSH tunnel) is fine.")
    else:
        add(
            "https",
            "warn",
            "Not encrypted",
            "Plain HTTP from another machine: the password and the session travel unencrypted. "
            "Acceptable only on a network you trust; otherwise put a TLS reverse proxy in front or use an SSH "
            "tunnel (docs/operations.md#reaching-the-ui).",
        )
    secure, mode = cookie_secure(request), os.environ.get("COOKIE_SECURE", "auto").strip().lower() or "auto"
    if scheme == "https" and not secure:
        add("cookie", "bad", "Session cookie", f"COOKIE_SECURE={mode}: the cookie is not marked Secure over HTTPS.")
    elif scheme != "https" and secure and not local:
        add("cookie", "bad", "Session cookie", f"COOKIE_SECURE={mode}: a Secure cookie is not kept over plain HTTP.")
    else:
        add(
            "cookie",
            "ok",
            "Session cookie",
            f"{'Secure' if secure else 'Not Secure (plain HTTP)'}, COOKIE_SECURE={mode}.",
        )
    fwd = [h for h in ("X-Forwarded-For", "X-Forwarded-Proto", "X-Forwarded-Host") if h in request.headers]
    trusted = TRUST_FORWARDED and _peer_trusted(request)
    if fwd and trusted:
        add("proxy", "ok", "Reverse proxy", f"Detected and trusted ({request.remote} is in TRUSTED_PROXIES).")
    elif fwd:
        add(
            "proxy",
            "warn",
            "Reverse proxy",
            f"A proxy at {request.remote} sends {', '.join(fwd)}, which is ignored. To use it, set "
            f"TRUST_FORWARDED_FOR=1 and TRUSTED_PROXIES={request.remote}/32.",
        )
    elif TRUST_FORWARDED:
        add("proxy", "warn", "Reverse proxy", "TRUST_FORWARDED_FOR=1, but this request came without forwarded headers.")
    else:
        add("proxy", "ok", "Direct connection", "No reverse proxy in between; forwarded headers are not trusted.")
    browser_origin = f"{browser_scheme}://{u.netloc}" if browser_scheme and u.netloc else ""
    if PUBLIC_URL:
        p = urllib.parse.urlsplit(PUBLIC_URL)
        want = f"{p.scheme}://{p.netloc}".lower()
        if browser_origin and browser_origin != want:
            add(
                "public_url",
                "bad",
                "PUBLIC_URL",
                f"PUBLIC_URL is {want}, but this browser uses {browser_origin}: changes are refused (origin check). "
                "Open the UI at PUBLIC_URL or correct it.",
            )
        else:
            add("public_url", "ok", "PUBLIC_URL", f"Matches this browser ({want}).")
    else:
        add(
            "public_url",
            "info",
            "PUBLIC_URL",
            "Not set. Set it to the address you use, so links in Telegram and Matrix messages open the UI.",
        )
    name = _hostname(request.host or "")
    if ALLOWED_HOSTS:
        add(
            "hosts",
            "ok",
            "Host names",
            f"Served only as {', '.join(sorted(ALLOWED_HOSTS))} (ALLOWED_HOSTS), by address and at PUBLIC_URL.",
        )
    elif not PUBLIC_URL and name != "localhost" and not _is_address(name):
        add(
            "hosts",
            "warn",
            "Host names",
            f"The UI answers under any host name (you use {name[:100]}). A web page you visit can then reach "
            "the login form through DNS rebinding and try passwords. Set PUBLIC_URL to the address you use "
            f"and ALLOWED_HOSTS={name[:100]} (docs/configuration.md).",
        )
    add(
        "reach",
        "info",
        "From another machine",
        (f"Other devices use the same address: {browser_origin}. " if browser_origin and not local else "")
        + "By default the UI is published only on the Docker host itself (CONTROL_PUBLISH=127.0.0.1:8080): "
        "other machines reach it through a TLS reverse proxy on that host or an SSH tunnel "
        "(ssh -L 8080:127.0.0.1:8080 <host>). CONTROL_PUBLISH=0.0.0.0:8080 publishes it on every interface "
        "of the host, unencrypted: http://<host's LAN address>:8080, for a trusted network only.",
    )
    return web.json_response({"checks": checks, "password": password_state()})


# ------------------------------------------------------------------ versions and update notice (#81)
# Control asks GitHub's releases API itself (it has egress on mgmt), never through the agent. UPDATE_CHECK=0
# switches it off. Results are cached: a release for 6 h, a failure for 30 min.
UPDATE_REPO = "PhilippMundhenk/tallygate"
UPDATE_COMPOSE = f"https://github.com/{UPDATE_REPO}/releases/latest/download/compose.yaml"
UPDATE_TTL, UPDATE_RETRY = 6 * 3600, 30 * 60
UPDATE_MAX_BYTES = 256 * 1024
RELEASE_TAG = re.compile(r"v?(\d{1,4})\.(\d{1,4})\.(\d{1,6})")
_release: dict = {}  # {"at": ts, "data": {...}}
_release_lock = asyncio.Lock()


def update_check_enabled() -> bool:
    return os.environ.get("UPDATE_CHECK", "1").strip().lower() not in ("0", "false", "no", "off")


def parse_version(v: object) -> tuple[int, int, int] | None:
    m = RELEASE_TAG.fullmatch(str(v or "").strip())
    return tuple(int(x) for x in m.groups()) if m else None  # type: ignore[return-value]


async def latest_release(app: web.Application) -> dict:
    """{"version", "url", "published"} of the latest release, or {"error"}; cached."""
    async with _release_lock:
        now = time.time()
        if _release and now - _release["at"] < (UPDATE_RETRY if "error" in _release["data"] else UPDATE_TTL):
            return _release["data"]
        try:
            async with app["http"].get(
                f"{GITHUB_API}/repos/{UPDATE_REPO}/releases/latest",
                headers={"Accept": "application/vnd.github+json", "User-Agent": "tallygate-update-check"},
                timeout=aiohttp.ClientTimeout(total=15),
            ) as r:
                raw = b""  # read() returns what has arrived so far: read until the end or the cap
                while len(raw) <= UPDATE_MAX_BYTES and (chunk := await r.content.read(UPDATE_MAX_BYTES + 1 - len(raw))):
                    raw += chunk
                if r.status == 404:
                    # releases/latest is 404 when the repo has published no releases yet: a normal
                    # state (fresh install, development build), not a failure to report in red.
                    data = {"none": True}
                elif r.status != 200:
                    raise ValueError(f"GitHub answered {r.status}")
                else:
                    if len(raw) > UPDATE_MAX_BYTES:
                        raise ValueError("answer too large")
                    rel = json.loads(raw)
                    tag = rel.get("tag_name") if isinstance(rel, dict) else None
                    v = parse_version(tag)
                    if not v:
                        raise ValueError("no release version in the answer")
                    published = str(rel.get("published_at") or "")[:40]
                    data = {
                        "version": ".".join(map(str, v)),
                        # built here, not taken from the answer
                        "url": f"https://github.com/{UPDATE_REPO}/releases/tag/{urllib.parse.quote(str(tag))}",
                        "published": published if re.fullmatch(r"[0-9TZ:.+-]*", published) else "",
                    }
        except (TimeoutError, aiohttp.ClientError, ValueError) as e:
            data = {"error": f"update check failed: {e}"[:200]}
        _release.update(at=now, data=data)
        return data


async def api_version(request: web.Request):
    """The running versions in one place and whether a newer tallygate release exists."""
    app = request.app
    out: dict = {
        "tallygate": None,
        "claude_code": None,
        "changelog": f"https://github.com/{UPDATE_REPO}/blob/main/CHANGELOG.md",
        # the compose file carries the isolation settings of its release and is pinned to its images (#232)
        "upgrade": f"cp -p compose.yaml compose.yaml.previous && curl -fsSLO {UPDATE_COMPOSE} && "
        "docker compose pull && docker compose up -d",
        "check": "off",
        "latest": None,
        "update_available": None,
    }
    try:
        _, info = await gw(app, "GET", "/info")
        if isinstance(info, dict) and parse_version(info.get("version")):
            out["tallygate"] = str(info["version"])
    except (TimeoutError, aiohttp.ClientError, ValueError):
        pass
    try:
        _, st = await agent_call(app, "GET", "status")
        v = re.match(r"\d{1,4}\.\d{1,4}\.\d{1,6}", str(st.get("claude_version", "")))
        out["claude_code"] = v.group(0) if v else None
    except (TimeoutError, aiohttp.ClientError, ValueError):
        pass
    if update_check_enabled():
        rel = await latest_release(app)
        if "error" in rel:
            out.update(check="error", error=rel["error"])
        elif rel.get("none"):
            out.update(check="none")  # no releases published yet — benign
        else:
            out.update(check="ok", latest=rel)
            cur = parse_version(out["tallygate"])
            out["update_available"] = parse_version(rel["version"]) > cur if cur else None
    return web.json_response(out)


# ------------------------------------------------------------------ workspace files (#76)
# Through the agent's status server only (no new network path). Paths are checked here and again in the agent
# (which also refuses symlink escapes). Downloads are attachments of type application/octet-stream with a
# sandboxing CSP: nothing from the workspace is ever rendered on the UI origin.
FILES_MAX_UPLOAD = int(os.environ.get("FILES_MAX_UPLOAD", str(50 * 1024 * 1024)))
FILES_MAX_DOWNLOAD = int(os.environ.get("FILES_MAX_DOWNLOAD", str(200 * 1024 * 1024)))
FILE_TYPES = {"file", "dir", "link", "other"}
FILE_CHUNK = 64 * 1024


def files_path(request: web.Request, file: bool = False) -> str:
    """The normalised relative path of ?path= (400 if it is absolute, has . / .. or control characters)."""
    p = request.query.get("path", "")
    parts = [x for x in p.split("/") if x]
    bad = len(p) > 1024 or p.startswith("/") or "\\" in p or re.search(r"[\x00-\x1f\x7f]", p)
    if bad or any(x in (".", "..") for x in parts) or (file and not parts):
        raise web.HTTPBadRequest(text=json.dumps({"error": "invalid path"}), content_type="application/json")
    return "/".join(parts)


def _agent_files_url(what: str, **query) -> str:
    return f"http://{AGENT_HOST}:{AGENT_STATUS_PORT}/{what}?" + urllib.parse.urlencode(query)


def _agent_status(status: int) -> int:
    return status if status in (400, 403, 404, 409, 411, 413) else 502


async def api_files_list(request: web.Request):
    path = files_path(request)
    try:
        status, data = await agent_call(request.app, "GET", "files?" + urllib.parse.urlencode({"path": path}))
    except UpstreamRedirect:
        return _redirect_502("the agent")
    except (TimeoutError, aiohttp.ClientError, ValueError) as e:
        return web.json_response({"error": f"agent unreachable or invalid response: {e}"}, status=502)
    if status != 200:
        return web.json_response({"error": str(data.get("error", "failed"))[:200]}, status=_agent_status(status))
    entries = []
    raw = data.get("entries")
    for e in raw if isinstance(raw, list) else []:
        if not isinstance(e, dict):
            continue
        name, kind, size, mtime = e.get("name"), e.get("type"), e.get("size"), e.get("mtime")
        if (
            not isinstance(name, str)
            or not 0 < len(name) <= 255
            or "/" in name
            or name in (".", "..")
            or re.search(r"[\x00-\x1f\x7f]", name)
            or kind not in FILE_TYPES
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
            or not isinstance(mtime, (int, float))
        ):
            continue  # the agent's answer is untrusted: odd entries are dropped
        entries.append({"name": name, "type": kind, "size": size, "mtime": mtime})
    return web.json_response(
        {
            "path": path,
            "entries": entries[:2000],
            "truncated": data.get("truncated") is True,
            "max_upload": FILES_MAX_UPLOAD,
            "max_download": FILES_MAX_DOWNLOAD,
        }
    )


def content_disposition(name: str) -> str:
    ascii_name = re.sub(r"[^A-Za-z0-9._-]", "_", name)[:100] or "download"
    return f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{urllib.parse.quote(name, safe='')}"


async def api_files_download(request: web.Request):
    # A GET with a SameSite=Lax cookie: a link on another site could start the download of an agent-written
    # file from this origin (#246). Browsers that send Sec-Fetch-Site say where the request comes from:
    # only the UI itself (same-origin) or the address bar / a bookmark (none) may. Without the header
    # (older browsers, scripts) the request is served as before.
    if request.headers.get("Sec-Fetch-Site", "same-origin").strip().lower() not in ("same-origin", "none"):
        return web.json_response({"error": "downloads start from the tallygate UI only"}, status=403)
    path = files_path(request, file=True)
    resp = None
    try:
        async with request.app["agent"].get(
            _agent_files_url("files/download", path=path),
            timeout=aiohttp.ClientTimeout(total=None, sock_connect=10, sock_read=60),
        ) as r:
            if r.status != 200:
                try:
                    err = json.loads(await r.content.read(4096)).get("error")
                except (ValueError, AttributeError):
                    err = None
                return web.json_response({"error": str(err or "download failed")[:200]}, status=_agent_status(r.status))
            size = r.content_length
            if size is None:
                return web.json_response({"error": "the agent sent no length"}, status=502)
            if size > FILES_MAX_DOWNLOAD:
                return web.json_response(
                    {"error": f"file larger than FILES_MAX_DOWNLOAD ({FILES_MAX_DOWNLOAD} bytes)"}, status=413
                )
            resp = web.StreamResponse(
                headers={
                    "Content-Type": "application/octet-stream",
                    "Content-Disposition": content_disposition(path.rsplit("/", 1)[-1]),
                    "Content-Security-Policy": "sandbox; default-src 'none'",
                    "Cache-Control": "no-store",
                }
            )
            resp.content_length = size
            _security_headers(resp, request.path)
            await resp.prepare(request)
            async for chunk in r.content.iter_chunked(FILE_CHUNK):
                await resp.write(chunk)
            await resp.write_eof()
            return resp
    except UpstreamRedirect:  # raised before any byte of an answer is passed on
        return _redirect_502("the agent")
    except (TimeoutError, aiohttp.ClientError) as e:
        if resp is None:
            return web.json_response({"error": f"agent unreachable: {e}"}, status=502)
        log.warning("download of %s from the agent broke off: %s", path, e)
        resp.force_close()  # the browser sees an incomplete download (fewer bytes than Content-Length)
        return resp


async def api_files_upload(request: web.Request):
    path = files_path(request, file=True)
    length = request.content_length
    if length is None:
        return web.json_response({"error": "Content-Length required"}, status=411)
    if length > FILES_MAX_UPLOAD:
        return web.json_response({"error": f"file larger than FILES_MAX_UPLOAD ({FILES_MAX_UPLOAD} bytes)"}, status=413)

    async def body():
        left = length
        while left > 0:
            chunk = await request.content.read(min(FILE_CHUNK, left))
            if not chunk:
                raise ConnectionResetError("upload ended early")
            left -= len(chunk)
            yield chunk

    overwrite = "1" if request.query.get("overwrite") == "1" else "0"
    try:
        async with request.app["agent"].put(
            _agent_files_url("files", path=path, overwrite=overwrite),
            data=body(),
            headers={"Content-Length": str(length), "Content-Type": "application/octet-stream"},
            timeout=aiohttp.ClientTimeout(total=None, sock_connect=10, sock_read=120),
        ) as r:
            data = json.loads(await r.content.read(64 * 1024))
            if not isinstance(data, dict):
                raise ValueError("not an object")
            status = r.status
    except UpstreamRedirect:
        return _redirect_502("the agent")
    except (TimeoutError, aiohttp.ClientError, ConnectionResetError, ValueError) as e:
        return web.json_response({"error": f"upload failed: {e}"}, status=502)
    if status != 200:
        return web.json_response({"error": str(data.get("error", "failed"))[:200]}, status=_agent_status(status))
    log.info("workspace upload: %s (%d bytes) by %s", path, length, request["user"])
    return web.json_response({"path": path, "size": length})


async def api_files_delete(request: web.Request):
    """Delete one file or folder (recursively) in the workspace (#199); never the workspace itself."""
    path = files_path(request, file=True)
    try:
        status, data = await agent_call(request.app, "DELETE", "files?" + urllib.parse.urlencode({"path": path}))
    except UpstreamRedirect:
        return _redirect_502("the agent")
    except (TimeoutError, aiohttp.ClientError, ValueError) as e:
        return web.json_response({"error": f"agent unreachable or invalid response: {e}"}, status=502)
    if status != 200:
        log.info("workspace delete refused: %s by %s (%d)", path, request["user"], status)
        return web.json_response({"error": str(data.get("error", "failed"))[:200]}, status=_agent_status(status))
    kind = "dir" if data.get("type") == "dir" else "file"
    log.info("workspace delete: %s (%s) by %s", path, kind, request["user"])
    return web.json_response({"path": path, "type": kind})


async def api_meta(request: web.Request):
    return web.json_response(
        {
            "user": request["user"],
            "terminals": list(TERMINALS),
            "notify": request.app["notifier"].describe(),
            "notify_status": request.app["notifier"].status(),
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
        async with request.app["agent"].ws_connect(
            upstream, protocols=("tty",), headers=headers, max_msg_size=AGENT_MAX_BYTES
        ) as ws_up:

            async def browser_to_agent():
                first = True
                async for msg in ws_client:
                    if msg.type not in (WSMsgType.TEXT, WSMsgType.BINARY):
                        break
                    # session ended (logout/expiry): nothing reaches the agent. A frame is not activity (#242):
                    # xterm also sends by itself, e.g. answers to queries the agent prints; term.js reports keys
                    if read_session(request, touch=False) is None:
                        return
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

            async def agent_to_browser():
                async for msg in ws_up:
                    if msg.type not in (WSMsgType.TEXT, WSMsgType.BINARY):
                        break
                    data = msg.data.encode() if msg.type == WSMsgType.TEXT else msg.data
                    if data[:1] == b"0":  # terminal output only; title/preferences are dropped
                        await ws_client.send_bytes(data)

            await _first_done(browser_to_agent(), agent_to_browser(), session_ended(request))
            if read_session(request, touch=False) is None:  # tells the browser not to reconnect
                await ws_client.close(code=4401, message=b"session expired")
    except (aiohttp.ClientError, TimeoutError) as e:
        log.warning("terminal %s websocket failed: %s", name, e)
    finally:
        await ws_client.close()
    return ws_client


# ------------------------------------------------------------------ app
async def on_startup(app: web.Application):
    app["http"] = _client()  # GitHub, Telegram, Pushover, Web Push: fixed or allow-listed hosts, never a redirect
    app["notify_http"] = _client(guarded=True)  # Matrix, ntfy, Gotify: the URL is free text (#240)
    app["agent"] = _client(_agent_peers)  # the agent's status server and ttyd, nothing else
    app["gw"] = _client(_gateway_peers)  # the gateway API, nothing else
    app["notifier"] = notify.Notifier(
        app,
        decide_grant=lambda rid, decision, by: gw(
            app, "POST", f"/grant-requests/{rid}/decide", {"decision": decision, "by": by}
        ),
        revoke_grant=lambda aid, by: gw(app, "DELETE", f"/active-grants/{aid}", params={"by": by}),
        decide=lambda pid, scope, by: gw(app, "POST", f"/pending/{pid}/decide", {"scope": scope, "by": by}),
        push=app["webpush"],
        config=app["notifycfg"],
    )
    app["bg"] = [asyncio.create_task(watch_gateway(app)), *app["notifier"].start()]


async def on_cleanup(app: web.Application):
    for t in app["bg"]:
        t.cancel()
    await asyncio.gather(*app["bg"], return_exceptions=True)  # finished before their HTTP session closes
    await app["notifier"].close()
    for name in ("http", "notify_http", "agent", "gw"):
        await app[name].close()


async def watch_gateway(app: web.Application):
    """Single upstream SSE subscription that drives notifications."""
    while True:
        try:
            async with app["gw"].get(
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
                        if ev.get("type") in (
                            "ask",
                            "resolved",
                            "grant_request",
                            "grant_resolved",
                            "digest",
                            "connectivity",
                        ):
                            app["notifier"].enqueue(ev)
        except asyncio.CancelledError:
            raise
        except Exception as e:  # noqa: BLE001
            log.warning("gateway stream: %s (retrying)", e)
        await asyncio.sleep(3)


def build_app() -> web.Application:
    global GW_TOKEN, TTYD_AUTH, SESSION_SECRET
    bootstrap.check_dirs(proxy_auth=bool(PROXY_AUTH_HEADER))
    GW_TOKEN = bootstrap.gw_token()
    TTYD_AUTH = bootstrap.ttyd_credential()
    if 0 < len(os.environ.get("SESSION_SECRET", "")) < SESSION_SECRET_MIN:
        raise SystemExit(
            f"SESSION_SECRET must be at least {SESSION_SECRET_MIN} characters (e.g. `openssl rand -hex 32`), "
            "or leave it empty: a random one is then created in the control data volume"
        )
    SESSION_SECRET = bootstrap.session_secret()
    if not PROXY_AUTH_HEADER:
        bootstrap.ensure_password()
    if PROXY_AUTH_HEADER and not TRUSTED_PROXIES:
        raise SystemExit("TRUST_PROXY_AUTH_HEADER requires TRUSTED_PROXIES (CIDRs of your auth proxy)")
    if PROXY_SECRET and len(PROXY_SECRET) < 16:
        raise SystemExit("TRUST_PROXY_SECRET must be at least 16 characters")
    if TRUST_FORWARDED and not TRUSTED_PROXIES:
        log.warning("TRUST_FORWARDED_FOR=1 but TRUSTED_PROXIES is empty: X-Forwarded-* headers are ignored")
    if not _per_ip_lockout():
        log.info(
            "per-IP login lockout off (set TRUST_FORWARDED_FOR=1 + TRUSTED_PROXIES behind a proxy to enable it); "
            "brute force stays capped at ~1 guess/s by the global lock"
        )
    if os.environ.get("CONTROL_PASSWORD") and not os.environ.get("CONTROL_PASSWORD_HASH"):
        log.warning("CONTROL_PASSWORD (plain text) is in use - prefer CONTROL_PASSWORD_HASH")
    app = web.Application(middlewares=[security], client_max_size=2 * 1024 * 1024)
    pem = bootstrap.vapid_private_pem()
    subject = PUBLIC_URL if PUBLIC_URL.startswith("https://") else "https://github.com/PhilippMundhenk/tallygate"
    app["webpush"] = (
        webpush.WebPush(
            pem, bootstrap.DATA / "push-subscriptions.json", os.environ.get("VAPID_SUBJECT") or subject, SESSION_SECRET
        )
        if pem
        else None
    )
    app["notifycfg"] = notifyconfig.NotifyConfig(bootstrap.DATA / "notify.json")
    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)
    app.router.add_get("/healthz", healthz)
    app.router.add_route("*", "/login", login_page)
    app.router.add_post("/logout", logout)
    app.router.add_get("/", index)
    app.router.add_get("/api/stream", api_stream)
    app.router.add_get("/api/meta", api_meta)
    app.router.add_get("/api/version", api_version)
    app.router.add_get("/api/files", api_files_list)
    app.router.add_put("/api/files", api_files_upload)
    app.router.add_delete("/api/files", api_files_delete)
    app.router.add_get("/api/files/download", api_files_download)
    app.router.add_post("/api/github/check", api_github_check)
    app.router.add_route("*", "/api/agent/{what:.*}", api_agent)
    app.router.add_get("/api/setup/checks", api_setup_checks)
    app.router.add_get("/api/push", api_push)
    app.router.add_post("/api/push/subscribe", api_push_subscribe)
    app.router.add_post("/api/push/test", api_push_test)
    app.router.add_post("/api/notify/test", api_notify_test)
    app.router.add_get("/api/notify/config", api_notify_config)
    app.router.add_put("/api/notify/config/{channel}", api_notify_config_put)
    app.router.add_delete("/api/notify/config/{channel}", api_notify_config_delete)
    app.router.add_put("/api/notify/actions", api_notify_actions_put)
    app.router.add_delete("/api/notify/actions", api_notify_actions_delete)
    app.router.add_post(PUSH_ACT, api_push_act)
    app.router.add_delete("/api/push/{sid}", api_push_delete)
    for path in PUBLIC_FILES:
        if not path.startswith("/static/"):
            app.router.add_get(path, public_file)
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
