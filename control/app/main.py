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
SESSION_RECHECK = float(os.environ.get("SESSION_RECHECK", "10"))  # open streams/consoles re-check this often (s)
PROXY_AUTH_HEADER = os.environ.get("TRUST_PROXY_AUTH_HEADER", "")  # e.g. Remote-User (only behind a trusted proxy!)
TRUST_FORWARDED = os.environ.get("TRUST_FORWARDED_FOR") == "1"
# Peers whose X-Forwarded-* / auth headers are believed. Required for TRUST_PROXY_AUTH_HEADER.
TRUSTED_PROXIES = [
    ipaddress.ip_network(c.strip(), strict=False) for c in os.environ.get("TRUSTED_PROXIES", "").split(",") if c.strip()
]
# Optional shared secret: when set, the proxy must also send it, or its forwarded/auth headers are ignored.
PROXY_SECRET = os.environ.get("TRUST_PROXY_SECRET", "")
PROXY_SECRET_HEADER = "X-Tallygate-Proxy-Secret"  # noqa: S105 (a header name)
PUBLIC_URL = os.environ.get("PUBLIC_URL", "").rstrip("/")
GITHUB_API = os.environ.get("GITHUB_API_URL", "https://api.github.com").rstrip("/")  # tests point it elsewhere
COOKIE = "tallygate_session"
AGENT_MAX_BYTES = 1024 * 1024  # cap on anything read from the agent (status JSON, terminal frames)
BROWSER_MAX_FRAME = 64 * 1024

# Gateway API paths the UI may use: (method, regex)
GW_ALLOW = [
    ("GET", r"/policy"),
    ("PUT", r"/policy"),
    ("PATCH", r"/policy"),
    ("POST", r"/emergency-stop"),
    ("POST", r"/rules"),
    ("DELETE", r"/rules/[A-Za-z0-9_:-]+"),  # template rules are <preset>:<id>
    ("GET", r"/pending"),
    ("POST", r"/pending/[a-f0-9]+/decide"),
    ("GET", r"/events"),
    ("GET", r"/events/summary"),
    ("POST", r"/test"),
    ("GET", r"/presets"),
    ("POST", r"/presets/[A-Za-z_][A-Za-z0-9_]*"),
    ("DELETE", r"/presets/[A-Za-z_][A-Za-z0-9_]*"),
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
    if not sid or not hmac.compare_digest(sig, _sign(sid)):
        return None
    return sid


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
    return _request_scheme(request) == "https"


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
            # taken before the check: a password change during the check can only end the new session
            fingerprint = password_fingerprint()
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
    if (sub.endswith("/decide") or sub.endswith("/activate") or sub == "/emergency-stop") and isinstance(body, dict):
        body["by"] = by  # attribution is set here, never taken from the browser
    qs = ("?" + request.query_string) if request.query_string else ""
    if sub.startswith("/active-grants/"):
        qs = "?" + urllib.parse.urlencode({"by": by})
    try:
        status, data = await gw(request.app, request.method, sub + qs, body)
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
            async with request.app["http"].get(
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
    async with app["http"].request(
        method, f"http://{AGENT_HOST}:{AGENT_STATUS_PORT}/{what}", json=body, timeout=aiohttp.ClientTimeout(total=90)
    ) as r:
        raw = b""  # read() returns what has arrived so far: read until the end or the cap
        while len(raw) <= AGENT_MAX_BYTES and (chunk := await r.content.read(AGENT_MAX_BYTES + 1 - len(raw))):
            raw += chunk
        if len(raw) > AGENT_MAX_BYTES:
            raise ValueError("agent response too large")
        data = json.loads(raw)
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
            "Fine for a trusted home network; otherwise put a TLS reverse proxy in front.",
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
    add(
        "reach",
        "info",
        "From another machine",
        (f"Other devices use the same address: {browser_origin}. " if browser_origin and not local else "")
        + "By default the UI is published on port 8080 of the Docker host (CONTROL_PUBLISH=0.0.0.0:8080): "
        "http://<host's LAN address>:8080. With CONTROL_PUBLISH=127.0.0.1:8080 only this host, an SSH tunnel "
        "or a reverse proxy reaches it.",
    )
    return web.json_response({"checks": checks, "password": password_state()})


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
                    if read_session(request) is None:  # session ended (logout/expiry): nothing reaches the agent
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
    await asyncio.gather(*app["bg"], return_exceptions=True)  # finished before their HTTP session closes
    await app["notifier"].close()
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
    SESSION_SECRET = bootstrap.session_secret()
    if not PROXY_AUTH_HEADER:
        bootstrap.ensure_password()
    if PROXY_AUTH_HEADER and not TRUSTED_PROXIES:
        raise SystemExit("TRUST_PROXY_AUTH_HEADER requires TRUSTED_PROXIES (CIDRs of your auth proxy)")
    if PROXY_SECRET and len(PROXY_SECRET) < 16:
        raise SystemExit("TRUST_PROXY_SECRET must be at least 16 characters")
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
    app.router.add_route("*", "/api/agent/{what:.*}", api_agent)
    app.router.add_get("/api/setup/checks", api_setup_checks)
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
