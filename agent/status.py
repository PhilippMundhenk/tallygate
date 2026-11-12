#!/usr/bin/env python3
"""Status, isolation self-test and setup actions for the setup wizard (agent network only, port 7680).

NOTE: results come from inside the agent, so a compromised agent could lie. They are a setup
aid. The authoritative check is tests/integration/bypass.sh, run by the admin via `docker compose exec`.

The setup actions (POST /setup/...) only do what the agent user can already do in its own container:
start `claude auth login` in a tmux session and type the code into it, set the git identity, and record
Remote Control's one-time consent in ~/.claude.json. They give the agent nothing new.
"""

import json
import os
import re
import shutil
import socket
import ssl
import struct
import subprocess
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HOME = Path.home()
PROC = Path("/proc")
WORKSPACE = Path(os.environ.get("WORKSPACE", "/workspace"))
TIMEOUT = 5
MAX_BODY = 4096  # setup requests are tiny JSON objects
LOGIN_SESSION = "tg-login"
LOGIN_WAIT = 20.0  # seconds to wait for the login URL
CODE_WAIT = 30.0  # seconds to wait for the result after the code was typed in
POLL = 0.5
CLAUDE_JSON_MAX = 8 * 1024 * 1024
LOGIN_URL_RE = re.compile(r"https://[^\s\"'<>]+/oauth/authorize\?[^\s\"'<>]+")
LOGIN_ENDED_RE = re.compile(r"\[tallygate\] login ended \(exit (\d+)\)")
CODE_RE = re.compile(r"[A-Za-z0-9._~#+/=-]{8,2048}")
EMAIL_RE = re.compile(r"[^\s@<>\"]+@[^\s@<>\"]+")
GH_LOGIN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}")
PROMPT_RE = re.compile(r"[(\[]y/n[)\]]", re.IGNORECASE)
CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def sh(*cmd: str) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return ""


def run(*cmd: str, timeout: float = 10) -> subprocess.CompletedProcess | None:
    """Run a fixed argv (never a shell); None if it could not run or timed out."""
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return None


def clean(s: object, limit: int = 300) -> str:
    """Printable text only (no terminal escapes), stripped and truncated."""
    return CONTROL_CHARS.sub("", str(s or "")).strip()[:limit]


class SetupError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


_version_cache: dict = {}


def git_get(key: str) -> str | None:
    """A global git setting: None if it is not set at all, "" if it is set to an empty value."""
    r = run("git", "config", "--global", "--get", key)
    if r is None or r.returncode != 0:
        return None
    return r.stdout.strip()


def git_identity() -> dict:
    name, email = git_get("user.name"), git_get("user.email")
    state = "missing" if name is None or email is None else "empty" if not name or not email else "ok"
    return {"name": name or "", "email": email or "", "state": state}


def claude_config() -> dict:
    """~/.claude.json (Claude Code's global config), or {} if it is missing, too big or not an object."""
    p = HOME / ".claude.json"
    try:
        if p.stat().st_size > CLAUDE_JSON_MAX:
            return {}
        cfg = json.loads(p.read_bytes() or b"{}")
    except (OSError, ValueError):
        return {}
    return cfg if isinstance(cfg, dict) else {}


def logged_in() -> bool:
    return (HOME / ".claude" / ".credentials.json").exists()


def tmux(*args: str) -> subprocess.CompletedProcess | None:
    return run("tmux", *args)


def pane(session: str) -> str | None:
    """The text of a tmux session's pane (wrapped lines joined), or None if the session does not exist."""
    r = tmux("capture-pane", "-p", "-J", "-t", session, "-S", "-200")
    return r.stdout if r is not None and r.returncode == 0 else None


def rc_running() -> bool:
    for p in PROC.iterdir():
        if p.name.isdigit():
            try:
                cmd = (p / "cmdline").read_bytes().split(b"\0")
            except OSError:
                continue
            if b"remote-control" in cmd and any(b"claude" in c for c in cmd):
                return True
    return False


def rc_prompt() -> str:
    """The question Remote Control waits for in the rc console, if any (consent y/n, folder trust)."""
    lines = [line.strip() for line in (pane("rc") or "").splitlines() if line.strip()]
    last = lines[-1] if lines else ""
    return clean(last, 120) if PROMPT_RE.search(last) else ""


def disk(path: Path) -> dict | None:
    """Size and use of the file system that holds `path` (statvfs: cheap, unlike adding up a workspace)."""
    try:
        d = shutil.disk_usage(path)
    except OSError:
        return None
    return {"total": d.total, "used": d.used, "free": d.free}


def status() -> dict:
    if "v" not in _version_cache:
        _version_cache["v"] = sh("claude", "--version")
    git = git_identity()
    return {
        "claude_version": _version_cache["v"],
        "claude_logged_in": logged_in(),
        "git_name": git["name"],
        "git_email": git["email"],
        "git_identity": git["state"],  # ok | empty (set, but to "") | missing
        "remote_control_enabled": os.environ.get("RC_ENABLE", "1") == "1",
        "remote_control_running": rc_running(),
        "remote_control_consent": claude_config().get("remoteDialogSeen") is True,
        "remote_control_prompt": rc_prompt(),
        "remote_control_name": clean(os.environ.get("RC_NAME", "tallygate"), 100),
        "gateway_ca_trusted": bool(os.environ.get("NODE_EXTRA_CA_CERTS")),
        "workspace_disk": disk(WORKSPACE),
        "home_disk": disk(HOME),
        "time": time.time(),
    }


# ---------------------------------------------------------------- setup: Claude login
_login_lock = threading.Lock()


def login_state() -> dict:
    """Where `claude auth login` in its tmux session stands: idle | starting | waiting_code | done | failed."""
    text = pane(LOGIN_SESSION)
    out: dict = {"logged_in": logged_in(), "url": "", "message": ""}
    if text is None:
        return {**out, "state": "idle"}
    m = LOGIN_URL_RE.search(text)
    if m:
        out["url"] = m.group(0)[:2048]
    ended = LOGIN_ENDED_RE.search(text)
    if ended:
        lines = [re.sub(r"^.*if prompted >", "", clean(x)).strip() for x in text.splitlines()]
        msgs = [x for x in lines if x and not x.startswith("[tallygate]") and "oauth/authorize" not in x]
        out["message"] = msgs[-1] if msgs else ""
        return {**out, "state": "done" if ended.group(1) == "0" else "failed"}
    return {**out, "state": "waiting_code" if m else "starting"}


def _wait(until, timeout: float) -> dict:
    deadline = time.monotonic() + timeout
    while True:
        st = login_state()
        if until(st) or time.monotonic() >= deadline:
            return st
        time.sleep(POLL)


def login_start() -> dict:
    """(Re)start `claude auth login` in its own tmux session and wait for the login URL."""
    with _login_lock:
        tmux("kill-session", "-t", LOGIN_SESSION)
        r = tmux(
            "new-session",
            "-d",
            "-s",
            LOGIN_SESSION,
            "-x",
            "400",
            "-y",
            "50",
            'claude auth login; rc=$?; echo; echo "[tallygate] login ended (exit $rc)"; sleep 900',
        )
        if r is None or r.returncode != 0:
            raise SetupError(500, "could not start the login session (tmux)")
        return _wait(lambda s: s["state"] != "starting", LOGIN_WAIT)


def login_code(body: dict) -> dict:
    """Type the code from the login page into the waiting `claude auth login`."""
    code = str(body.get("code", "")).strip()
    if not CODE_RE.fullmatch(code):
        raise SetupError(400, "the code looks wrong: copy it completely from the login page")
    with _login_lock:
        if login_state()["state"] != "waiting_code":
            raise SetupError(409, "no login is waiting for a code: start the login again")
        tmux("send-keys", "-t", LOGIN_SESSION, "-l", code)
        tmux("send-keys", "-t", LOGIN_SESSION, "Enter")
        return _wait(lambda s: s["state"] in ("done", "failed"), CODE_WAIT)


# ---------------------------------------------------------------- setup: git identity
def gh_user() -> dict:
    """The GitHub account behind the token the gateway injects (`gh api -i user`), or why it failed."""
    r = run("gh", "api", "-i", "user", timeout=30)
    if r is None:
        return {"ok": False, "reason": "network", "message": "gh did not answer in time"}
    head, _, body = (r.stdout or "").replace("\r\n", "\n").partition("\n\n")
    m = re.match(r"HTTP/[\d.]+ (\d{3})", head)
    if not m:
        err = [x for x in (r.stderr or "").splitlines() if x.strip()]
        detail = clean(err[-1]) if err else "no response"
        return {"ok": False, "reason": "network", "message": f"GitHub is not reachable through the gateway: {detail}"}
    code = int(m.group(1))
    if code == 401:
        return {
            "ok": False,
            "reason": "token",
            "message": "GitHub refused the request (401): no valid token is stored in the gateway",
        }
    if code != 200:
        return {"ok": False, "reason": "github", "message": f"GitHub answered {code}"}
    headers = {}
    for line in head.splitlines()[1:]:
        k, _, v = line.partition(":")
        headers[k.strip().lower()] = v.strip()
    try:
        user = json.loads(body)
        uid, login = int(user["id"]), str(user["login"])
    except (ValueError, KeyError, TypeError):
        uid, login = 0, ""
    if uid <= 0 or not GH_LOGIN_RE.fullmatch(login):
        return {"ok": False, "reason": "github", "message": "unexpected answer from GitHub"}
    return {
        "ok": True,
        "login": login,
        "name": clean(user.get("name"), 100) or login,
        "email": f"{uid}+{login}@users.noreply.github.com",
        "token_expires": clean(headers.get("github-authentication-token-expiration"), 60),
    }


def git_preview() -> dict:
    return {**gh_user(), "current": git_identity()}


def git_apply(body: dict) -> dict:
    """Set user.name and user.email. Never writes an empty or malformed value."""
    name, email = clean(body.get("name"), 1000), clean(body.get("email"), 1000)
    if not name or len(name) > 100:
        raise SetupError(400, "the name must not be empty (at most 100 characters)")
    if len(email) > 254 or not EMAIL_RE.fullmatch(email):
        raise SetupError(400, "the email address is not valid")
    for key, value in (("user.name", name), ("user.email", email)):
        r = run("git", "config", "--global", key, value)
        if r is None or r.returncode != 0:
            raise SetupError(500, f"git config {key} failed")
    return git_identity()


# ---------------------------------------------------------------- setup: Remote Control
def update_claude_config(change) -> None:
    """Read-modify-write ~/.claude.json atomically (mode 0600), keeping every other setting."""
    p = HOME / ".claude.json"
    try:
        raw = p.read_bytes()
    except FileNotFoundError:
        raw = b""
    if len(raw) > CLAUDE_JSON_MAX:
        raise SetupError(500, "~/.claude.json is too big")
    try:
        cfg = json.loads(raw or b"{}")
    except ValueError:
        raise SetupError(500, "~/.claude.json is not valid JSON") from None
    if not isinstance(cfg, dict):
        raise SetupError(500, "~/.claude.json is not a JSON object")
    change(cfg)
    tmp = p.with_name(f".claude.json.tallygate-{os.getpid()}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
        json.dump(cfg, f, indent=2)
    os.replace(tmp, p)


def rc_enable() -> dict:
    """Give Remote Control's one-time consent (and trust the workspace) so it starts without asking,
    then restart the Remote Control loop in its tmux pane. respawn-pane keeps the session (an open rc
    console stays attached); without a session the agent's supervisor starts one within a few seconds."""
    if os.environ.get("RC_ENABLE", "1") != "1":
        raise SetupError(409, "Remote Control is switched off (RC_ENABLE=0)")
    if not logged_in():
        raise SetupError(409, "log in to Claude first")

    def change(cfg: dict) -> None:
        cfg["remoteDialogSeen"] = True
        projects = cfg.get("projects")
        if not isinstance(projects, dict):
            projects = cfg["projects"] = {}
        ws = projects.get(str(WORKSPACE))
        if not isinstance(ws, dict):
            ws = projects[str(WORKSPACE)] = {}
        ws["hasTrustDialogAccepted"] = True

    update_claude_config(change)
    r = tmux("respawn-pane", "-k", "-t", "rc")
    return {"consent": True, "restarted": r is not None and r.returncode == 0}


# ---------------------------------------------------------------- self-test
def _proxy() -> tuple[str, int]:
    u = urllib.parse.urlparse(os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy") or "http://egress-gw:3128")
    return u.hostname, u.port or 3128


def expect_fail(name: str, fn) -> dict:
    try:
        detail = fn()
        return {"name": name, "pass": False, "detail": f"UNEXPECTEDLY SUCCEEDED: {detail}"}
    except Exception as e:  # noqa: BLE001
        return {"name": name, "pass": True, "detail": f"blocked ({type(e).__name__}: {e})"[:200]}


def tcp(host: str, port: int, family=socket.AF_UNSPEC) -> str:
    infos = socket.getaddrinfo(host, port, family, socket.SOCK_STREAM)
    with socket.create_connection(infos[0][4][:2], timeout=TIMEOUT):
        return f"connected to {host}:{port}"


def udp_dns(server: str, port: int = 53) -> str:
    q = struct.pack(">HHHHHH", 0x4242, 0x0100, 1, 0, 0, 0) + b"\x07example\x03com\x00" + struct.pack(">HH", 1, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(TIMEOUT)
        s.sendto(q, (server, port))
        data = s.recv(512)
    return f"got {len(data)} byte reply from {server}"


def connect_via_proxy(host: str, port: int) -> str:
    ph, pp = _proxy()
    with socket.create_connection((ph, pp), timeout=TIMEOUT + 60) as s:
        s.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
        s.settimeout(TIMEOUT + 60)
        line = s.recv(256).split(b"\r\n", 1)[0].decode(errors="replace")
        if " 200 " not in line + " ":
            raise ConnectionRefusedError(line)
        return line


def https_via_proxy(host: str) -> str:
    line = connect_via_proxy(host, 443)
    ph, pp = _proxy()
    raw = socket.create_connection((ph, pp), timeout=TIMEOUT)
    raw.sendall(f"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n".encode())
    raw.recv(256)
    ctx = ssl.create_default_context()
    with ctx.wrap_socket(raw, server_hostname=host) as t:
        t.sendall(f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
        return f"{line} / TLS ok, {t.recv(64).split(b'\r\n')[0].decode(errors='replace')}"


def selftest() -> list[dict]:
    probes = [p for p in os.environ.get("SELFTEST_BLOCKED_PROBES", "").split(",") if p]
    results = [
        expect_fail("Direct TCP to the internet (1.1.1.1:443)", lambda: tcp("1.1.1.1", 443)),
        expect_fail(
            "Direct IPv6 (2606:4700:4700::1111:443)", lambda: tcp("2606:4700:4700::1111", 443, socket.AF_INET6)
        ),
        expect_fail("Agent DNS resolution of public names", lambda: socket.getaddrinfo("api.anthropic.com", 443)),
        expect_fail("UDP DNS to 1.1.1.1", lambda: udp_dns("1.1.1.1")),
        expect_fail("LAN via proxy (192.168.1.1:80, hard-deny)", lambda: connect_via_proxy("192.168.1.1", 80)),
        expect_fail(
            "Loopback/metadata via proxy (169.254.169.254:80)", lambda: connect_via_proxy("169.254.169.254", 80)
        ),
    ]
    for p in probes:
        h, port = p.rsplit(":", 1)
        results.append(expect_fail(f"Management endpoint {p}", lambda h=h, port=int(port): tcp(h, port)))
    try:
        results.append(
            {
                "name": "Allowed path: api.anthropic.com via proxy",
                "pass": True,
                "detail": https_via_proxy("api.anthropic.com"),
            }
        )
    except Exception as e:  # noqa: BLE001
        results.append({"name": "Allowed path: api.anthropic.com via proxy", "pass": False, "detail": str(e)[:200]})
    return results


# ---------------------------------------------------------------- HTTP
# Looked up at call time (lambdas), so the functions can be replaced in tests.
GET_ROUTES = {
    "/status": lambda: status(),
    "/selftest": lambda: {"results": selftest()},
    "/setup/claude-login": lambda: login_state(),
    "/setup/git-identity": lambda: git_preview(),
}
POST_ROUTES = {
    "/setup/claude-login": lambda _body: login_start(),
    "/setup/claude-code": lambda body: login_code(body),
    "/setup/git-identity": lambda body: git_apply(body),
    "/setup/remote-control": lambda _body: rc_enable(),
}


class Handler(BaseHTTPRequestHandler):
    def _send(self, status: int, body: dict) -> None:
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _dispatch(self, fn, *args) -> None:
        try:
            self._send(200, fn(*args))
        except SetupError as e:
            self._send(e.status, {"error": str(e)})

    def do_GET(self):
        fn = GET_ROUTES.get(self.path)
        if fn is None:
            self._send(404, {"error": "not found"})
            return
        self._dispatch(fn)

    def do_POST(self):
        fn = POST_ROUTES.get(self.path)
        if fn is None:
            self._send(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = -1
        if not 0 <= length <= MAX_BODY:
            self._send(413, {"error": "request body missing or too large"})
            return
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            body = None
        if not isinstance(body, dict):
            self._send(400, {"error": "expected a JSON object"})
            return
        self._dispatch(fn, body)

    def log_message(self, *args):
        pass


def main(argv: list[str]) -> int:
    if "--selftest" in argv:
        res = selftest()
        for r in res:
            print(("PASS " if r["pass"] else "FAIL ") + r["name"] + "  -- " + r["detail"])
        return 0 if all(r["pass"] for r in res) else 1
    ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("STATUS_PORT", "7680"))), Handler).serve_forever()
    return 0


if __name__ == "__main__":  # pragma: no cover - process entry point, main() is tested
    import sys

    sys.exit(main(sys.argv[1:]))
