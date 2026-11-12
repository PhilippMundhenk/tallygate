"""agent/status.py setup actions (#75): Claude login in a tmux session, git identity from GitHub, Remote Control
consent. tmux, gh and git are replaced by fakes; tests/e2e/test_setup_wizard.py runs the real process."""

import importlib.util
import json
import subprocess
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

STATUS = Path(__file__).resolve().parents[2] / "agent" / "status.py"
NO_PROXY = urllib.request.build_opener(urllib.request.ProxyHandler({}))
URL = "https://claude.com/cai/oauth/authorize?code=true&client_id=x&state=y"


@pytest.fixture
def st(monkeypatch, tmp_path):
    for v in ("RC_ENABLE", "RC_NAME", "WORKSPACE"):
        monkeypatch.delenv(v, raising=False)
    spec = importlib.util.spec_from_file_location("agent_status_setup", STATUS)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    monkeypatch.setattr(mod, "HOME", tmp_path)
    monkeypatch.setattr(mod, "POLL", 0.01)
    monkeypatch.setattr(mod, "LOGIN_WAIT", 0.2)
    monkeypatch.setattr(mod, "CODE_WAIT", 0.2)
    return mod


def done(args, code=0, out="", err=""):
    return subprocess.CompletedProcess(args, code, out, err)


class FakeTmux:
    """Sessions with a pane text; `on_keys` reacts to typed text like the program in the pane would."""

    def __init__(self) -> None:
        self.panes: dict[str, str] = {}
        self.calls: list[tuple] = []
        self.fail_new = False
        self.on_new = lambda name: ""
        self.on_keys = lambda name, keys: None

    def __call__(self, *args):
        self.calls.append(args)
        cmd, t = args[0], args[args.index("-t") + 1] if "-t" in args else None
        if cmd == "new-session":
            if self.fail_new:
                return None
            name = args[args.index("-s") + 1]
            self.panes[name] = self.on_new(name)
            return done(args)
        if t not in self.panes:
            return done(args, 1, err="can't find session")
        if cmd == "capture-pane":
            return done(args, out=self.panes[t])
        if cmd == "kill-session":
            del self.panes[t]
        if cmd == "send-keys":
            self.on_keys(t, args[-1])
        return done(args)


@pytest.fixture
def tmux(st, monkeypatch):
    t = FakeTmux()
    monkeypatch.setattr(st, "tmux", t)
    return t


# ---------------------------------------------------------------- login
def test_login_state_follows_the_pane(st, tmux, tmp_path):
    assert st.login_state() == {"logged_in": False, "url": "", "message": "", "state": "idle"}
    tmux.panes["tg-login"] = "Opening browser to sign in…\n"
    assert st.login_state()["state"] == "starting"
    tmux.panes["tg-login"] += f"If the browser didn't open, visit: {URL}\nPaste code here if prompted > "
    s = st.login_state()
    assert s["state"] == "waiting_code" and s["url"] == URL
    tmux.panes["tg-login"] += "\x1b[31mLogin failed: invalid code\n\n[tallygate] login ended (exit 1)\n"
    s = st.login_state()
    assert s["state"] == "failed" and s["message"] == "[31mLogin failed: invalid code"  # escapes stripped
    tmux.panes["tg-login"] = "[tallygate] login ended (exit 0)\n"
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / ".credentials.json").write_text("{}")
    assert st.login_state() == {"logged_in": True, "url": "", "message": "", "state": "done"}


def test_login_start_restarts_the_session_and_waits_for_the_url(st, tmux):
    tmux.panes["tg-login"] = "old login"
    tmux.on_new = lambda name: f"visit: {URL}\nPaste code here if prompted > "
    s = st.login_start()
    assert s["state"] == "waiting_code" and s["url"] == URL
    assert tmux.calls[0] == ("kill-session", "-t", "tg-login")
    new = tmux.calls[1]
    assert new[:4] == ("new-session", "-d", "-s", "tg-login") and new[-1].startswith("claude auth login;")
    tmux.on_new = lambda name: "Opening browser to sign in…"  # no URL in time
    assert st.login_start()["state"] == "starting"
    tmux.fail_new = True
    with pytest.raises(st.SetupError, match="could not start the login session") as e:
        st.login_start()
    assert e.value.status == 500


def test_login_code_is_validated_typed_in_and_awaited(st, tmux, tmp_path):
    with pytest.raises(st.SetupError, match="code looks wrong") as e:
        st.login_code({"code": "short"})
    assert e.value.status == 400
    for bad in ("x" * 9 + "; rm -rf ~", "a\nb" * 5, 12345678):
        with pytest.raises(st.SetupError):
            st.login_code({"code": bad})
    with pytest.raises(st.SetupError, match="no login is waiting") as e:
        st.login_code({"code": "good-code-1234#state"})
    assert e.value.status == 409
    typed = []

    def on_keys(name, keys):
        typed.append(keys)
        if keys == "Enter":
            ok = typed[0] == "good-code-1234#state"
            if ok:
                (tmp_path / ".claude").mkdir(exist_ok=True)
                (tmp_path / ".claude" / ".credentials.json").write_text("{}")
            tmux.panes[name] += ("Login successful." if ok else "Login failed: bad code") + (
                f"\n[tallygate] login ended (exit {0 if ok else 1})\n"
            )

    tmux.on_keys = on_keys
    tmux.panes["tg-login"] = f"visit: {URL}\nPaste code here if prompted > "
    s = st.login_code({"code": "  good-code-1234#state "})
    assert s["state"] == "done" and s["logged_in"] and s["message"] == "Login successful."
    assert typed == ["good-code-1234#state", "Enter"]
    assert ("send-keys", "-t", "tg-login", "-l", "good-code-1234#state") in tmux.calls  # literal, not key names
    typed.clear()
    tmux.panes["tg-login"] = f"visit: {URL}\nPaste code here if prompted > "
    assert st.login_code({"code": "wrong-code-123"})["state"] == "failed"
    tmux.on_keys = lambda *a: None  # no answer at all: still waiting when CODE_WAIT is over
    tmux.panes["tg-login"] = f"visit: {URL}\nPaste code here if prompted > "
    assert st.login_code({"code": "slow-code-1234"})["state"] == "waiting_code"


# ---------------------------------------------------------------- git identity
def gh_reply(st, monkeypatch, reply):
    seen = []

    def run(*cmd, timeout=10):
        seen.append(cmd)
        if cmd[0] == "gh":
            return reply
        return done(cmd, 1)  # git: nothing set

    monkeypatch.setattr(st, "run", run)
    return seen


OK_HEAD = "HTTP/2.0 200 OK\r\nContent-Type: application/json\r\nGithub-Authentication-Token-Expiration: 2027-01-01 00:00:00 UTC\r\n\r\n"


@pytest.mark.parametrize(
    ("reply", "expected"),
    [
        (None, {"ok": False, "reason": "network", "message": "gh did not answer in time"}),
        (
            done((), 1, "", 'error connecting to api.github.com\nGet "https://api.github.com/user": Forbidden\n'),
            {
                "ok": False,
                "reason": "network",
                "message": 'GitHub is not reachable through the gateway: Get "https://api.github.com/user": Forbidden',
            },
        ),
        (
            done((), 1, None, ""),
            {"ok": False, "reason": "network", "message": "GitHub is not reachable through the gateway: no response"},
        ),
        (
            done((), 1, 'HTTP/2.0 401 Unauthorized\r\n\r\n{"message": "Bad credentials"}', "gh: Bad credentials"),
            {
                "ok": False,
                "reason": "token",
                "message": "GitHub refused the request (401): no valid token is stored in the gateway",
            },
        ),
        (
            done((), 1, "HTTP/2.0 403 Forbidden\r\n\r\n{}"),
            {"ok": False, "reason": "github", "message": "GitHub answered 403"},
        ),
        (done((), 0, OK_HEAD + "[]"), {"ok": False, "reason": "github", "message": "unexpected answer from GitHub"}),
        (done((), 0, OK_HEAD + "{bad"), {"ok": False, "reason": "github", "message": "unexpected answer from GitHub"}),
        (
            done((), 0, OK_HEAD + '{"id": 1, "login": "evil login"}'),
            {"ok": False, "reason": "github", "message": "unexpected answer from GitHub"},
        ),
        (
            done((), 0, OK_HEAD + '{"id": 0, "login": "octo"}'),
            {"ok": False, "reason": "github", "message": "unexpected answer from GitHub"},
        ),
        (
            done((), 0, OK_HEAD + '{"id": 583231, "login": "octocat", "name": "The\\u001b Octocat"}'),
            {
                "ok": True,
                "login": "octocat",
                "name": "The Octocat",
                "email": "583231+octocat@users.noreply.github.com",
                "token_expires": "2027-01-01 00:00:00 UTC",
            },
        ),
        (
            done((), 0, 'HTTP/1.1 200 OK\n\n{"id": 7, "login": "a-b", "name": null}'),
            {"ok": True, "login": "a-b", "name": "a-b", "email": "7+a-b@users.noreply.github.com", "token_expires": ""},
        ),
    ],
)
def test_gh_user_explains_every_failure(st, monkeypatch, reply, expected):
    seen = gh_reply(st, monkeypatch, reply)
    assert st.gh_user() == expected
    assert seen[0] == ("gh", "api", "-i", "user")


def test_git_preview_shows_the_current_identity_too(st, monkeypatch):
    gh_reply(st, monkeypatch, done((), 0, OK_HEAD + '{"id": 7, "login": "octo"}'))
    p = st.git_preview()
    assert p["email"] == "7+octo@users.noreply.github.com" and p["current"] == {
        "name": "",
        "email": "",
        "state": "missing",
    }


def test_git_apply_never_writes_empty_or_odd_values(st, monkeypatch):
    store = {}

    def run(*cmd, timeout=10):
        if cmd[:4] == ("git", "config", "--global", "--get"):
            return done(cmd, 0, store[cmd[4]] + "\n") if cmd[4] in store else done(cmd, 1)
        assert cmd[:3] == ("git", "config", "--global") and len(cmd) == 5  # argv, never a shell
        store[cmd[3]] = cmd[4]
        return done(cmd)

    monkeypatch.setattr(st, "run", run)
    for body, msg in (
        ({}, "name must not be empty"),
        ({"name": "  ", "email": "a@b.c"}, "name must not be empty"),
        ({"name": "\x1b\x07", "email": "a@b.c"}, "name must not be empty"),
        ({"name": "x" * 101, "email": "a@b.c"}, "name must not be empty"),
        ({"name": "Dev", "email": ""}, "email address is not valid"),
        ({"name": "Dev", "email": "no-at-sign"}, "email address is not valid"),
        ({"name": "Dev", "email": "a b@c.d"}, "email address is not valid"),
        ({"name": "Dev", "email": "x" * 250 + "@b.cd"}, "email address is not valid"),
    ):
        with pytest.raises(st.SetupError, match=msg) as e:
            st.git_apply(body)
        assert e.value.status == 400
    assert store == {}  # nothing was written
    got = st.git_apply({"name": " The Octocat\n", "email": "7+octo@users.noreply.github.com"})
    assert got == {"name": "The Octocat", "email": "7+octo@users.noreply.github.com", "state": "ok"}
    monkeypatch.setattr(st, "run", lambda *a, **k: None)
    with pytest.raises(st.SetupError, match=r"git config user\.name failed"):
        st.git_apply({"name": "Dev", "email": "a@b.c"})


# ---------------------------------------------------------------- Remote Control
def test_rc_enable_records_consent_and_restarts_the_loop(st, tmux, tmp_path, monkeypatch):
    with pytest.raises(st.SetupError, match="log in to Claude first") as e:
        st.rc_enable()
    assert e.value.status == 409
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / ".credentials.json").write_text("{}")
    cfg = tmp_path / ".claude.json"
    cfg.write_text(json.dumps({"machineID": "m", "projects": {"/other": {"x": 1}, "/workspace": "odd"}}))
    tmux.panes["rc"] = "Enable Remote Control? (y/n) "
    assert st.rc_enable() == {"consent": True, "restarted": True}
    data = json.loads(cfg.read_text())
    assert data["remoteDialogSeen"] is True and data["machineID"] == "m"  # other settings stay
    assert data["projects"] == {"/other": {"x": 1}, "/workspace": {"hasTrustDialogAccepted": True}}
    assert cfg.stat().st_mode & 0o777 == 0o600
    assert ("respawn-pane", "-k", "-t", "rc") in tmux.calls  # the session (and an open console) stays
    del tmux.panes["rc"]  # no rc session yet: the supervisor starts one
    cfg.unlink()
    monkeypatch.setenv("WORKSPACE", "/ws")
    monkeypatch.setattr(st, "WORKSPACE", Path("/ws"))
    assert st.rc_enable() == {"consent": True, "restarted": False}
    assert json.loads(cfg.read_text()) == {
        "remoteDialogSeen": True,
        "projects": {"/ws": {"hasTrustDialogAccepted": True}},
    }
    cfg.write_text('{"projects": []}')
    st.rc_enable()
    assert json.loads(cfg.read_text())["projects"] == {"/ws": {"hasTrustDialogAccepted": True}}
    monkeypatch.setenv("RC_ENABLE", "0")
    with pytest.raises(st.SetupError, match="RC_ENABLE=0"):
        st.rc_enable()


@pytest.mark.parametrize(
    ("raw", "msg"), [(b"[]", "not a JSON object"), (b"{bad", "not valid JSON"), (b"{}" + b" " * 64, "too big")]
)
def test_update_claude_config_refuses_broken_files(st, tmp_path, monkeypatch, raw, msg):
    monkeypatch.setattr(st, "CLAUDE_JSON_MAX", 32)
    (tmp_path / ".claude.json").write_bytes(raw)
    with pytest.raises(st.SetupError, match=msg):
        st.update_claude_config(lambda c: None)
    assert (tmp_path / ".claude.json").read_bytes() == raw  # untouched


# ---------------------------------------------------------------- HTTP
@pytest.fixture
def server(st, monkeypatch):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), st.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    srv.server_close()


def call(base, path, method="GET", data=None, headers=None):
    req = urllib.request.Request(base + path, method=method, data=data, headers=headers or {})
    try:
        with NO_PROXY.open(req, timeout=5) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_handler_routes_setup_actions(st, server, monkeypatch):
    got = []
    monkeypatch.setitem(st.POST_ROUTES, "/setup/git-identity", lambda body: got.append(body) or {"state": "ok"})
    monkeypatch.setitem(st.GET_ROUTES, "/setup/claude-login", lambda: {"state": "idle"})

    def refuse(body):
        raise st.SetupError(409, "log in to Claude first")

    monkeypatch.setitem(st.POST_ROUTES, "/setup/remote-control", refuse)
    assert call(server, "/setup/claude-login") == (200, {"state": "idle"})
    body = json.dumps({"name": "n", "email": "e@x.y"}).encode()
    assert call(server, "/setup/git-identity", "POST", body) == (200, {"state": "ok"})
    assert got == [{"name": "n", "email": "e@x.y"}]
    assert call(server, "/setup/git-identity", "POST", b"") == (200, {"state": "ok"})  # empty body = {}
    assert call(server, "/setup/remote-control", "POST", b"{}") == (409, {"error": "log in to Claude first"})
    assert call(server, "/setup/git-identity", "POST", b"[1]")[0] == 400
    assert call(server, "/setup/git-identity", "POST", b"{bad")[0] == 400
    assert call(server, "/setup/git-identity", "POST", b"{}" + b" " * 5000)[0] == 413
    assert call(server, "/setup/nope", "POST", b"{}")[0] == 404
    assert call(server, "/setup/claude-code", "GET")[0] == 404  # POST only


def test_handler_refuses_a_bad_content_length(st, server):
    import http.client

    host, port = server.removeprefix("http://").split(":")
    c = http.client.HTTPConnection(host, int(port), timeout=5)
    c.putrequest("POST", "/setup/claude-code")
    c.putheader("Content-Length", "abc")
    c.endheaders()
    r = c.getresponse()
    assert r.status == 413
    c.close()


# ---------------------------------------------------------------- disk use (Overview, #68)
def test_disk_use_of_workspace_and_home(st, tmp_path, monkeypatch):
    d = st.disk(tmp_path)
    assert d["total"] > 0 and set(d) == {"total", "used", "free"}
    assert st.disk(tmp_path / "missing") is None
    monkeypatch.setattr(st, "WORKSPACE", tmp_path)
    monkeypatch.setattr(st, "sh", lambda *a: "2.0.0")
    monkeypatch.setattr(st, "git_get", lambda k: None)
    monkeypatch.setattr(st, "pane", lambda s: None)
    monkeypatch.setattr(st, "rc_running", lambda: False)
    s = st.status()
    assert s["workspace_disk"]["total"] > 0 and s["home_disk"]["total"] > 0
