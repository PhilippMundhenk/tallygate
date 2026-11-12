"""Guided first start (#75) end to end: browser API → control → the real agent/status.py, which drives fakes of
tmux, claude, gh and git (tests/e2e/fake_agent_tools.py)."""

from __future__ import annotations

import json

import pytest

from .conftest import CONTROL_PASSWORD
from .helpers import Api


def login(base: str) -> Api:
    api = Api(base, csrf_header="X-Tallygate")
    assert api.call("POST", "/login", form={"password": CONTROL_PASSWORD})[0] == 302
    return api


@pytest.fixture
def ui(agent_control):
    return login(agent_control["base"])


def set_state(fake_agent, name: str, value: str | None) -> None:
    p = fake_agent["state"] / name
    if value is None:
        p.unlink(missing_ok=True)
    else:
        p.write_text(value)


def test_setup_actions_need_session_and_csrf(agent_control):
    anon = Api(agent_control["base"], csrf_header="X-Tallygate")
    assert anon.call("POST", "/api/agent/setup/claude-login", {})[0] == 401
    ui = login(agent_control["base"])
    no_csrf = Api(agent_control["base"])
    no_csrf.jar, no_csrf.opener = ui.jar, ui.opener
    for path in ("claude-login", "claude-code", "git-identity", "remote-control"):
        status, data, _ = no_csrf.call("POST", f"/api/agent/setup/{path}", {})
        assert status == 403 and data["error"] == "csrf check failed"
    assert ui.call("PUT", "/api/agent/setup/git-identity", {})[0] == 404  # only the listed methods and paths
    assert ui.call("POST", "/api/agent/setup/claude-code", {"code": "x" * 5000})[0] == 413


def test_git_identity_from_github_explains_failures_and_never_writes_empty_values(ui, fake_agent):
    status = ui.call("GET", "/api/agent/status")[1]
    assert status["git_identity"] == "missing" and status["remote_control_name"] == "e2e-session"
    set_state(fake_agent, "gh-mode", "401")  # no token stored in the gateway yet
    r = ui.call("GET", "/api/agent/setup/git-identity")[1]
    assert r["ok"] is False and r["reason"] == "token" and "401" in r["message"]
    set_state(fake_agent, "gh-mode", "down")
    r = ui.call("GET", "/api/agent/setup/git-identity")[1]
    assert r["reason"] == "network" and "Forbidden" in r["message"]
    set_state(fake_agent, "gh-mode", "ok")
    r = ui.call("GET", "/api/agent/setup/git-identity")[1]
    assert r["ok"] and r["name"] == "The Octocat" and r["email"] == "583231+octocat@users.noreply.github.com"
    assert r["current"]["state"] == "missing"
    status, data, _ = ui.call("POST", "/api/agent/setup/git-identity", {"name": "", "email": r["email"]})
    assert status == 400 and "must not be empty" in data["error"]
    assert not (fake_agent["state"] / "gitconfig.json").exists()  # nothing written
    status, data, _ = ui.call("POST", "/api/agent/setup/git-identity", {"name": r["name"], "email": r["email"]})
    assert status == 200 and data == {"name": "The Octocat", "email": r["email"], "state": "ok"}
    assert ui.call("GET", "/api/agent/status")[1]["git_identity"] == "ok"
    # an earlier `git config --global user.name "$(gh api ...)"` whose gh failed stored an empty value
    (fake_agent["state"] / "gitconfig.json").write_text(json.dumps({"user.name": "", "user.email": r["email"]}))
    assert ui.call("GET", "/api/agent/status")[1]["git_identity"] == "empty"


def test_claude_login_without_a_console(ui, fake_agent):
    (fake_agent["home"] / ".claude" / ".credentials.json").unlink(missing_ok=True)
    set_state(fake_agent, "login-url", None)
    assert ui.call("GET", "/api/agent/setup/claude-login")[1]["state"] == "idle"
    status, data, _ = ui.call("POST", "/api/agent/setup/claude-code", {"code": "good-code-1234#e2e"})
    assert status == 409 and "no login is waiting" in data["error"]
    r = ui.call("POST", "/api/agent/setup/claude-login", {})[1]
    assert r["state"] == "waiting_code" and r["url"].startswith("https://claude.com/cai/oauth/authorize?")
    assert ui.call("POST", "/api/agent/setup/claude-code", {"code": "a b"})[0] == 400
    r = ui.call("POST", "/api/agent/setup/claude-code", {"code": "wrong-code-123"})[1]
    assert r["state"] == "failed" and r["message"] == "Login failed: invalid code" and not r["logged_in"]
    # remote control needs the login first
    status, data, _ = ui.call("POST", "/api/agent/setup/remote-control", {})
    assert status == 409 and data["error"] == "log in to Claude first"
    assert ui.call("POST", "/api/agent/setup/claude-login", {})[1]["state"] == "waiting_code"  # starts afresh
    r = ui.call("POST", "/api/agent/setup/claude-code", {"code": "good-code-1234#e2e"})[1]
    assert r["state"] == "done" and r["logged_in"] and r["message"] == "Login successful."
    assert ui.call("GET", "/api/agent/status")[1]["claude_logged_in"] is True


def test_login_url_from_the_agent_is_only_passed_on_for_anthropic(ui, fake_agent):
    for url in (
        "https://evil.example/oauth/authorize?x=1",
        "https://claude.com.evil.example/oauth/authorize?x=1",
        "https://claude.com:8443/oauth/authorize?x=1",
        "https://claude.com/x?next=https://evil.example/oauth/authorize?a=1",  # host is fine, the page is not
    ):
        set_state(fake_agent, "login-url", url)
        r = ui.call("POST", "/api/agent/setup/claude-login", {})[1]
        assert r["state"] == "waiting_code" and r["url"] == "", url
    set_state(fake_agent, "login-url", None)


def test_remote_control_consent_without_the_prompt(ui, fake_agent):
    creds = fake_agent["home"] / ".claude" / ".credentials.json"
    creds.parent.mkdir(parents=True, exist_ok=True)
    creds.write_text("{}")
    cfg = fake_agent["home"] / ".claude.json"
    cfg.write_text(json.dumps({"machineID": "e2e"}))
    assert ui.call("GET", "/api/agent/status")[1]["remote_control_consent"] is False
    r = ui.call("POST", "/api/agent/setup/remote-control", {})[1]
    assert r == {"consent": True, "restarted": False}  # no rc session in the fake agent yet
    data = json.loads(cfg.read_text())
    assert data["remoteDialogSeen"] is True and data["machineID"] == "e2e"
    assert data["projects"][str(fake_agent["workspace"])] == {"hasTrustDialogAccepted": True}
    assert ui.call("GET", "/api/agent/status")[1]["remote_control_consent"] is True


def test_deployment_checks(ui, control_with):
    r = ui.call("GET", "/api/setup/checks?origin=http://127.0.0.1:1234")[1]
    states = {c["id"]: c["state"] for c in r["checks"]}
    assert states == {"https": "ok", "cookie": "ok", "proxy": "ok", "public_url": "info", "reach": "info"}
    assert r["password"] == "env-plain"  # the e2e control uses CONTROL_PASSWORD
    r = ui.call("GET", "/api/setup/checks?origin=http://192.0.2.5:8080", headers={"X-Forwarded-For": "1.2.3.4"})[1]
    states = {c["id"]: c for c in r["checks"]}
    assert states["https"]["state"] == "warn" and states["proxy"]["state"] == "warn"
    assert "TRUSTED_PROXIES=127.0.0.1/32" in states["proxy"]["detail"]
    assert "http://192.0.2.5:8080" in states["reach"]["detail"]
    base = control_with(
        PUBLIC_URL="https://tally.example",
        TRUST_FORWARDED_FOR="1",
        TRUSTED_PROXIES="127.0.0.1/32",
        COOKIE_SECURE="auto",
    )
    other = login(base)
    hdrs = {"X-Forwarded-Proto": "https", "X-Forwarded-Host": "tally.example"}
    r = other.call("GET", "/api/setup/checks?origin=https://tally.example", headers=hdrs)[1]
    states = {c["id"]: c["state"] for c in r["checks"]}
    assert states == {"https": "ok", "cookie": "ok", "proxy": "ok", "public_url": "ok", "reach": "info"}
    r = other.call("GET", "/api/setup/checks?origin=http://192.0.2.5:8080", headers=hdrs)[1]
    assert {c["id"]: c["state"] for c in r["checks"]}["public_url"] == "bad"


def test_wizard_page_loads_its_script(ui):
    _, page, _ = ui.call("GET", "/")
    assert b'src="/static/wizard.js"' in page and b'id="st-claude"' in page
    status, js, _ = ui.call("GET", "/static/wizard.js")
    assert status == 200 and b"tabHooks.setup" in js
