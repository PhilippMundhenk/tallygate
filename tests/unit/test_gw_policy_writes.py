"""PATCH /policy and POST /emergency-stop in-process (#60): partial policy writes, best-effort stop with a
result per step, and the auto-approval suspension that lasts until the mode changes."""

import asyncio
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "gateway"))

pytest.importorskip("mitmproxy")
pytest.importorskip("aiohttp")

from aiohttp.test_utils import TestClient, TestServer

from egressgw import api, core
from egressgw.core import Pending

TOKEN = "t" * 32
PRESETS = Path(__file__).resolve().parents[2] / "gateway" / "presets"


def make_gw(_data=None):
    g = core.Gateway()
    g.api_token = TOKEN
    return g


@pytest.fixture
def gw(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "DATA_DIR", tmp_path)
    monkeypatch.setattr(core, "CONFIG_PATH", tmp_path / "config.yaml")
    monkeypatch.setattr(core, "PRESET_DIR", PRESETS)
    monkeypatch.setattr(core, "CA_EXPORT", tmp_path / "ca")
    monkeypatch.setattr(core, "STATIC_HOSTS", {})
    (tmp_path / "config.yaml").write_text(
        yaml.safe_dump(
            {
                "grants": {
                    "nas": {"targets": [{"host": "nas.example", "port": 443}], "levels": ["write"]},
                    "auto": {"targets": [{"host": "a.example", "port": 443}], "approval": "auto"},
                },
            }
        )
    )
    (tmp_path / "policy.yaml").write_text(
        yaml.safe_dump({"default": "ask", "rules": [{"id": "ok", "action": "allow", "host": "ok.example"}]})
    )
    return make_gw(tmp_path)


def admin(gw, method, path, body=None, raw=None):
    async def go():
        async with TestClient(TestServer(api.build_app(gw))) as c:
            kw = {"data": raw} if raw is not None else {"json": body}
            r = await c.request(method, path, headers={"Authorization": f"Bearer {TOKEN}"}, **kw)
            return r.status, await r.json()

    return asyncio.run(go())


# ------------------------------------------------------------------ PATCH /policy
@pytest.mark.parametrize(
    ("body", "error"),
    [
        ({}, "expected an object"),
        (["deny"], "expected an object"),
        ({"default": "deny", "rules": []}, "changes only default and ask_timeout"),
        ({"default": "block"}, "default must be one of"),
        ({"ask_timeout": 4}, "ask_timeout must be"),
        ({"ask_timeout": 3601}, "ask_timeout must be"),
        ({"ask_timeout": "60"}, "ask_timeout must be"),
        ({"ask_timeout": 60.5}, "ask_timeout must be"),
        ({"ask_timeout": True}, "ask_timeout must be"),
        ({"ask_timeout": None}, "ask_timeout must be"),
    ],
)
def test_patch_validates_and_changes_nothing_on_error(gw, body, error):
    status, data = admin(gw, "PATCH", "/policy", body)
    assert status == 400 and error in data["error"]
    assert (gw.policy.default, gw.policy.ask_timeout) == ("ask", 60)


def test_patch_changes_only_mode_and_timeout(gw):
    # a copy the browser loaded earlier knows only "ok"; rules added since must survive a mode change
    admin(gw, "POST", "/rules", {"id": "new", "action": "allow", "host": "new.example"})
    gw.policy.remove_rule("ok")
    status, data = admin(gw, "PATCH", "/policy", {"default": "deny"})
    assert status == 200 and data["default"] == "deny" and [r["id"] for r in data["rules"]] == ["new"]
    status, data = admin(gw, "PATCH", "/policy", {"ask_timeout": 120})
    assert data["default"] == "deny" and data["ask_timeout"] == 120
    saved = yaml.safe_load((core.DATA_DIR / "policy.yaml").read_text())
    assert saved["default"] == "deny" and saved["ask_timeout"] == 120 and len(saved["rules"]) == 1
    assert gw.events.recent(1)[0]["reason"] == "mode deny, approval timeout 120 s via API"


# ------------------------------------------------------------------ emergency stop
def add_pending(gw, host, done=False):
    loop = asyncio.new_event_loop()
    fut = loop.create_future()
    if done:
        fut.set_result(None)
    p = Pending(host=host, port=443, ips=[], proto="http", client="c", timeout=60, future=fut)
    gw.pending[(host, 443)] = p
    return p


def test_emergency_stop_runs_every_step_and_suspends_auto_approval(gw):
    assert gw.request_grant("auto", "read", None, "", "c").status == "approved"  # auto grant active
    req = gw.request_grant("nas", "write", None, "", "c")  # waiting for a human
    p = add_pending(gw, "ask.example")
    add_pending(gw, "done.example", done=True)
    gw.pending[("nofuture.example", 443)] = Pending("nofuture.example", 443, [], "http", "c", 60)
    assert admin(gw, "POST", "/presets/internet", {"ttl": 600})[0] == 200
    assert admin(gw, "POST", "/presets/open", {})[0] == 200
    seen = asyncio.Queue()
    gw.subscribers.add(seen)

    status, res = admin(gw, "POST", "/emergency-stop", {"by": "web:admin"})
    assert status == 200 and res["ok"] is True
    steps = {s["step"]: s for s in res["steps"]}
    assert list(steps) == [
        "suspend_auto_approval",
        "revoke_grants",
        "deny_pending",
        "deny_grant_requests",
        "remove_internet_presets",
        "mode_deny",
    ]
    assert steps["revoke_grants"]["revoked"] == ["auto"] and not gw.grants.active
    assert sorted(steps["deny_pending"]["denied"]) == ["ask.example:443", "done.example:443", "nofuture.example:443"]
    assert not gw.pending and p.future.result().action == "deny"
    assert steps["deny_grant_requests"]["denied"] == ["nas"] and req.status == "denied"
    assert sorted(steps["remove_internet_presets"]["removed"]) == ["internet:all", "open:web"]
    assert [r.id for r in gw.policy.rules] == ["ok"]
    assert steps["mode_deny"]["previous"] == "ask" and gw.policy.default == "deny"
    assert gw.grants.auto_suspended["by"] == "web:admin"
    ev = gw.events.recent(1)[0]
    assert ev["action"] == "emergency-stop" and ev["reason"].startswith("emergency stop by web:admin (")
    assert "revoke_grants: 1" in ev["reason"] and ev["reason"].endswith("complete)")
    published = [seen.get_nowait()["type"] for _ in range(seen.qsize())]
    assert "resolved" in published and "grants" in published and "policy" in published

    # an auto level now needs a human, also after a restart
    assert gw.request_grant("auto", "read", None, "", "c").status == "pending"
    assert make_gw(core.DATA_DIR).grants.auto_suspended["by"] == "web:admin"
    # a write that keeps the mode does not end it; changing the mode does
    admin(gw, "PATCH", "/policy", {"ask_timeout": 30, "default": "deny"})
    assert gw.grants.auto_suspended
    admin(gw, "PATCH", "/policy", {"default": "ask"})
    assert gw.grants.auto_suspended is None and gw.events.recent(1)[0]["reason"].endswith("auto-approval resumed")
    assert make_gw(core.DATA_DIR).grants.auto_suspended is None


def test_a_full_replace_that_changes_the_mode_also_resumes_auto_approval(gw):
    admin(gw, "POST", "/emergency-stop")  # no body: attributed to "api"
    assert gw.grants.auto_suspended["by"] == "api"
    admin(gw, "PUT", "/policy", {**gw.policy.to_dict()})  # same mode
    assert gw.grants.auto_suspended
    admin(gw, "PUT", "/policy", {**gw.policy.to_dict(), "default": "ask"})
    assert gw.grants.auto_suspended is None
    assert gw.events.recent(1)[0]["reason"] == "policy replaced via API; grant auto-approval resumed"
    admin(gw, "PATCH", "/policy", {"default": "allow"})  # nothing to resume
    assert gw.events.recent(1)[0]["reason"] == "mode allow, approval timeout 60 s via API"


def test_emergency_stop_continues_after_a_failed_step(gw, monkeypatch, tmp_path):
    gw.request_grant("auto", "read", None, "", "c")
    gw.request_grant("nas", "write", None, "", "c")

    def broken(*_a, **_k):
        raise RuntimeError("boom")

    monkeypatch.setattr(gw, "revoke_grant", broken)
    monkeypatch.setattr(gw, "decide_grant", broken)
    monkeypatch.setattr(gw.grants, "suspend_auto", broken)
    presets = tmp_path / "presets"
    presets.mkdir()
    (presets / "bad.yaml").write_text("category: nonsense\n")
    monkeypatch.setattr(core, "PRESET_DIR", presets)
    status, res = admin(gw, "POST", "/emergency-stop", raw="[1]")  # not an object: attributed to "api"
    assert status == 200 and res["ok"] is False
    steps = {s["step"]: s for s in res["steps"]}
    assert steps["suspend_auto_approval"] == {
        "step": "suspend_auto_approval",
        "ok": False,
        "errors": ["RuntimeError: boom"],
    }
    assert steps["revoke_grants"]["errors"] == ["auto: boom"] and not steps["revoke_grants"]["ok"]
    assert steps["deny_grant_requests"]["errors"] == ["nas: boom"]
    errors = steps["remove_internet_presets"]["errors"]
    assert errors[0].startswith("preset bad: ") and errors[1].startswith("no internet presets found")
    assert steps["mode_deny"]["ok"] and gw.policy.default == "deny"  # the last step still ran
    reason = gw.events.recent(1)[0]["reason"]
    assert reason.startswith("emergency stop by api (") and "failed: suspend_auto_approval, revoke_grants" in reason


def test_emergency_stop_result_survives_a_broken_event_log(gw, monkeypatch):
    def broken(**_ev):
        raise OSError("disk full")

    monkeypatch.setattr(gw, "record", broken)
    status, res = admin(gw, "POST", "/emergency-stop", {})
    assert status == 200 and res["ok"] and gw.policy.default == "deny"


def test_unreadable_suspension_state_keeps_auto_approval_off(gw, caplog):
    (core.DATA_DIR / "grants-state.yaml").write_text("auto_suspended: [unclosed\n")
    g = make_gw(core.DATA_DIR)
    assert g.grants.auto_suspended == {"since": 0, "by": "unreadable state file"}
    assert "auto-approval stays suspended" in caplog.text
    assert g.request_grant("auto", "read", None, "", "c").status == "pending"
    assert admin(g, "GET", "/grants")[1]["auto_suspended"]["by"] == "unreadable state file"
    assert g.grants.resume_auto() and not g.grants.resume_auto()
