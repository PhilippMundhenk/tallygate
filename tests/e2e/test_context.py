"""Context for decisions end to end (#74): the hook reports, the approval carries it, labelled as a claim."""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

from .conftest import clean_env, start_echo
from .helpers import http_via_proxy
from .test_gateway import in_thread

HOOK = Path(__file__).resolve().parents[2] / "agent" / "tallygate-hook.py"


def run_hook(gw, event: dict) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(HOOK)],
        input=json.dumps(event),
        capture_output=True,
        text=True,
        timeout=10,
        env=clean_env(TALLYGATE_URL=f"http://127.0.0.1:{gw['ports']['grants']}"),
    )


def wait_pending(gw, port, timeout=5):
    deadline = time.time() + timeout
    while time.time() < deadline:
        for p in gw["api"].call("GET", "/pending")[1]:
            if p["port"] == port:
                return p
        time.sleep(0.1)
    raise AssertionError("no pending request")


def test_the_hook_report_is_attached_to_the_next_approval(gateway):
    event = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "curl -H 'Authorization: Bearer s3cr3t' http://x", "description": "Fetch the data"},
    }
    r = run_hook(gateway, event)
    assert r.returncode == 0 and r.stdout == "" and r.stderr == ""  # never in Claude Code's way
    port = start_echo()
    t, _ = in_thread(http_via_proxy, gateway["ports"]["http"], f"http://127.0.0.1:{port}/")
    p = wait_pending(gateway, port)
    ctx = p["context"][0]
    assert ctx["tool"] == "Bash" and ctx["note"] == "Fetch the data" and "s3cr3t" not in json.dumps(p)
    assert ctx["text"] == "curl -H 'Authorization: <redacted> <redacted>' http://x"
    ask = next(e for e in gateway["api"].call("GET", "/events?limit=30")[1] if e["kind"] == "ask" and e["port"] == port)
    assert ask["extra"]["context"][0]["note"] == "Fetch the data"  # in the audit log too
    gateway["api"].call("POST", f"/pending/{p['id']}/decide", {"scope": "deny", "by": "e2e"})
    t.join(10)


def test_a_note_and_its_limits(gateway):
    agent = gateway["agent"]
    assert agent.call("POST", "/v1/activity", {"kind": "note", "note": "updating the lock file"})[0] == 202
    assert agent.call("POST", "/v1/activity", {"kind": "evil", "text": "x"})[0] == 400
    assert agent.call("POST", "/v1/activity", ["x"])[0] == 400
    big = agent.call("POST", "/v1/activity", {"text": "x" * 10_000})
    assert big[0] in (400, 413)
    port = start_echo()
    t, _ = in_thread(http_via_proxy, gateway["ports"]["http"], f"http://127.0.0.1:{port}/")
    p = wait_pending(gateway, port)
    assert p["context"][0] == {"ts": p["context"][0]["ts"], "kind": "note", "note": "updating the lock file"}
    gateway["api"].call("POST", f"/pending/{p['id']}/decide", {"scope": "deny", "by": "e2e"})
    t.join(10)


def test_activity_has_its_own_rate_limit(make_gateway):
    gw = make_gateway({"activity_rate": 2, "grant_api_rate": 5}, {"default": "deny"})
    codes = [gw["agent"].call("POST", "/v1/activity", {"text": f"cmd {i}"})[0] for i in range(4)]
    assert codes == [202, 202, 429, 429]
    assert gw["agent"].call("GET", "/v1/grants")[0] == 200  # grant requests are not starved
    r = run_hook(gw, {"tool_name": "Bash", "tool_input": {"command": "ls"}})
    assert r.returncode == 0 and r.stdout == ""  # rate limited: still silent
