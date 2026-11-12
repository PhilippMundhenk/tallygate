"""agent/tallygate-hook.py, the PreToolUse hook (#74): reports the tool call, never gets in the agent's way."""

import importlib.util
import io
import json
import time
from pathlib import Path

import pytest

from .test_agent_cli import FakeGateway

HOOK = Path(__file__).resolve().parents[2] / "agent" / "tallygate-hook.py"


def load(monkeypatch, url: str):
    monkeypatch.setenv("TALLYGATE_URL", url)
    monkeypatch.setenv("http_proxy", "http://127.0.0.1:9")  # the agent's proxy settings must be ignored
    spec = importlib.util.spec_from_file_location("tallygate_hook", HOOK)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def fake():
    f = FakeGateway()
    f.on("POST", "/v1/activity", (202, {"ok": True}))
    yield f
    f.srv.shutdown()


def event(tool="Bash", **args):
    return io.StringIO(json.dumps({"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": args}))


def test_reports_command_and_description(fake, monkeypatch):
    hook = load(monkeypatch, fake.url)
    assert hook.main(event(command="TOKEN=abc npm install", description="Install dependencies")) == 0
    (_, path, body, _), *_ = fake.seen
    assert path == "/v1/activity"
    assert body == {
        "kind": "tool",
        "tool": "Bash",
        "text": "TOKEN=<redacted> npm install",
        "note": "Install dependencies",
    }


def test_webfetch_url_and_nothing_for_other_tools(fake, monkeypatch):
    hook = load(monkeypatch, fake.url)
    hook.main(event("WebFetch", url="https://user:pw@docs.example.org/x", prompt="summarise"))
    assert fake.seen[-1][2]["text"] == "https://<redacted>@docs.example.org/x"
    before = len(fake.seen)
    hook.main(event("Read", file_path="/etc/passwd"))  # no command, no description: nothing sent
    hook.main(io.StringIO("[1]"))
    hook.main(io.StringIO(json.dumps({"tool_name": "Bash", "tool_input": "x"})))
    assert len(fake.seen) == before
    assert hook.report({"tool_name": "Bash", "tool_input": {"command": "x " * 300}})["text"].count("x") <= 200


@pytest.mark.parametrize("url", ["http://127.0.0.1:9", "file:///etc/passwd"])
def test_never_fails_or_blocks(monkeypatch, url):
    hook = load(monkeypatch, url)
    t0 = time.time()
    assert hook.main(event(command="ls")) == 0  # unreachable gateway / bad URL
    assert hook.main(io.StringIO("not json")) == 0
    assert time.time() - t0 < 2


def test_slow_gateway_is_given_up(monkeypatch):
    import socket

    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)  # accepts the connection, never answers
    hook = load(monkeypatch, f"http://127.0.0.1:{srv.getsockname()[1]}")
    t0 = time.time()
    assert hook.main(event(command="ls")) == 0
    assert time.time() - t0 < hook.TIMEOUT + 1
    srv.close()
