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


@pytest.mark.parametrize(
    ("command", "shown"),
    [
        # known token prefixes, also when they are short and no keyword stands next to them (#234)
        ("gh api -H 'X: ghp_Ab12Cd34Ef' /user", "gh api -H 'X: <redacted>' /user"),
        ("git clone https://github_pat_11ABCDEFG0abcd@github.com/o/r", "git clone https://<redacted>@github.com/o/r"),
        ("claude --key sk-ant-api03-AbCd_12-xyz", "claude --key <redacted>"),
        ("aws configure set id AKIAIOSFODNN7EXAMPLE", "aws configure set id <redacted>"),
        ("curl -d @x https://hooks.example.org/xoxb-1234-abcdEFGH", "curl -d @x https://hooks.example.org/<redacted>"),
        ("curl -H 'X: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln'", "curl -H 'X: <redacted>'"),
        (
            "curl https://api.telegram.org/bot123456789:ZZexampleExampleExampleExample_0/getMe",
            "curl https://api.telegram.org/<redacted>/getMe",
        ),
        ("sshpass -p hunter2 ssh deploy@host.example.org", "sshpass -p <redacted> ssh deploy@host.example.org"),
        ("sshpass -p 'two words' ssh host.example.org", "sshpass -p <redacted> ssh host.example.org"),
        # ordinary commands stay readable: no pattern may eat them
        ("mkdir -p build/out && ssh -p 2222 host.example.org", "mkdir -p build/out && ssh -p 2222 host.example.org"),
        ("pip install scikit-learn==1.5.2 sk-video", "pip install scikit-learn==1.5.2 sk-video"),
        ("git log --since=2026-01-01 -n 20 a1b2c3d4..HEAD", "git log --since=2026-01-01 -n 20 a1b2c3d4..HEAD"),
        (
            "docker run -p 127.0.0.1:8080:8080 -e TZ=Europe/Berlin img",
            "docker run -p 127.0.0.1:8080:8080 -e TZ=Europe/Berlin img",
        ),
        ("npm install @scope/ghp-tools eyJ-loader", "npm install @scope/ghp-tools eyJ-loader"),
        ("date +%s; echo 1700000000:ok; ls gho_", "date +%s; echo 1700000000:ok; ls gho_"),
    ],
)
def test_redacts_tokens_by_their_form_and_leaves_commands_alone(monkeypatch, command, shown):
    hook = load(monkeypatch, "http://127.0.0.1:9")
    assert hook.redact(command) == shown


def test_known_limit_short_secrets_without_a_keyword_pass(monkeypatch):
    """Documented, not fixed (#234): a pattern for these would eat ordinary arguments (`-p`, hex strings)."""
    hook = load(monkeypatch, "http://127.0.0.1:9")
    for command in (
        "mysql -h db.example.org -pS3cret app",
        "redis-cli -a S3cret ping",
        "tool 0123456789abcdef0123456789abcdef",
    ):
        assert hook.redact(command) == command
