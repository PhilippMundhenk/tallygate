"""control/app/agentschema.py (#243): the agent's answers are reduced to known keys with their expected types
before the UI sees them. The status server runs as the agent user, so every answer may be hostile."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "control"))

from app import agentschema
from app.agentschema import BOOL, NUM, clean, normalise, text

STATUS = {
    "claude_version": "2.1.0 (Claude Code)",
    "claude_logged_in": True,
    "git_name": "Alex Example",
    "git_email": "alex@example.org",
    "git_identity": "ok",
    "remote_control_enabled": True,
    "remote_control_running": False,
    "remote_control_consent": True,
    "remote_control_prompt": "",
    "remote_control_name": "tallygate",
    "gateway_ca_trusted": True,
    "workspace_disk": {"total": 1000, "used": 400, "free": 600},
    "home_disk": None,
    "time": 1795000000.5,
}


def test_a_genuine_status_passes_unchanged():
    assert clean("GET", "status", STATUS) == STATUS


def test_every_relayed_route_has_a_schema_and_takes_an_error():
    sys.modules.pop("app.main", None)
    for route, schema in agentschema.SCHEMAS.items():
        assert clean(*route, {"error": "x" * 1000}) == {"error": "x" * 300}, route
        assert "error" in schema


@pytest.mark.parametrize(
    "key,bad",
    [
        ("claude_version", 1),  # the reviewer's case: .replace() on a number stopped the Setup tab
        ("claude_version", ["2.0.0"]),
        ("claude_version", {"toString": "x"}),
        ("claude_version", None),
        ("claude_logged_in", "yes"),
        ("claude_logged_in", 1),
        ("git_name", True),
        ("remote_control_prompt", 0),
        ("workspace_disk", "full"),
        ("workspace_disk", [1, 2, 3]),
        ("time", "now"),
        ("time", True),
        ("time", float("nan")),
        ("time", float("inf")),
    ],
)
def test_a_value_of_the_wrong_type_is_left_out(key, bad):
    out = clean("GET", "status", {**STATUS, key: bad})
    assert key not in out and out == {k: v for k, v in STATUS.items() if k != key}


def test_unknown_keys_are_dropped_and_strings_are_cut():
    out = clean(
        "GET",
        "status",
        {
            "claude_version": "v" * 5000,
            "__proto__": {"polluted": True},
            "constructor": "x",
            "html": "<script>alert(1)</script>",
            "workspace_disk": {"total": 1, "used": "2", "free": 3, "path": "/etc"},
        },
    )
    assert out == {"claude_version": "v" * 100, "workspace_disk": {"total": 1, "free": 3}}


def test_lists_are_capped_and_their_items_checked():
    results = [{"name": f"t{i}", "pass": True, "detail": "d" * 999, "extra": 1} for i in range(500)]
    results[1] = "not a row"
    results[2] = {"name": 7, "pass": "yes"}
    out = clean("GET", "selftest", {"results": results})
    assert len(out["results"]) == 199  # 200 looked at, the one that is no object dropped
    assert out["results"][0] == {"name": "t0", "pass": True, "detail": "d" * 300}
    assert out["results"][1] == {}  # nothing usable in it: the UI shows an empty, failed row
    assert clean("GET", "selftest", {"results": "all passed"}) == {}
    assert clean("GET", "selftest", {"results": {"0": {}}}) == {}


def test_nested_answers_keep_their_shape_only():
    out = clean(
        "GET",
        "setup/git-identity",
        {"ok": True, "login": "octo", "current": {"name": "A", "email": 5, "state": "ok", "x": []}, "extra": {}},
    )
    assert out == {"ok": True, "login": "octo", "current": {"name": "A", "state": "ok"}}
    assert clean("GET", "setup/git-identity", {"current": "none"}) == {}
    login = clean("POST", "setup/claude-login", {"logged_in": False, "url": "u" * 5000, "state": "waiting_code"})
    assert login == {"logged_in": False, "url": "u" * 2048, "state": "waiting_code"}
    assert clean("POST", "setup/remote-control", {"consent": True, "restarted": "no"}) == {"consent": True}


@pytest.mark.parametrize("data", [[1, 2], "x", 7, None, True])
def test_an_answer_that_is_no_object_is_refused(data):
    with pytest.raises(ValueError, match="not an object"):
        clean("GET", "status", data)


def test_normalise_primitives():
    assert normalise(True, BOOL) is True and normalise(0, BOOL) is ...
    assert normalise(3, NUM) == 3 and normalise(2.5, NUM) == 2.5 and normalise("3", NUM) is ...
    assert normalise("abc", text(2)) == "ab" and normalise(b"abc", text(2)) is ...
    assert normalise(None, (NUM, None)) is None and normalise(4, (NUM, None)) == 4
    assert normalise("x", (NUM, None)) is ...
    assert normalise([1, "a", 2, 3], [NUM, 3]) == [1, 2]
