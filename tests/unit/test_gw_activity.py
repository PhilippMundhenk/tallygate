"""Context for decisions (#74): agent-written activity is cleaned, redacted, bounded and attached briefly."""

import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "gateway"))

from egressgw import activity
from egressgw.activity import Activity, clean


@pytest.mark.parametrize(
    ("raw", "shown"),
    [
        ("npm install", "npm install"),
        ("line1\nline2\x1b[31m red", "line1 line2 [31m red"),
        (
            "curl -H 'Authorization: Bearer abc.def' https://x",
            "curl -H 'Authorization: <redacted> <redacted>' https://x",
        ),
        ("GH_TOKEN=ghp_abcdefghijklmnop gh pr list", "GH_TOKEN=<redacted> gh pr list"),
        ("mysql --password hunter2 db", "mysql --password <redacted> db"),
        ("git clone https://user:pw@example.org/r.git", "git clone https://<redacted>@example.org/r.git"),
        ("export OPENAI_API_KEY=sk-abcdefghijklmnopqrstu", "export OPENAI_API_KEY=<redacted>"),
        ("echo sk-abcdefghijklmnopqrstu", "echo <redacted>"),
        ("echo eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig", "echo <redacted>"),
        ("use " + "A1b2" * 12, "use <redacted>"),
        ("curl -u bob:secret x", "curl -u <redacted> x"),
        ("echo token abc123", "echo token <redacted>"),
    ],
)
def test_clean_redacts_obvious_secrets(raw, shown):
    assert clean(raw) == shown


def test_clean_bounds_the_length():
    assert len(clean("x " * 500)) == activity.MAX_TEXT and clean("x " * 500).endswith("…")
    assert clean(None) == "" and clean(42) == "42"


def test_add_validates_and_cleans():
    a = Activity()
    e = a.add({"tool": "Bash", "text": "pip install requests", "note": "Install deps\n"}, "10.0.0.5")
    assert e["kind"] == "tool" and e["note"] == "Install deps"
    assert a.add({"kind": "note", "tool": "ignored", "note": "updating the lock file"}, "c")["tool"] == ""
    for bad in ([1], {"kind": "shell", "text": "x"}, {"tool": "Bash"}, {"text": "  "}):
        with pytest.raises(ValueError):
            a.add(bad, "c")


def test_recent_is_per_client_newest_first_short_and_bounded(monkeypatch):
    a = Activity()
    now = time.time()
    monkeypatch.setattr(activity.time, "time", lambda: now - 500)
    a.add({"text": "old"}, "c")
    for i in range(5):
        monkeypatch.setattr(activity.time, "time", lambda i=i: now - 10 + i)
        a.add({"tool": "Bash", "text": f"cmd {i}"}, "c")
    a.add({"text": "other agent"}, "d")
    got = a.recent("c", now)
    assert [g["text"] for g in got] == ["cmd 4", "cmd 3", "cmd 2"] and "client" not in got[0]
    assert a.recent("c", now + 1000) == [] and a.recent("x", now) == []
    assert "note" not in got[0]  # empty fields are left out
