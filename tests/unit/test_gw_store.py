"""Event log, secrets store and template rendering (gateway/egressgw/store.py)."""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "gateway"))

from egressgw.store import EventLog, Secrets, atomic_write, render


@pytest.fixture
def log(tmp_path):
    return EventLog(tmp_path / "events.db", keep_days=1, max_events=5)


def test_atomic_write_replaces_content_with_the_given_mode(tmp_path):
    p = tmp_path / "f.yaml"
    p.write_text("old")
    atomic_write(p, "new ü", 0o600)
    assert p.read_text(encoding="utf-8") == "new ü"
    assert p.stat().st_mode & 0o777 == 0o600
    assert not (tmp_path / "f.tmp").exists()


def test_events_roundtrip_with_defaults(log):
    ev = log.add({"host": "a.example", "port": 443, "action": "allow", "ips": ["1.2.3.4"], "extra": {"k": 1}})
    assert ev["id"] and ev["ts"]
    plain = log.add({"host": "b.example"})
    rows = log.recent()
    assert [r["id"] for r in rows] == [plain["id"], ev["id"]]  # newest first
    assert rows[0]["kind"] == "conn" and rows[0]["ips"] == [] and rows[0]["extra"] is None
    assert rows[1]["ips"] == ["1.2.3.4"] and rows[1]["extra"] == {"k": 1}


def test_recent_paging_search_and_limit_cap(log):
    ids = [
        log.add({"host": f"h{i}.example", "reason": "r", "action": "deny" if i % 2 else "allow"})["id"]
        for i in range(6)
    ]
    assert [r["id"] for r in log.recent(limit=2)] == ids[:-3:-1]
    assert [r["id"] for r in log.recent(limit=10, before_id=ids[2])] == [ids[1], ids[0]]
    assert {r["host"] for r in log.recent(q="h3")} == {"h3.example"}
    assert len(log.recent(q="deny")) == 3  # matches the action column too
    assert [r["id"] for r in log.recent(q="deny", before_id=ids[3])] == [ids[1]]
    # the search term is a bound parameter, not SQL
    assert log.recent(q="' OR 1=1 --") == []
    assert len(log.recent(limit=10**9)) == 6  # capped at 2000, no error


def test_age_retention_prunes_old_events(log):
    log.add({"host": "old.example", "ts": 1000.0})
    log.add({"host": "new.example", "ts": 1000.0 + 2 * 86400})  # > 1 h later: prune with keep_days=1
    assert [r["host"] for r in log.recent()] == ["new.example"]


def test_retention_runs_at_most_hourly(log):
    t = 1_000_000.0
    log.add({"host": "a.example", "ts": t})  # prunes (first time)
    log.add({"host": "stale.example", "ts": 0.0})
    log.add({"host": "b.example", "ts": t + 1800})  # within the hour: no prune yet
    assert "stale.example" in {r["host"] for r in log.recent()}
    log.add({"host": "c.example", "ts": t + 3601})
    assert "stale.example" not in {r["host"] for r in log.recent()}


def test_row_cap(log):
    for i in range(8):
        log.add({"host": f"h{i}.example"})
    log.enforce_cap()
    hosts = [r["host"] for r in log.recent()]
    assert hosts == [f"h{i}.example" for i in range(7, 2, -1)]  # only the newest max_events kept
    log.enforce_cap()  # idempotent below the cap
    assert len(log.recent()) == 5


def test_row_cap_on_an_empty_log(log):
    log.enforce_cap()
    assert log.recent() == []


def test_secrets_are_write_only_persisted_and_removable(tmp_path):
    p = tmp_path / "secrets.json"
    s = Secrets(p)
    assert s.names() == [] and s.get("x") is None
    s.set("b_tok", "v1")
    s.set("a_tok", "v2")
    assert s.names() == ["a_tok", "b_tok"]
    assert json.loads(p.read_text()) == {"b_tok": "v1", "a_tok": "v2"}
    s.set("b_tok", None)
    s.set("a_tok", "")  # empty means remove, too
    s.set("never_set", None)  # removing an unknown name is fine
    assert Secrets(p).names() == []


def test_secrets_file_permissions_are_repaired_on_load(tmp_path):
    p = tmp_path / "secrets.json"
    p.write_text('{"t": "v"}')
    p.chmod(0o644)
    s = Secrets(p)
    assert p.stat().st_mode & 0o777 == 0o600 and s.get("t") == "v"


def test_empty_secrets_file_loads(tmp_path):
    p = tmp_path / "secrets.json"
    p.write_text("")
    assert Secrets(p).names() == []


@pytest.mark.parametrize("name", ["", "Upper", "with-dash", "x" * 65, "../etc", "a b"])
def test_secret_names_are_validated(tmp_path, name):
    with pytest.raises(ValueError, match="secret name"):
        Secrets(tmp_path / "s.json").set(name, "v")
    assert not (tmp_path / "s.json").exists()


@pytest.mark.parametrize("value", ["a\nb", "a\x00", "a\x7f", "\t", "x" * 8193])
def test_secret_values_are_validated(tmp_path, value):
    with pytest.raises(ValueError, match="secret value"):
        Secrets(tmp_path / "s.json").set("t", value)


def test_secret_value_at_the_size_limit_is_accepted(tmp_path):
    s = Secrets(tmp_path / "s.json")
    s.set("t", "x" * 8192)
    assert len(s.get("t")) == 8192


def test_render_nested_missing_and_malformed(tmp_path):
    s = Secrets(tmp_path / "s.json")
    s.set("user", "u")
    assert render("no placeholders } here", s) == "no placeholders } here"
    assert render("${b64:${user}:${missing}}", s) is None  # a missing secret anywhere -> no header at all
    assert render("${b64:}", s) == ""
    with pytest.raises(ValueError, match="unterminated"):
        render("Basic ${b64:${user}", s)
    with pytest.raises(ValueError):
        render("Bearer ${user", s)  # no closing brace
