"""Rule usage (#70): hit counters, unused rules, suggestions from repeated temporary approvals."""

import asyncio
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "gateway"))

from egressgw.policy import Policy
from egressgw.store import EventLog
from egressgw.usage import rule_usage, suggestions

DAY = 86400


def pol(*rules, default="ask"):
    return Policy.from_dict({"default": default, "rules": list(rules)})


def test_hits_are_flushed_added_up_and_forgotten_for_gone_rules(tmp_path):
    ev = EventLog(tmp_path / "e.db", keep_days=30)
    now = 1_000_000_000.0
    ev.flush_hits({"a": [2, now - 5]}, ["a", "b"], now)
    ev.flush_hits({"a": [3, now - 10]}, ["a", "b"], now + 1)  # an older last match does not go back in time
    s = ev.hit_stats()
    assert s["a"] == {"hits": 5, "last": now - 5, "since": now} and s["b"] == {"hits": 0, "last": None, "since": now}
    ev.flush_hits({}, ["b"], now + 31 * DAY)  # rule a is gone and was not used for keep_days
    assert set(ev.hit_stats()) == {"b"}
    ev.flush_hits({}, [], now + 62 * DAY)
    assert ev.hit_stats() == {}


def test_usage_merges_unflushed_hits_and_finds_stale_rules():
    p = pol(
        {"id": "used", "action": "allow", "host": "used.example"},
        {"id": "old", "action": "allow", "host": "old.example", "port": 443},
        {"id": "new", "action": "allow", "host": "new.example"},
        {"id": "tmp", "action": "allow", "host": "tmp.example", "expires": 2_000_000_000},
        {"id": "gone", "action": "deny", "host": "gone.example"},
    )
    now = 1_000_000_000.0
    stored = {
        "used": {"hits": 4, "last": now - 40 * DAY, "since": now - 90 * DAY},
        "old": {"hits": 9, "last": now - 31 * DAY, "since": now - 90 * DAY},
        "new": {"hits": 0, "last": None, "since": now - 2 * DAY},
        "tmp": {"hits": 0, "last": None, "since": now - 90 * DAY},
        "gone": {"hits": 0, "last": None, "since": now - 90 * DAY},
    }
    u = {r["id"]: r for r in rule_usage(p, stored, {"used": [1, now - 60]}, now, 30)}
    assert u["used"]["hits"] == 5 and u["used"]["last"] == now - 60 and not u["used"]["stale"]
    assert u["old"]["stale"] and u["old"]["port"] == 443 and u["old"]["pos"] == 2
    assert not u["new"]["stale"]  # known for 2 days only
    assert not u["tmp"]["stale"]  # temporary rules end by themselves
    assert u["gone"]["stale"] and u["gone"]["last"] is None
    fresh = rule_usage(pol({"id": "x", "action": "allow", "host": "x.example"}), {}, {}, now, 30)
    assert fresh[0]["hits"] == 0 and fresh[0]["since"] == now and not fresh[0]["stale"]


def test_suggestions_from_repeated_temporary_approvals():
    now = time.time()
    approvals = [
        ("files.pythonhosted.org", 443, "hour", now - 100),
        ("files.pythonhosted.org", 443, "once", now - 90),
        ("cdn.pythonhosted.org", 443, "hour", now - 80),
        ("api.example.com", 443, "once", now - 70),
        ("api.example.com", 443, "once", now - 60),
        ("api.example.com", 443, "hour", now - 50),
        ("api.example.com", 443, "always", now - 40),  # permanent scopes do not count
        ("rare.example.org", 443, "hour", now - 30),
        ("203.0.113.5", 443, "hour", now - 20),
        ("203.0.113.5", 443, "hour", now - 20),
        ("203.0.113.5", 443, "hour", now - 20),
        ("covered.example.net", 443, "hour", now),
        ("covered.example.net", 443, "hour", now),
        ("covered.example.net", 443, "hour", now),
        ("github.io", 443, "hour", now),  # a public suffix stays an exact host
        ("github.io", 443, "hour", now),
        ("github.io", 443, "hour", now),
    ]
    p = pol(
        {"id": "perm", "action": "allow", "host": "*.example.net", "port": 443},
        {"id": "t", "action": "allow", "host": "api.example.com", "expires": int(now) + 3600},
    )
    s = suggestions(approvals, p, set(), 3)
    assert [x["key"] for x in s] == ["*.pythonhosted.org:443", "api.example.com:443", "github.io:443"]
    assert s[0]["rule"] == {"action": "allow", "host": "*.pythonhosted.org", "port": 443} and s[0]["count"] == 3
    assert s[0]["hosts"] == ["cdn.pythonhosted.org", "files.pythonhosted.org"] and s[0]["last"] == now - 80
    assert s[1]["rule"]["host"] == "api.example.com"  # a temporary rule does not count as covered
    assert [x["key"] for x in suggestions(approvals, p, {"api.example.com:443"}, 3)][1] == "github.io:443"
    assert suggestions(approvals, p, set(), 4) == []


# ------------------------------------------------------------------ gateway and API
pytest.importorskip("mitmproxy")
pytest.importorskip("aiohttp")

from egressgw.core import Pending  # noqa: E402
from egressgw.policy import Decision  # noqa: E402

from .test_gw_api import admin, gw  # noqa: E402, F401  (fixture)


def approve(g, host, scope, by="web:admin"):
    p = Pending(host=host, port=443, ips=[], proto="regular", client="c", timeout=30)
    g.pending[(host, 443)] = p

    async def go():
        p.future = asyncio.get_running_loop().create_future()
        g.answer(p.id, scope, by)

    asyncio.run(go())


def test_counting_is_a_dict_update_and_housekeeping_flushes_it(gw):  # noqa: F811
    gw._hit(Decision("allow", "rule ok", "ok"))
    gw._hit(Decision("allow", "rule ok", "ok"))
    gw._hit(Decision("deny", "hard-deny", "hard_deny"))
    gw._hit(Decision("ask", "default"))
    assert list(gw.hits) == ["ok"] and gw.hits["ok"][0] == 2
    rules = admin(gw, "GET", "/rules/stats")[1]
    assert rules["stale_days"] == 30 and rules["rules"][0]["hits"] == 2  # unflushed counts are included
    gw._housekeep()
    assert gw.hits == {} and gw.events.hit_stats()["ok"]["hits"] == 2
    assert admin(gw, "GET", "/rules/stats")[1]["rules"][0]["hits"] == 2


def test_cleanup_removes_only_rules_that_are_still_unused(gw):  # noqa: F811
    admin(gw, "POST", "/rules", {"id": "idle", "action": "allow", "host": "idle.example"})
    gw.flush_hits()
    old = time.time() - 40 * DAY
    gw.events.db.execute("UPDATE rule_hits SET since = ?", (old,))
    gw._hit(Decision("allow", "rule ok", "ok"))  # ok is in use
    status, r = admin(gw, "POST", "/rules/cleanup", {"ids": ["idle", "ok", "idle", "nope"]})
    assert status == 200 and r == {"removed": ["idle"], "kept": ["ok", "nope"]}
    assert [x.id for x in gw.policy.rules] == ["ok"] and gw.history.versions()[0][
        "what"
    ] == "unused rules removed: idle"
    assert admin(gw, "POST", "/rules/cleanup", {"ids": ["ok"]})[1] == {"removed": [], "kept": ["ok"]}
    assert admin(gw, "POST", "/rules/cleanup", {"ids": "ok"})[0] == 400
    assert admin(gw, "POST", "/rules/cleanup", [1])[0] == 400


def test_suggestion_accept_and_dismiss(gw):  # noqa: F811
    for _ in range(3):
        approve(gw, "pkg.example", "hour")
    approve(gw, "other.example", "once")
    s = admin(gw, "GET", "/suggestions")[1]
    assert s["min_approvals"] == 3 and s["window_days"] == 7
    assert [x["key"] for x in s["suggestions"]] == ["pkg.example:443"]
    assert admin(gw, "POST", "/suggestions/accept", {"key": "evil.example:443"})[0] == 404
    status, rule = admin(gw, "POST", "/suggestions/accept", {"key": "pkg.example:443"})
    assert status == 201 and rule["host"] == "pkg.example" and rule["port"] == 443 and rule["source"] == "suggestion"
    assert "approved 3x in 7 days" in rule["note"] and "expires" not in rule
    assert admin(gw, "GET", "/suggestions")[1]["suggestions"] == []  # covered by a permanent rule now
    for _ in range(2):
        approve(gw, "other.example", "hour")
    assert [x["key"] for x in admin(gw, "GET", "/suggestions")[1]["suggestions"]] == ["other.example:443"]
    assert admin(gw, "POST", "/suggestions/dismiss", {"key": "other.example:443"})[0] == 200
    assert admin(gw, "GET", "/suggestions")[1]["suggestions"] == []
    assert admin(gw, "POST", "/suggestions/dismiss", {})[0] == 400


def test_a_broken_approval_store_does_not_break_the_decision(gw, monkeypatch, caplog):  # noqa: F811
    def boom(*a):
        raise OSError("disk full")

    monkeypatch.setattr(gw.events, "add_approval", boom)
    approve(gw, "x.example", "hour")
    assert gw.policy.rules[0].host == "x.example" and "approval not stored" in caplog.text
