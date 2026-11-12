"""Log search (#80): filters, time ranges, destinations and the per-destination view."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "gateway"))

from egressgw.store import EventLog


@pytest.fixture
def log(tmp_path):
    ev = EventLog(tmp_path / "e.db")
    rows = [
        (100, "conn", "a.example.com", 443, "allow"),
        (200, "conn", "b.example.com", 443, "deny"),
        (300, "ask", "b.example.com", 443, "ask"),
        (400, "conn", "example.com", 80, "allow"),
        (500, "conn", "exampleXcom.org", 443, "deny"),
        (600, "dns", "x.example.com", 53, "deny"),
        (700, "admin", None, None, "rule+"),
        (800, "conn", "new_one.example.com", 443, "allow"),
        (900, "conn", "a.example.com", 443, "allow"),
    ]
    for ts, kind, host, port, action in rows:
        ev.add({"ts": ts, "kind": kind, "host": host, "port": port, "action": action, "reason": "r"})
    return ev


def hosts(rows):
    return [(r["host"], r["port"]) for r in rows]


def test_filters_combine(log):
    assert hosts(log.recent(host="a.example.com")) == [("a.example.com", 443)] * 2
    sub = log.recent(host="*.example.com")
    assert {h for h, _ in hosts(sub)} == {
        "a.example.com",
        "b.example.com",
        "example.com",
        "x.example.com",
        "new_one.example.com",
    }
    assert hosts(log.recent(host="*.new_one.example.com")) == [("new_one.example.com", 443)]
    assert hosts(log.recent(host="*.new%one.example.com")) == []  # LIKE wildcards in the name are literal
    assert hosts(log.recent(kind="conn", action="deny")) == [("exampleXcom.org", 443), ("b.example.com", 443)]
    assert len(log.recent(kind=["conn", "ask"], since=200, until=500)) == 3
    assert hosts(log.recent(port=80)) == [("example.com", 80)]
    assert [r["ts"] for r in log.recent(since=800)] == [900, 800]
    assert [r["ts"] for r in log.recent(2, before_id=5, q="example")] == [400, 300]


def test_destinations_count_and_find_new_ones(log):
    d = {(x["host"], x["port"]): x for x in log.destinations()}
    assert set(d) == {
        ("a.example.com", 443),
        ("b.example.com", 443),
        ("example.com", 80),
        ("exampleXcom.org", 443),
        ("new_one.example.com", 443),
    }  # dns and admin events are not destinations
    b = d[("b.example.com", 443)]
    assert (b["events"], b["allowed"], b["denied"], b["asked"], b["first"], b["last"]) == (2, 0, 1, 1, 200, 300)
    assert not b["new"]
    recent = log.destinations(since=700)
    assert {x["host"]: x["new"] for x in recent} == {"a.example.com": False, "new_one.example.com": True}
    assert hosts(log.destinations(since=700, only_new=True)) == [("new_one.example.com", 443)]
    assert hosts(log.destinations(q="xcom")) == [("exampleXcom.org", 443)]
    assert hosts(log.destinations(limit=1)) == [("a.example.com", 443)]  # most recent first


# ------------------------------------------------------------------ API
pytest.importorskip("mitmproxy")
pytest.importorskip("aiohttp")

from .test_gw_api import admin, gw  # noqa: E402, F401  (fixture)


def test_events_route_validates_and_passes_the_filters(gw):  # noqa: F811
    gw.record(kind="conn", host="ok.example", port=443, action="allow", reason="rule ok", proto="regular", client="c")
    gw.record(kind="conn", host="bad.example", port=443, action="deny", reason="default", proto="regular", client="c")
    assert hosts(admin(gw, "GET", "/events?host=ok.example")[1]) == [("ok.example", 443)]
    assert hosts(admin(gw, "GET", "/events?kind=conn&action=deny&since=1&until=99999999999")[1]) == [
        ("bad.example", 443)
    ]
    assert hosts(admin(gw, "GET", "/events?host=*.example&port=443&action=allow,deny")[1]) == [
        ("bad.example", 443),
        ("ok.example", 443),
    ]
    for bad in ("kind=nope", "action=DROP%20TABLE", "host=a%20b", "since=yesterday", "port=x"):
        assert admin(gw, "GET", f"/events?{bad}")[0] == 400, bad
    dests = admin(gw, "GET", "/destinations?since=1&new=1&host=ignored.example")[1]
    assert {d["host"] for d in dests} == {"ok.example", "bad.example"} and all(d["new"] for d in dests)


def test_destination_detail_says_what_decides_now_without_resolving(gw, monkeypatch):  # noqa: F811
    async def resolve(*a):
        raise AssertionError("must not resolve")

    monkeypatch.setattr(gw, "resolve", resolve)
    gw.record(kind="conn", host="ok.example", port=443, action="allow", reason="rule ok", proto="regular", client="c")
    d = admin(gw, "GET", "/destinations/detail?host=OK.example.&port=443")[1]
    assert d["host"] == "ok.example" and d["stats"]["events"] == 1 and len(d["events"]) == 1
    assert d["decision"]["action"] == "allow" and d["decision"]["rule"]["id"] == "ok"
    d = admin(gw, "GET", "/destinations/detail?host=unknown.example")[1]
    assert (
        d["port"] == 443 and d["stats"] is None and d["decision"]["rule"] is None and d["decision"]["action"] == "ask"
    )
    d = admin(gw, "GET", "/destinations/detail?host=10.1.2.3&port=22")[1]
    assert d["decision"]["action"] == "deny" and d["decision"]["rule_id"] == "hard_deny"
    assert admin(gw, "GET", "/destinations/detail?host=-bad-")[0] == 400
