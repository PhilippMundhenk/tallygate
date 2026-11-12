"""Data for the Overview tab (#68): the event summary and disk use in the gateway API."""

import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "gateway"))

from egressgw import api
from egressgw.store import EventLog, summarize

from .test_gw_api import admin, gw  # noqa: F401 (fixture)


def test_summary_counts_top_and_new_destinations(tmp_path):
    log = EventLog(tmp_path / "events.db")
    now = time.time()
    old, recent = now - 2 * 3600, now - 600
    for ts, host, port, action in (
        (old, "known.example", 443, "allow"),  # seen before the window: not new
        (recent, "known.example", 443, "allow"),
        (recent, "known.example", 443, "allow"),
        (recent + 1, "new.example", 443, "deny"),
        (recent + 2, "new.example", 443, "ask"),
        (recent + 3, "other.example", 80, "allow"),
        (old, "gone.example", 443, "deny"),  # only before the window
    ):
        log.add({"ts": ts, "kind": "conn", "host": host, "port": port, "action": action})
    log.add({"ts": recent, "kind": "dns", "host": "dns.example", "action": "deny"})  # not a connection
    log.add({"ts": recent, "kind": "admin", "action": "policy"})  # no host
    s = summarize(log.path, now - 3600)
    assert s["counts"] == {"allow": 3, "deny": 1, "ask": 1}
    assert [(t["host"], t["count"], t["allow"], t["deny"], t["ask"]) for t in s["top"]] == [
        ("new.example", 2, 0, 1, 1),  # same count: the more recent first
        ("known.example", 2, 2, 0, 0),
        ("other.example", 1, 1, 0, 0),
    ]
    assert [(n["host"], n["port"], n["count"]) for n in s["new"]] == [("other.example", 80, 1), ("new.example", 443, 2)]
    assert s["new"][1]["first"] == pytest.approx(recent + 1)
    assert summarize(log.path, now - 3600, top=1, new=1)["top"][0]["host"] == "new.example"
    empty = summarize(log.path, now + 10)
    assert empty == {"since": now + 10, "counts": {"allow": 0, "deny": 0, "ask": 0}, "top": [], "new": []}


def test_summary_route_defaults_to_the_last_hour_and_is_clamped(gw):  # noqa: F811
    gw.record(kind="conn", host="a.example", port=443, action="allow", reason="rule")
    status, body = admin(gw, "GET", "/events/summary")
    assert status == 200 and body["counts"]["allow"] == 1 and body["top"][0]["host"] == "a.example"
    assert time.time() - 3700 < body["since"] < time.time() - 3500
    assert admin(gw, "GET", "/events/summary?since=0")[1]["since"] > time.time() - 7 * 86400 - 60  # at most 7 days
    assert admin(gw, "GET", f"/events/summary?since={time.time() + 999}")[1]["since"] <= time.time()
    assert admin(gw, "GET", "/events/summary?since=abc")[0] == 400


def test_info_reports_disk_use_of_the_state(gw, tmp_path, monkeypatch):  # noqa: F811
    gw.record(kind="admin", action="policy", reason="x")
    body = admin(gw, "GET", "/info")[1]
    d = body["data_disk"]
    assert d["total"] > 0 and d["used"] + d["free"] <= d["total"] + 1 and body["events_db_bytes"] > 0

    def broken(path):
        raise OSError("gone")

    monkeypatch.setattr(api.shutil, "disk_usage", broken)
    assert api._disk(tmp_path) is None
    assert api._size(tmp_path / "missing.db") == 0
