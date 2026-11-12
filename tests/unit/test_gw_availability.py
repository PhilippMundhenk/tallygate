"""Away mode, quiet hours and the digest (#73): nobody can answer, so nothing waits and nothing is allowed."""

import asyncio
import sys
import time
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "gateway"))

from egressgw.availability import Availability, QuietHours, Unavailable

BERLIN = ZoneInfo("Europe/Berlin")


def ts(y, mo, d, h, mi, tz=BERLIN) -> float:
    return datetime(y, mo, d, h, mi, tzinfo=tz).timestamp()


# 2026-11-13 is a Friday
FRI_23 = ts(2026, 11, 13, 23, 0)
SAT_06 = ts(2026, 11, 14, 6, 30)
SAT_08 = ts(2026, 11, 14, 8, 0)


# ---------------------------------------------------------------- quiet hours
def test_parse_and_round_trip():
    q = QuietHours.parse({"start": "22:00", "end": "7:00", "days": ["FRI", "mon"], "tz": "Europe/Berlin"})
    assert q.to_dict() == {"start": "22:00", "end": "07:00", "days": ["mon", "fri"], "tz": "Europe/Berlin"}
    assert QuietHours.parse({"start": "22:00", "end": "07:00"}).days == tuple(range(7))
    assert QuietHours.parse(None) is None and QuietHours.parse({}) is None
    assert "tz" not in QuietHours.parse({"start": "22:00", "end": "07:00"}).to_dict()


@pytest.mark.parametrize(
    "bad",
    [
        "22:00-07:00",
        {"start": "22:00"},
        {"start": "24:00", "end": "07:00"},
        {"start": "22:00", "end": "22:00"},
        {"start": "22:00", "end": "07:00", "days": []},
        {"start": "22:00", "end": "07:00", "days": ["someday"]},
        {"start": "22:00", "end": "07:00", "days": "mon"},
        {"start": "22:00", "end": "07:00", "tz": "Mars/Olympus"},
        {"start": "22:00", "end": "07:00", "extra": 1},
    ],
)
def test_invalid_quiet_hours_are_refused(bad):
    with pytest.raises(ValueError):
        QuietHours.parse(bad)


def test_overnight_period_belongs_to_the_day_it_starts():
    q = QuietHours.parse({"start": "22:00", "end": "07:00", "days": ["fri"], "tz": "Europe/Berlin"})
    assert q.ends(FRI_23) == ts(2026, 11, 14, 7, 0)  # Friday night ends Saturday morning
    assert q.ends(SAT_06) == ts(2026, 11, 14, 7, 0)
    assert q.ends(SAT_08) is None
    assert q.ends(ts(2026, 11, 14, 23, 0)) is None  # Saturday night: not a quiet day
    assert q.ends(ts(2026, 11, 13, 6, 0)) is None  # Friday early morning belongs to Thursday's period
    assert q.zone(FRI_23) == "Europe/Berlin"


def test_daytime_period():
    q = QuietHours.parse({"start": "12:00", "end": "13:30", "days": ["sat"], "tz": "Europe/Berlin"})
    assert q.ends(ts(2026, 11, 14, 12, 15)) == ts(2026, 11, 14, 13, 30)
    assert q.ends(ts(2026, 11, 14, 13, 30)) is None
    assert q.ends(ts(2026, 11, 13, 12, 15)) is None  # Friday


def test_local_time_without_tz():
    q = QuietHours.parse({"start": "00:00", "end": "23:59"})
    now = time.time()
    local = datetime.fromtimestamp(now).astimezone()
    if local.hour * 60 + local.minute < 23 * 60 + 59:
        assert q.ends(now) is not None
    assert q.zone(now)


# ---------------------------------------------------------------- state
def make(tmp_path, **config) -> Availability:
    return Availability(config, tmp_path)


def test_available_by_default(tmp_path):
    a = make(tmp_path)
    assert a.mode() == ("available", None) and a.blocking() is None
    assert a.describe()["mode"] == "available" and a.describe()["quiet_hours"] is None


def test_away_with_and_without_end_survives_a_restart(tmp_path):
    a = make(tmp_path)
    a.set_away(True, None, "web:admin")
    assert a.mode()[0] == "away" and "operator away:" in a.blocking()
    assert make(tmp_path).mode()[0] == "away"  # persisted
    until = time.time() + 3600
    a.set_away(True, until, "web:admin")
    assert a.mode() == ("away", int(until)) and " until " in a.blocking()
    assert not a.expire_away(time.time())
    assert a.expire_away(until + 1) and a.mode(until + 1)[0] == "available"
    a.set_away(False, None, "web:admin")
    assert make(tmp_path).mode()[0] == "available"


@pytest.mark.parametrize("until", ["soon", True, 10.0, time.time() + 40 * 86400])
def test_away_until_is_validated(tmp_path, until):
    with pytest.raises(ValueError):
        make(tmp_path).set_away(True, until, "x")


def test_quiet_hours_from_config_and_ui(tmp_path):
    a = make(tmp_path, quiet_hours={"start": "22:00", "end": "07:00", "tz": "Europe/Berlin"})
    assert a.quiet_source == "config" and a.mode(FRI_23) == ("quiet", ts(2026, 11, 14, 7, 0))
    assert a.blocking(FRI_23).startswith("quiet hours until ")
    a.set_quiet(None)  # switched off in the UI: stored, wins over the config
    b = make(tmp_path, quiet_hours={"start": "22:00", "end": "07:00"})
    assert b.quiet is None and b.quiet_source == "ui"
    b.set_quiet({"start": "12:00", "end": "13:00"})
    assert make(tmp_path).quiet.to_dict()["start"] == "12:00"
    assert b.describe(FRI_23)["quiet_zone"]


def test_away_wins_over_quiet_hours(tmp_path):
    a = make(tmp_path, quiet_hours={"start": "22:00", "end": "07:00", "tz": "Europe/Berlin"})
    a.set_away(True, None, "x")
    assert a.mode(FRI_23)[0] == "away"


def test_invalid_config_stops_the_gateway(tmp_path):
    with pytest.raises(ValueError):
        make(tmp_path, quiet_hours={"start": "nope", "end": "07:00"})
    with pytest.raises(ValueError):
        make(tmp_path, digest_minutes=-1)


@pytest.mark.parametrize("content", ["away: [unclosed", "- a list", "quiet_hours: {start: x}"])
def test_unreadable_state_means_away(tmp_path, content):
    (tmp_path / "availability.yaml").write_text(content)
    a = make(tmp_path)
    assert a.mode()[0] == "away" and a.away["by"] == "unreadable state file"  # fail closed


# ---------------------------------------------------------------- digest
def test_missed_items_are_counted_bounded_and_taken(tmp_path, monkeypatch):
    import egressgw.availability as av

    monkeypatch.setattr(av, "MAX_MISSED", 2)
    a = make(tmp_path)
    a.note("conn", "a.example", 443, "away")
    a.note("conn", "a.example", 443, "away")
    a.note("grant", "nas", 0, "away")
    a.note("conn", "c.example", 443, "away")  # beyond the cap: counted only
    d = a.describe()
    assert [m["count"] for m in d["missed"] if m["host"] == "a.example"] == [2] and d["missed_dropped"] == 1
    items, more = a.take()
    assert len(items) == 2 and more == 1 and not a.missed and a.missed_dropped == 0


def test_digest_is_due_only_while_away_with_items(tmp_path):
    a = make(tmp_path, digest_minutes=1)
    now = time.time()
    assert not a.digest_due(now + 120)  # not away
    a.set_away(True, None, "x")
    assert not a.digest_due(now + 120)  # nothing missed
    a.note("conn", "a.example", 443, "away")
    assert not a.digest_due(now)  # not yet
    assert a.digest_due(now + 120)
    a.digest_minutes = 0
    assert not a.digest_due(now + 120)  # only when back


# ---------------------------------------------------------------- the gateway
pytest.importorskip("mitmproxy")
from egressgw import core  # noqa: E402


@pytest.fixture
def gw(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "DATA_DIR", tmp_path)
    monkeypatch.setattr(core, "CONFIG_PATH", tmp_path / "config.yaml")
    monkeypatch.setattr(core, "STATIC_HOSTS", {})
    (tmp_path / "config.yaml").write_text(
        yaml.safe_dump(
            {
                "grants": {
                    "nas": {"targets": [{"host": "nas.example", "port": 443}], "approval": {"read": "auto"}},
                    "w": {"targets": [{"host": "w.example", "port": 443}], "levels": ["write"]},
                }
            }
        )
    )
    (tmp_path / "policy.yaml").write_text(yaml.safe_dump({"default": "ask", "ask_timeout": 30}))
    g = core.Gateway()
    g.q = asyncio.Queue()
    g.subscribers.add(g.q)
    return g


def published(g) -> list[dict]:
    out = []
    while not g.q.empty():
        out.append(g.q.get_nowait())
    return out


def test_ask_while_away_is_denied_at_once_and_remembered(gw):
    gw.availability.set_away(True, None, "x")
    t0 = time.time()
    dec = asyncio.run(gw.ask("new.example", 443, [], "regular", "10.0.0.1"))
    assert dec.action == "deny" and "operator away" in dec.reason and time.time() - t0 < 1
    assert not gw.pending and gw.availability.missed[("conn", "new.example", 443)]["count"] == 1


def test_grant_requests_that_need_a_human_are_refused_auto_ones_still_work(gw):
    gw.availability.set_away(True, None, "x")
    with pytest.raises(Unavailable):
        gw.request_grant("w", "write", None, "deploy", "10.0.0.1")
    assert not gw.grants.pending()
    assert gw.request_grant("nas", "read", None, "check", "10.0.0.1").status == "approved"  # auto, logged
    assert gw.events.recent(5)[-1]["action"] in ("allow", "deny")


def test_going_away_denies_what_waits_and_coming_back_sends_the_digest(gw):
    async def scenario():
        held = asyncio.create_task(gw.ask("held.example", 443, [], "regular", "c"))
        await asyncio.sleep(0.05)
        r = gw.request_grant("w", "write", None, "deploy", "c")
        assert gw.pending and r.status == "pending"
        gw.availability.set_away(True, None, "x")
        gw.availability_tick()
        dec = await asyncio.wait_for(held, 1)
        return dec, r

    dec, r = asyncio.run(scenario())
    assert dec.action == "deny" and "operator away" in dec.reason and r.status == "denied"
    evs = published(gw)
    assert {"type": "availability"} in evs and any(e["type"] == "resolved" for e in evs)
    gw.availability_tick()  # still away, digest not due
    assert not [e for e in published(gw) if e["type"] == "digest"]
    gw.availability.set_away(False, None, "x")
    gw.availability_tick()
    digest = next(e for e in published(gw) if e["type"] == "digest")
    assert digest["why"] == "away ended" and {i["host"] for i in digest["items"]} == {"held.example", "w"}
    gw.availability_tick()
    assert not published(gw)  # nothing changed, nothing sent


def test_periodic_digest_while_away_and_expiry(gw):
    gw.availability.digest_minutes = 1
    gw.availability.set_away(True, time.time() + 3600, "x")
    gw.availability_tick()
    published(gw)
    gw.availability.note("conn", "a.example", 443, "away")
    gw.availability.last_digest -= 120
    gw.availability_tick()
    assert [e["why"] for e in published(gw) if e["type"] == "digest"] == ["while away"]
    gw.availability.away["until"] = time.time() - 1  # the away period ends by itself
    gw.availability_tick()
    assert gw.availability.mode()[0] == "available"
    assert any(e["reason"] == "away period ended" for e in gw.events.recent(5))
    assert {"type": "availability"} in published(gw)  # nothing missed since: no digest


def test_quiet_hours_end_sends_the_digest_and_switching_to_away_is_published(gw, monkeypatch):
    gw.availability.set_quiet({"start": "00:00", "end": "23:59"})
    gw.availability_tick()
    published(gw)
    if gw.availability.mode()[0] != "quiet":  # the last minute of the day
        pytest.skip("not quiet right now")
    gw.availability.set_away(True, None, "x")
    gw.availability_tick()
    assert {"type": "availability"} in published(gw)  # quiet -> away
    gw.availability.set_away(False, None, "x")
    gw.availability_tick()
    gw.availability.note("conn", "q.example", 443, "quiet")
    gw.availability.set_quiet(None)
    gw.availability_tick()
    assert [e["why"] for e in published(gw) if e["type"] == "digest"] == ["quiet hours ended"]
