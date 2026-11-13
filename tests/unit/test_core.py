"""Gateway internals that the e2e tests cannot observe (#15)."""

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "gateway"))

pytest.importorskip("mitmproxy")

from egressgw import core
from egressgw.grants import Grants
from egressgw.policy import Policy
from egressgw.store import Secrets


@pytest.fixture
def gw(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "DATA_DIR", tmp_path)
    monkeypatch.setattr(core, "CONFIG_PATH", tmp_path / "config.yaml")
    return core.Gateway()


def test_repeat_count_survives_an_event_replacing_it_before_the_flush(gw):
    ev = {"kind": "dns", "proto": "dns", "client": "a", "host": "loop.example", "port": 53, "action": "deny"}
    gw.record(**ev, reason="r")
    for _ in range(3):
        gw.record(**ev, reason="r")  # counted, not stored
    next(iter(gw._dups.values()))[0] -= core.DUP_WINDOW + 1  # window over, housekeeping has not run yet
    gw.record(**ev, reason="r")
    reasons = [e["reason"] for e in gw.events.recent(10) if e["host"] == "loop.example"]
    assert "r (repeated 3x)" in reasons and len(reasons) == 3


def test_failed_upstream_connect_releases_connection_state(gw):
    gw.verdicts["s1"] = "verdict"
    gw.tls_refused.add("s1")
    gw.server_connect_error(SimpleNamespace(server=SimpleNamespace(id="s1")))
    assert "s1" not in gw.verdicts and "s1" not in gw.tls_refused


def test_state_files_are_fsynced_before_the_rename(tmp_path, monkeypatch):
    synced = []
    real = core.os.fsync
    monkeypatch.setattr(core.os, "fsync", lambda fd: synced.append(fd) or real(fd))
    Policy().save(tmp_path / "policy.yaml")
    Secrets(tmp_path / "secrets.json").set("t", "v")
    g = Grants({}, tmp_path)
    g.upsert_ui("cam", {"targets": [{"host": "cam.example", "port": 80, "scheme": "http"}]})
    assert len(synced) >= 6  # file + directory for each of the three
    assert Policy.load(tmp_path / "policy.yaml").default == "ask" and "cam" in Grants({}, tmp_path).defs
    assert not list(tmp_path.glob("*.tmp"))
