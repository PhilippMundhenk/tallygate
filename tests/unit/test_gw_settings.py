"""Behaviour settings the UI owns (ADR-0015, gateway/egressgw/settings.py)."""

import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "gateway"))

from egressgw.settings import DEFAULTS, RESTART, Settings


def test_first_start_seeds_from_config_then_the_file_wins(tmp_path):
    path = tmp_path / "settings.yaml"
    s = Settings(path, {"log_keep_days": 7, "max_pending": 20})  # gateway.yaml values seed the file
    assert path.exists()
    saved = yaml.safe_load(path.read_text())
    assert saved["log_keep_days"] == 7 and saved["max_pending"] == 20
    assert saved["rule_stale_days"] == DEFAULTS["rule_stale_days"]  # the rest are the built-in defaults
    # a later start reads the file and ignores a changed gateway.yaml (settings moved to the UI)
    s2 = Settings(path, {"log_keep_days": 99})
    assert s2.get("log_keep_days") == 7
    assert s.all().keys() == set(DEFAULTS)


def test_update_validates_persists_and_reports_restart_keys(tmp_path):
    path = tmp_path / "settings.yaml"
    s = Settings(path, {})
    restart = s.update({"rule_stale_days": 45, "log_keep_days": 14})
    assert restart == ["log_keep_days"]  # log retention needs a restart; rule_stale_days is live
    assert s.get("rule_stale_days") == 45 and s.get("log_keep_days") == 14
    assert yaml.safe_load(path.read_text())["rule_stale_days"] == 45  # persisted
    assert set(RESTART) == {
        "log_keep_days",
        "log_max_events",
        "learning_ports",
        "learning_max_minutes",
        "policy_history_keep",
    }


def test_update_rejects_unknown_and_out_of_range_and_trust_critical(tmp_path):
    s = Settings(tmp_path / "settings.yaml", {})
    with pytest.raises(ValueError, match="not a behaviour setting"):
        s.update({"inject": [{"host": "x"}]})  # trust-critical stays file-only
    with pytest.raises(ValueError, match="not a behaviour setting"):
        s.update({"grants_lan_allow": ["10.0.0.0/8"]})
    with pytest.raises(ValueError, match="out of range"):
        s.update({"log_keep_days": 0})
    with pytest.raises(ValueError, match="is not a port"):
        s.update({"learning_ports": [70000]})
    with pytest.raises(ValueError, match="non-empty"):
        s.update({})


def test_a_broken_settings_file_stops_the_gateway(tmp_path):
    path = tmp_path / "settings.yaml"
    path.write_text(yaml.safe_dump({"log_keep_days": "lots"}))
    with pytest.raises(ValueError):
        Settings(path, {})  # fail closed
    path.write_text(yaml.safe_dump({"nonsense": 1}))
    with pytest.raises(ValueError, match="unknown keys"):
        Settings(path, {})


def test_learning_ports_accepts_a_scalar_or_list(tmp_path):
    s = Settings(tmp_path / "settings.yaml", {})
    assert s.update({"learning_ports": 443}) == ["learning_ports"] and s.get("learning_ports") == [443]
    s.update({"learning_ports": [80, 443]})
    assert s.get("learning_ports") == [80, 443]
