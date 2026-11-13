"""Printing a gateway config in the current form (gateway/egressgw/convert.py)."""

import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "gateway"))

from egressgw import convert


def test_old_never_keys_are_translated(tmp_path, capsys):
    cfg = tmp_path / "gateway.yaml"
    cfg.write_text(
        yaml.safe_dump(
            {
                "readonly": ["registry.npmjs.org"],
                "never": ["203.0.113.7/32"],
                "hard_deny_floor": ["198.51.100.0/24"],
                "grants_never": ["192.168.1.1/32"],
            }
        )
    )
    assert convert.main([str(cfg)]) == 0
    out, err = capsys.readouterr()
    assert yaml.safe_load(out) == {
        "readonly": ["registry.npmjs.org"],
        "never": ["203.0.113.7/32", "198.51.100.0/24", {"range": "192.168.1.1/32", "scope": "all+lan"}],
    }
    assert "hard_deny_floor -> never" in err and "grants_never -> never" in err


def test_nothing_to_convert_and_errors(tmp_path, capsys):
    cfg = tmp_path / "gateway.yaml"
    cfg.write_text("log_keep_days: 7\n")
    assert convert.main([str(cfg)]) == 0
    out, err = capsys.readouterr()
    assert yaml.safe_load(out) == {"log_keep_days": 7} and "nothing to convert" in err
    cfg.write_text("never: [not-a-cidr]\n")
    assert convert.main([str(cfg)]) == 1 and "invalid CIDR" in capsys.readouterr().err
    assert convert.main([str(tmp_path / "missing.yaml")]) == 1
    assert convert.main([]) == 2 and "python -m egressgw.convert" in capsys.readouterr().err
    cfg.write_text("")
    assert convert.main([str(cfg)]) == 0 and capsys.readouterr().out.strip() == "{}"
