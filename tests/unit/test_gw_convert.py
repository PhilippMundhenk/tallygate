"""Printing a gateway config in the current form (gateway/egressgw/convert.py)."""

import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "gateway"))

from egressgw import convert


def test_old_keys_become_destinations_and_never(tmp_path, capsys):
    cfg = tmp_path / "gateway.yaml"
    cfg.write_text(
        yaml.safe_dump(
            {
                "readonly": ["registry.npmjs.org"],
                "inject": [{"host": "api.example", "value": "Bearer ${t}"}],
                "github_repos": ["me/app"],
                "github_hosts": ["git.example"],
                "log_keep_days": 7,  # an unrelated key is kept
                "never": ["203.0.113.7/32"],
                "hard_deny_floor": ["198.51.100.0/24"],
                "grants_never": ["192.168.1.1/32"],
            }
        )
    )
    assert convert.main([str(cfg)]) == 0
    out, err = capsys.readouterr()
    got = yaml.safe_load(out)
    assert got["log_keep_days"] == 7
    assert got["never"] == ["203.0.113.7/32", "198.51.100.0/24", {"range": "192.168.1.1/32", "scope": "all+lan"}]
    assert {"match": {"host": "registry.npmjs.org"}, "methods": "no-writes"} in got["destinations"]
    assert {"match": {"host": "git.example"}, "repos": {"patterns": ["me/app"]}} in got["destinations"]
    assert any(
        d.get("credentials") == [{"header": "Authorization", "value": "Bearer ${t}"}] for d in got["destinations"]
    )
    assert "readonly, inject, github_repos, github_hosts -> destinations" in err
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
