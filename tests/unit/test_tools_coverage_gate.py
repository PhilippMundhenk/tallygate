"""tools/coverage_gate.py: every module must reach the gate on its own, not just the total."""

import importlib.util
import json
import runpy
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def gate():
    spec = importlib.util.spec_from_file_location("coverage_gate", ROOT / "tools" / "coverage_gate.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.main


def report(tmp_path, **pcts) -> str:
    """coverage.json with one file per keyword: name=percent (None = no statements)."""
    files = {
        f"{name}.py": {"summary": {"num_statements": 0 if p is None else 100, "percent_covered": p or 0.0}}
        for name, p in pcts.items()
    }
    path = tmp_path / "coverage.json"
    path.write_text(json.dumps({"files": files, "totals": {"percent_covered": 99.0}}), encoding="utf-8")
    return str(path)


def test_passes_when_every_module_is_at_the_gate(gate, tmp_path, capsys):
    assert gate([report(tmp_path, a=95.0, b=100.0)]) == 0
    out = capsys.readouterr().out
    assert "ok    95.00 %  a.py" in out and "2/2 modules at or above 95 %" in out


def test_one_module_below_fails_although_the_total_is_high(gate, tmp_path, capsys):
    assert gate([report(tmp_path, a=100.0, b=94.99, c=100.0)]) == 1
    out = capsys.readouterr().out
    assert "FAIL  94.99 %  b.py" in out and "2/3 modules" in out


def test_custom_minimum(gate, tmp_path, capsys):
    path = report(tmp_path, a=80.0)
    assert gate([path, "--min", "80"]) == 0
    assert gate([path, "--min", "80.5"]) == 1
    assert "at or above 80.5 %" in capsys.readouterr().out


def test_files_without_statements_are_not_gated(gate, tmp_path, capsys):
    assert gate([report(tmp_path, empty=None, a=96.0)]) == 0
    assert "empty.py" not in capsys.readouterr().out


def test_missing_report_is_an_error(gate, tmp_path):
    with pytest.raises(FileNotFoundError):
        gate([str(tmp_path / "nope.json")])


def test_exit_code_of_the_script(tmp_path, monkeypatch):
    """`make coverage` relies on the process exit code."""
    script = str(ROOT / "tools" / "coverage_gate.py")
    for pct, code in ((94.0, 1), (95.0, 0)):
        monkeypatch.setattr(sys, "argv", [script, report(tmp_path, a=pct)])
        with pytest.raises(SystemExit) as e:
            runpy.run_path(script, run_name="__main__")
        assert e.value.code == code
