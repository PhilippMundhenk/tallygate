"""Password tools: `python -m app.passwd` (stored hash) and control/hashpw.py (CONTROL_PASSWORD_HASH).

Both must refuse short and mistyped passwords and produce a hash the login really accepts.
"""

import importlib
import importlib.util
import runpy
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "control"))


def answers(monkeypatch, *replies):
    """getpass returns the given replies in order; records the prompts."""
    prompts, it = [], iter(replies)

    def fake(prompt=""):
        prompts.append(prompt)
        return next(it)

    monkeypatch.setattr("getpass.getpass", fake)
    return prompts


@pytest.fixture
def passwd(tmp_path, monkeypatch):
    monkeypatch.delenv("CONTROL_PASSWORD_HASH", raising=False)
    monkeypatch.delenv("CONTROL_PASSWORD", raising=False)
    monkeypatch.setattr(sys, "argv", ["app.passwd"])  # main() parses the command line, not pytest's
    import app.passwd

    mod = importlib.reload(app.passwd)
    monkeypatch.setattr(mod, "PASSWORD_FILE", tmp_path / "data" / "password-hash")
    return mod


@pytest.fixture
def hashpw():
    spec = importlib.util.spec_from_file_location("hashpw", ROOT / "control" / "hashpw.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # nothing runs on import: the prompt is in main()
    return mod


def check(monkeypatch, stored_hash: str, pw: str) -> bool:
    """What the login does with a hash: app.main.check_password."""
    monkeypatch.setenv("CONTROL_PASSWORD_HASH", stored_hash)
    import app.main

    return app.main.check_password(pw)


# ---------------------------------------------------------------- app.passwd
@pytest.mark.parametrize("var", ["CONTROL_PASSWORD_HASH", "CONTROL_PASSWORD"])
def test_passwd_refuses_while_the_environment_wins(passwd, monkeypatch, var):
    monkeypatch.setenv(var, "scrypt:16:00:00" if var.endswith("HASH") else "from-env-password")
    prompts = answers(monkeypatch)
    with pytest.raises(SystemExit, match="takes precedence"):
        passwd.main()
    assert prompts == []  # does not even ask
    assert not passwd.PASSWORD_FILE.exists()


def test_passwd_refuses_short_password(passwd, monkeypatch):
    answers(monkeypatch, "elevenchars")
    with pytest.raises(SystemExit, match="at least 12"):
        passwd.main()
    assert not passwd.PASSWORD_FILE.exists()


def test_passwd_refuses_mismatch_and_keeps_the_old_hash(passwd, monkeypatch):
    passwd.PASSWORD_FILE.parent.mkdir(parents=True)
    passwd.PASSWORD_FILE.write_text("scrypt:16:old:old")
    answers(monkeypatch, "correct horse battery", "correct horse batterY")
    with pytest.raises(SystemExit, match="mismatch"):
        passwd.main()
    assert passwd.PASSWORD_FILE.read_text() == "scrypt:16:old:old"


def test_passwd_stores_a_hash_the_login_accepts(passwd, monkeypatch, capsys):
    prompts = answers(monkeypatch, "correct horse battery", "correct horse battery")
    passwd.GENERATED_MARK.parent.mkdir(parents=True, exist_ok=True)
    passwd.GENERATED_MARK.write_text("")  # the password generated on first start
    passwd.main()
    assert prompts == ["New password: ", "Repeat: "]
    assert not passwd.GENERATED_MARK.exists()  # no longer the generated one
    stored = passwd.PASSWORD_FILE.read_text()
    assert stored.startswith("scrypt:16:") and "correct horse" not in stored
    out = capsys.readouterr().out
    assert "password updated" in out and "Sessions opened with the old password end" in out
    assert check(monkeypatch, stored, "correct horse battery")
    assert not check(monkeypatch, stored, "correct horse batterx")


def test_passwd_print_hash_writes_nothing_and_works_with_the_environment(passwd, monkeypatch, capsys):
    monkeypatch.setenv("CONTROL_PASSWORD", "from-env-password")  # compose-only users set the hash there
    answers(monkeypatch, "correct horse battery", "correct horse battery")
    passwd.main(["--print-hash"])
    out = capsys.readouterr().out.strip()
    assert out.startswith("scrypt:16:") and "\n" not in out
    assert not passwd.PASSWORD_FILE.exists()
    monkeypatch.delenv("CONTROL_PASSWORD")
    assert check(monkeypatch, out, "correct horse battery")
    answers(monkeypatch, "short")
    with pytest.raises(SystemExit, match="at least 12"):
        passwd.main(["--print-hash"])
    with pytest.raises(SystemExit):
        passwd.main(["--bogus"])


# ---------------------------------------------------------------- control/hashpw.py
def test_hashpw_refuses_short_password(hashpw, monkeypatch, capsys):
    answers(monkeypatch, "short")
    with pytest.raises(SystemExit, match="at least 12"):
        hashpw.main()
    assert capsys.readouterr().out == ""


def test_hashpw_refuses_mismatch(hashpw, monkeypatch, capsys):
    answers(monkeypatch, "correct horse battery", "something else entirely")
    with pytest.raises(SystemExit, match="mismatch"):
        hashpw.main()
    assert capsys.readouterr().out == ""


def test_hashpw_prints_a_hash_the_login_accepts(hashpw, monkeypatch, capsys):
    answers(monkeypatch, "correct horse battery", "correct horse battery")
    hashpw.main()
    out = capsys.readouterr().out.strip()
    salt, digest = out.split(":")[2:]
    assert out.startswith("scrypt:16:") and len(bytes.fromhex(salt)) == 16 and len(bytes.fromhex(digest)) == 64
    assert check(monkeypatch, out, "correct horse battery")
    assert not check(monkeypatch, out, "wrong horse battery")
    answers(monkeypatch, "correct horse battery", "correct horse battery")
    hashpw.main()
    assert capsys.readouterr().out.strip() != out  # fresh salt every time


# ---------------------------------------------------------------- as scripts
def test_scripts_run_main(monkeypatch, capsys):
    """`python control/hashpw.py` and `python -m app.passwd` run their main()."""
    monkeypatch.setattr(sys, "argv", ["hashpw.py"])
    answers(monkeypatch, "short")
    with pytest.raises(SystemExit, match="at least 12"):
        runpy.run_path(str(ROOT / "control" / "hashpw.py"), run_name="__main__")
    monkeypatch.setenv("CONTROL_PASSWORD", "from-env-password")
    monkeypatch.delitem(sys.modules, "app.passwd", raising=False)  # run it fresh, as `python -m` does
    with pytest.raises(SystemExit, match="takes precedence"):  # refuses before writing anything
        runpy.run_module("app.passwd", run_name="__main__")
