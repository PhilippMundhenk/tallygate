"""Zero-config secrets of the control plane and the gateway (docker compose up without .env)."""

import importlib
import logging
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "control"))

SECRET_VARS = ("GW_API_TOKEN", "SESSION_SECRET", "TTYD_CREDENTIAL", "CONTROL_PASSWORD", "CONTROL_PASSWORD_HASH")


@pytest.fixture
def boot(tmp_path, monkeypatch):
    for v in SECRET_VARS:
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setenv("CONTROL_DATA", str(tmp_path / "data"))
    monkeypatch.setenv("GW_API_TOKEN_FILE", str(tmp_path / "gw" / "api-token"))
    monkeypatch.setenv("TTYD_CREDENTIAL_FILE", str(tmp_path / "ttyd" / "credential"))
    import app.bootstrap

    return importlib.reload(app.bootstrap)


def test_secrets_are_created_once_and_reused(boot, tmp_path):
    s1, t1 = boot.session_secret(), boot.ttyd_credential()
    assert len(s1) == 64 and t1.startswith("agent:") and len(t1) > 30
    assert boot.session_secret() == s1 and boot.ttyd_credential() == t1
    assert (tmp_path / "data" / "session-secret").stat().st_mode & 0o777 == 0o600 or os.name == "nt"


def test_environment_wins(boot, monkeypatch):
    monkeypatch.setenv("SESSION_SECRET", "from-env")
    monkeypatch.setenv("TTYD_CREDENTIAL", "agent:env")
    monkeypatch.setenv("GW_API_TOKEN", "x" * 32)
    assert boot.session_secret() == b"from-env"
    assert boot.ttyd_credential() == "agent:env"
    assert boot.gw_token() == "x" * 32


def test_gw_token_from_file_and_missing(boot, tmp_path):
    with pytest.raises(SystemExit):
        boot.gw_token(timeout=0)
    (tmp_path / "gw").mkdir()
    (tmp_path / "gw" / "api-token").write_text("t" * 40 + "\n")
    assert boot.gw_token(timeout=0) == "t" * 40


def test_generated_password_is_logged_once_and_checks(boot, caplog, monkeypatch):
    with caplog.at_level(logging.WARNING, logger="control"):
        boot.ensure_password()
    pw = re.search(r"password \(shown only once\): (\S+)", caplog.text).group(1)
    assert boot.password_hash().startswith("scrypt:16:")
    caplog.clear()
    boot.ensure_password()  # second start: nothing new, nothing logged
    assert "shown only once" not in caplog.text

    monkeypatch.setenv("CONTROL_BIND_HOST", "127.0.0.1")
    import app.main

    main = importlib.reload(app.main)
    assert main.check_password(pw)
    assert not main.check_password(pw + "x")


def test_no_password_generated_when_configured(boot, monkeypatch):
    monkeypatch.setenv("CONTROL_PASSWORD_HASH", "scrypt:00:00")
    boot.ensure_password()
    assert boot.password_hash() == ""


def test_gateway_creates_token_file(tmp_path):
    """run.py creates the API token before exec'ing mitmdump (stubbed by a missing GW_LISTEN_HOST exit)."""
    env = {k: v for k, v in os.environ.items() if k not in SECRET_VARS and k != "GW_LISTEN_HOST"}
    env.update(DATA_DIR=str(tmp_path / "data"), GW_API_TOKEN_FILE=str(tmp_path / "gw" / "api-token"))
    r = subprocess.run([sys.executable, str(ROOT / "gateway" / "run.py")], env=env, capture_output=True, text=True)
    assert r.returncode != 0 and "GW_LISTEN_HOST" in r.stderr  # stopped before exec
    token = (tmp_path / "gw" / "api-token").read_text()
    assert len(token) >= 40
    subprocess.run([sys.executable, str(ROOT / "gateway" / "run.py")], env=env, capture_output=True)
    assert (tmp_path / "gw" / "api-token").read_text() == token  # reused, not rotated
