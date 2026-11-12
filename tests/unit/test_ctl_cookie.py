"""#97: COOKIE_SECURE=auto follows the connection the browser uses."""

import importlib
import sys
from pathlib import Path

import pytest
from aiohttp.test_utils import make_mocked_request

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "control"))


@pytest.fixture
def main(monkeypatch):
    monkeypatch.setenv("CONTROL_BIND_HOST", "127.0.0.1")
    monkeypatch.setenv("TRUST_FORWARDED_FOR", "1")
    monkeypatch.setenv("TRUSTED_PROXIES", "10.9.9.9/32")
    monkeypatch.delenv("COOKIE_SECURE", raising=False)
    import app.main

    return importlib.reload(app.main)


def req(peer: str, headers: dict | None = None, https: bool = False):
    r = make_mocked_request("POST", "/login", headers=headers or {}, sslcontext=object() if https else None)
    r._transport_peername = (peer, 5555)
    return r


def test_auto_is_secure_only_over_https(main):
    assert main.cookie_secure(req("192.0.2.5")) is False  # plain HTTP on the LAN: the login must work
    assert main.cookie_secure(req("192.0.2.5", https=True)) is True


def test_auto_believes_x_forwarded_proto_only_from_a_trusted_proxy(main):
    assert main.cookie_secure(req("10.9.9.9", {"X-Forwarded-Proto": "https"})) is True
    assert main.cookie_secure(req("192.0.2.5", {"X-Forwarded-Proto": "https"})) is False


@pytest.mark.parametrize(("value", "expected"), [("1", True), ("true", True), ("0", False), ("no", False)])
def test_explicit_values_force_it(main, monkeypatch, value, expected):
    monkeypatch.setenv("COOKIE_SECURE", value)
    assert main.cookie_secure(req("192.0.2.5")) is expected
    assert main.cookie_secure(req("192.0.2.5", https=True)) is expected
