"""gateway/run.py: the mitmdump command line and the zero-config API token."""

import importlib.util
import stat
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("gw_run", ROOT / "gateway" / "run.py")
run = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(run)


def modes(args: list[str]) -> list[str]:
    return [args[i + 1] for i, a in enumerate(args) if a == "--mode"]


def sets(args: list[str]) -> list[str]:
    return [args[i + 1] for i, a in enumerate(args) if a == "--set"]


# ---------------------------------------------------------------- ensure_api_token
def test_token_from_environment_wins_and_no_file_is_written(tmp_path):
    f = tmp_path / "gw" / "api-token"
    assert run.ensure_api_token({"GW_API_TOKEN": "from-env", "GW_API_TOKEN_FILE": str(f)}) == "from-env"
    assert not f.exists()


def test_token_file_is_created_once_readable_by_control_and_reused(tmp_path, capsys):
    f = tmp_path / "gw" / "api-token"  # parent directory does not exist yet
    env = {"GW_API_TOKEN": "", "GW_API_TOKEN_FILE": str(f)}
    token = run.ensure_api_token(env)
    assert len(token) >= 40 and f.read_text() == token
    assert stat.S_IMODE(f.stat().st_mode) == 0o644  # control plane (other uid) reads it
    assert not list(f.parent.glob("*.tmp"))
    assert "created API token" in capsys.readouterr().out
    assert run.ensure_api_token(env) == token  # not rotated on restart
    assert capsys.readouterr().out == ""


def test_existing_token_file_is_stripped(tmp_path):
    f = tmp_path / "api-token"
    f.write_text("  handwritten-token\n")
    assert run.ensure_api_token({"GW_API_TOKEN_FILE": str(f)}) == "handwritten-token"


# ---------------------------------------------------------------- build_args
def test_listen_host_is_required(tmp_path):
    with pytest.raises(SystemExit, match="GW_LISTEN_HOST"):
        run.build_args({}, tmp_path)


def test_defaults_without_config_file(tmp_path):
    args = run.build_args({"GW_LISTEN_HOST": "10.9.0.2"}, tmp_path)
    assert args[:3] == ["mitmdump", "-s", str(ROOT / "gateway" / "egressgw" / "addon.py")]
    # regression: -q forced termlog_verbosity=error and swallowed every warning of the gateway
    assert "-q" not in args and "--quiet" not in args
    assert "termlog_verbosity=warn" in sets(args) and "flow_detail=0" in sets(args)
    assert modes(args) == ["regular@10.9.0.2:3128", "socks5@10.9.0.2:1080", "dns@10.9.0.2:53"]
    opts = sets(args)
    assert f"confdir={tmp_path / 'mitmproxy'}" in opts
    # security-relevant mitmproxy options: upstream certificates are verified, no built-in pages
    assert "ssl_insecure=false" in opts and "onboarding=false" in opts and "dns_use_hosts_file=false" in opts
    assert args[-1] == "onboarding=false"  # no extra args appended


def test_ports_services_and_extra_args(tmp_path):
    (tmp_path / "config.yaml").write_text(
        "services:\n  - {name: db, listen: '5432', target: 'db.example:5432'}\n"
        "  - {name: v6, listen: 8443, target: '[2001:db8::1]:443'}\n"
    )
    env = {
        "GW_LISTEN_HOST": "10.9.0.2",
        "GW_HTTP_PORT": "8080",
        "GW_SOCKS_PORT": "1081",
        "GW_DNS_PORT": "5353",
        "GW_EXTRA_ARGS": "--set  foo=1   -v",
    }
    args = run.build_args(env, tmp_path)
    assert modes(args) == [
        "regular@10.9.0.2:8080",
        "socks5@10.9.0.2:1081",
        "dns@10.9.0.2:5353",
        "reverse:tcp://db.example:5432@10.9.0.2:5432",
        "reverse:tcp://[2001:db8::1]:443@10.9.0.2:8443",
    ]
    assert args[-3:] == ["--set", "foo=1", "-v"]


def test_gw_config_overrides_the_path_and_an_empty_file_is_no_config(tmp_path):
    (tmp_path / "config.yaml").write_text("services: [{listen: 1, target: 'x:1'}]\n")
    other = tmp_path / "empty.yaml"
    other.write_text("")
    args = run.build_args({"GW_LISTEN_HOST": "h", "GW_CONFIG": str(other)}, tmp_path)
    assert len(modes(args)) == 3


def test_service_with_a_non_numeric_listen_port_stops_startup(tmp_path):
    (tmp_path / "config.yaml").write_text("services: [{listen: http, target: 'x:1'}]\n")
    with pytest.raises(ValueError):
        run.build_args({"GW_LISTEN_HOST": "h"}, tmp_path)
