"""addon.py: the mitmdump entry point never runs the proxy without the policy."""

import importlib.util
import logging
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "gateway"))

pytest.importorskip("mitmproxy")

from mitmproxy.proxy import server_hooks
from mitmproxy.test import tflow

from egressgw import core

GATEWAY = Path(__file__).resolve().parents[2] / "gateway"


def load_addon():
    spec = importlib.util.spec_from_file_location("gw_addon_under_test", GATEWAY / "egressgw" / "addon.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_working_gateway_is_the_only_addon(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "DATA_DIR", tmp_path)
    monkeypatch.setattr(core, "CONFIG_PATH", tmp_path / "config.yaml")
    mod = load_addon()
    assert [type(a) for a in mod.addons] == [core.Gateway]


def test_startup_failure_refuses_everything(monkeypatch, caplog):
    def broken():
        raise ValueError("hard_deny_floor: invalid CIDR")

    monkeypatch.setattr(core, "Gateway", broken)
    with caplog.at_level(logging.ERROR, "egressgw"):
        mod = load_addon()
    assert "refusing all connections" in caplog.text and "invalid CIDR" in caplog.text
    [refuse] = mod.addons
    assert isinstance(refuse, mod.RefuseAll)

    data = server_hooks.ServerConnectionHookData(server=tflow.tserver_conn(), client=tflow.tclient_conn())
    refuse.server_connect(data)
    assert data.server.error == "egress policy: gateway failed to start (fail closed)"
    http_flow, dns_flow = tflow.tflow(), tflow.tdnsflow()
    refuse.request(http_flow)
    refuse.dns_request(dns_flow)
    assert not http_flow.killable and not dns_flow.killable  # both killed
