"""Real gateway process: degraded startup (weak API token, CA export failure) and tls_verify: false grants."""

from __future__ import annotations

import socket
import subprocess
import sys
import time

import pytest
import yaml

from .conftest import ROOT, clean_env, free_port
from .helpers import Api, tls_request, wait_http


@pytest.fixture
def weak_gateway(tmp_path, upstream):
    """A gateway with a too-short API token and a CA export path that is a regular file."""
    import shutil

    if not shutil.which("mitmdump"):
        pytest.skip("mitmproxy not installed")
    data = tmp_path / "gw"
    data.mkdir()
    (data / "config.yaml").write_text(yaml.safe_dump({"grants": {"x": {"targets": [{"host": "x.test", "port": 443}]}}}))
    (data / "ca-is-a-file").write_text("not a directory")
    ports = {k: free_port() for k in ("http", "socks", "dns", "api", "grants")}
    env = clean_env(
        DATA_DIR=data,
        CA_EXPORT_DIR=data / "ca-is-a-file",
        GW_LISTEN_HOST="127.0.0.1",
        GW_HTTP_PORT=ports["http"],
        GW_SOCKS_PORT=ports["socks"],
        GW_DNS_PORT=ports["dns"],
        GW_API_HOST="127.0.0.1",
        GW_API_PORT=ports["api"],
        GW_API_TOKEN="too-short",
        PRESET_DIR=ROOT / "gateway" / "presets",
        GW_GRANTS_PORT=ports["grants"],
        PYTHONUNBUFFERED="1",  # the warnings are checked in the log while the gateway runs
    )
    with open(data / "gateway.log", "w") as log:
        proc = subprocess.Popen(
            [sys.executable, str(ROOT / "gateway" / "run.py")], env=env, stdout=log, stderr=subprocess.STDOUT
        )
    try:
        wait_http(f"http://127.0.0.1:{ports['grants']}/v1/grants")
        yield {"proc": proc, "ports": ports, "log": data / "gateway.log"}
    finally:
        proc.terminate()
        proc.wait(10)


def test_weak_api_token_disables_the_admin_api_but_the_gateway_runs(weak_gateway):
    ports = weak_gateway["ports"]
    log = weak_gateway["log"]
    deadline = time.time() + 10
    while "could not export CA cert" not in log.read_text() and time.time() < deadline:
        time.sleep(0.1)
    text = log.read_text()
    assert "GW_API_TOKEN missing or shorter than 24 chars - API disabled" in text
    assert "could not export CA cert" in text  # logged, not fatal
    with pytest.raises(OSError), socket.create_connection(("127.0.0.1", ports["api"]), timeout=2):
        pass  # nothing listens: a guessable token never protects the management API
    status, body, _ = Api(f"http://127.0.0.1:{ports['grants']}").call("GET", "/v1/grants")
    assert status == 200 and [g["name"] for g in body["grants"]] == ["x"]
    assert weak_gateway["proc"].poll() is None


def test_tls_verify_false_only_for_the_grant_that_says_so(make_gateway, upstream):
    https = {"scheme": "https", "port": upstream["https"]}
    gw = make_gateway(
        {
            "hard_deny_floor": ["10.0.0.0/8"],
            "grants_never": ["169.254.0.0/16"],  # the upstreams live on 127.0.0.1
            "grants": {
                # the upstream certificate does not name these hosts
                "selfsigned": {"targets": [{"host": "nover.test", "tls_verify": False, **https}], "approval": "auto"},
                "verified": {"targets": [{"host": "strict.test", **https}], "approval": "auto"},
            },
        },
        {"default": "deny"},
        GW_TEST_FLOOR_REPLACE="1",
        GW_TEST_STATIC_HOSTS="nover.test=127.0.0.1,strict.test=127.0.0.1",
    )
    proxy, port = gw["ports"]["http"], upstream["https"]
    for name in ("selfsigned", "verified"):
        assert gw["agent"].call("POST", f"/v1/grants/{name}/request", {"reason": "e2e"})[0] == 200
    status, body = tls_request(proxy, f"nover.test:{port}", "nover.test", gw["ca"], path="/ok")
    assert status == 200 and b'"path": "/ok"' in body
    status, _ = tls_request(proxy, f"strict.test:{port}", "strict.test", gw["ca"])
    assert status != 200  # hostname mismatch is still refused for every other target
