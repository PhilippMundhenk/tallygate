"""The gateway has no connection (#218), end to end: a real gateway behind the proxy whose lookups fail like in
the outage of 2026-11-16 (`Temporary failure in name resolution`), then recover.

The test-only switch `GW_TEST_DNS_DOWN_FILE` makes every lookup fail while the file exists; the control probe
resolves a static name that is served by a local socket, so the same resolver path is used."""

from __future__ import annotations

import time

import pytest

from .conftest import start_echo
from .helpers import connect_tunnel, http_via_proxy


def info(gw) -> dict:
    return gw["api"].call("GET", "/info")[1]["connectivity"]


def wait_for(cond, timeout=15.0):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.2)
    return False


def refused(gw, names, port, step=0.6):
    for n in names:
        _, line = connect_tunnel(gw["ports"]["http"], f"{n}:{port}", 15)
        assert " 200" not in line
        time.sleep(step)


@pytest.fixture
def world(make_gateway, tmp_path):
    probe_port = start_echo()
    flag = tmp_path / "dns-down"
    gw = make_gateway(
        {
            "hard_deny_floor": ["10.0.0.0/8"],
            "connectivity_min_age": 2,
            "connectivity_probe_interval": 1,
            "connectivity_probe_hosts": [f"probe.test:{probe_port}"],
            "grant_api_rate": 1000,
        },
        {"default": "allow"},
        GW_TEST_FLOOR_REPLACE="1",
        GW_TEST_STATIC_HOSTS="probe.test=127.0.0.1,ok.test=127.0.0.1",
        GW_TEST_DNS_DOWN_FILE=str(flag),
    )
    return gw, flag, probe_port


def test_a_flood_of_failing_names_while_the_network_is_fine_is_no_outage(world):
    gw, _flag, port = world
    # names the agent made up: the lookups fail or answer "no such name", but the control probe succeeds
    refused(gw, [f"flood{i}.invalid" for i in range(7)], port)
    time.sleep(2)
    assert info(gw)["down"] is False
    assert not [e for e in gw["api"].call("GET", "/events?limit=200")[1] if e["action"] == "connectivity"]


def test_an_outage_is_shown_tagged_and_ends_with_the_first_success(world):
    gw, flag, port = world
    assert info(gw) == {"down": False, "since": None, "last_failure": None, "failures": 0, "kinds": []}
    flag.write_text("")  # the host's network is gone
    refused(gw, [f"lost{i}.invalid" for i in range(7)], port)
    assert wait_for(lambda: info(gw)["down"]), info(gw)
    st = info(gw)
    assert st["kinds"] == ["dns"] and st["failures"] >= 5 and st["since"] <= st["last_failure"]
    assert "lost" not in str(st)  # never a name the agent chose
    # the agent can learn that it is not a policy decision, from the port it already uses
    _, cat, _ = gw["agent"].call("GET", "/v1/grants")
    assert cat["network"]["down"] is True and cat["network"]["since"] == st["since"]
    events = gw["api"].call("GET", "/events?limit=200")[1]
    assert any(e["action"] == "connectivity" and "no connection from the gateway" in e["reason"] for e in events)
    # a refusal during the outage is tagged, a filter for denies can tell it apart
    refused(gw, ["later.invalid"], port, step=0)
    later = next(e for e in gw["api"].call("GET", "/events?limit=50")[1] if e["host"] == "later.invalid")
    assert later["action"] == "deny" and later["reason"].startswith("no connection: dns failure:")
    summary = gw["api"].call("GET", "/events/summary")[1]
    # the refusals before the outage was recognised are ordinary denies, the later ones are counted apart
    assert summary["no_connection"] >= 1 and summary["counts"]["deny"] + summary["no_connection"] == 8
    # the network is back: the first connection that works ends it, with its duration in the log
    flag.unlink()
    status, _ = http_via_proxy(gw["ports"]["http"], f"http://ok.test:{port}/")
    assert status == 200
    assert info(gw)["down"] is False
    events = gw["api"].call("GET", "/events?limit=200")[1]
    assert any(e["action"] == "connectivity" and "is back after" in e["reason"] for e in events)
    assert gw["agent"].call("GET", "/v1/grants")[1]["network"] == {"down": False, "since": None}


def test_the_probe_ends_an_outage_nobody_is_using(world):
    gw, flag, port = world
    flag.write_text("")
    refused(gw, [f"quiet{i}.invalid" for i in range(7)], port)
    assert wait_for(lambda: info(gw)["down"])
    flag.unlink()  # no more traffic; the housekeeping probe notices within its tick (15 s)
    assert wait_for(lambda: not info(gw)["down"], timeout=40)
