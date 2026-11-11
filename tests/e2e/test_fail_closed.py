"""The gateway fails closed: a broken config stops it, an error inside a hook refuses the connection."""

from __future__ import annotations

import sqlite3
import time

from .helpers import http_via_proxy


def test_invalid_floor_entry_stops_the_gateway(make_gateway, upstream):
    """A /33 used to be accepted at startup and raised per connection - which let the connection through."""
    gw = make_gateway({"hard_deny_floor": ["10.0.0.0/33"]}, {"default": "deny"}, wait=False)
    outcomes = set()
    deadline = time.time() + 30
    while gw["proc"].poll() is None and time.time() < deadline:
        try:
            outcomes.add(http_via_proxy(gw["ports"]["http"], f"http://127.0.0.1:{upstream['http']}/x", timeout=2)[0])
        except OSError:
            time.sleep(0.1)
    assert gw["proc"].poll() not in (None, 0)  # exited with an error, not still proxying
    assert 200 not in outcomes
    assert "hard_deny_floor: invalid CIDR '10.0.0.0/33'" in gw["log"].read_text()


def test_event_log_failure_refuses_the_connection(make_gateway, upstream):
    """With events.db locked, recording raises: denied and allowed connections must both be refused."""
    port, other = upstream["http"], upstream["http2"]
    gw = make_gateway(
        {"hard_deny_floor": ["10.0.0.0/8"]},
        {"default": "deny", "rules": [{"id": "echo", "action": "allow", "cidr": "127.0.0.1/32", "port": port}]},
        GW_TEST_FLOOR_REPLACE="1",
    )
    proxy = gw["ports"]["http"]
    assert http_via_proxy(proxy, f"http://127.0.0.1:{port}/ok")[0] == 200
    assert http_via_proxy(proxy, f"http://127.0.0.1:{other}/denied")[0] == 502
    time.sleep(2.5)  # past DUP_WINDOW: identical events would otherwise only be counted, not written
    lock = sqlite3.connect(str(gw["data"] / "events.db"), isolation_level=None)
    lock.execute("BEGIN EXCLUSIVE")
    try:
        allowed, _ = http_via_proxy(proxy, f"http://127.0.0.1:{port}/while-locked")
        denied, _ = http_via_proxy(proxy, f"http://127.0.0.1:{other}/while-locked")
    finally:
        lock.execute("ROLLBACK")
        lock.close()
    assert allowed == 502 and denied == 502
