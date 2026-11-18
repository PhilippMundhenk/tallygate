"""The gateway has no connection (#218): detection, the control probe, end, restart, and what an agent cannot do.

The clock is a fake one and the resolver and the probe are fakes, so no test waits and none touches a network."""

import asyncio
import json
import socket
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "gateway"))

pytest.importorskip("mitmproxy")

from mitmproxy.proxy import server_hooks
from mitmproxy.test import tflow

from egressgw import connectivity as cs
from egressgw import core
from egressgw.connectivity import Connectivity

TEMP = socket.gaierror(socket.EAI_AGAIN, "Temporary failure in name resolution")
NXDOMAIN = socket.gaierror(socket.EAI_NONAME, "Name or service not known")
NODATA = socket.gaierror(-5, "No address associated with hostname")


class Clock:
    def __init__(self) -> None:
        self.now = 1_800_000_000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, secs: float) -> None:
        self.now += secs


@pytest.fixture
def clock(monkeypatch):
    c = Clock()
    monkeypatch.setattr(time, "time", c)
    return c


@pytest.fixture
def make(tmp_path, monkeypatch, clock):
    monkeypatch.setattr(core, "DATA_DIR", tmp_path)
    monkeypatch.setattr(core, "CONFIG_PATH", tmp_path / "config.yaml")
    monkeypatch.setattr(core, "STATIC_HOSTS", {})

    def factory(config: dict | None = None) -> core.Gateway:
        (tmp_path / "config.yaml").write_text(yaml.safe_dump(config or {}))
        if not (tmp_path / "policy.yaml").exists():
            (tmp_path / "policy.yaml").write_text(yaml.safe_dump({"default": "allow"}))
        return core.Gateway()

    return factory


class World:
    """A fake network: what a lookup does, and what the control probe finds."""

    def __init__(self, gw) -> None:
        self.gw = gw
        self.up = False  # the host's network
        self.probes = 0
        gw._probe = self.probe

    async def probe(self) -> bool:
        self.probes += 1
        return self.up

    async def lookup(self, host, port):
        if not self.up:
            raise TEMP
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

    def fail(self, *names, step=0.0):
        """Connections for `names` whose lookup fails (the real path: server_connect -> resolve)."""
        self.gw._lookup = self.lookup
        out = []
        for n in names:
            out.append(connect(self.gw, n).server.error)
            time.time.advance(step)
        return out


def connect(gw, host):
    """One connection through the hook, in one event loop (as in mitmproxy), including a check it starts."""

    async def go():
        data = server_hooks.ServerConnectionHookData(server=_server(host), client=tflow.tclient_conn())
        await gw.server_connect(data)
        if gw._check_task:
            await gw._check_task
        return data

    return asyncio.run(go())


def _server(host):
    s = tflow.tserver_conn()
    s.address = (host, 443)
    return s


def names(n, prefix="n"):
    return [f"{prefix}{i}.example" for i in range(n)]


def outage_run(world, count=6, minutes=3):
    """`count` failures for different names, spread over `minutes`."""
    for n in names(count):
        world.fail(n, step=minutes * 60 / (count - 1))


def events(gw, action="connectivity"):
    return [e for e in gw.events.recent(500) if e["kind"] == "admin" and e["action"] == action]


def stream(gw):
    q = asyncio.Queue()
    gw.subscribers.add(q)
    return q


def drained(q):
    out = []
    while not q.empty():
        out.append(q.get_nowait())
    return out


def settle(gw):
    """What the check does after the housekeeping tick."""
    asyncio.run(gw.connectivity_check())


# ------------------------------------------------------------------ the state object
def test_classify_what_counts_as_a_failure():
    assert cs.classify(TEMP) == "dns"
    assert cs.classify(OSError("no such host")) == "dns"
    assert cs.classify(TimeoutError()) == "timeout"
    assert cs.classify(NXDOMAIN) is None  # the resolver answered: the name does not exist
    assert cs.classify(NODATA) is None
    assert cs.classify_connect("Connection timed out") == "timeout"
    assert cs.classify_connect("Network is unreachable") == "connect"


def test_the_pattern_needs_count_names_age_and_no_success():
    c = Connectivity(min_failures=3, min_names=2, window=600, min_age=120)
    t = 1000.0
    for i, n in enumerate(["a", "a", "a"]):  # one name only
        c.failure(n, "dns", t + i)
    assert not c.suspect(t + 300)  # a single failing name is no outage, however often
    c.failure("b", "dns", t + 3)
    assert not c.suspect(t + 60)  # not old enough yet
    assert c.suspect(t + 130)
    assert not c.suspect(t + 700)  # all forgotten: too old
    c.failure("a", "dns", t + 800), c.failure("b", "dns", t + 801)
    assert not c.suspect(t + 810)  # fewer than the count
    c.failure("c", "dns", t + 802)
    c.success(t + 803)  # any success forgets the run
    assert not c.suspect(t + 1000)


def test_a_failure_without_a_kind_is_ignored():
    c = Connectivity(min_failures=1, min_names=1, min_age=0)
    c.failure("x", None, 1.0)
    assert not c.suspect(2.0)


def test_status_has_times_counts_and_kinds_only(tmp_path):
    c = Connectivity(tmp_path / "c.json", min_failures=2, min_names=2, min_age=0)
    assert c.status() == {"down": False, "since": None, "last_failure": None, "failures": 0, "kinds": []}
    c.failure("secret-name.example", "dns", 10.0)
    c.failure("other-name.example", "timeout", 12.0)
    c.begin(20.0)
    c.failure("third.example", "connect", 25.0)
    st = c.status()
    assert st == {
        "down": True,
        "since": 10.0,
        "last_failure": 25.0,
        "failures": 3,
        "kinds": ["connect", "dns", "timeout"],
    }
    assert "example" not in json.dumps(st) and "example" not in (tmp_path / "c.json").read_text()
    assert c.end(30.0) == (10.0, 3) and not c.down and not (tmp_path / "c.json").exists()


def test_the_outage_survives_a_restart_and_a_broken_file_is_ignored(tmp_path):
    path = tmp_path / "c.json"
    a = Connectivity(path, min_failures=1, min_names=1, min_age=0)
    a.failure("x", "dns", 5.0)
    a.begin(6.0)
    b = Connectivity(path)
    assert b.down and b.since == 5.0 and b.status()["kinds"] == ["dns"]
    path.write_text("{not json")
    assert not Connectivity(path).down
    path.write_text(json.dumps({"since": "yesterday", "last_failure": 1}))
    assert not Connectivity(path).down


def test_an_unwritable_state_file_does_not_stop_the_gateway(tmp_path):
    c = Connectivity(tmp_path / "missing-dir" / "c.json", min_failures=1, min_names=1, min_age=0)
    c.failure("x", "dns", 1.0)
    c.begin(2.0)  # the state cannot be stored: logged, not raised
    assert c.down


# ------------------------------------------------------------------ the gateway
def test_an_outage_starts_after_the_pattern_and_a_failed_probe(make):
    gw = make()
    world, q = World(gw), stream(gw)
    outage_run(world)  # 6 names over 3 min; the check runs from the lookup that completes the pattern
    assert gw.connectivity.down and world.probes == 1
    st = gw.connectivity.status()
    assert st["kinds"] == ["dns"] and st["failures"] >= 5
    (ev,) = events(gw)
    assert "no connection from the gateway" in ev["reason"] and "not a policy decision" in ev["reason"]
    assert any(m["type"] == "connectivity" and m["down"] for m in drained(q))
    # what is refused from now on carries the tag, so that a filter for denies can tell it apart
    (err,) = world.fail("late.example")
    assert err == "egress policy: blocked (no connection: dns failure: [Errno -3] Temporary failure in name resolution)"
    late = next(e for e in gw.events.recent(10) if e["host"] == "late.example")
    assert late["action"] == "deny" and late["reason"].startswith(cs.PREFIX)
    assert gw.connectivity.status()["failures"] == st["failures"] + 1


def test_a_single_failing_name_is_no_outage(make):
    gw = make()
    world = World(gw)
    for _ in range(40):
        world.fail("same.example", step=10)
    settle(gw)
    assert not gw.connectivity.down and world.probes == 0 and events(gw) == []


def test_names_that_do_not_exist_are_no_outage(make):
    gw = make()
    world = World(gw)

    async def lookup(host, port):
        raise NXDOMAIN if host.startswith("a") else NODATA

    gw._lookup = lookup
    for i in range(30):
        data = server_hooks.ServerConnectionHookData(
            server=_server(f"{'a' if i % 2 else 'b'}{i}.example"), client=tflow.tclient_conn()
        )
        asyncio.run(gw.server_connect(data))
        time.time.advance(20)
    settle(gw)
    assert not gw.connectivity.down and world.probes == 0
    refused = [e for e in gw.events.recent(50) if e["kind"] == "conn"]
    assert refused and all(not e["reason"].startswith(cs.PREFIX) for e in refused)


def test_flooding_failing_names_while_the_network_is_fine_is_no_outage(make):
    """The agent chooses the names that fail. The control probe (a name it did not choose) succeeds, so the
    flood neither starts an outage nor gets a banner or a notification; the probe runs at most once per 30 s."""
    gw = make()
    world = World(gw)
    q = stream(gw)
    world.up = True

    async def only_chosen_fail(host, port):
        if host.startswith("flood"):
            raise TEMP
        return await world.lookup(host, port)

    gw._lookup = only_chosen_fail
    for i in range(120):  # 120 names in 6 minutes
        connect(gw, f"flood{i}.example")
        time.time.advance(3)
        asyncio.run(gw.connectivity_check())
    assert not gw.connectivity.down and events(gw) == []
    assert not [m for m in drained(q) if m["type"] == "connectivity"]
    assert 1 <= world.probes <= 3  # a probe only when the pattern is there, never more often than every 30 s


def test_the_probe_is_limited_to_one_per_interval(make):
    gw = make()
    world = World(gw)
    world.up = True
    gw._lookup = World.lookup.__get__(SimpleNamespace(up=False))  # lookups fail, the probe says the net is fine
    for i in range(10):
        connect(gw, f"p{i}.example")
        time.time.advance(15)
    for _ in range(50):
        asyncio.run(gw.connectivity_check())  # a hostile caller cannot ask for more probes
    assert world.probes <= 2


def test_the_outage_ends_at_the_first_success_with_its_duration(make):
    gw = make()
    world = World(gw)
    outage_run(world)
    assert gw.connectivity.down
    q = stream(gw)
    time.time.advance(3 * 3600)
    world.up = True
    gw._lookup = world.lookup
    data = connect(gw, "ok.example")
    assert not gw.connectivity.down and data.server.error is None
    assert "back after 3.1 h" in events(gw)[0]["reason"]  # newest first
    assert any(m["type"] == "connectivity" and not m["down"] for m in drained(q))
    after = world.fail("late.example")  # the network is up in this fake; a normal failure has no tag
    assert after == [None]


def test_the_outage_ends_by_the_probe_when_nothing_else_is_going_on(make):
    gw = make()
    world = World(gw)
    outage_run(world)
    time.time.advance(31)
    asyncio.run(gw.connectivity_check())  # the probe while the outage is on: still down
    probes = world.probes
    asyncio.run(gw.connectivity_check())  # inside the interval: no second probe
    assert world.probes == probes and gw.connectivity.down
    world.up = True
    time.time.advance(31)
    asyncio.run(gw.connectivity_check())
    assert not gw.connectivity.down and world.probes == probes + 1
    assert "back after" in events(gw)[0]["reason"]


def test_a_probe_that_fails_while_the_outage_is_on_changes_nothing(make):
    gw = make()
    world = World(gw)
    outage_run(world)
    n = len(events(gw))
    time.time.advance(31)
    asyncio.run(gw.connectivity_check())
    assert gw.connectivity.down and len(events(gw)) == n


def test_flapping_needs_the_whole_pattern_again(make):
    gw = make()
    world = World(gw)
    outage_run(world)
    world.up = True
    gw._lookup = world.lookup
    asyncio.run(gw.resolve("ok.example", 443))  # one success ends it
    assert not gw.connectivity.down
    world.up = False
    for n in names(8, "x"):  # many failures at once: not old enough
        world.fail(n)
    asyncio.run(gw.connectivity_check())
    assert not gw.connectivity.down
    time.time.advance(130)
    asyncio.run(gw.connectivity_check())
    assert gw.connectivity.down
    assert [e["reason"][:19] for e in reversed(events(gw))] == [
        "no connection from ",
        "connection from the",
        "no connection from ",
    ]


def test_a_success_during_the_probe_wins(make):
    gw = make()
    world = World(gw)

    async def probe_that_loses_the_race() -> bool:
        gw.connectivity.success(time.time())  # a real connection worked while the probe was running
        return False

    gw._probe = probe_that_loses_the_race
    for n in names(5):
        world.fail(n, step=10)  # the pattern is there, but not old enough for a probe yet
    time.time.advance(100)
    asyncio.run(gw.connectivity_check())
    assert not gw.connectivity.down and events(gw) == []


def test_a_restart_during_an_outage_keeps_it_and_ends_it_with_the_whole_duration(make, clock):
    gw = make()
    world = World(gw)
    outage_run(world)
    since = gw.connectivity.since
    time.time.advance(600)
    gw2 = make()  # the gateway restarts
    assert gw2.connectivity.down and gw2.connectivity.since == since
    w2 = World(gw2)
    w2.up = True
    time.time.advance(31)
    asyncio.run(gw2.connectivity_check())
    assert not gw2.connectivity.down
    assert "back after" in events(gw2)[0]["reason"]


def test_upstream_connect_errors_count_and_success_clears(make):
    gw = make()
    world = World(gw)

    def connect_error(host, error):
        data = SimpleNamespace(server=SimpleNamespace(id="s", address=(host, 443), error=error))
        gw.server_connect_error(data)

    for i in range(6):
        connect_error(f"203.0.113.{i}", "Connection timed out" if i % 2 else "Network is unreachable")
        time.time.advance(40)
    asyncio.run(gw.connectivity_check())
    assert gw.connectivity.down and gw.connectivity.status()["kinds"] == ["connect", "timeout"]
    connect_error("203.0.113.9", "egress policy: blocked (rule x)")  # a decision is not a failure
    assert gw.connectivity.status()["failures"] == 6
    world.up = True
    gw.server_connected(SimpleNamespace(server=SimpleNamespace(id="s", address=("203.0.113.9", 443))))
    assert not gw.connectivity.down


def test_the_hint_never_contains_a_name_the_agent_chose(make):
    gw = make()
    world = World(gw)
    q = stream(gw)
    for n in [
        "evil-name-1.example",
        "evil-name-2.example",
        "evil-name-3.example",
        "evil-name-4.example",
        "evil-name-5.example",
    ]:
        world.fail(n, step=40)
    assert gw.connectivity.down
    text = json.dumps(
        [
            gw.connectivity.status(),
            [m for m in drained(q) if m["type"] == "connectivity"],
            [e["reason"] for e in events(gw)],
        ]
    )
    assert "evil" not in text


def test_the_gateway_itself_is_not_blocked_by_a_flood_of_tasks(make):
    """A burst of failures starts at most one background check at a time."""
    gw = make()
    world = World(gw)
    gw._lookup = world.lookup

    async def burst():
        for i in range(60):
            with pytest.raises(OSError):
                await gw.resolve(f"b{i}.example", 443)
            time.time.advance(5)
        await asyncio.sleep(0)
        if gw._check_task:
            await gw._check_task

    asyncio.run(burst())
    assert world.probes == 1 and gw.connectivity.down


# ------------------------------------------------------------------ the probe and the configuration
def test_the_real_probe_resolves_and_connects(make, monkeypatch):
    async def go():
        server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        monkeypatch.setattr(core, "STATIC_HOSTS", {"probe.example": "127.0.0.1"})
        gw = make({"connectivity_probe_hosts": [f"missing.example:{port}", f"probe.example:{port}"]})
        assert gw.probe_hosts == [("missing.example", port), ("probe.example", port)]
        assert await gw._probe()  # the first host does not resolve, the second works
        server.close()
        await server.wait_closed()
        assert not await gw._probe()  # nothing listens any more

        async def hang(host, port):
            raise TimeoutError

        gw._lookup = hang
        assert not await gw._probe()

    asyncio.run(go())


@pytest.mark.parametrize("bad", ["not a host", "ok.example:0", "ok.example:http", "ok.example:70000", "a b.example"])
def test_probe_hosts_are_validated(make, bad):
    with pytest.raises(ValueError, match="connectivity_probe_hosts"):
        make({"connectivity_probe_hosts": [bad]})


def test_defaults_and_overrides(make):
    gw = make()
    assert gw.probe_hosts == [("api.anthropic.com", 443)]
    assert (gw.connectivity.min_failures, gw.connectivity.min_age) == (5, 120.0)
    gw = make(
        {
            "connectivity_min_failures": 3,
            "connectivity_min_names": 3,
            "connectivity_window": 60,
            "connectivity_min_age": 10,
            "connectivity_probe_interval": 5,
        }
    )
    c = gw.connectivity
    assert (c.min_failures, c.min_names, c.window, c.min_age, c.probe_interval) == (3, 3, 60.0, 10.0, 5.0)


def test_the_test_only_outage_switch_fails_every_lookup(make, monkeypatch, tmp_path):
    flag = tmp_path / "down"
    monkeypatch.setattr(core, "TEST_DNS_DOWN", str(flag))
    monkeypatch.setattr(core, "STATIC_HOSTS", {"s.example": "127.0.0.1", "v6.example": "::1"})
    gw = make()
    assert asyncio.run(gw.resolve("s.example", 80)) == ["127.0.0.1"]
    assert asyncio.run(gw.resolve("v6.example", 80)) == ["::1"]
    flag.write_text("")
    with pytest.raises(socket.gaierror):
        asyncio.run(gw.resolve("s.example", 80))


def test_a_real_lookup_goes_through_the_event_loop(make):
    assert asyncio.run(make().resolve("localhost", 80))  # no static host, no switch: getaddrinfo
    assert asyncio.run(make().resolve("203.0.113.5", 80)) == ["203.0.113.5"]
