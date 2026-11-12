"""Learning mode (#69): time-limited, only instead of the default decision, never past the hard deny."""

import asyncio
import sqlite3
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "gateway"))

from egressgw.learning import Learning, check_rule, parse_ports, summary
from egressgw.policy import Policy


def test_ports_from_the_config_are_strict():
    assert parse_ports([443, 80, 443]) == [80, 443]
    for bad in ([], "443", [0], [True], ["443"], None, [70000]):
        with pytest.raises(ValueError, match="learning_ports"):
            parse_ports(bad)


def test_sessions_start_end_and_survive_only_as_records(tmp_path):
    db = sqlite3.connect(tmp_path / "e.db", isolation_level=None)
    lm = Learning(db, [80, 443], 60)
    assert not lm.covers(443) and lm.current() is None and lm.end("x", "y") is None and not lm.expired()
    for minutes, ports in ((0, [443]), (61, [443]), (True, [443]), ("5", [443]), (5, []), (5, [22]), (5, "443")):
        with pytest.raises(ValueError):
            lm.start(minutes, ports, "web:admin")
    first = lm.start(5, [443], "web:admin")
    assert lm.covers(443) and not lm.covers(80) and lm.current()["id"] == first["id"]
    second = lm.start(10, [80, 443], "web:admin")  # replaces the running session
    assert lm.sessions()[1]["end_reason"] == "replaced by a new session (web:admin)" and lm.covers(80)
    lm.active["until"] = time.time() - 1  # time is up: nothing is covered any more, even before housekeeping
    assert not lm.covers(443) and lm.current() is None and lm.expired()
    ended = lm.end("gateway", "time is up")
    assert ended["id"] == second["id"] and ended["ended"] <= time.time()
    lm.start(5, [443], "api")
    again = Learning(db, [443], 30)  # a restart ends the open session
    assert again.active is None and again.sessions()[0]["end_reason"] == "gateway restart"
    assert again.session(first["id"])["ports"] == [443] and again.session("nope") is None


@pytest.mark.parametrize(
    ("rule", "ok"),
    [
        ({"host": "files.pythonhosted.org", "port": 443}, ("files.pythonhosted.org", 443)),
        ({"host": "*.npmjs.org", "port": 443}, ("*.npmjs.org", 443)),
        ({"host": "Example.COM.", "port": 80}, ("example.com", 80)),
        ({"host": "*", "port": 443}, None),
        ({"host": "*.github.io", "port": 443}, None),  # a public suffix
        ({"host": "*.api.example.com", "port": 443}, None),  # not a registrable domain
        ({"host": "203.0.113.5", "port": 443}, None),
        ({"host": "-bad", "port": 443}, None),
        ({"host": "a.example", "port": 0}, None),
        ({"host": "a.example", "port": True}, None),
        ({"host": "a.example", "port": 443, "action": "deny"}, None),
        (["a.example"], None),
    ],
)
def test_only_exact_hosts_or_registrable_domains_can_be_saved(rule, ok):
    if ok:
        assert check_rule(rule) == ok
    else:
        with pytest.raises(ValueError):
            check_rule(rule)


def test_summary_groups_by_domain_and_proposes_only_what_learning_allowed(tmp_path):
    from egressgw.store import EventLog

    ev = EventLog(tmp_path / "e.db")
    lm = Learning(ev.db, [443], 60)
    s = lm.start(30, [443], "web:admin")
    for host, reason, action in [
        ("registry.npmjs.org", "learning mode", "allow"),
        ("registry.npmjs.org", "learning mode (repeated 4x)", "allow"),
        ("www.npmjs.org", "learning mode", "allow"),
        ("pypi.org", "learning mode", "allow"),
        ("api.github.com", "rule gh", "allow"),
        ("blocked.example", "rule no", "deny"),
        ("203.0.113.9", "learning mode", "allow"),
    ]:
        ev.add({"kind": "conn", "host": host, "port": 443, "action": action, "reason": reason})
    ev.add({"kind": "dns", "host": "x.example", "port": 53, "action": "deny", "reason": "dns"})
    ev.add(
        {
            "kind": "conn",
            "host": "late.example",
            "port": 443,
            "action": "allow",
            "reason": "learning mode",
            "ts": time.time() + 9999,
        }
    )
    pol = Policy.from_dict({"rules": [{"id": "pypi", "action": "allow", "host": "pypi.org"}]})
    g = {x["domain"]: x for x in summary(ev.db, lm.session(s["id"]), pol)}
    assert set(g) == {"npmjs.org", "pypi.org", "github.com", "blocked.example"}  # no IPs, no DNS, nothing later
    assert g["npmjs.org"]["proposal"] == {"host": "*.npmjs.org", "port": 443} and g["npmjs.org"]["count"] == 3
    assert g["pypi.org"]["proposal"] is None  # a permanent rule allows it now
    assert g["github.com"]["proposal"] is None and g["blocked.example"]["denied"] == 1
    out = summary(ev.db, lm.session(s["id"]), pol)
    assert out[0]["domain"] == "npmjs.org"  # proposals first


# ------------------------------------------------------------------ gateway: decisions, API, emergency stop
pytest.importorskip("mitmproxy")
pytest.importorskip("aiohttp")

from egressgw import core  # noqa: E402

from .test_gw_api import admin, gw  # noqa: E402, F401  (fixture)


class Server:
    def __init__(self, host, port):
        self.address, self.error, self.id, self.sni = (host, port), None, "s1", None


class Data:
    def __init__(self, host, port):
        from types import SimpleNamespace

        self.server = Server(host, port)
        self.client = SimpleNamespace(proxy_mode=SimpleNamespace(type_name="regular"), peername=("10.0.0.10", 1))


def connect(g, host, port=443, ips=("93.184.216.34",)):
    resolved = []

    async def resolve(h, p):
        resolved.append(h)
        return list(ips)

    g.resolve = resolve
    d = Data(host, port)

    async def go():
        await g.server_connect(d)

    asyncio.run(asyncio.wait_for(go(), 10))
    return d.server.error, resolved


def test_learning_replaces_only_the_default_decision(gw):  # noqa: F811
    gw.policy.default = "deny"
    gw.policy.ask_timeout = 5
    admin(gw, "POST", "/rules", {"id": "no", "action": "deny", "host": "*.blocked.example"})
    admin(gw, "POST", "/rules", {"id": "q", "action": "ask", "host": "asked.example"})
    assert connect(gw, "new.example")[0] is not None  # deny mode, no learning
    status, st = admin(gw, "POST", "/learning", {"minutes": 30, "ports": [443]})
    assert status == 201 and st["active"]["ports"] == [443] and st["ports_allowed"] == [80, 443]
    err, resolved = connect(gw, "new.example")
    assert err is None and resolved == ["new.example"]
    assert gw.events.recent(1)[0]["reason"] == "learning mode"
    err, resolved = connect(gw, "x.blocked.example")  # a deny rule still decides, on the name
    assert "rule no" in err and resolved == []
    err, _ = connect(gw, "new.example", port=22)  # other ports: the mode decides
    assert "default" in err
    err, _ = connect(gw, "lan.example", ips=("192.168.1.10",))  # hard deny on the resolved address
    assert "hard-deny" in err
    err, _ = connect(gw, "1.1.1.1")  # IP literals are not covered
    assert "default" in err
    err, resolved = connect(gw, "nas.example")  # a grant is defined for it: no learning, no resolving
    assert "available via grant nas" in err and resolved == []
    assert gw.learning.covers(443) and gw.policy.default == "deny"  # the policy itself is unchanged


def test_learning_ends_by_time_by_stop_and_by_emergency_stop(gw):  # noqa: F811
    assert admin(gw, "POST", "/learning", {"minutes": 999, "ports": [443]})[0] == 400
    assert admin(gw, "POST", "/learning", ["x"])[0] == 400
    admin(gw, "POST", "/learning", {"minutes": 5, "ports": [443]})
    gw.learning.active["until"] = time.time() - 1
    gw._housekeep()
    st = admin(gw, "GET", "/learning")[1]
    assert st["active"] is None and st["sessions"][0]["end_reason"] == "time is up (gateway)"
    assert "learning mode ended: time is up" in gw.events.recent(1)[0]["reason"]
    admin(gw, "POST", "/learning", {"minutes": 5, "ports": [443]})
    st = admin(gw, "DELETE", "/learning")[1]
    assert st["active"] is None and st["sessions"][0]["end_reason"] == "stopped (api)"
    admin(gw, "POST", "/learning", {"minutes": 5, "ports": [443]})
    r = admin(gw, "POST", "/emergency-stop", {"by": "web:admin"})[1]
    step = next(s for s in r["steps"] if s["step"] == "end_learning")
    assert step["ok"] and len(step["ended"]) == 1 and not gw.learning.covers(443)
    r = admin(gw, "POST", "/emergency-stop", {"by": "web:admin"})[1]
    assert next(s for s in r["steps"] if s["step"] == "end_learning")["ended"] == []


def test_summary_and_saving_rules(gw):  # noqa: F811
    st = admin(gw, "POST", "/learning", {"minutes": 5, "ports": [443]})[1]
    sid = st["active"]["id"]
    connect(gw, "a.pkg.example")
    connect(gw, "b.pkg.example")
    s = admin(gw, "GET", f"/learning/{sid}")[1]
    assert s["session"]["ended"] is None and s["groups"][0]["proposal"] == {"host": "*.pkg.example", "port": 443}
    assert admin(gw, "GET", "/learning/abc123")[0] == 404
    assert admin(gw, "POST", "/learning/apply", {"rules": [{"host": "*", "port": 443}]})[0] == 400
    assert admin(gw, "POST", "/learning/apply", {"rules": []})[0] == 400
    status, r = admin(
        gw,
        "POST",
        "/learning/apply",
        {
            "rules": [
                {"host": "*.pkg.example", "port": 443},
                {"host": "*.pkg.example", "port": 443},
                {"host": "c.example", "port": 80},
            ]
        },
    )
    assert status == 201 and [x["host"] for x in r["added"]] == ["*.pkg.example", "c.example"]
    assert [x.host for x in gw.policy.rules[-2:]] == ["*.pkg.example", "c.example"]  # below the existing rules
    assert gw.policy.rules[-1].source == "learning"
    assert gw.history.versions()[0]["what"] == "2 rules from learning mode"
    s = admin(gw, "GET", f"/learning/{sid}")[1]
    assert s["groups"][0]["proposal"] is None  # allowed by a permanent rule now


def test_learning_config_is_validated(tmp_path, monkeypatch):
    import yaml

    monkeypatch.setattr(core, "DATA_DIR", tmp_path)
    monkeypatch.setattr(core, "CONFIG_PATH", tmp_path / "config.yaml")
    (tmp_path / "config.yaml").write_text(yaml.safe_dump({"learning_ports": ["https"]}))
    with pytest.raises(ValueError, match="learning_ports"):
        core.Gateway()
    (tmp_path / "config.yaml").write_text(yaml.safe_dump({"learning_ports": [443, 8443], "learning_max_minutes": 10}))
    g = core.Gateway()
    assert g.learning.ports == [443, 8443] and g.learning.max_minutes == 10
