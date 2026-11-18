import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "gateway"))

import ipaddress
import logging

import yaml

from egressgw.grants import (
    GrantDef,
    Grants,
    Target,
    clean_reason,
    internal_nets,
    own_sockets,
    parse_ttl,
    path_ok,
)

HA = {
    "description": "Home Assistant",
    "targets": [{"host": "ha.lan", "port": 8123, "scheme": "http", "paths": ["/api/*"], "lan": True}],
    "levels": ["read", "write"],
    "approval": {"read": "auto", "write": "ask"},
    "default_ttl": "1h",
    "max_ttl": "4h",
}


def make(tmp_path, **cfg):
    return Grants({"grants": {"ha": HA}, **cfg}, tmp_path)


def test_ttl_parsing():
    assert parse_ttl("90s") == 90 and parse_ttl("30m") == 1800 and parse_ttl("4h") == 14400 and parse_ttl(60) == 60
    with pytest.raises(ValueError):
        parse_ttl("1 week")


@pytest.mark.parametrize(
    "path,ok",
    [
        ("/api/states", True),
        ("/api/states?x=1", True),
        ("/api/states/light.k%C3%BCche", True),
        ("/apix", False),
        ("/api/../config", False),
        ("/api/./x", False),
        ("/api//x", False),
        ("/api/%2e%2e/config", False),
        ("/api%2fconfig", False),
        ("/api/x\\..\\y", False),
        ("/api/x%00", False),
        ("api/states", False),
        ("/api/%252e%252e/config", False),  # double-encoded .. -> upstream /api/../config (#111)
        ("/api/%252f%252f", False),  # double-encoded //
        ("/api/%25%32%65%25%32%65/config", False),  # another double-encoding of %2e%2e
        ("/api/%25252e%25252e", False),  # triple-encoded: still changing / residual %
        ("/api/x#/../admin", False),  # `#` kept and refused: a server may normalise `..` across it (#137)
        ("/api/..;/admin", False),  # `;` matrix-parameter trick
        ("/api/%23/x", False),  # encoded `#`
        ("/api/a%3bb", False),  # encoded `;`
    ],
)
def test_path_matching_rejects_traversal_tricks(path, ok):
    assert path_ok(path, ["/api/*"]) is ok


def test_definition_validation():
    with pytest.raises(ValueError):
        GrantDef.from_dict("Bad Name", HA, "config")
    with pytest.raises(ValueError):  # tcp cannot be read-only
        GrantDef.from_dict(
            "x", {"targets": [{"host": "db.lan", "port": 5432, "scheme": "tcp"}], "levels": ["read"]}, "config"
        )
    with pytest.raises(ValueError):  # inject needs an exact https target
        GrantDef.from_dict("x", {**HA, "inject": [{"host": "ha.lan", "value": "Bearer ${t}"}]}, "config")
    with pytest.raises(ValueError):
        GrantDef.from_dict("x", {**HA, "max_ttl": "30d"}, "config")
    with pytest.raises(ValueError):
        Target.from_dict({"host": "pve.lan", "port": 8006, "tls_fingerprint": "abc"})
    t = Target.from_dict({"host": "pve.lan", "port": 8006, "tls_fingerprint": "AB:" * 31 + "AB"})
    assert t.tls_fingerprint == "ab" * 32


def test_activation_matching_and_levels(tmp_path):
    g = make(tmp_path)
    assert g.match("ha.lan", 8123) is None
    assert g.defined_for("ha.lan", 8123) == ["ha"] and g.defined_for("ha.lan", 80) == []
    a = g.activate("ha", "read", 99999, "check lights", "test")
    assert a.expires - a.created == 4 * 3600  # clamped to max_ttl
    assert g.match("HA.LAN.", 8123)[0].level == "read"
    b = g.activate("ha", "write", 600, "", "test")
    assert len(g.active) == 1 and g.match("ha.lan", 8123)[0].level == "write"  # replaced, not stacked
    assert b.id == a.id  # #14: same id, so open connections bound to it keep working
    with pytest.raises(ValueError):
        g.activate("ha", "admin", 60, "", "t")


def test_wildcard_targets(tmp_path):
    g = Grants({"grants": {"w": {"targets": [{"host": "*.lan", "port": 443}], "levels": ["read"]}}}, tmp_path)
    g.activate("w", "read", 60, "", "t")
    assert g.match("nas.lan", 443) and not g.match("lan", 443) and not g.match("nas.lan.evil.example", 443)


def test_requests_dedupe_cap_and_expiry(tmp_path):
    g = make(tmp_path, grant_max_pending=2, grant_request_timeout=1)
    r1 = g.new_request("ha", "write", "2h", "turn \x1b[31mon\n the heating", "10.0.0.1")
    assert g.new_request("ha", "write", None, "again", "x") is r1
    assert r1.reason == "turn [31mon the heating" and r1.ttl == 7200
    g.defs["ha2"] = GrantDef.from_dict("ha2", HA, "config")
    g.new_request("ha2", "write", None, "", "x")
    g.defs["ha3"] = GrantDef.from_dict("ha3", HA, "config")
    with pytest.raises(OverflowError):
        g.new_request("ha3", "write", None, "", "x")
    with pytest.raises(ValueError):
        g.new_request("ha", "admin", None, "", "x")
    with pytest.raises(KeyError):
        g.new_request("nope", "read", None, "", "x")
    time.sleep(1.1)
    _, timed_out = g.prune()
    assert {r.status for r in timed_out} == {"expired"}


def test_lan_flag_and_lan_allow_are_read_from_old_files_and_ignored(tmp_path, caplog):
    """ADR-0019: `lan`, `grants_lan_allow` (and the grants' own never list) are gone. Old files still load;
    the log says once what that means for each target, and the UI file is rewritten without the flag."""
    old = {
        "cam": {"targets": [{"host": "cam.lan", "port": 80, "scheme": "http", "lan": True}]},
        "pin": {"targets": [{"host": "pin.lan", "port": 80, "scheme": "http", "lan": True, "address": "192.168.1.9"}]},
        "lit": {"targets": [{"host": "192.168.1.7", "port": 22, "scheme": "tcp", "lan": True}], "levels": ["write"]},
        "pub": {"targets": [{"host": "api.example", "port": 443}]},
    }
    (tmp_path / "grants.yaml").write_text(yaml.safe_dump(old))
    with caplog.at_level(logging.WARNING, "egressgw"):
        g = make(tmp_path, grants_lan_allow=["192.168.1.0/24"])
    assert not hasattr(g, "ui_lan_allow") and not hasattr(g, "never")
    assert not any(hasattr(t, "lan") for d in g.defs.values() for t in d.targets)
    assert all("lan" not in t for d in g.defs.values() for t in d.to_dict()["targets"])
    assert "(LAN)" not in " ".join(t.label() for d in g.defs.values() for t in d.targets)
    log = caplog.text
    assert "grants_lan_allow is ignored since ADR-0019" in log
    # the config-file grant (HA: a name only, with lan) and the UI file, each target once
    assert (
        log.count(
            "gateway config: grant ha, target ha.lan:8123: `lan` is ignored now, and a target that is only a name"
        )
        == 1
    )
    assert (
        log.count("grant cam, target cam.lan:80: `lan` is ignored now, and a target that is only a name cannot open")
        == 1
    )
    assert "It keeps working for a local address only with a fixed `address`" in log
    assert (
        log.count("grant pin, target pin.lan:80: `lan` is ignored now; the target names an address and keeps working")
        == 1
    )
    assert log.count("grant lit, target 192.168.1.7:22: `lan` is ignored now; the target names an address") == 1
    assert "grant pub" not in log
    # migrated once: the old file is kept, the new one has no flag, and the next start is silent
    assert yaml.safe_load((tmp_path / "grants.yaml.pre-0019").read_text()) == old
    assert "lan" not in (tmp_path / "grants.yaml").read_text().replace(".lan", "")
    caplog.clear()
    with caplog.at_level(logging.WARNING, "egressgw"):
        again = Grants({}, tmp_path)
    # (the word itself would also match "plane" in the unrelated GW_INTERNAL_NETS message: look for the notes)
    assert not any(w in caplog.text for w in ("`lan`", "grants_lan_allow", "migrated", ".lan:"))
    assert set(again.defs) == {"cam", "pin", "lit", "pub"}
    assert (
        again.defs["pin"].targets[0].fixed() == "192.168.1.9" and again.defs["lit"].targets[0].fixed() == "192.168.1.7"
    )
    assert again.defs["cam"].targets[0].fixed() is None
    # a backup that exists is never overwritten
    (tmp_path / "grants.yaml").write_text(
        yaml.safe_dump({"x": {"targets": [{"host": "x.lan", "port": 1, "lan": True}]}})
    )
    Grants({}, tmp_path)
    assert yaml.safe_load((tmp_path / "grants.yaml.pre-0019").read_text()) == old


def test_ui_grants_and_config_grants_follow_the_same_rules(tmp_path):
    g = make(tmp_path)
    ui = g.upsert_ui("cam", {"targets": [{"host": "cam.lan", "port": 80, "scheme": "http", "address": "192.168.7.7"}]})
    assert ui.targets[0].fixed() == "192.168.7.7"  # a local address, defined in the UI: an address rule
    with pytest.raises(ValueError):
        g.upsert_ui("ha", HA)  # config grants cannot be overridden from the UI
    assert (tmp_path / "grants.yaml").exists() and Grants({"grants": {"ha": HA}}, tmp_path).defs["cam"].source == "ui"


def test_a_grant_that_names_the_stack_itself_is_refused_when_it_is_saved(tmp_path, monkeypatch):
    # #112 / ADR-0019: the stack's own networks (GW_INTERNAL_NETS, set in compose.yaml) and the gateway's own
    # listeners are locked. A target that names such an address is refused at once; every connection is
    # checked again by the policy (tests/unit/test_gw_locked.py).
    monkeypatch.setenv("GW_INTERNAL_NETS", "172.31.11.0/24, 172.31.12.0/24,")
    monkeypatch.setenv("GW_API_HOST", "192.168.5.2")
    monkeypatch.setenv("GW_API_PORT", "8123")
    monkeypatch.setenv("GW_LISTEN_HOST", "192.168.5.3")
    g = make(tmp_path)
    cam = {"host": "cam.lan", "port": 80, "scheme": "http"}
    for target, error in (
        ({**cam, "address": "172.31.11.2"}, "172.31.11.2 belongs to the tallygate stack itself"),
        ({**cam, "host": "172.31.12.9"}, "172.31.12.9 belongs to the tallygate stack itself"),
        ({**cam, "host": "::ffff:172.31.12.9"}, "belongs to the tallygate stack itself"),
        ({**cam, "port": 8123, "address": "192.168.5.2"}, "192.168.5.2:8123 is the gateway itself"),
        ({**cam, "port": 3128, "host": "192.168.5.3"}, "192.168.5.3:3128 is the gateway itself"),
    ):
        with pytest.raises(ValueError, match=error):
            g.upsert_ui("cam", {"targets": [target]})
    assert "cam" not in g.defs and not (tmp_path / "grants.yaml").exists()
    assert g.upsert_ui("cam", {"targets": [{**cam, "address": "172.31.99.9"}]}).targets[0].address == "172.31.99.9"
    assert g.upsert_ui("cam", {"targets": [{**cam, "address": "192.168.5.2"}]})  # port 80 there is not the listener


def test_an_empty_gw_internal_nets_stops_the_gateway(tmp_path, monkeypatch, caplog):
    """Without the stack's networks nothing is locked: only the built-in blocks stand between the agent and the
    control plane, and those can be deleted. compose.yaml sets it; a start without it is refused (#232), e.g.
    new images under a compose.yaml from before the setting existed."""
    monkeypatch.delenv("GW_TEST_NO_INTERNAL_NETS")
    for switch in (None, "", "0", "true"):  # only the exact test switch "1" lets it start
        if switch is not None:
            monkeypatch.setenv("GW_TEST_NO_INTERNAL_NETS", switch)
        for value in ("", " ", ","):
            monkeypatch.setenv("GW_INTERNAL_NETS", value)
            with pytest.raises(ValueError, match="GW_INTERNAL_NETS is empty: no network of the stack") as e:
                make(tmp_path)
            assert "Set it to the stack's networks as compose.yaml does" in str(e.value), (switch, value)
        monkeypatch.delenv("GW_INTERNAL_NETS")
        with pytest.raises(ValueError, match="GW_INTERNAL_NETS is empty"):  # not set at all: the same
            make(tmp_path)
    # set: starts without the switch and says nothing
    monkeypatch.delenv("GW_TEST_NO_INTERNAL_NETS")
    monkeypatch.setenv("GW_INTERNAL_NETS", "172.31.11.0/24")
    with caplog.at_level(logging.WARNING, "egressgw"):
        g = make(tmp_path)
    assert [str(n) for n in g.internal] == ["172.31.11.0/24"] and "GW_INTERNAL_NETS" not in caplog.text


def test_the_test_switch_starts_a_gateway_without_stack_networks_and_says_so(tmp_path, monkeypatch, caplog):
    """The unit and e2e suites run gateways outside the compose stack: GW_TEST_NO_INTERNAL_NETS=1, loud."""
    monkeypatch.setenv("GW_TEST_NO_INTERNAL_NETS", "1")
    for value in ("", " ", ","):
        monkeypatch.setenv("GW_INTERNAL_NETS", value)
        caplog.clear()
        with caplog.at_level(logging.WARNING, "egressgw"):
            g = make(tmp_path)
        notes = [r for r in caplog.records if r.levelno == logging.WARNING and "GW_INTERNAL_NETS" in r.getMessage()]
        assert g.internal == [] and len(notes) == 1, value
        assert notes[0].getMessage() == (
            "GW_TEST_NO_INTERNAL_NETS is set - GW_INTERNAL_NETS is empty and no network of the stack is locked "
            "(test only)"
        )
    # the switch does not excuse a broken value, and is silent when the networks are set
    monkeypatch.setenv("GW_INTERNAL_NETS", "nonsense")
    with pytest.raises(ValueError, match="invalid CIDR"):
        make(tmp_path)
    monkeypatch.setenv("GW_INTERNAL_NETS", "172.31.11.0/24")
    caplog.clear()
    with caplog.at_level(logging.WARNING, "egressgw"):
        make(tmp_path)
    assert "GW_INTERNAL_NETS" not in caplog.text


def test_local_notes_name_the_address_targets_that_start_working_with_the_upgrade(tmp_path):
    """Before ADR-0019 a grant target inside a blocked range was refused unless it carried `lan`. Now a target
    that names an address is an address rule at the top: one stored WITHOUT `lan` starts working. The
    operator is told which ones; nothing is changed."""
    from egressgw.policy import Policy, Rule, builtin_blocks

    grants = {
        "was-lan": {"targets": [{"host": "192.168.1.7", "port": 22, "scheme": "tcp", "lan": True}], "levels": ["write"]},
        "no-lan": {"targets": [{"host": "192.168.1.8", "port": 22, "scheme": "tcp"}], "levels": ["write"]},
        "pin-lan": {"targets": [{"host": "nas.example", "port": 443, "address": "10.0.0.9", "lan": True}]},
        "pin-no-lan": {"targets": [{"host": "nas2.example", "port": 443, "address": "10.0.0.10"}], "approval": "auto"},
        "name": {"targets": [{"host": "printer.example", "port": 631}]},  # only a name: cannot open a range
        "public": {"targets": [{"host": "140.82.112.3", "port": 22, "scheme": "tcp"}], "levels": ["write"]},
        "mixed": {"targets": [{"host": "192.168.1.9", "port": 80, "scheme": "http", "lan": True},
                              {"host": "192.168.1.9", "port": 81, "scheme": "http"}]},
    }  # fmt: skip
    g = Grants({"grants": grants}, tmp_path)
    p = Policy()
    p.seed_blocks(builtin_blocks(), [])
    notes = g.local_notes(p)
    assert notes == [
        "NOTE grant no-lan: target 192.168.1.8:22 names the address 192.168.1.8 inside blocked range 192.168.0.0/16. "
        "It was refused before; now it is reachable while the grant is active. Delete the target if that is not wanted",
        "NOTE grant pin-no-lan: target nas2.example:443 names the address 10.0.0.10 inside blocked range 10.0.0.0/8. "
        "It was refused before; now it is reachable while the grant is active (approval for read is automatic). "
        "Delete the target if that is not wanted",
        "NOTE grant mixed: target 192.168.1.9:81 names the address 192.168.1.9 inside blocked range 192.168.0.0/16. "
        "It was refused before; now it is reachable while the grant is active. Delete the target if that is not wanted",
    ]
    assert set(g.defs) == set(grants) and g.local_notes(p) == notes  # it reports, it changes nothing
    # where the range is not blocked (the operator had opened it, or allows the address above the block) the
    # target was not refused before: nothing to say
    p.remove_rule("block-192.168.0.0_16")
    p.add_rule(Rule(action="allow", cidr="10.0.0.10/32", id="open"))
    assert g.local_notes(p) == []
    # a UI grant from grants.yaml is told apart the same way
    (tmp_path / "ui").mkdir()
    ui = {"cam": {"targets": [{"host": "192.168.1.20", "port": 80, "scheme": "http"}]},
          "cam2": {"targets": [{"host": "192.168.1.21", "port": 80, "scheme": "http", "lan": True}]}}  # fmt: skip
    (tmp_path / "ui" / "grants.yaml").write_text(yaml.safe_dump(ui))
    g = Grants({}, tmp_path / "ui")
    p = Policy()
    p.seed_blocks(builtin_blocks(), [])
    assert [n.split(":")[0] for n in g.local_notes(p)] == ["NOTE grant cam"]


def test_local_notes_know_the_old_never_list_the_locked_ranges_and_other_spellings(tmp_path, monkeypatch):
    """`lan` never opened the old never list (loopback, metadata, the config's `never`): such a target was
    refused with the flag too, and is named. A locked address stays refused and is not named. The flag is
    recognised however host and port were spelled in the file."""
    from egressgw.policy import DEFAULT_NEVER, Policy, builtin_blocks, ip_addr

    monkeypatch.setenv("GW_INTERNAL_NETS", "172.31.11.0/24")
    grants = {
        "meta": {"targets": [{"host": "169.254.169.254", "port": 80, "scheme": "http", "lan": True}]},
        "cfg": {"targets": [{"host": "203.0.113.9", "port": 80, "scheme": "http", "lan": True}]},
        "stack": {"targets": [{"host": "172.31.11.3", "port": 80, "scheme": "http"}]},
        "spelled": {"targets": [{"host": "NAS.Lan.", "port": "443", "address": "192.168.1.9", "lan": True}]},
    }
    g = Grants({"grants": grants}, tmp_path)
    p = Policy()
    p.seed_blocks(builtin_blocks(), ["203.0.113.9/32"])
    p.locked_nets = list(g.internal)
    assert p.locked("172.31.11.3", 80) and ip_addr("192.168.1.9")
    assert [n.split(":")[0] for n in g.local_notes(p, [*DEFAULT_NEVER, "203.0.113.9/32"])] == [
        "NOTE grant meta",
        "NOTE grant cfg",
    ]
    assert g.local_notes(p) == []  # without the old never list only targets that lacked `lan` are named


def test_own_listeners_and_internal_nets_from_the_environment(tmp_path, monkeypatch):
    for var in ("GW_INTERNAL_NETS", "GW_API_HOST", "GW_API_PORT", "GW_LISTEN_HOST"):
        monkeypatch.delenv(var, raising=False)
    net = ipaddress.ip_network
    g = make(tmp_path)
    assert g.internal == []
    # nothing configured: the listeners bind to 127.0.0.1 with their default ports, and that is what is locked
    assert g.own == [(net("127.0.0.1/32"), p) for p in (8081, 8079, 3128, 1080)]
    assert own_sockets({"GW_LISTEN_HOST": "172.31.10.2", "GW_API_HOST": "172.31.11.2", "GW_SOCKS_PORT": "1081"}) == [
        (net("172.31.11.2/32"), 8081),
        (net("172.31.10.2/32"), 8079),
        (net("172.31.10.2/32"), 3128),
        (net("172.31.10.2/32"), 1081),
    ]
    # a listener on every address (or bound by name) is reached through any local address: its port is locked
    # on loopback and on the unspecified addresses, not only on one of them
    for host in ("0.0.0.0", "::", "egress-gw"):
        own = own_sockets({"GW_API_HOST": host, "GW_LISTEN_HOST": "10.9.9.9"})
        assert [str(n) for n, p in own if p == 8081] == ["127.0.0.0/8", "0.0.0.0/32", "::1/128", "::/128"], host
    assert [str(n) for n in internal_nets("10.1.0.0/16,fd00::/8")] == ["10.1.0.0/16", "fd00::/8"]
    monkeypatch.setenv("GW_INTERNAL_NETS", "172.31.10.0/24,nonsense")
    with pytest.raises(ValueError, match="GW_INTERNAL_NETS: invalid CIDR 'nonsense'"):
        make(tmp_path)  # a broken entry stops the gateway


def test_agent_sees_no_secrets(tmp_path):
    g = Grants(
        {
            "grants": {
                "pve": {
                    "targets": [{"host": "pve.lan", "port": 8006}],
                    "inject": [{"host": "pve.lan", "header": "Authorization", "value": "PVEAPIToken=${pve}"}],
                }
            }
        },
        tmp_path,
    )
    s = g.defs["pve"].summary()
    assert "inject" not in s and "PVEAPIToken" not in str(s)


def test_ui_grants_cannot_inject_or_disable_tls_verification(tmp_path):
    """#12: a UI session must not be able to send a stored secret to a host of its choosing."""
    import yaml

    g = make(tmp_path)
    target = {"host": "x.example", "port": 443}
    inject = [{"host": "x.example", "header": "Authorization", "value": "Bearer ${github_token}"}]
    for bad in ({"targets": [target], "inject": inject}, {"targets": [{**target, "tls_verify": False}]}):
        with pytest.raises(ValueError, match="config file"):
            g.upsert_ui("exfil", bad)
        assert GrantDef.from_dict("ok", bad, "config")  # still fine in the config file
    # a UI grant with inject saved by an older version is ignored at startup instead of being used
    (tmp_path / "grants.yaml").write_text(yaml.safe_dump({"old": {"targets": [target], "inject": inject}}))
    assert "old" not in Grants({"grants": {"ha": HA}}, tmp_path).defs


def test_clean_reason():
    assert clean_reason("a\nb\tc" + "x" * 500)[:5] == "a b c" and len(clean_reason("x" * 500)) == 300


def test_agent_api_is_rate_limited(tmp_path):
    """The agent API is unauthenticated: it must not be usable for flooding (unit-level, own app)."""
    import asyncio
    from types import SimpleNamespace

    from aiohttp.test_utils import TestClient, TestServer

    from egressgw import agentapi
    from egressgw.availability import Availability
    from egressgw.connectivity import Connectivity

    fake_gw = SimpleNamespace(
        config={"grant_api_rate": 3},
        grants=SimpleNamespace(defs={}, active={}, requests={}),
        availability=Availability({}, tmp_path),
        connectivity=Connectivity(),
    )

    async def run():
        async with TestClient(TestServer(agentapi.build_app(fake_gw))) as c:
            codes = [(await c.get("/v1/grants")).status for _ in range(5)]
            big = await c.post("/v1/grants/x/request", data=b"x" * 10000)
            return codes, big.status

    codes, big = asyncio.run(run())
    assert codes == [200, 200, 200, 429, 429] and big in (413, 429)
