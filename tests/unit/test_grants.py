import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "gateway"))

from egressgw.grants import GrantDef, Grants, Target, clean_reason, parse_ttl, path_ok

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


def test_never_reachable_and_ui_lan_limits(tmp_path):
    g = make(tmp_path, grants_lan_allow=["192.168.1.0/24"])
    d, t = g.defs["ha"], g.defs["ha"].targets[0]
    assert g.address_problem(d, t, ["192.168.7.7"]) is None  # config grant: any LAN address
    assert "never reachable" in g.address_problem(d, t, ["127.0.0.1"])
    assert "never reachable" in g.address_problem(d, t, ["169.254.169.254"])
    ui = g.upsert_ui("cam", {"targets": [{"host": "cam.lan", "port": 80, "scheme": "http", "lan": True}]})
    assert g.address_problem(ui, ui.targets[0], ["192.168.1.20"]) is None
    assert "outside grants_lan_allow" in g.address_problem(ui, ui.targets[0], ["192.168.7.7"])
    with pytest.raises(ValueError):
        g.upsert_ui("ha", HA)  # config grants cannot be overridden from the UI
    assert (tmp_path / "grants.yaml").exists() and Grants({"grants": {"ha": HA}}, tmp_path).defs["cam"].source == "ui"


def test_ui_lan_grants_need_config_opt_in(tmp_path):
    g = make(tmp_path)
    with pytest.raises(ValueError):
        g.upsert_ui("cam", {"targets": [{"host": "cam.lan", "port": 80, "scheme": "http", "lan": True}]})


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

    fake_gw = SimpleNamespace(
        config={"grant_api_rate": 3},
        grants=SimpleNamespace(defs={}, active={}, requests={}),
        availability=Availability({}, tmp_path),
    )

    async def run():
        async with TestClient(TestServer(agentapi.build_app(fake_gw))) as c:
            codes = [(await c.get("/v1/grants")).status for _ in range(5)]
            big = await c.post("/v1/grants/x/request", data=b"x" * 10000)
            return codes, big.status

    codes, big = asyncio.run(run())
    assert codes == [200, 200, 200, 429, 429] and big in (413, 429)
