"""Grant definitions and lifecycle: validation of every field, matching rules, UI store, pruning."""

import sys
import time
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "gateway"))

from egressgw.grants import GrantDef, Grants, Target, fmt_ttl, host_match, parse_ttl

T = {"host": "nas.example", "port": 443}


def gdef(**over) -> dict:
    return {"targets": [T], "levels": ["read", "write"], **over}


def test_ttl_format_roundtrip():
    assert [fmt_ttl(s) for s in (90, 60, 7200, 86400 * 2, 3601)] == ["90s", "1m", "2h", "2d", "3601s"]
    for s in (59, 90, 3600, 5400, 86400):
        assert parse_ttl(fmt_ttl(s)) == s
    assert parse_ttl(" 2d ") == 172800 and parse_ttl(7.9) == 7
    with pytest.raises(ValueError):
        parse_ttl(True)  # bools are not durations


def test_host_matching_rules():
    assert host_match("*.example", "a.example") and host_match("*.example", "a.b.example.")
    assert not host_match("*.example", "example")  # the wildcard does not cover the apex
    assert not host_match("*.example", "aexample")
    assert host_match("10.0.0.5", "10.0.0.5") and host_match("::ffff:10.0.0.5", "10.0.0.5")
    assert not host_match("10.0.0.5", "10.0.0.6")
    assert host_match("NAS.example", "nas.example.") and not host_match("nas.example", "nas.example.evil")


@pytest.mark.parametrize(
    ("target", "error"),
    [
        ({**T, "user": "x"}, "unknown target fields"),
        ({**T, "host": "bad host"}, "invalid target host"),
        ({**T, "host": "*.10.0.0.1x-"}, "invalid target host"),
        ({**T, "port": 0}, "invalid port"),
        ({**T, "port": 65536}, "invalid port"),
        ({**T, "scheme": "ftp"}, "scheme must be one of"),
        ({**T, "address": "nas.lan"}, "address must be an IP"),
        ({**T, "host": "*.example", "address": "10.0.0.1"}, "needs an exact host"),
        ({**T, "scheme": "tcp", "paths": ["/x"]}, "tcp targets take no paths"),
        ({**T, "scheme": "tcp", "tls_verify": False}, "tcp targets take no paths"),
        ({**T, "scheme": "tcp", "tls_fingerprint": "ab" * 32}, "tcp targets take no paths"),
        ({**T, "scheme": "http", "tls_verify": False}, "TLS options only apply to https"),
        ({**T, "scheme": "http", "tls_fingerprint": "ab" * 32}, "TLS options only apply to https"),
        ({**T, "tls_fingerprint": "zz" * 32}, "SHA-256 fingerprint"),
        ({**T, "paths": ["api/*"]}, "must start with '/'"),
        ({**T, "paths": ["/" + "x" * 200]}, "must start with '/'"),
    ],
)
def test_target_validation(target, error):
    with pytest.raises(ValueError, match=error):
        Target.from_dict(target)


def test_target_serialisation_and_label():
    t = Target.from_dict(
        {"host": "PVE.example.", "port": 8006, "address": " 10.0.0.9 ", "lan": True, "tls_verify": False}
    )
    assert t.host == "pve.example" and t.address == "10.0.0.9"
    assert t.to_dict() == {
        "host": "pve.example",
        "port": 8006,
        "scheme": "https",
        "paths": ["/*"],
        "lan": True,
        "address": "10.0.0.9",
        "tls_verify": False,
    }
    assert Target.from_dict(t.to_dict()) == t
    assert t.label() == "https://pve.example:8006 (LAN)"
    tcp = Target.from_dict({"host": "db.example", "port": 5432, "scheme": "tcp"})
    assert "paths" not in tcp.to_dict() and tcp.label() == "tcp://db.example:5432"
    api = Target.from_dict({**T, "paths": ["/api/*", "/v2/*"], "tls_fingerprint": "AB" * 32})
    assert api.label() == "https://nas.example:443 /api/*,/v2/*" and api.to_dict()["tls_fingerprint"] == "ab" * 32


@pytest.mark.parametrize(
    ("d", "error"),
    [
        ({**gdef(), "owner": "me"}, "unknown fields"),
        (gdef(targets=[]), "at least one target"),
        (gdef(levels=["admin"]), "levels must be a subset"),
        (gdef(levels=["read", "read"]), "levels must be a subset"),
        (gdef(approval="yes"), "approval must be one of"),
        (gdef(approval={"write": "always"}), "approval must be one of"),
        (gdef(default_ttl="30s"), "default_ttl <= max_ttl"),
        (gdef(default_ttl="5h", max_ttl="4h"), "default_ttl <= max_ttl"),
        (
            gdef(inject=[{"host": "nas.example", "header": "Bad Header", "value": "x"}]),
            "invalid header name",
        ),
        (gdef(inject=[{"host": "other.example", "value": "x"}]), "must be an exact https target"),
    ],
)
def test_grant_definition_validation(d, error):
    with pytest.raises(ValueError, match=error):
        GrantDef.from_dict("g", d, "config")


def test_grant_definition_defaults_and_per_level_approval():
    g = GrantDef.from_dict("g", {"targets": [T], "levels": ["read", "write"], "approval": {"read": "auto"}}, "config")
    assert g.approval == {"read": "auto", "write": "ask"}  # unspecified levels must be approved by a human
    assert (g.default_ttl, g.max_ttl) == (3600, 4 * 3600)
    assert GrantDef.from_dict("r", {"targets": [T]}, "config").levels == ["read"]
    assert GrantDef.from_dict("d", {"targets": [T], "description": "x" * 400}, "config").description == "x" * 300


def test_config_grant_wins_over_a_ui_grant_of_the_same_name(tmp_path):
    (tmp_path / "grants.yaml").write_text(
        yaml.safe_dump({"nas": {"targets": [{"host": "evil.example", "port": 443}]}, "cam": {"targets": [T]}})
    )
    g = Grants({"grants": {"nas": {"targets": [T]}}}, tmp_path)
    assert g.defs["nas"].source == "config" and g.defs["nas"].targets[0].host == "nas.example"
    assert g.defs["cam"].source == "ui"


def test_empty_ui_store_and_empty_config_entries(tmp_path):
    (tmp_path / "grants.yaml").write_text("")
    g = Grants({}, tmp_path)
    assert g.defs == {} and g.request_timeout == 300 and g.max_requests == 3
    with pytest.raises(ValueError, match="at least one target"):
        Grants({"grants": {"x": None}}, tmp_path)  # a broken config grant stops the gateway


def test_ui_lan_target_address_must_be_inside_the_allowed_ranges(tmp_path):
    g = Grants({"grants_lan_allow": ["192.168.1.0/24"]}, tmp_path)
    lan = {"host": "cam.example", "port": 80, "scheme": "http", "lan": True}
    with pytest.raises(ValueError, match="outside grants_lan_allow"):
        g.upsert_ui("cam", {"targets": [{**lan, "address": "192.168.2.5"}]})
    assert "cam" not in g.defs and not (tmp_path / "grants.yaml").exists()
    g.upsert_ui("cam", {"targets": [{**lan, "address": "192.168.1.5"}]})
    assert Grants({}, tmp_path).defs["cam"].targets[0].address == "192.168.1.5"


def test_delete_ui_grant_revokes_its_active_instance(tmp_path):
    g = Grants({"grants": {"cfg": {"targets": [T]}}}, tmp_path)
    g.upsert_ui("cam", {"targets": [{"host": "cam.example", "port": 443}]})
    a = g.activate("cam", "read", 600, "", "t")
    keep = g.activate("cfg", "read", 600, "", "t")
    with pytest.raises(KeyError):
        g.delete_ui("nope")
    with pytest.raises(ValueError, match="cannot be deleted"):
        g.delete_ui("cfg")
    g.delete_ui("cam")
    assert a.id not in g.active and keep.id in g.active
    assert "cam" not in Grants({}, tmp_path).defs


def test_match_ignores_expired_and_orphaned_grants_and_tcp_needs_write(tmp_path):
    cfg = {
        "grants": {
            "web": {"targets": [T], "levels": ["read", "write"]},
            "raw": {"targets": [{**T, "scheme": "tcp"}], "levels": ["read", "write"]},
        }
    }
    g = Grants(cfg, tmp_path)
    a = g.activate("raw", "read", 600, "", "t")
    assert g.match("nas.example", 443) is None  # a read grant never opens a raw tcp target
    g.activate("raw", "write", 600, "", "t")
    assert g.match("nas.example", 443)[1].name == "raw"
    a.expires = time.time() - 1
    assert g.match("nas.example", 443) is None
    w = g.activate("web", "read", 600, "", "t")
    del g.defs["web"]  # e.g. removed from the config while active
    assert g.match("nas.example", 443) is None
    assert g.revoke(w.id) is w and w.id not in g.active
    with pytest.raises(KeyError):
        g.revoke(w.id)


def test_write_grant_beats_read_grant_for_the_same_target(tmp_path):
    g = Grants({"grants": {"r": {"targets": [T]}, "w": {"targets": [T], "levels": ["write"]}}}, tmp_path)
    g.activate("r", "read", 600, "", "t")
    g.activate("w", "write", 600, "", "t")
    assert g.match("nas.example", 443)[1].name == "w"
    g.activate("r", "read", 600, "", "t")  # re-approval later does not demote the connection
    assert g.match("nas.example", 443)[1].name == "w"


def test_request_ttl_is_clamped_and_activation_too(tmp_path):
    g = Grants({"grants": {"x": gdef(max_ttl="2h")}}, tmp_path)
    assert g.new_request("x", "read", "1d", "", "c").ttl == 7200
    assert g.new_request("x", "write", 1, "", "c").ttl == 60
    assert g.activate("x", "read", 0, "", "t").expires - time.time() == pytest.approx(60, abs=2)
    with pytest.raises(ValueError):
        g.new_request("x", "read", "soon", "", "c")


def test_prune_expires_grants_and_forgets_old_decided_requests(tmp_path):
    g = Grants({"grants": {"x": gdef()}}, tmp_path)
    a = g.activate("x", "read", 600, "", "t")
    r_old = g.new_request("x", "read", None, "", "c")
    r_old.status = "approved"
    r_recent = g.new_request("x", "write", None, "", "c")
    r_recent.status = "denied"
    assert g.prune() == ([], [])
    a.expires = time.time() - 1
    r_old.created -= r_old.timeout + 3601  # decided more than an hour after its timeout
    expired, timed_out = g.prune()
    assert expired == [a] and timed_out == [] and g.active == {}
    assert r_old.id not in g.requests and r_recent.id in g.requests  # kept for status polling
    assert g.pending() == []
