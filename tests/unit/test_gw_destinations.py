"""ADR-0014 step 1: the destination data model and `translate` (gateway/egressgw/destinations.py).

This is data only - it must mirror the live configuration faithfully and round-trip through the file format.
It does not decide anything yet; the enforcement path stays in model.Access.
"""

import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "gateway"))

pytest.importorskip("mitmproxy")

from egressgw import core
from egressgw.destinations import Destination, Match, Model, RepoScopeSpec, Request, translate

CONFIG = {
    "inject": [{"host": "api.example", "header": "X-Token", "value": "Bearer ${tok}"}],
    "readonly": ["ro.example", {"host": "*.oci.example", "post_is_write": True, "read_posts": ["/q/*"]}],
    "github_repos": ["me/app"],
    "github_hosts": ["git.example"],
    "grants": {
        "ha": {
            "targets": [{"host": "ha.example", "port": 443, "paths": ["/api/*"]}],
            "levels": ["read", "write"],
            "approval": {"read": "auto", "write": "ask"},
            "inject": [{"host": "ha.example", "header": "X-HA", "value": "${tok}"}],
        },
        "ssh": {"targets": [{"host": "nas.example", "port": 22, "scheme": "tcp"}], "levels": ["write"]},
    },
}
POLICY = {
    "default": "deny",
    "rules": [
        {"id": "ok", "action": "allow", "host": "ok.example", "note": "fine"},
        {"id": "net", "action": "deny", "cidr": "10.0.0.0/8", "port": [80, 443]},
    ],
}


@pytest.fixture
def gw(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "DATA_DIR", tmp_path)
    monkeypatch.setattr(core, "CONFIG_PATH", tmp_path / "config.yaml")
    monkeypatch.setattr(core, "STATIC_HOSTS", {})
    (tmp_path / "config.yaml").write_text(yaml.safe_dump(CONFIG))
    (tmp_path / "policy.yaml").write_text(yaml.safe_dump(POLICY))
    return core.Gateway()


def build_gw(d, monkeypatch, config, policy=None):
    d.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(core, "DATA_DIR", d)
    monkeypatch.setattr(core, "CONFIG_PATH", d / "config.yaml")
    monkeypatch.setattr(core, "STATIC_HOSTS", {})
    (d / "config.yaml").write_text(yaml.safe_dump(config))
    (d / "policy.yaml").write_text(yaml.safe_dump(policy or {"default": "ask", "rules": []}))
    return core.Gateway()


OLD_KEYS = {
    "readonly": ["ro.example", {"host": "*.oci.example", "post_is_write": True, "read_posts": ["/q/*"]}],
    "inject": [{"host": "api.example", "header": "X-Token", "value": "Bearer ${t}"}],
    "github_repos": ["me/app"],
    "github_hosts": ["git.example"],
    "github_graphql": True,
    "grants": {
        "ha": {
            "targets": [{"host": "ha.example", "port": 443, "paths": ["/api/*"]}],
            "levels": ["read", "write"],
            "approval": {"read": "auto", "write": "ask"},
            "inject": [{"host": "ha.example", "header": "X-HA", "value": "${t}"}],
        }
    },
}


def test_a_destinations_config_loads_like_the_old_keys(tmp_path, monkeypatch):
    from egressgw import convert

    new, _ = convert.convert(OLD_KEYS)  # the same config in the destinations form
    assert "destinations" in new and not any(k in new for k in config_keys())

    a = build_gw(tmp_path / "a", monkeypatch, OLD_KEYS)
    b = build_gw(tmp_path / "b", monkeypatch, new)

    assert {r.host: (r.post_is_write, r.read_posts) for r in a.readonly} == {
        r.host: (r.post_is_write, r.read_posts) for r in b.readonly
    }
    assert sorted(a.inject, key=str) == sorted(b.inject, key=str)
    assert (set(a.github.patterns), a.github.hosts, a.github.graphql) == (
        set(b.github.patterns),
        b.github.hosts,
        b.github.graphql,
    )
    ga, gb = a.grants.defs["ha"], b.grants.defs["ha"]
    assert (ga.levels, ga.approval, ga.default_ttl, ga.max_ttl) == (gb.levels, gb.approval, gb.default_ttl, gb.max_ttl)
    assert [t.to_dict() for t in ga.targets] == [t.to_dict() for t in gb.targets] and ga.inject == gb.inject
    for host in ("ro.example", "x.oci.example", "api.example", "git.example", "other.example"):
        assert b.access.host_limits(host) == a.access.host_limits(host), host


def test_destinations_cannot_be_mixed_with_old_keys(tmp_path, monkeypatch):
    cfg = {"destinations": [{"match": {"host": "a.example"}, "methods": "no-writes"}], "readonly": ["b.example"]}
    with pytest.raises(ValueError, match="cannot be combined with the old keys"):
        build_gw(tmp_path, monkeypatch, cfg)


def test_access_rules_are_refused_in_the_gateway_config(tmp_path, monkeypatch):
    cfg = {"destinations": [{"match": {"host": "a.example"}, "access": "allow"}]}
    with pytest.raises(ValueError, match="belong in the policy"):
        build_gw(tmp_path, monkeypatch, cfg)


def config_keys():
    from egressgw.destinations import CONFIG_KEYS

    return CONFIG_KEYS


def by_match(model, host=None, cidr=None, port=None):
    """The destinations whose match names this host/cidr (and port, if given), in model order."""
    out = []
    for d in model.destinations:
        if d.match.host == host and d.match.cidr == cidr and (port is None or d.match.port == port):
            out.append(d)
    return out


def test_translate_lists_rules_then_grants_then_properties(gw):
    m = translate(gw)
    assert isinstance(m, Model) and m.default == "deny"

    # the two rules keep their order, action and metadata, and carry no properties
    ok = by_match(m, host="ok.example")[0]
    assert (ok.access, ok.note, ok.id, ok.source) == ("allow", "fine", "ok", "user")
    net = by_match(m, cidr="10.0.0.0/8")[0]
    assert net.access == "deny" and net.match.port == [80, 443]
    assert m.destinations[0] is ok and m.destinations[1] is net  # access entries come first, in rule order

    # grants became `access: request` destinations, one per target
    ha = by_match(m, host="ha.example", port=443)[0]
    assert ha.access == "request" and ha.scheme == "https" and ha.paths == ["/api/*"]
    assert ha.request == Request("ha", ["read", "write"], {"read": "auto", "write": "ask"}, 3600, 4 * 3600)
    assert ha.credentials == (("X-HA", "${tok}"),)  # the grant's own injection, https only
    ssh = by_match(m, host="nas.example", port=22)[0]
    assert ssh.access == "request" and ssh.scheme == "tcp" and ssh.paths is None  # tcp takes no paths

    # read-only hosts, repositories and credentials are properties-only entries (access is None)
    ro = by_match(m, host="ro.example")[0]
    assert ro.access is None and ro.methods == "no-writes" and ro.read_paths == ()
    oci = by_match(m, host="*.oci.example")[0]
    assert oci.methods == "no-writes+post" and oci.read_paths == ("/q/*",)
    assert by_match(m, host="git.example")[0].repos == RepoScopeSpec(["me/app"], graphql=False)
    inj = [d for d in by_match(m, host="api.example") if d.credentials]
    assert inj and inj[0].credentials == (("X-Token", "Bearer ${tok}"),) and inj[0].access is None


def test_translate_never_list_has_the_lan_floor_and_hard_deny(gw):
    m = translate(gw)
    assert {e["scope"] for e in m.never} <= {"all", "all+lan"}
    lan = {e["range"] for e in m.never if e["scope"] == "all+lan"}
    assert lan == {str(n) for n in gw.grants.never} | {str(n) for n in gw.grants.internal}
    assert [e["range"] for e in m.never if e["scope"] == "all"] == list(gw.policy.hard_deny)


def test_every_translated_entry_round_trips_through_the_file_format(gw):
    for d in translate(gw).destinations:
        assert Destination.from_dict(d.to_dict()) == d


def test_destination_serialisation_keeps_only_set_fields():
    d = Destination(match=Match(host="a.example"), access="allow")
    assert d.to_dict() == {"match": {"host": "a.example"}, "access": "allow"}
    full = Destination(
        match=Match(cidr="10.0.0.0/8", port=[80, 443]),
        access="deny",
        methods="no-writes+post",
        paths=["/x/*"],
        read_paths=("/q",),
        credentials=(("Authorization", "Bearer ${t}"),),
        repos=RepoScopeSpec(["me/app", "org/*"], graphql=True),
        scheme="https",
        lan=True,
        address="1.2.3.4",
        tls_fingerprint="ab" * 32,
        tls_verify=False,
        note="n",
        expires=100,
        id="r2",
        source="config",
    )
    assert Destination.from_dict(full.to_dict()) == full
    assert full.to_dict()["tls"] == {"fingerprint": "ab" * 32, "verify": False}
    # expiry is stored as whole seconds, like a rule
    assert Destination(match=Match(host="a.example"), expires=100.6).to_dict()["expires"] == 101


def test_request_destination_round_trips():
    d = Destination(
        match=Match(host="ha.example", port=443),
        access="request",
        request=Request("ha", ["read", "write"], {"read": "auto"}, 1800, 7200),
        scheme="https",
    )
    assert Destination.from_dict(d.to_dict()) == d


def test_repo_scope_spec_round_trips_and_graphql_is_optional():
    assert RepoScopeSpec(["me/app", "org/*"]).to_dict() == {"patterns": ["me/app", "org/*"]}  # graphql off is omitted
    assert RepoScopeSpec(["me/app"], graphql=True).to_dict() == {"patterns": ["me/app"], "graphql": True}
    d = Destination(match=Match(host="git.example"), repos=RepoScopeSpec(["me/app"], graphql=True))
    assert Destination.from_dict(d.to_dict()) == d
    with pytest.raises(ValueError, match="unknown repos keys"):
        RepoScopeSpec.from_dict({"patterns": ["me/app"], "grafql": True})


def test_validation_errors():
    with pytest.raises(ValueError, match="needs 'host' or 'cidr'"):
        Match().validate()
    with pytest.raises(ValueError, match="not both"):
        Match(host="a", cidr="1.2.3.0/24").validate()
    with pytest.raises(ValueError, match="invalid port"):
        Destination(match=Match(host="a", port=[])).validate()
    with pytest.raises(ValueError, match="invalid access"):
        Destination(match=Match(host="a"), access="permit").validate()
    with pytest.raises(ValueError, match="invalid methods"):
        Destination(match=Match(host="a"), methods="readonly").validate()
    with pytest.raises(ValueError, match="request' is set exactly"):
        Destination(match=Match(host="a"), access="request").validate()  # access request without a request block
    with pytest.raises(ValueError, match="request' is set exactly"):
        Destination(match=Match(host="a"), access="allow", request=Request("x")).validate()
    with pytest.raises(ValueError, match="unknown destination keys"):
        Destination.from_dict({"match": {"host": "a"}, "acces": "allow"})
    with pytest.raises(ValueError, match="unknown tls keys"):
        Destination.from_dict({"match": {"host": "a"}, "tls": {"verfy": True}})


def test_file_only_properties_are_flagged_for_the_trust_split():
    # §4: the API/UI may add entries and narrow them, but not set these - a loader rejects them off-file.
    plain = Destination(match=Match(host="a.example"), access="allow", methods="read", paths=["/x"])
    assert plain.file_only_set() == []
    risky = Destination(
        match=Match(host="a.example"),
        credentials=(("Authorization", "Bearer ${t}"),),
        lan=True,
        tls_verify=False,
    )
    assert risky.file_only_set() == ["credentials", "lan", "tls.verify: false"]
