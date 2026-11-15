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


def test_policy_file_round_trips_and_reads_the_old_form():
    from egressgw.destinations import policy_from_file, policy_to_file
    from egressgw.policy import Policy, Rule

    p = Policy()
    p.default, p.ask_timeout, p.hard_deny = "deny", 90, ["203.0.113.0/24"]
    p.floor_open = ["192.168.0.0/16"]  # ADR-0017: the admin's opened floor range survives the round-trip
    p.add_rule(Rule(action="allow", host="a.example", port=443, note="n", group="g", id="r1"), top=False)
    p.add_rule(Rule(action="deny", cidr="10.0.0.0/8", id="r2"), top=False)
    f = policy_to_file(p)
    assert "destinations" in f and "rules" not in f and f["default"] == "deny" and f["ask_timeout"] == 90
    assert f["floor_open"] == ["192.168.0.0/16"]
    q = Policy.from_dict(policy_from_file(f))
    assert (q.default, q.ask_timeout, q.hard_deny, q.floor_open) == ("deny", 90, ["203.0.113.0/24"], ["192.168.0.0/16"])
    key = lambda pol: [(r.id, r.action, r.host or r.cidr, r.port, r.note, r.group) for r in pol.rules]  # noqa: E731
    assert key(q) == key(p)
    # a pre-0014 file (with `rules`) is passed through so it keeps loading
    assert policy_from_file({"default": "ask", "rules": [{"action": "allow", "host": "x"}]})["rules"]
    # a crafted policy.yaml cannot smuggle a grant or a credential destination into the policy (#137)
    with pytest.raises(ValueError, match="must be an access rule"):
        policy_from_file({"destinations": [{"match": {"host": "x"}, "access": "request", "request": {"name": "g"}}]})
    with pytest.raises(ValueError, match="must be an access rule"):
        policy_from_file({"destinations": [{"match": {"host": "x"}, "credentials": [{"value": "Bearer ${t}"}]}]})


def test_grants_file_round_trips_and_reads_the_old_form():
    from egressgw.destinations import grants_from_file, grants_to_file
    from egressgw.grants import GrantDef

    g = GrantDef.from_dict(
        "ha",
        {
            "description": "d",
            "levels": ["read", "write"],
            "approval": {"read": "auto", "write": "ask"},
            "targets": [
                {"host": "ha.example", "port": 443, "paths": ["/api/*"]},
                {"host": "ha2.example", "port": 8443},
            ],
        },
        "ui",
    )
    f = grants_to_file({"ha": g})
    assert "destinations" in f and len(f["destinations"]) == 2  # one request destination per target
    g2 = GrantDef.from_dict("ha", grants_from_file(f)["ha"], "ui")
    assert [t.to_dict() for t in g2.targets] == [t.to_dict() for t in g.targets]
    assert (g2.levels, g2.approval, g2.default_ttl, g2.max_ttl) == (g.levels, g.approval, g.default_ttl, g.max_ttl)
    # a pre-0014 file ({name: def}) is passed through
    assert grants_from_file({"ha": {"targets": [{"host": "x", "port": 1}], "levels": ["read"]}})["ha"]


def test_old_state_files_are_migrated_on_load(tmp_path, monkeypatch):
    d = tmp_path / "mig"
    d.mkdir()
    monkeypatch.setattr(core, "DATA_DIR", d)
    monkeypatch.setattr(core, "CONFIG_PATH", d / "config.yaml")
    monkeypatch.setattr(core, "STATIC_HOSTS", {})
    (d / "config.yaml").write_text("")
    (d / "policy.yaml").write_text(
        yaml.safe_dump({"default": "deny", "rules": [{"id": "r1", "action": "allow", "host": "a.example"}]})
    )
    (d / "grants.yaml").write_text(
        yaml.safe_dump(
            {"ha": {"targets": [{"host": "ha.example", "port": 443}], "levels": ["read"], "approval": "auto"}}
        )
    )
    g = core.Gateway()
    # policy.yaml migrated to the destinations form, old kept as *.pre-0014, rules preserved
    pol = yaml.safe_load((d / "policy.yaml").read_text())
    assert "destinations" in pol and "rules" not in pol
    assert (d / "policy.yaml.pre-0014").exists() and "rules:" in (d / "policy.yaml.pre-0014").read_text()
    assert [r.id for r in g.policy.rules] == ["r1"] and g.policy.default == "deny"
    # grants.yaml migrated too
    gr = yaml.safe_load((d / "grants.yaml").read_text())
    assert "destinations" in gr and (d / "grants.yaml.pre-0014").exists()
    assert "ha" in g.grants.defs and g.grants.defs["ha"].source == "ui"
    # loading the already-migrated (new-form) files again changes nothing and makes no second backup
    g2 = core.Gateway()
    assert [r.id for r in g2.policy.rules] == ["r1"] and "ha" in g2.grants.defs


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


def test_translate_never_list_has_the_whole_floor_and_marks_it_removable(gw):
    # ADR-0017: the Destinations floor list now includes the whole scope-all floor (hard_deny_floor + the
    # policy hard_deny), each marked `removable`/`open`, not just the policy additions.
    m = translate(gw)
    assert all(set(e) == {"range", "scope", "reason", "removable", "open"} for e in m.never)
    assert {e["scope"] for e in m.never} <= {"all", "all+lan"}
    ranges = {e["range"] for e in m.never}
    assert set(gw.policy.hard_deny_floor) <= ranges  # the built-in floor is listed now (it was missing)
    lan = {e["range"] for e in m.never if e["scope"] == "all+lan"}
    assert lan == {str(n) for n in gw.grants.never} | {str(n) for n in gw.grants.internal}
    # this fixture has no stack networks, so every row is an editable floor range and nothing is open
    assert all(e["removable"] for e in m.never) and not any(e["open"] for e in m.never)


def test_translate_never_marks_locked_and_open(tmp_path, monkeypatch):
    # ADR-0017: the stack's own networks (grants.internal) are shown once, locked; a scope-all floor range
    # the admin put in floor_open is marked open; loopback/metadata stay removable.
    monkeypatch.setenv("GW_INTERNAL_NETS", "172.20.0.0/16")
    g = build_gw(
        tmp_path / "locked", monkeypatch, CONFIG,
        {"default": "ask", "rules": [], "floor_open": ["192.168.0.0/16"]},
    )  # fmt: skip
    rows = {e["range"]: e for e in translate(g).never}
    assert rows["172.20.0.0/16"] == {
        "range": "172.20.0.0/16", "scope": "all+lan",
        "reason": "the tallygate stack's own network (locked)", "removable": False, "open": False,
    }  # fmt: skip
    assert rows["192.168.0.0/16"]["removable"] and rows["192.168.0.0/16"]["open"]  # opened by the admin
    assert rows["127.0.0.0/8"]["removable"] and not rows["127.0.0.0/8"]["open"]  # loopback stays removable
    assert rows["169.254.0.0/16"]["removable"] and not rows["169.254.0.0/16"]["open"]  # metadata too
    assert len(rows) == len(translate(g).never)  # every range once (the stack net is not duplicated)


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
        group="shops",
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


def test_more_validation_errors():
    from egressgw.destinations import Request, destinations_to_config, from_rules
    from egressgw.policy import Rule

    with pytest.raises(ValueError, match="unknown match keys"):
        Match.from_dict({"host": "a", "porttt": 443})
    with pytest.raises(ValueError, match="unknown request keys"):
        Request.from_dict({"name": "g", "levls": ["read"]})
    with pytest.raises(ValueError, match="invalid scheme"):
        Destination(match=Match(host="a"), access="request", request=Request("g"), scheme="ftp").validate()
    with pytest.raises(ValueError, match="needs a 'match'"):
        Destination.from_dict({"access": "allow"})
    with pytest.raises(ValueError, match="needs a host match"):
        destinations_to_config([Destination(match=Match(cidr="10.0.0.0/8"))])
    # from_rules mirrors rules to access destinations
    dests = from_rules([Rule(action="deny", cidr="1.2.3.0/24", id="d", group="g")])
    assert dests[0].access == "deny" and dests[0].match.cidr == "1.2.3.0/24" and dests[0].group == "g"


def test_destinations_to_config_carries_grant_target_options():
    # a request destination with the file-only target options (lan / address / pinned TLS / no verify)
    d = Destination(
        match=Match(host="nas.example", port=22),
        access="request",
        request=Request("nas", ["write"]),
        scheme="https",
        lan=True,
        address="10.0.0.5",
        tls_fingerprint="ab" * 32,
        tls_verify=False,
    )
    cfg = __import__("egressgw.destinations", fromlist=["destinations_to_config"]).destinations_to_config([d])
    t = cfg["grants"]["nas"]["targets"][0]
    assert (
        t["lan"] is True
        and t["address"] == "10.0.0.5"
        and t["tls_fingerprint"] == "ab" * 32
        and t["tls_verify"] is False
    )


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
