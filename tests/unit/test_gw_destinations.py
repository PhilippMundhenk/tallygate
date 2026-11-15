"""ADR-0014 step 1: the destination data model and `translate` (gateway/egressgw/destinations.py).

This is data only - it must mirror the live configuration faithfully and round-trip through the file format.
It does not decide anything yet; the enforcement path stays in model.Access.
"""

import sys
import time
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
    "seeded": [],  # the current form (ADR-0019): the rules stay in this order, the blocks are seeded below
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


def test_policy_file_round_trips_and_reads_the_old_forms():
    from egressgw.destinations import policy_from_file, policy_to_file
    from egressgw.policy import Policy, Rule, is_pre_0019, policy_from_any

    p = Policy()
    p.default, p.ask_timeout, p.seeded = "deny", 90, ["192.168.0.0/16", "10.0.0.0/8"]
    p.add_rule(Rule(action="allow", host="a.example", port=443, note="n", group="g", id="r1"), top=False)
    p.add_rule(Rule(action="deny", cidr="10.0.0.0/8", id="block-10.0.0.0_8", source="builtin"), top=False)
    f = policy_to_file(p)
    assert set(f) == {"default", "ask_timeout", "seeded", "destinations"} and f["default"] == "deny"
    assert f["seeded"] == ["192.168.0.0/16", "10.0.0.0/8"]  # which blocks were seeded: the deleted one stays deleted
    doc = policy_from_file(f)
    assert not is_pre_0019(doc)
    q = Policy.from_dict(doc)
    assert (q.default, q.ask_timeout, q.seeded) == ("deny", 90, p.seeded)
    key = lambda pol: [(r.id, r.action, r.host or r.cidr, r.port, r.note, r.group, r.source) for r in pol.rules]  # noqa: E731
    assert key(q) == key(p)
    assert policy_to_file(Policy())["seeded"] == []  # always written: its absence marks a pre-0019 file
    # a pre-0014 file (with `rules`) is passed through so it keeps loading
    assert policy_from_file({"default": "ask", "rules": [{"action": "allow", "host": "x"}]})["rules"]
    # a destinations-form file from before ADR-0019: `never` was the hard_deny extras, floor_open what was opened
    old = {
        "default": "ask",
        "never": [{"range": "203.0.113.0/24", "scope": "all"}, "198.51.100.7/32"],
        "floor_open": ["192.168.0.0/16"],
        "destinations": [{"match": {"host": "a.example"}, "access": "allow", "id": "r1"}],
    }
    doc = policy_from_file(old)
    assert is_pre_0019(doc) and doc["hard_deny"] == ["203.0.113.0/24", "198.51.100.7/32"]
    assert doc["floor_open"] == ["192.168.0.0/16"]
    m, _ = policy_from_any(doc, ["192.168.0.0/16", "203.0.113.0/24"], [])
    assert [(r.id, r.cidr) for r in m.rules] == [("r1", None), ("block-198.51.100.7_32", "198.51.100.7/32")]
    assert m.seeded == ["192.168.0.0/16"]
    for bad, error in (
        ({"destinations": [], "hard_deny": []}, "unknown policy keys"),
        ({"destinations": [], "never": "10.0.0.0/8"}, "never: expected a list"),
        ([1], "expected a mapping"),
    ):
        with pytest.raises(ValueError, match=error):
            policy_from_file(bad)
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
    assert [r.id for r in g.policy.rules if r.source == "user"] == ["r1"] and g.policy.default == "deny"
    # ... and in the same start to one ordered rule list (ADR-0019): the blocks are rules at the bottom
    assert pol["seeded"] == g.blocks_builtin and len(g.policy.rules) == 1 + len(g.blocks_builtin)
    assert (d / "policy.yaml.pre-0019").read_text() == (d / "policy.yaml.pre-0014").read_text()
    # grants.yaml migrated too
    gr = yaml.safe_load((d / "grants.yaml").read_text())
    assert "destinations" in gr and (d / "grants.yaml.pre-0014").exists()
    assert "ha" in g.grants.defs and g.grants.defs["ha"].source == "ui"
    # loading the already-migrated (new-form) files again changes nothing and makes no second backup
    before = (d / "policy.yaml").read_text()
    (d / "policy.yaml.pre-0019").write_text("kept")
    g2 = core.Gateway()
    assert [r.to_dict() for r in g2.policy.rules] == [r.to_dict() for r in g.policy.rules] and "ha" in g2.grants.defs
    assert (d / "policy.yaml").read_text() == before and (d / "policy.yaml.pre-0019").read_text() == "kept"
    assert not (d / "grants.yaml.pre-0019").exists()  # no `lan` in it: nothing to migrate for ADR-0019


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


def test_translate_lists_the_rules_in_evaluation_order_then_the_locked_ranges_and_the_default(tmp_path, monkeypatch):
    """ADR-0019: the model is the list as it is evaluated - the operator's rules, the seeded blocks (ordinary
    rules, deletable), and separately what is locked. There is no `never` list any more."""
    monkeypatch.setenv("GW_INTERNAL_NETS", "172.20.0.0/16,fd00:31::/64")
    monkeypatch.setenv("GW_API_HOST", "172.20.0.2")
    monkeypatch.setenv("GW_LISTEN_HOST", "0.0.0.0")
    g = build_gw(tmp_path / "locked", monkeypatch, {**CONFIG, "never": ["203.0.113.7/32"]}, POLICY)
    m = translate(g)
    d = m.to_dict()
    assert set(d) == {"default", "destinations", "locked"} and d["default"] == "deny"
    rules = [x for x in m.destinations if x.access in ("allow", "ask", "deny")]
    assert [x.id for x in rules] == [r.id for r in g.policy.rules]  # evaluation order, nothing left out
    assert m.destinations[: len(rules)] == rules  # ... and before the grants and the file properties
    assert [x.id for x in rules[:2]] == ["ok", "net"]
    blocks = rules[2:]
    assert [x.match.cidr for x in blocks] == [*g.blocks_builtin, "203.0.113.7/32"]
    assert {x.source for x in blocks[:-1]} == {"builtin"} and blocks[-1].source == "config"
    assert all(x.access == "deny" and x.id.startswith("block-") for x in blocks)
    # locked: the stack's networks and the gateway's own listeners; plain rows with a reason, nothing to act on
    assert all(set(row) == {"range", "source", "reason"} for row in m.locked)
    assert [row["range"] for row in m.locked if row["source"] == "stack"] == ["172.20.0.0/16", "fd00:31::/64"]
    listeners = [row["range"] for row in m.locked if row["source"] == "listener"]
    assert "172.20.0.2:8081" in listeners and "127.0.0.0/8:3128" in listeners and "::1:1080" in listeners
    assert g.never_reachable() == m.locked
    # a locked range is not a rule: it is in no rule list and cannot be addressed as a destination
    assert not any(x.match.cidr == "172.20.0.0/16" for x in m.destinations)


def test_translate_marks_shadowed_and_never_reached_rules(gw):
    from egressgw.policy import Decision, Rule

    gw.policy.add_rule(Rule(action="allow", cidr="10.1.0.0/16", port=443, id="in"), top=False)  # inside `net`, below it
    gw.policy.add_rule(Rule(action="deny", cidr="10.2.0.0/16", port=80, id="dup"), top=False)  # inside `net`, a deny
    gw.policy.add_rule(Rule(action="allow", host="nas.example", id="nas"))
    by_id = lambda: {x.id: x for x in translate(gw).destinations if x.id}  # noqa: E731
    rows = by_id()
    assert rows["in"].covered_by == "net" and rows["dup"].covered_by == "net"
    assert rows["ok"].covered_by == "" and rows["net"].covered_by == "" and rows["nas"].shadowed is None
    assert "covered_by" not in rows["ok"].to_dict() and rows["dup"].to_dict()["covered_by"] == "net"
    dec = gw.policy.evaluate("nas.example", 443, ["192.168.1.10"])
    gw._hit(dec)
    gw._hit(dec)
    sh = by_id()["nas"].shadowed  # not flushed yet: counted already
    assert (sh["count"], sh["address"], sh["by"], sh["range"]) == (2, "192.168.1.10", "block-192.168.0.0_16", "192.168.0.0/16")
    gw.flush_hits()
    gw._hit(gw.policy.evaluate("nas.example", 443, ["10.9.9.9"]))
    sh = by_id()["nas"].to_dict()["shadowed"]  # stored + unflushed, with the latest case
    assert (sh["count"], sh["address"], sh["by"]) == (3, "10.9.9.9", "net") and sh["last"] <= time.time()
    gw.flush_hits()
    assert gw.events.shadow_stats()["nas"]["count"] == 3 and gw.shadows == {}
    assert gw.events.hit_stats()["net"]["hits"] == 1  # the blocking rule is what decided, and is counted
    gw._hit(Decision("allow", "rule ok", "ok"))  # nothing shadowed: nothing recorded
    assert gw.shadows == {}
    # the record goes with the rule
    gw.policy.remove_rule("nas")
    assert "nas" not in gw.shadow_stats()
    gw.flush_hits()
    assert gw.events.shadow_stats() == {}
    # display fields are ignored on input: a model entry can be sent back as it is
    d = Destination.from_dict({"match": {"host": "a"}, "access": "allow", "shadowed": {"count": 1}, "covered_by": "x"})
    assert d.shadowed is None and d.covered_by == ""


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
    # `lan` is read from pre-0019 files (so the migration can report it) and never written (ADR-0019)
    old = Destination.from_dict({**full.to_dict(), "lan": True})
    assert old.lan and "lan" not in old.to_dict()
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
    # a request destination with its target options (address / pinned TLS / no verify); `lan` only from old files
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
        lan=True,  # from an old file: ignored, so nothing to guard any more (ADR-0019)
        tls_verify=False,
    )
    assert risky.file_only_set() == ["credentials", "tls.verify: false"]
