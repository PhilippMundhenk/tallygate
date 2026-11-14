"""Policy engine edge cases: validation errors, port specs, CIDR rules without addresses, presets."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "gateway"))

from egressgw.policy import Policy, Rule, load_preset, parse_cidrs, port_matches, registrable_domain


@pytest.mark.parametrize("values", ["10.0.0.0/8", None, 10, {"a": 1}])
def test_cidr_lists_must_be_lists(values):
    # a bare string would otherwise be iterated character by character
    with pytest.raises(ValueError, match="hard_deny: expected a list of CIDRs"):
        parse_cidrs(values, "hard_deny")


def test_cidr_lists_are_normalised_and_deduplicated():
    assert parse_cidrs(["10.1.2.3/8", "10.0.0.0/8", ("fd00::1/8")], "x") == ["10.0.0.0/8", "fd00::/8"]
    with pytest.raises(ValueError, match="x: invalid CIDR 'nope'"):
        parse_cidrs(["nope"], "x")


@pytest.mark.parametrize(
    ("spec", "port", "hit"),
    [
        (None, 1, True),
        ("any", 22, True),
        (443, 443, True),
        (443, 80, False),
        ("443", 443, True),
        ("443", 444, False),
        ("8000-8100", 8000, True),
        ("8000-8100", 8100, True),
        ("8000-8100", 8101, False),
        ("8000-8100", 7999, False),
        ([80, "8000-8100"], 8050, True),
        ((80, 443), 22, False),
        (4.43, 443, False),  # unknown spec type never matches
    ],
)
def test_port_matching(spec, port, hit):
    assert port_matches(spec, port) is hit


def test_rule_validation_errors():
    with pytest.raises(ValueError, match="invalid action 'permit'"):
        Rule(action="permit", host="a.example").validate()
    with pytest.raises(ValueError, match="needs 'host' or 'cidr'"):
        Rule(action="allow").validate()
    with pytest.raises(ValueError, match="not both"):
        Rule(action="allow", host="a.example", cidr="1.2.3.0/24").validate()
    with pytest.raises(ValueError):
        Rule(action="deny", cidr="1.2.3.0/33").validate()
    with pytest.raises(ValueError, match="invalid port"):
        Rule(action="allow", host="a.example", port=[]).validate()
    with pytest.raises(ValueError, match="unknown rule keys"):
        Rule.from_dict({"action": "allow", "host": "a.example", "hosts": "typo"})


def test_cidr_rule_never_matches_without_addresses():
    for action in ("allow", "deny"):
        assert not Rule(action=action, cidr="0.0.0.0/0").matches("x.example", 443, [])


def test_a_cidr_deny_wins_over_a_host_allow_wherever_it_stands():
    # #119: approvals and shortcuts are added on top; they must not switch off a CIDR deny further down.
    p = Policy.from_dict(
        {
            "default": "ask",
            "rules": [
                {"id": "open", "action": "allow", "host": "*", "port": [80, 443]},  # e.g. "Allow web for 15 min"
                {"id": "ok", "action": "allow", "host": "evil.example"},  # e.g. an "Always allow" approval
                {"id": "net", "action": "deny", "cidr": "93.184.0.0/16", "note": "never there"},
                {"id": "old", "action": "deny", "cidr": "8.8.0.0/16", "expires": 1},
                {"id": "p", "action": "deny", "cidr": "9.9.9.0/24", "port": 22},
            ],
        }
    )
    dec = p.evaluate("evil.example", 443, ["93.184.0.7"])
    assert (dec.action, dec.rule_id, dec.reason) == ("deny", "net", "rule net (never there)")
    assert p.evaluate("evil.example", 443, ["1.1.1.1", "93.184.255.1"]).rule_id == "net"  # any address inside
    assert p.evaluate("evil.example", 443, ["1.1.1.1"]).rule_id == "open"  # outside: first match, as before
    assert p.evaluate("x.example", 443, ["8.8.8.8"]).rule_id == "open"  # an expired deny decides nothing
    assert p.evaluate("x.example", 443, ["9.9.9.9"]).rule_id == "open"  # another port
    assert p.evaluate_name("evil.example", 443).action == "allow"  # the name alone: still resolved, then refused
    # IP literals too: a CIDR deny wins over any allow above it (a host pattern, or a broader CIDR allow) (#137)
    assert p.evaluate("93.184.0.7", 443, ["93.184.0.7"]).rule_id == "net"  # the `*` allow does not shadow it
    q = Policy.from_dict(
        {
            "rules": [
                {"id": "a", "action": "allow", "cidr": "93.184.0.7/32"},  # a narrower allow above
                {"id": "d", "action": "deny", "cidr": "93.184.0.0/16"},
            ]
        }
    )
    assert q.evaluate("93.184.0.7", 443, ["93.184.0.7"]).rule_id == "d"  # the deny still wins
    assert q.evaluate("93.184.0.8", 443, ["93.184.0.8"]).rule_id == "d"
    assert q.evaluate("9.9.9.9", 443, ["9.9.9.9"]).reason == "default"  # outside the deny: the mode decides


def test_cidr_allow_needs_every_address_inside_deny_any():
    ips = ["1.2.3.4", "5.6.7.8"]
    assert not Rule(action="allow", cidr="1.2.3.0/24").matches("1.2.3.4", 443, ips)
    assert Rule(action="deny", cidr="1.2.3.0/24").matches("1.2.3.4", 443, ips)


def test_rule_serialisation_keeps_only_set_fields():
    assert Rule(action="deny", host="a.example", id="r1").to_dict() == {
        "id": "r1",
        "action": "deny",
        "host": "a.example",
    }
    full = Rule(action="allow", cidr="1.2.3.0/24", port=[443], note="n", expires=100.4, id="r2", source="approval")
    assert full.to_dict() == {
        "id": "r2",
        "action": "allow",
        "cidr": "1.2.3.0/24",
        "port": [443],
        "note": "n",
        "expires": 100,
        "source": "approval",
    }
    assert Rule.from_dict(full.to_dict()).to_dict() == full.to_dict()


def test_add_rule_top_or_bottom_and_remove():
    p = Policy()
    a = p.add_rule(Rule(action="allow", host="a.example", id="a"))
    p.add_rule(Rule(action="deny", host="*", id="catchall"), top=False)
    p.add_rule(Rule(action="deny", host="a.example", id="top"))
    assert [r.id for r in p.rules] == ["top", "a", "catchall"]
    assert p.evaluate_name("a.example", 443).rule_id == "top"
    with pytest.raises(ValueError):
        p.add_rule(Rule(action="allow"))  # invalid rules are never inserted
    assert len(p.rules) == 3
    assert p.remove_rule("top") and not p.remove_rule("top")
    assert p.evaluate_name("a.example", 443).rule_id == a.id
    assert p.evaluate_name("b.example", 443).rule_id == "catchall"


def test_update_rule_edits_in_place_keeping_id_and_position():
    # #141: give a permanent "always allow" a time limit later, instead of deleting and re-adding it.
    p = Policy()
    p.add_rule(Rule(action="allow", host="a.example", id="a"))
    p.add_rule(Rule(action="deny", host="b.example", id="b"), top=False)
    new = p.update_rule("a", {"expires": 100, "action": "deny", "port": [80, 443], "note": "limited"})
    assert [r.id for r in p.rules] == ["a", "b"]  # id and position unchanged
    assert (new.action, new.port, new.note, new.expires) == ("deny", [80, 443], "limited", 100)
    assert p.rules[0].expires == 100  # the rule in the list is the edited one
    assert p.update_rule("gone", {"note": "x"}) is None  # no such rule
    with pytest.raises(ValueError, match="cannot edit"):
        p.update_rule("a", {"host": "c.example"})  # host/cidr are not editable
    with pytest.raises(ValueError):
        p.update_rule("a", {"action": "permit"})  # the result is still validated
    assert p.rules[0].action == "deny"  # a rejected edit leaves the rule untouched


def test_update_rule_can_clear_an_expiry():
    p = Policy()
    p.add_rule(Rule(action="allow", host="a.example", id="a", expires=100))
    assert p.update_rule("a", {"expires": None}).expires is None  # blank in the UI makes it permanent again


def test_policy_from_dict_validation():
    with pytest.raises(ValueError, match=r"unknown policy keys: \['rule'\]"):
        Policy.from_dict({"rule": []})
    with pytest.raises(ValueError, match="invalid default action"):
        Policy.from_dict({"default": "maybe"})
    for t in (4, 3601):
        with pytest.raises(ValueError, match="ask_timeout"):
            Policy.from_dict({"ask_timeout": t})
    with pytest.raises(ValueError, match="duplicate rule ids"):
        Policy.from_dict(
            {"rules": [{"id": "x", "action": "allow", "host": "a.example"}, {"id": "x", "action": "deny", "host": "b"}]}
        )
    # the read-only floor is echoed back by UIs and ignored, an empty document is the default policy
    assert Policy.from_dict({"hard_deny_floor": ["1.0.0.0/8"]}).hard_deny_floor != ["1.0.0.0/8"]
    assert Policy.from_dict(None).default == "ask"


def test_missing_or_empty_policy_file_is_the_default(tmp_path):
    assert Policy.load(tmp_path / "nope.yaml").to_dict() == Policy().to_dict()
    (tmp_path / "empty.yaml").write_text("")
    assert Policy.load(tmp_path / "empty.yaml").to_dict() == Policy().to_dict()


@pytest.mark.parametrize("host", ["10.0.0.1", "[::1]", "bad_host-.example", "", "a..b"])
def test_no_registrable_domain_for_ips_and_invalid_names(host):
    assert registrable_domain(host) is None


def test_preset_metadata_defaults_and_category_check(tmp_path):
    (tmp_path / "mine.yaml").write_text("default: deny\nrules: []\n")
    meta, pol = load_preset(tmp_path / "mine.yaml")
    assert meta == {"title": "mine", "description": "", "category": "template"} and pol.default == "deny"
    (tmp_path / "bad.yaml").write_text("category: everything\n")
    with pytest.raises(ValueError, match="preset bad: category must be one of"):
        load_preset(tmp_path / "bad.yaml")
    (tmp_path / "empty.yaml").write_text("")
    assert load_preset(tmp_path / "empty.yaml")[1].default == "ask"


def test_template_host_lists():
    """#59: hosts the tools really use, ids that namespace cleanly as <preset>:<id>."""
    presets = Path(__file__).resolve().parents[2] / "gateway" / "presets"
    hosts = {}
    for p in presets.glob("*.yaml"):
        _, pol = load_preset(p)
        assert all(":" not in r.id for r in pol.rules), p.stem
        hosts[p.stem] = {r.host: r.port for r in pol.rules}
    assert {"pkg-containers.githubusercontent.com", "ghcr.io", "registry-1.docker.io"} <= set(hosts["containers"])
    assert any(
        h.endswith(".r2.cloudflarestorage.com") and h.startswith("docker-images-prod.") for h in hosts["containers"]
    )
    assert "repo.yarnpkg.com" in hosts["node"]
    # port 80 stays: Debian images use http:// sources, and #57 ties the Host to the checked name
    assert hosts["debian"]["deb.debian.org"] == [80, 443] and hosts["debian"]["security.debian.org"] == [80, 443]
