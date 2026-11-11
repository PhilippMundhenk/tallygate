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
