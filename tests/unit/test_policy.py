import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "gateway"))

from egressgw.policy import (
    DEFAULT_HARD_DENY,
    Policy,
    Rule,
    host_matches,
    load_preset,
    registrable_domain,
    rule_for_approval,
)
from egressgw.store import Secrets, render

PRESETS = Path(__file__).resolve().parents[2] / "gateway" / "presets"


def test_host_matching():
    assert host_matches("*.github.com", "github.com")
    assert host_matches("*.github.com", "api.github.com")
    assert not host_matches("*.github.com", "evilgithub.com")
    assert not host_matches("github.com", "api.github.com")
    assert host_matches("*", "anything.example")
    assert host_matches("API.GitHub.com", "api.github.com.")


def test_hard_deny_resolved_private_ip():
    p = Policy()
    p.rules = [Rule(action="allow", host="*")]
    d = p.evaluate("nas.example.org", 443, ["192.168.1.10"])
    assert d.action == "deny" and d.rule_id == "hard_deny"
    # IPv4-mapped IPv6 is normalised
    assert p.evaluate("x", 443, ["::ffff:10.0.0.1"]).action == "deny"
    assert p.evaluate("10.1.2.3", 22, []).action == "deny"
    assert p.evaluate("example.com", 443, ["93.184.215.14"]).action == "allow"


def test_hard_deny_cannot_be_overridden_by_rules_or_approvals():
    p = Policy()
    p.add_rule(rule_for_approval("192.168.1.1", 22, "always"))
    assert p.evaluate("192.168.1.1", 22, ["192.168.1.1"]).action == "deny"


def test_first_match_and_default():
    p = Policy.from_dict(
        {
            "default": "deny",
            "rules": [
                {"id": "a", "action": "deny", "host": "bad.github.com"},
                {"id": "b", "action": "allow", "host": "*.github.com", "port": 443},
            ],
        }
    )
    assert p.evaluate("bad.github.com", 443, ["140.82.1.1"]).action == "deny"
    assert p.evaluate("api.github.com", 443, ["140.82.1.1"]).action == "allow"
    assert p.evaluate("api.github.com", 22, ["140.82.1.1"]).action == "deny"
    assert p.evaluate("example.org", 443, ["1.2.3.4"]).reason == "default"


def test_cidr_allow_applies_to_ip_literals_only():
    # #10: a name is never allowed (or asked about) because of the addresses it resolves to
    p = Policy.from_dict({"default": "deny", "rules": [{"id": "c", "action": "allow", "cidr": "140.82.112.0/20"}]})
    assert p.evaluate("140.82.112.3", 443, ["140.82.112.3"]).action == "allow"
    assert p.evaluate("8.8.8.8", 443, ["8.8.8.8"]).action == "deny"
    assert p.evaluate("github.com", 443, ["140.82.112.3"]).action == "deny"
    p = Policy.from_dict({"default": "allow", "rules": [{"id": "d", "action": "deny", "cidr": "140.82.112.0/20"}]})
    assert p.evaluate("github.com", 443, ["8.8.8.8", "140.82.112.3"]).action == "deny"  # CIDR deny: any IP


def test_expiry_and_prune():
    p = Policy()
    r = p.add_rule(Rule(action="allow", host="x.org", expires=time.time() - 1))
    assert p.evaluate("x.org", 443, ["1.1.1.1"]).action == "ask"
    assert p.prune_expired() and r not in p.rules


def test_approval_scopes():
    r = rule_for_approval("api.github.com", 443, "domain")
    assert r.host == "*.github.com" and r.expires is None
    r = rule_for_approval("pypi.org", 443, "once")
    assert r.expires and r.expires - time.time() <= 120
    assert registrable_domain("a.b.example.co.uk") == "example.co.uk"
    with pytest.raises(ValueError):
        rule_for_approval("x.org", 443, "bogus")


def test_validation_rejects_garbage():
    for bad in (
        {"default": "maybe"},
        {"rules": [{"action": "allow"}]},
        {"rules": [{"action": "allow", "host": "x", "cidr": "1.0.0.0/8"}]},
        {"rules": [{"action": "allow", "host": "x", "evil": 1}]},
        {"ask_timeout": 1},
        {"hard_deny": ["not-a-net"]},
    ):
        with pytest.raises((ValueError, TypeError)):
            Policy.from_dict(bad)


@pytest.mark.parametrize("port", [None, [443, None], [], "https", "443;8443", "44 3", "9-1", 0, 65536, 44.3, True])
def test_rule_ports_are_validated_strictly(port):
    # #13: null used to mean "all ports" - and the UI sent null for typos
    with pytest.raises(ValueError, match="invalid port"):
        Rule.from_dict({"action": "allow", "host": "x.example", "port": port})


def test_rule_ports_accepted_forms():
    for port in (443, "443", [80, 443], "8000-8100", [80, "8000-8100"], "*", "any"):
        Rule.from_dict({"action": "allow", "host": "x.example", "port": port})
    assert Rule.from_dict({"action": "allow", "host": "x.example"}).port == "*"  # omitted = all ports


def test_ipv4_mapped_ipv6_is_matched_like_ipv4():
    # #13: a CIDR deny on 127.0.0.1/32 did not match [::ffff:127.0.0.1]
    p = Policy.from_dict({"default": "allow", "rules": [{"id": "d", "action": "deny", "cidr": "8.8.8.8/32"}]})
    assert p.evaluate("::ffff:8.8.8.8", 443, ["::ffff:8.8.8.8"]).action == "deny"
    assert p.evaluate("x.example", 443, ["::ffff:8.8.8.8"]).action == "deny"
    r = rule_for_approval("[::ffff:8.8.4.4]", 443, "always")
    assert r.cidr == "8.8.4.4"
    assert r.matches("8.8.4.4", 443, ["8.8.4.4"]) and r.matches("::ffff:8.8.4.4", 443, ["::ffff:8.8.4.4"])


def test_presets_load():
    for f in PRESETS.glob("*.yaml"):
        meta, pol = load_preset(f)
        assert meta["title"] and meta["description"] and meta["category"] in ("policy", "internet", "template")
        assert pol.rules, f.name
        assert all(r.action == "allow" for r in pol.rules) or meta["category"] == "policy"
    ids = [
        r.id
        for f in PRESETS.glob("*.yaml")
        if load_preset(f)[0]["category"] != "policy"
        for r in load_preset(f)[1].rules
    ]
    assert len(ids) == len(set(ids)), "template rule ids must be unique (undo works per template)"
    p = load_preset(PRESETS / "baseline.yaml")[1]
    assert p.default == "ask"
    assert p.evaluate("api.anthropic.com", 443, ["160.79.104.10"]).action == "allow"
    assert p.evaluate("evil.example", 443, ["1.2.3.4"]).action == "ask"


def test_roundtrip(tmp_path):
    p = load_preset(PRESETS / "baseline.yaml")[1]
    p.save(tmp_path / "p.yaml")
    assert Policy.load(tmp_path / "p.yaml").to_dict() == p.to_dict()


def test_render(tmp_path):
    s = Secrets(tmp_path / "s.json")
    assert render("Bearer ${github_token}", s) is None
    s.set("github_token", "ghp_abc")
    assert render("Bearer ${github_token}", s) == "Bearer ghp_abc"
    import base64

    out = render("Basic ${b64:x-access-token:${github_token}}", s)
    assert base64.b64decode(out.split()[1]).decode() == "x-access-token:ghp_abc"
    assert (tmp_path / "s.json").stat().st_mode & 0o777 == 0o600


def test_domain_scope_respects_private_public_suffixes():
    # TG-04: widening must never cover other tenants of a shared suffix
    assert rule_for_approval("foo.github.io", 443, "domain").host == "*.foo.github.io"
    assert rule_for_approval("x.ngrok-free.app", 443, "domain").host == "*.x.ngrok-free.app"
    assert rule_for_approval("b.s3.amazonaws.com", 443, "domain").host == "*.b.s3.amazonaws.com"
    for host in ("github.io", "co.uk", "localhost"):
        with pytest.raises(ValueError):
            rule_for_approval(host, 443, "domain")


def test_hostname_validation():
    from egressgw.policy import valid_hostname

    assert (
        valid_hostname("api.github.com")
        and valid_hostname("_dmarc.example.com.")
        and valid_hostname("xn--80ak6aa92e.com")
    )
    for bad in (
        "",
        "a..b",
        "-a.com",
        "a-.com",
        "gïthub.com",
        "a b.com",
        "x" * 64 + ".com",
        "a.com\r\n",
        "[x].com",
        "*.com",
    ):
        assert not valid_hostname(bad), bad


def test_hard_deny_floor_cannot_be_removed_via_policy():
    # TG-03: an API/UI-supplied policy can only add CIDRs
    p = Policy.from_dict({"default": "allow", "hard_deny": [], "rules": [{"id": "a", "action": "allow", "host": "*"}]})
    assert p.evaluate("nas.example.org", 443, ["192.168.1.10"]).action == "deny"
    p = Policy.from_dict({"hard_deny": ["203.0.113.7/32", "10.0.0.0/8"], "hard_deny_floor": ["junk"]})
    p.use_floor(DEFAULT_HARD_DENY)
    assert p.hard_deny == ["203.0.113.7/32"]  # 10/8 is already in the floor (deduped); floor key ignored
    # #11: compared with the floor in force - a range missing from it is kept as an extra
    p = Policy.from_dict({"hard_deny": ["203.0.113.7/32", "10.0.0.0/8"]})
    p.use_floor(["192.168.0.0/16"])
    assert p.hard_deny == ["203.0.113.7/32", "10.0.0.0/8"]
    assert p.evaluate("10.1.2.3", 22, []).action == "deny"
    p = Policy.from_dict({"hard_deny": ["8.8.8.8/32"]})
    assert p.evaluate("dns.google", 443, ["8.8.8.8"]).action == "deny"


def test_tunnelling_prefixes_are_hard_denied():
    p = Policy.from_dict({"default": "allow"})
    for ip in ("64:ff9b::a00:1", "2002:c0a8:101::1", "2001:0:1::1", "::127.0.0.1", "fec0::1"):
        assert p.evaluate("x.example", 443, [ip]).action == "deny", ip


def test_name_first_evaluation():
    # TG-02: names are decided before resolution; only CIDR allow/ask rules need the IPs
    p = Policy.from_dict(
        {
            "default": "ask",
            "rules": [
                {"id": "d", "action": "deny", "host": "*.evil.example"},
                {"id": "a", "action": "allow", "host": "ok.example"},
            ],
        }
    )
    assert p.evaluate_name("x.evil.example", 443).action == "deny"
    assert p.evaluate_name("ok.example", 443).action == "allow"
    assert p.evaluate_name("new.example", 443).action == "ask"
    # #10: CIDR rules (e.g. an approved IP literal) never make the name phase inconclusive
    p.add_rule(rule_for_approval("140.82.112.3", 443, "always"), top=True)
    assert p.evaluate_name("new.example", 443).action == "ask"
    assert p.evaluate("new.example", 443, ["140.82.112.3"]).action == "ask"
    assert p.evaluate("140.82.112.3", 443, ["140.82.112.3"]).action == "allow"
    p.add_rule(Rule(action="deny", cidr="1.2.3.0/24"), top=True)
    assert p.evaluate_name("x.evil.example", 443).action == "deny"  # CIDR deny doesn't force a lookup


def test_service_exception_only_in_reverse_mode():
    # TG-15: the allow_private exception is bound to the service listener, not the proxy modes
    from egressgw.policy import Exception_

    p = Policy.from_dict({"default": "allow"})
    p.exceptions = [Exception_(host="192.168.1.5", port=5432)]
    assert p.evaluate("192.168.1.5", 5432, ["192.168.1.5"], "reverse").action == "allow"
    assert p.evaluate("192.168.1.5", 5432, ["192.168.1.5"], "regular").action == "deny"
    assert p.evaluate("192.168.1.5", 5432, ["192.168.1.5"], "socks5").action == "deny"


def test_secret_values_reject_control_characters(tmp_path):
    s = Secrets(tmp_path / "s.json")
    with pytest.raises(ValueError):
        s.set("t", "abc\r\nX-Evil: 1")
    s.set("t", "ghp_ok")
    assert (tmp_path / "s.json").stat().st_mode & 0o777 == 0o600
