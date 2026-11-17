import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "gateway"))

from egressgw.policy import (
    TTL_MAX,
    TTL_MIN,
    Policy,
    Rule,
    builtin_blocks,
    clamp_ttl,
    host_matches,
    ip_addr,
    load_preset,
    registrable_domain,
    rule_for_approval,
)
from egressgw.store import Secrets, render

PRESETS = Path(__file__).resolve().parents[2] / "gateway" / "presets"


def seeded(p: Policy) -> Policy:
    """The policy as a gateway has it in force: with the built-in blocks seeded at the bottom (ADR-0019)."""
    p.seed_blocks(builtin_blocks(), [])
    return p


def test_host_matching():
    assert host_matches("*.github.com", "github.com")
    assert host_matches("*.github.com", "api.github.com")
    assert not host_matches("*.github.com", "evilgithub.com")
    assert not host_matches("github.com", "api.github.com")
    assert host_matches("*", "anything.example")
    assert host_matches("API.GitHub.com", "api.github.com.")


def test_built_in_blocks_on_resolved_private_ip():
    p = seeded(Policy())
    p.rules.insert(0, Rule(action="allow", host="*"))
    d = p.evaluate("nas.example.org", 443, ["192.168.1.10"])
    assert d.action == "deny" and d.rule_id == "block-192.168.0.0_16"
    # IPv4-mapped IPv6 is normalised
    assert p.evaluate("x", 443, ["::ffff:10.0.0.1"]).action == "deny"
    assert p.evaluate("10.1.2.3", 22, []).action == "deny"
    assert p.evaluate("example.com", 443, ["93.184.215.14"]).action == "allow"


def test_approving_an_address_opens_exactly_that_address_and_port():
    # ADR-0019: an approval of an IP literal is an address rule for that address only, at the top
    p = seeded(Policy())
    r = p.add_rule(rule_for_approval("192.168.1.1", 22, "always"))
    assert (r.cidr, r.port, p.rules[0]) == ("192.168.1.1/32", 22, r)
    assert p.evaluate("192.168.1.1", 22, ["192.168.1.1"]).action == "allow"
    assert p.evaluate("192.168.1.1", 80, ["192.168.1.1"]).action == "deny"
    assert p.evaluate("192.168.1.2", 22, ["192.168.1.2"]).action == "deny"
    # approving a NAME never opens a blocked range, whatever it resolves to
    p.add_rule(rule_for_approval("nas.example", 443, "always"))
    assert p.evaluate("nas.example", 443, ["192.168.1.2"]).action == "deny"


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


def test_an_address_allow_is_for_the_ip_literal_and_an_address_deny_for_every_destination():
    # ADR-0019, amendment (the rule of #10 again): an address allow decides for the IP literal; it never lets a
    # name through by itself. An address deny blocks the address, however it was named.
    p = Policy.from_dict({"default": "deny", "rules": [{"id": "c", "action": "allow", "cidr": "140.82.112.0/20"}]})
    assert p.evaluate("140.82.112.3", 443, ["140.82.112.3"]).action == "allow"
    assert p.evaluate("8.8.8.8", 443, ["8.8.8.8"]).action == "deny"
    d = p.evaluate("github.com", 443, ["140.82.112.3"])
    assert (d.action, d.reason) == ("deny", "default")  # the name is not allowed: the mode decides
    p.add_rule(Rule(action="allow", host="github.com", id="n"), top=False)
    assert p.evaluate("github.com", 443, ["140.82.112.3"]).rule_id == "n"  # allowed by its name
    p.add_rule(Rule(action="deny", cidr="8.8.8.0/24", id="blk"), top=False)
    assert p.evaluate("github.com", 443, ["140.82.112.3", "8.8.8.8"]).rule_id == "blk"  # every address must pass
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


def test_clamp_ttl_validates_and_clamps():
    assert clamp_ttl(3600) == 3600
    assert clamp_ttl(TTL_MIN) == TTL_MIN and clamp_ttl(TTL_MAX) == TTL_MAX
    assert clamp_ttl(1) == TTL_MIN  # below the floor -> 1 minute
    assert clamp_ttl(TTL_MAX + 9999) == TTL_MAX  # above the ceiling -> 30 days
    for bad in ("3600", 3600.0, True, False, None, [60]):
        with pytest.raises(ValueError, match="ttl must be an integer"):
            clamp_ttl(bad)


def test_custom_duration_allow_installs_a_temporary_rule():
    before = time.time()
    r = rule_for_approval("host.example", 443, "allow", ttl=1800)
    assert r.action == "allow" and r.host == "host.example" and r.source == "approval"
    assert r.expires is not None and 1800 - 2 <= r.expires - before <= 1800 + 2
    # "allow" has no default lifetime, so it must be given a ttl
    with pytest.raises(ValueError, match="requires a ttl"):
        rule_for_approval("host.example", 443, "allow")


def test_temporary_deny_rule_has_custom_or_default_expiry():
    before = time.time()
    r = rule_for_approval("block.example", 443, "deny", ttl=600)
    assert r.action == "deny" and r.host == "block.example"
    assert r.expires is not None and 600 - 2 <= r.expires - before <= 600 + 2
    # no ttl keeps the unchanged 120 s default (still a temporary deny that may be re-asked)
    r2 = rule_for_approval("block.example", 443, "deny")
    assert r2.action == "deny" and r2.expires is not None and r2.expires - before <= 120 + 2


def test_permanent_and_fixed_scopes_ignore_a_supplied_ttl():
    # permanent scopes stay permanent even if a ttl is sent
    for scope in ("always", "domain", "deny_always"):
        host = "api.github.com" if scope == "domain" else "host.example"
        assert rule_for_approval(host, 443, scope, ttl=600).expires is None
    # once/hour keep their fixed durations (backward compat): a ttl does not move them
    assert rule_for_approval("host.example", 443, "once", ttl=99999).expires - time.time() <= 120
    assert 3600 - 5 <= rule_for_approval("host.example", 443, "hour", ttl=60).expires - time.time() <= 3600


def test_temporary_deny_suppresses_reask_until_it_expires():
    p = Policy()
    p.default = "ask"
    r = rule_for_approval("block.example", 443, "deny", ttl=600)
    p.add_rule(r, top=True)
    # while the rule is live the destination is denied, not re-asked
    assert p.evaluate_name("block.example", 443).action == "deny"
    # once it expires the rule no longer decides and the destination may be asked again
    r.expires = time.time() - 1
    assert p.evaluate_name("block.example", 443).action == "ask"
    assert p.prune_expired() and p.rules == []


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
    assert r.cidr == "8.8.4.4/32"
    assert r.contains(ip_addr("8.8.4.4")) and r.contains(ip_addr("::ffff:8.8.4.4"))


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


def test_tunnelling_prefixes_are_blocked():
    p = seeded(Policy.from_dict({"default": "allow"}))
    for ip in ("64:ff9b::a00:1", "2002:c0a8:101::1", "2001:0:1::1", "::127.0.0.1", "fec0::1"):
        assert p.evaluate("x.example", 443, [ip]).action == "deny", ip


def test_name_first_evaluation():
    # TG-02: names are decided before resolution, where no address can change the result (ADR-0019)
    p = Policy.from_dict(
        {
            "default": "ask",
            "rules": [
                {"id": "d", "action": "deny", "host": "*.evil.example"},
                {"id": "a", "action": "allow", "host": "ok.example"},
            ],
        }
    )
    assert p.evaluate_name("x.evil.example", 443).action == "deny" and p.evaluate_name("x.evil.example", 443).early
    assert p.evaluate_name("ok.example", 443).action == "allow"
    assert p.evaluate_name("new.example", 443).action == "ask" and p.evaluate_name("new.example", 443).early
    p.add_rule(Rule(action="deny", cidr="1.2.3.0/24"), top=True)
    assert p.evaluate_name("x.evil.example", 443).early  # an address deny doesn't force a lookup
    # An approved IP literal is an address allow for its port. It approves that literal, not the names that
    # resolve to it, so names on that port are still decided before they are resolved (ADR-0019 amendment; #10)
    p.add_rule(rule_for_approval("140.82.112.3", 443, "always"), top=True)
    assert p.evaluate("140.82.112.3", 443, ["140.82.112.3"]).action == "allow"
    assert p.evaluate("new.example", 443, ["140.82.112.3"]).action == "ask"
    assert p.evaluate("x.evil.example", 443, ["140.82.112.3"]).rule_id == "d"
    assert p.evaluate_name("new.example", 443).early and p.evaluate_name("x.evil.example", 443).early
    assert not p.evaluate_name("ok.example", 443).early  # only an allow waits for the addresses
    assert p.evaluate("ok.example", 443, ["140.82.112.3"]).rule_id == "a"


def test_secret_values_reject_control_characters(tmp_path):
    s = Secrets(tmp_path / "s.json")
    with pytest.raises(ValueError):
        s.set("t", "abc\r\nX-Evil: 1")
    s.set("t", "ghp_ok")
    assert (tmp_path / "s.json").stat().st_mode & 0o777 == 0o600
