import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "gateway"))

from egressgw.policy import Policy, Rule, host_matches, registrable_domain, rule_for_approval
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


def test_cidr_allow_requires_all_ips():
    p = Policy.from_dict({"default": "deny", "rules": [{"id": "c", "action": "allow", "cidr": "140.82.112.0/20"}]})
    assert p.evaluate("github.com", 443, ["140.82.112.3"]).action == "allow"
    assert p.evaluate("github.com", 443, ["140.82.112.3", "8.8.8.8"]).action == "deny"


def test_expiry_and_prune():
    p = Policy()
    r = p.add_rule(Rule(action="allow", host="x.org", expires=time.time() - 1))
    assert p.evaluate("x.org", 443, ["1.1.1.1"]).action == "ask"
    assert p.prune_expired() and r not in p.rules


def test_approval_scopes():
    r = rule_for_approval("objects.githubusercontent.com", 443, "domain")
    assert r.host == "*.githubusercontent.com" and r.expires is None
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


def test_presets_load():
    for f in PRESETS.glob("*.yaml"):
        Policy.load(f)
    p = Policy.load(PRESETS / "baseline.yaml")
    assert p.default == "ask"
    assert p.evaluate("api.anthropic.com", 443, ["160.79.104.10"]).action == "allow"
    assert p.evaluate("evil.example", 443, ["1.2.3.4"]).action == "ask"


def test_roundtrip(tmp_path):
    p = Policy.load(PRESETS / "baseline.yaml")
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
