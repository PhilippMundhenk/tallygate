"""ADR-0019: one ordered rule list, first match wins - the evaluation itself, as tables.

Every case is a rule list (the built-in blocks are seeded below it, as in a running gateway), a destination
with the addresses it resolved to, and what must be decided, by which rule. The pure policy only: what the
gateway does around it (asking, grants, the API) is in test_gw_locked.py and the other test_gw_* files."""

import ipaddress
import random
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "gateway"))

from egressgw.policy import (
    DEFAULT_HARD_DENY,
    DEFAULT_NEVER,
    LOCKED,
    Exception_,
    Policy,
    Rule,
    block_id,
    builtin_blocks,
    embedded_v4,
    is_pre_0019,
    locked_reason,
    migrate,
    policy_from_any,
    ports_within,
)

BUILTIN = builtin_blocks()
SEEDED = ("builtin", "config")
LAN16 = block_id("192.168.0.0/16")  # block-192.168.0.0_16
TEN8 = block_id("10.0.0.0/8")


def policy(rules=(), default="ask", seed=True, locked=(), socks=()) -> Policy:
    """A policy as the gateway has it in force: the rules, then the built-in blocks at the bottom."""
    p = Policy.from_dict({"default": default, "seeded": [], "rules": [dict(r) for r in rules]})
    if seed:
        p.seed_blocks(BUILTIN, [])
    p.locked_nets = [ipaddress.ip_network(c) for c in locked]
    p.locked_socks = [(ipaddress.ip_network(c), port) for c, port in socks]
    return p


def allow(rid, **match):
    return {"id": rid, "action": "allow", **match}


def deny(rid, **match):
    return {"id": rid, "action": "deny", **match}


def ask(rid, **match):
    return {"id": rid, "action": "ask", **match}


PUBLIC, PUBLIC2 = "93.184.215.14", "140.82.112.3"

# (what the case shows, rules above the built-in blocks, default, host, port, addresses, action, deciding rule)
CASES = [
    # --- an address allow above a range block opens that address, and only that
    ("address allow opens one host", [allow("dev", cidr="192.168.1.10/32", port=8123)], "ask",
     "192.168.1.10", 8123, ["192.168.1.10"], "allow", "dev"),
    ("... for a name that is allowed by name", [allow("dev", cidr="192.168.1.10/32", port=8123), allow("n", host="ha.lan")], "ask",
     "ha.lan", 8123, ["192.168.1.10"], "allow", "n"),
    ("... wherever the name rule stands", [allow("n", host="ha.lan"), allow("dev", cidr="192.168.1.10/32", port=8123)], "ask",
     "ha.lan", 8123, ["192.168.1.10"], "allow", "n"),
    ("... but it lets no name through by itself: the default decides", [allow("dev", cidr="192.168.1.10/32", port=8123)], "ask",
     "ha.lan", 8123, ["192.168.1.10"], "ask", None),
    ("... nor in deny mode", [allow("dev", cidr="192.168.1.10/32", port=8123)], "deny",
     "ha.lan", 8123, ["192.168.1.10"], "deny", None),
    ("... nor a public address (another site on a shared address, ADR-0013)", [allow("a", cidr=PUBLIC + "/32")], "ask",
     "other.example", 443, [PUBLIC], "ask", None),
    ("... but not on another port", [allow("dev", cidr="192.168.1.10/32", port=8123)], "ask",
     "192.168.1.10", 22, ["192.168.1.10"], "deny", LAN16),
    ("... and not its neighbour", [allow("dev", cidr="192.168.1.10/32", port=8123)], "ask",
     "192.168.1.11", 8123, ["192.168.1.11"], "deny", LAN16),
    ("an address ask is final too", [ask("dev", cidr="192.168.1.10/32")], "deny",
     "192.168.1.10", 80, ["192.168.1.10"], "ask", "dev"),
    ("... for the literal only: for a name it is skipped and the block below it stands", [ask("dev", cidr="192.168.1.10/32"), allow("n", host="ha.lan")], "ask",
     "ha.lan", 80, ["192.168.1.10"], "deny", LAN16),
    ("... and it turns no allowed name into a question", [ask("q", cidr=PUBLIC + "/32"), allow("n", host="x.example")], "deny",
     "x.example", 443, [PUBLIC], "allow", "n"),
    ("... and no unknown name either: the default decides", [ask("q", cidr=PUBLIC + "/32")], "deny",
     "x.example", 443, [PUBLIC], "deny", None),
    # --- three layers: a block above the allow closes part of it again
    ("layer 1: the block on top wins", [deny("cam", cidr="192.168.1.10/32"), allow("lan", cidr="192.168.1.0/24")], "ask",
     "192.168.1.10", 80, ["192.168.1.10"], "deny", "cam"),
    ("layer 2: the allow below it opens the rest", [deny("cam", cidr="192.168.1.10/32"), allow("lan", cidr="192.168.1.0/24")], "ask",
     "192.168.1.20", 80, ["192.168.1.20"], "allow", "lan"),
    ("layer 3: the built-in block below both", [deny("cam", cidr="192.168.1.10/32"), allow("lan", cidr="192.168.1.0/24")], "ask",
     "192.168.2.1", 80, ["192.168.2.1"], "deny", LAN16),
    # --- position decides: the same two rules the other way round
    ("an allow above a narrower block wins (#119 no longer holds)", [allow("lan", cidr="192.168.1.0/24"), deny("cam", cidr="192.168.1.10/32")], "ask",
     "192.168.1.10", 80, ["192.168.1.10"], "allow", "lan"),
    # --- a name rule cannot open a blocked range
    ("name allow + block below: deny", [allow("n", host="nas.example")], "ask",
     "nas.example", 443, ["192.168.1.10"], "deny", LAN16),
    ("name allow, public address: allow", [allow("n", host="nas.example")], "ask",
     "nas.example", 443, [PUBLIC], "allow", "n"),
    ("name ask + block below: deny, nobody is asked", [ask("n", host="nas.example")], "allow",
     "nas.example", 443, ["10.1.2.3"], "deny", TEN8),
    ("name ask, public address: ask", [ask("n", host="nas.example")], "allow",
     "nas.example", 443, [PUBLIC], "ask", "n"),
    ("wildcard name allow is a name rule", [allow("any", host="*")], "deny",
     "rebind.example", 443, ["169.254.169.254"], "deny", block_id("169.254.0.0/16")),
    ("a user block below a name allow blocks too", [allow("n", host="x.example"), deny("b", cidr="203.0.113.0/24")], "ask",
     "x.example", 443, ["203.0.113.9"], "deny", "b"),
    ("an address deny for another port does not block", [allow("n", host="x.example"), deny("b", cidr="8.8.8.0/24", port=53)], "ask",
     "x.example", 443, ["8.8.8.8"], "allow", "n"),
    # --- two addresses: the most restrictive result wins, whatever the order
    ("two addresses, the second blocked", [allow("n", host="two.example")], "ask",
     "two.example", 443, [PUBLIC, "192.168.1.10"], "deny", LAN16),
    ("two addresses, the first blocked", [allow("n", host="two.example")], "ask",
     "two.example", 443, ["192.168.1.10", PUBLIC], "deny", LAN16),
    ("two addresses, both fine", [allow("n", host="two.example")], "ask",
     "two.example", 443, [PUBLIC, PUBLIC2], "allow", "n"),
    ("one address allowed by an address rule, one left to the default", [allow("a", cidr=PUBLIC + "/32")], "ask",
     "mixed.example", 443, [PUBLIC, PUBLIC2], "ask", None),
    ("ask and deny: deny", [ask("a", cidr=PUBLIC + "/32"), deny("b", cidr=PUBLIC2 + "/32")], "allow",
     "mixed.example", 443, [PUBLIC, PUBLIC2], "deny", "b"),
    # --- name rules: deny is final wherever it stands, allow never opens a blocked address
    ("name deny is final", [deny("bad", host="*.evil.example"), allow("a", cidr=PUBLIC + "/32")], "allow",
     "x.evil.example", 443, [PUBLIC], "deny", "bad"),
    ("a name deny below an address allow wins too", [allow("a", cidr=PUBLIC + "/32"), deny("bad", host="*.evil.example")], "allow",
     "x.evil.example", 443, [PUBLIC], "deny", "bad"),
    ("a name ask below an address allow stays a question", [allow("a", cidr=PUBLIC + "/32"), ask("q", host="q.example")], "allow",
     "q.example", 443, [PUBLIC], "ask", "q"),
    ("an address deny above a name allow blocks the address", [deny("b", cidr=PUBLIC + "/32"), allow("n", host="ok.example")], "allow",
     "ok.example", 443, [PUBLIC], "deny", "b"),
    ("the first address rule decides whether the address is open: allow above deny", [allow("n", host="ok.example"), allow("a", cidr=PUBLIC + "/32"), deny("b", cidr="93.184.0.0/16")], "ask",
     "ok.example", 443, [PUBLIC], "allow", "n"),
    ("... deny above allow", [allow("n", host="ok.example"), deny("b", cidr="93.184.0.0/16"), allow("a", cidr=PUBLIC + "/32")], "ask",
     "ok.example", 443, [PUBLIC], "deny", "b"),
    ("the first matching name rule decides among names", [deny("bad", host="bad.github.com"), allow("gh", host="*.github.com", port=443)], "deny",
     "bad.github.com", 443, [PUBLIC2], "deny", "bad"),
    ("... and the next one for another name", [deny("bad", host="bad.github.com"), allow("gh", host="*.github.com", port=443)], "deny",
     "api.github.com", 443, [PUBLIC2], "allow", "gh"),
    ("... on its port only", [deny("bad", host="bad.github.com"), allow("gh", host="*.github.com", port=443)], "deny",
     "api.github.com", 22, [PUBLIC2], "deny", None),
    # --- IP literal destinations
    ("literal, public, wildcard name rule", [allow("any", host="*", port=[80, 443])], "deny",
     PUBLIC, 443, [PUBLIC], "allow", "any"),
    ("literal, private, wildcard name rule: still blocked", [allow("any", host="*", port=[80, 443])], "deny",
     "192.168.1.1", 443, ["192.168.1.1"], "deny", LAN16),
    # --- below a `*` name rule the first address rule that contains the literal decides, whatever its action
    ("literal below a wildcard allow: the address allow decides", [allow("any", host="*", port=443), allow("dev", cidr="192.168.44.1/32", port=443)], "ask",
     "192.168.44.1", 443, [], "allow", "dev"),
    ("... its neighbour is in the block", [allow("any", host="*", port=443), allow("dev", cidr="192.168.44.1/32", port=443)], "ask",
     "192.168.44.2", 443, [], "deny", LAN16),
    ("... an address ask below it asks", [allow("any", host="*"), ask("q", cidr=PUBLIC + "/32")], "deny",
     PUBLIC, 443, [], "ask", "q"),
    ("... an address deny below it blocks", [allow("any", host="*"), deny("b", cidr=PUBLIC + "/32"), allow("late", cidr=PUBLIC + "/32")], "allow",
     PUBLIC, 443, [], "deny", "b"),
    ("... the first of two decides", [ask("any", host="*"), allow("a", cidr="192.168.1.0/24"), deny("late", cidr="192.168.1.30/32")], "deny",
     "192.168.1.30", 443, [], "allow", "a"),
    ("... on its port only: elsewhere the wildcard stands", [allow("any", host="*"), ask("q", cidr=PUBLIC + "/32", port=22)], "deny",
     PUBLIC, 443, [], "allow", "any"),
    ("a wildcard deny is final for a literal too", [deny("none", host="*"), allow("dev", cidr="192.168.44.1/32")], "allow",
     "192.168.44.1", 443, [], "deny", "none"),
    ("an address rule above the wildcard is simply the first match", [allow("dev", cidr="192.168.44.1/32"), deny("none", host="*")], "allow",
     "192.168.44.1", 443, [], "allow", "dev"),
    ("literal with no addresses passed: the literal itself is checked", [], "allow",
     "10.1.2.3", 22, [], "deny", TEN8),
    ("IPv6 literal in brackets", [], "allow",
     "[fd00::5]", 443, [], "deny", block_id("fc00::/7")),
    ("IPv4-mapped IPv6 is the IPv4 address (#13)", [deny("d", cidr="8.8.8.8/32")], "allow",
     "::ffff:8.8.8.8", 443, ["::ffff:8.8.8.8"], "deny", "d"),
    ("... also behind a name", [], "allow",
     "x.example", 443, ["::ffff:10.0.0.1"], "deny", TEN8),
    # --- the default is the last line, for each mode
    ("default ask", [], "ask", "new.example", 443, [PUBLIC], "ask", None),
    ("default deny", [], "deny", "new.example", 443, [PUBLIC], "deny", None),
    ("default allow", [], "allow", "new.example", 443, [PUBLIC], "allow", None),
    ("default allow never reaches a blocked range", [], "allow", "new.example", 443, ["192.168.1.10"], "deny", LAN16),
    ("default allow, literal", [], "allow", PUBLIC, 25, [PUBLIC], "allow", None),
]  # fmt: skip


@pytest.mark.parametrize("case", CASES, ids=[c[0] for c in CASES])
def test_the_list_decides(case):
    _what, rules, default, host, port, ips, action, rule_id = case
    d = policy(rules, default).evaluate(host, port, ips)
    assert (d.action, d.rule_id) == (action, rule_id), d
    if rule_id is None:
        assert d.reason == "default"


def test_a_shadowed_name_rule_says_so_and_how_to_fix_it():
    """ADR-0019 "Why a name rule cannot open a blocked range": visible, not only documented."""
    p = policy([allow("n", host="nas.example")])
    d = p.evaluate("nas.example", 443, ["192.168.1.10"])
    assert d.action == "deny" and d.rule_id == LAN16
    assert d.reason == (
        "name allowed by rule n, but it resolves to 192.168.1.10, inside blocked range 192.168.0.0/16 "
        f"(rule {LAN16}): add an allow for the address above that rule"
    )
    assert d.shadow == {"rule": "n", "address": "192.168.1.10", "by": LAN16, "range": "192.168.0.0/16"}
    # the way out the reason names: an allow for the address, added at the top like every new rule
    p.add_rule(Rule(action="allow", cidr="192.168.1.10/32", id="dev"))
    d = p.evaluate("nas.example", 443, ["192.168.1.10"])
    assert (d.action, d.rule_id, d.shadow) == ("allow", "n", None)  # the address is open, the name rule decides
    # an ask rule is "matched", an IP literal has "the address"
    d = policy([ask("n", host="nas.example")]).evaluate("nas.example", 443, ["192.168.1.10"])
    assert d.reason.startswith("name matched by rule n, but it resolves to 192.168.1.10, inside blocked range")
    d = policy([allow("any", host="*")]).evaluate("192.168.1.1", 443, ["192.168.1.1"])
    assert d.reason.startswith("name allowed by rule any, but the address 192.168.1.1 is inside blocked range")
    # nothing is shadowed when a rule simply decides
    assert policy([allow("n", host="nas.example")]).evaluate("nas.example", 443, [PUBLIC]).shadow is None
    # no name rule: just the block, and the reason names the address that led into it
    d = policy().evaluate("x.example", 443, ["192.168.1.10"])
    assert (d.rule_id, d.shadow) == (LAN16, None)
    assert d.reason == f"resolves to 192.168.1.10, inside blocked range 192.168.0.0/16 (rule {LAN16} (built-in block))"


def test_for_a_name_the_position_of_the_name_rule_among_address_rules_does_not_matter():
    """ADR-0019, amendment: the order among the name rules decides the name, the order among the address rules
    decides whether an address is open. An allow for the address BELOW the name rule opens it just the same,
    so there is nothing to move (the old "stands below rule n: move it above" hint is gone)."""
    rules = [allow("n", host="nas.example"), allow("dev", cidr="192.168.1.10/32")]
    for order in (rules, rules[::-1]):
        d = policy(order).evaluate("nas.example", 443, ["192.168.1.10"])
        assert (d.action, d.rule_id, d.shadow) == ("allow", "n", None), order
        assert "move it above" not in d.reason
        # by IP literal the same list allows the address by its own rule (the name rule does not match a literal)
        assert policy(order).evaluate("192.168.1.10", 443, ["192.168.1.10"]).rule_id == "dev"
        # the allow is for one address: the name's other address is still inside the block
        d = policy(order).evaluate("nas.example", 443, ["192.168.1.10", "192.168.1.11"])
        assert (d.action, d.rule_id, d.shadow["rule"]) == ("deny", LAN16, "n")
        assert d.reason.endswith("add an allow for the address above that rule")
    # the address rule must stand above the BLOCK, as for a literal: below it, it opens nothing
    p = policy([allow("n", host="nas.example")])
    p.rules.append(Rule(action="allow", cidr="192.168.1.10/32", id="low"))
    assert p.evaluate("nas.example", 443, ["192.168.1.10"]).rule_id == LAN16
    # an address ask is a question about an IP literal: above the block it opens nothing for a name ...
    for order in ([allow("n", host="nas.example"), ask("q", cidr="192.168.1.10/32")],
                  [ask("q", cidr="192.168.1.10/32"), allow("n", host="nas.example")]):  # fmt: skip
        d = policy(order).evaluate("nas.example", 443, ["192.168.1.10"])
        assert (d.action, d.rule_id, d.shadow["rule"]) == ("deny", LAN16, "n"), order
        assert policy(order).evaluate("192.168.1.10", 443, []).rule_id == "q"  # ... the literal is asked about
    # ... and it does not turn an allowed name into a question
    d = policy([allow("n", host="x.example"), ask("q", cidr=PUBLIC + "/32")]).evaluate("x.example", 443, [PUBLIC])
    assert (d.action, d.rule_id) == ("allow", "n")


def test_an_address_allow_never_lets_a_name_through_by_itself():
    """ADR-0013, restored by the amendment: an approved address is not an approval of every name that resolves
    to it. The name is decided by the name rules or the default; the address allow only keeps the address open."""
    for default in ("ask", "deny", "allow"):
        p = policy([allow("ip", cidr=PUBLIC + "/32", port=443)], default)
        assert p.evaluate(PUBLIC, 443, []).rule_id == "ip"  # the literal it was approved for
        d = p.evaluate("other-site.example", 443, [PUBLIC])
        assert (d.action, d.rule_id, d.reason) == (default, None, "default")
    # a name deny below the address allow wins; a name ask below it still asks
    p = policy([allow("ip", cidr=PUBLIC + "/32"), deny("bad", host="bad.example"), ask("q", host="q.example")], "allow")
    assert p.evaluate("bad.example", 443, [PUBLIC]).rule_id == "bad"
    d = p.evaluate("q.example", 443, [PUBLIC])
    assert (d.action, d.rule_id) == ("ask", "q")
    # an allow for everything is no exception: names keep their mode, literals are allowed
    p = policy([allow("v4", cidr="0.0.0.0/0")], "ask")
    assert p.evaluate("new.example", 443, [PUBLIC]).action == "ask"
    assert p.evaluate("new.example", 443, ["192.168.1.10"]).action == "ask"  # open for a literal, asked for a name
    assert p.evaluate("192.168.1.10", 443, []).rule_id == "v4"


def test_ports_on_address_rules_and_expired_rules():
    p = policy([allow("web", cidr="10.0.0.5/32", port=[80, "8000-8100"])], "deny")
    assert p.evaluate("10.0.0.5", 80, []).rule_id == "web"
    assert p.evaluate("10.0.0.5", 8050, []).rule_id == "web"
    assert p.evaluate("10.0.0.5", 443, []).rule_id == TEN8
    p = policy([{**allow("old", cidr="10.0.0.5/32"), "expires": time.time() - 1}], "deny")
    assert p.evaluate("10.0.0.5", 80, []).rule_id == TEN8  # an expired allow opens nothing
    p = policy([{**deny("old", cidr=PUBLIC + "/32"), "expires": time.time() - 1}, allow("n", host="x.example")])
    assert p.evaluate("x.example", 443, [PUBLIC]).action == "allow"  # an expired block blocks nothing
    p = policy([{**allow("old", host="x.example"), "expires": time.time() - 1}])
    assert p.evaluate("x.example", 443, [PUBLIC]).reason == "default"


def test_no_address_is_never_allowed():
    """Fail closed: a name without addresses has not been checked against anything."""
    d = policy([allow("any", host="*")], "allow").evaluate("x.example", 443, [])
    assert (d.action, d.reason, d.rule_id) == ("deny", "no address to check", None)
    with pytest.raises(ValueError):  # garbage instead of an address is an error, which the hooks turn into a refusal
        policy([], "allow").evaluate("x.example", 443, ["not-an-ip"])


def test_every_built_in_range_is_blocked_once_seeded():
    assert set(BUILTIN) == {str(ipaddress.ip_network(c)) for c in [*DEFAULT_HARD_DENY, *DEFAULT_NEVER]}
    p = policy([allow("any", host="*")], "allow")
    samples = [
        "0.1.2.3", "10.1.2.3", "100.64.0.1", "127.0.0.1", "127.0.0.2", "169.254.169.254", "172.16.5.5",
        "192.168.1.10", "198.18.0.1", "224.0.0.1", "240.0.0.1", "::1", "::127.0.0.1", "64:ff9b::a00:1",
        "2002:c0a8:101::1", "2001:0:1::1", "fd00::1", "fe80::1", "fec0::1", "ff02::1",
    ]  # fmt: skip
    for ip in samples:
        d = p.evaluate("x.example", 443, [ip])
        assert d.action == "deny" and d.rule_id.startswith("block-"), ip
        assert p.evaluate(ip, 443, []).action == "deny", ip
    assert p.evaluate("x.example", 443, [PUBLIC]).action == "allow"


def test_an_ip_literal_below_a_catch_all_name_rule_is_decided_by_its_address_rule():
    """A `*` rule is a statement about names. Below it the first address rule that contains an IP literal
    decides - allow, ask or deny - and a deny keeps the reason that names both rules."""
    rules = [allow("any", host="*", port=443), allow("dev", cidr="192.168.44.1/32", port=443)]
    p = policy(rules)
    d = p.evaluate("192.168.44.1", 443, ["192.168.44.1"])
    assert (d.action, d.rule_id, d.reason, d.shadow) == ("allow", "dev", "rule dev", None)
    d = p.evaluate("192.168.44.2", 443, [])
    assert (d.action, d.rule_id) == ("deny", LAN16)
    assert d.shadow == {"rule": "any", "address": "192.168.44.2", "by": LAN16, "range": "192.168.0.0/16"}
    assert d.reason == (
        "name allowed by rule any, but the address 192.168.44.2 is inside blocked range 192.168.0.0/16 "
        f"(rule {LAN16}): add an allow for the address above that rule"
    )
    assert p.evaluate("192.168.44.1", 80, []).rule_id == LAN16  # the wildcard is for 443: the block is the first match
    # a name is not touched by this: the wildcard allows it by name, the address rules say what is open
    assert p.evaluate("x.example", 443, ["192.168.44.1"]).rule_id == "any"
    assert p.evaluate("x.example", 443, ["192.168.44.2"]).shadow["rule"] == "any"
    # what `covered_by` reports as never reached is never reached by a literal below a wildcard either
    p = policy([allow("any", host="*"), allow("lan", cidr="192.168.1.0/24"), deny("late", cidr="192.168.1.30/32")])
    assert p.covered_by(p.rules[2]).id == "lan"
    assert (
        p.evaluate("192.168.1.30", 443, []).rule_id == "lan"
        and p.evaluate("x.example", 443, ["192.168.1.30"]).action == "allow"
    )


def test_blocked_by_is_the_first_address_rule_with_allow_or_deny():
    """What blocks an address that only a name stands for (a name-only grant target): the first address rule
    with allow or deny that contains it, if that is a deny. Address `ask` rules are skipped."""
    p = policy(
        [
            ask("q", cidr="192.168.1.0/24"),
            allow("dev", cidr="192.168.1.50/32", port=631),
            deny("cam", cidr="8.8.8.8/32"),
        ]
    )
    assert p.blocked_by("192.168.1.50", 631) is None  # the allow above the block opens the address ...
    assert p.blocked_by("192.168.1.50", 80).id == LAN16  # ... on its port
    assert p.blocked_by("192.168.1.51", 631).id == LAN16  # the ask above the block opens nothing
    assert p.blocked_by("8.8.8.8", 53).id == "cam" and p.blocked_by("8.8.4.4", 53) is None
    assert p.blocked_by("::ffff:192.168.1.51", 631).id == LAN16
    # the order of the two decides; an expired rule is no rule
    p = policy([deny("cam", cidr="192.168.1.48/29"), allow("dev", cidr="192.168.1.50/32")])
    assert p.blocked_by("192.168.1.50", 631).id == "cam"
    p = policy([{**allow("old", cidr="192.168.1.50/32"), "expires": time.time() - 1}])
    assert p.blocked_by("192.168.1.50", 631).id == LAN16
    p = policy([{**deny("old", cidr="8.8.8.8/32"), "expires": time.time() - 1}])
    assert p.blocked_by("8.8.8.8", 53) is None
    # it agrees with the evaluation of an allowed name, for every address
    p = policy([allow("n", host="x.example"), ask("q", cidr="10.0.0.0/8"), allow("a", cidr="10.1.0.0/16"), deny("b", cidr="10.1.2.0/24"),
                deny("c", cidr="9.9.9.9/32", port=53)])  # fmt: skip
    for ip in ("10.1.2.3", "10.1.3.3", "10.2.0.1", "9.9.9.9", "1.1.1.1", "192.168.1.1"):
        for port in (53, 443):
            block, d = p.blocked_by(ip, port), p.evaluate("x.example", port, [ip])
            assert (block.id if block else None) == (d.rule_id if d.action == "deny" else None), (ip, port)


# ---------------------------------------------------------------- locked ranges
STACK = ["172.31.10.0/24", "172.31.11.0/24", "fd00:31::/64"]
EVERYTHING = [allow("v4", cidr="0.0.0.0/0"), allow("v6", cidr="::/0"), allow("names", host="*")]


@pytest.mark.parametrize(
    "host, ips",
    [
        ("172.31.11.2", []),
        ("172.31.11.2", ["172.31.11.2"]),
        ("control.example", ["172.31.11.3"]),
        ("two.example", [PUBLIC, "172.31.10.2"]),
        ("[fd00:31::2]", []),
        ("v6.example", ["fd00:31::2"]),
        ("mapped.example", ["::ffff:172.31.11.2"]),
    ],
)
def test_locked_ranges_are_denied_before_the_list_whatever_it_says(host, ips):
    # an allow for everything at the top, no built-in block left, default allow: the stack is still closed
    for seed in (True, False):
        p = policy(EVERYTHING, "allow", seed=seed, locked=STACK)
        d = p.evaluate(host, 8081, ips)
        assert d.action == "deny" and d.rule_id == LOCKED and d.reason.startswith("locked: "), d
        assert "belongs to the tallygate stack itself" in d.reason
        assert d.shadow is None  # not a rule: there is nothing to move or add
    assert policy(EVERYTHING, "allow", seed=False, locked=STACK).evaluate("x.example", 443, [PUBLIC]).action == "allow"


def test_locked_listeners_are_one_address_and_port():
    p = policy(EVERYTHING, "allow", seed=False, socks=[("203.0.113.5/32", 8081), ("127.0.0.0/8", 3128)])
    d = p.evaluate("203.0.113.5", 8081, [])
    assert (d.action, d.rule_id, d.reason) == ("deny", LOCKED, "locked: 203.0.113.5:8081 is the gateway itself")
    assert p.evaluate("api.example", 8081, ["203.0.113.5"]).rule_id == LOCKED
    assert p.evaluate("203.0.113.5", 443, []).action == "allow"  # another port of that address is not the listener
    assert p.evaluate("127.0.0.9", 3128, []).rule_id == LOCKED
    assert p.evaluate("203.0.113.6", 8081, []).action == "allow"


@pytest.mark.parametrize(
    "form, v4",
    [
        ("64:ff9b::ac1f:b02", "172.31.11.2"),  # NAT64, the well-known prefix
        ("64:ff9b::172.31.11.2", "172.31.11.2"),  # ... written with the dotted tail
        ("2002:ac1f:b02::1", "172.31.11.2"),  # 6to4: the IPv4 address in bits 16..48
        ("2002:ac1f:b02:1234:5678:9abc:def0:1", "172.31.11.2"),
        ("::ac1f:b02", "172.31.11.2"),  # IPv4-compatible (deprecated)
        ("::172.31.11.2", "172.31.11.2"),
        ("::ffff:172.31.11.2", None),  # IPv4-mapped: already normalised to the IPv4 address itself
        ("64:ff9b:1::ac1f:b02", None),  # the local-use NAT64 prefix carries no fixed position
        ("2001:db8::ac1f:b02", None),
        ("::1", None),  # loopback is not an embedded 0.0.0.1
        ("::", None),
        ("172.31.11.2", None),
    ],
)
def test_the_ipv4_address_an_ipv6_address_carries(form, v4):
    from egressgw.policy import ip_addr

    found = embedded_v4(ip_addr(form))
    assert (str(found) if found else None) == v4


def test_locked_ranges_also_match_the_ipv6_forms_that_carry_a_locked_ipv4_address():
    """NAT64, 6to4 and IPv4-compatible addresses reach the IPv4 address they carry on a host with a translator
    or tunnel. The built-in blocks close these prefixes - but blocks can be deleted, the lock cannot."""
    nets = [ipaddress.ip_network(c) for c in STACK]
    socks = [(ipaddress.ip_network("203.0.113.5/32"), 8081)]
    for form in ("64:ff9b::ac1f:b02", "2002:ac1f:b02::1", "::172.31.11.2", "[64:ff9b::ac1f:b02]"):
        why = locked_reason(form, 8081, nets, socks)
        assert why == f"locked: {form} belongs to the tallygate stack itself (172.31.11.0/24)", form
    # the gateway's own listener, by its port only
    for form in ("64:ff9b::cb00:7105", "2002:cb00:7105::", "::203.0.113.5"):
        assert locked_reason(form, 8081, nets, socks) == f"locked: {form}:8081 is the gateway itself"
        assert locked_reason(form, 443, nets, socks) is None
    # the same forms of an address that is not locked are not locked
    for form in ("64:ff9b::808:808", "2002:808:808::1", "::8.8.8.8", "64:ff9b:1::ac1f:b02", "2001:db8::ac1f:b02"):
        assert locked_reason(form, 8081, nets, socks) is None, form
    # in the evaluation: with every block deleted and an allow for everything, by literal and behind a name
    p = policy(EVERYTHING, "allow", seed=False, locked=STACK)
    for form in ("64:ff9b::ac1f:b02", "2002:ac1f:b02::1", "::172.31.11.2"):
        assert p.evaluate(f"[{form}]", 8080, []).rule_id == LOCKED
        d = p.evaluate("rebind.example", 8080, [PUBLIC, form])
        assert (d.action, d.rule_id) == ("deny", LOCKED) and d.reason.startswith(f"locked: {form} belongs to")
    assert p.evaluate("[64:ff9b::808:808]", 443, []).action == "allow"
    assert p.evaluate("[2002:ac1f:c02::1]", 443, []).action == "allow"  # 172.31.12.2: not the stack


def test_a_rule_cannot_be_named_like_the_lock():
    with pytest.raises(ValueError, match="invalid rule id"):
        Rule.from_dict({"id": LOCKED, "action": "allow", "host": "*"})
    with pytest.raises(ValueError, match="invalid rule id"):
        Rule.from_dict({"id": "", "action": "allow", "host": "*"})


def test_locked_applies_to_service_exceptions_which_only_skip_the_seeded_blocks():
    """TG-15, in the new model: `allow_private` exempts exactly one reverse-mode target from the built-in and
    config blocks. A block the operator wrote, every other rule and the locked ranges still apply."""
    p = policy([], "allow", locked=STACK)
    p.exceptions = [Exception_(host="192.168.1.5", port=5432), Exception_(host="172.31.11.2", port=8081)]
    assert p.evaluate("192.168.1.5", 5432, ["192.168.1.5"], "reverse").action == "allow"
    for mode in ("regular", "socks5", None):
        assert p.evaluate("192.168.1.5", 5432, ["192.168.1.5"], mode).rule_id == LAN16
    assert p.evaluate("192.168.1.5", 22, ["192.168.1.5"], "reverse").rule_id == LAN16  # another port
    assert p.evaluate("192.168.1.6", 5432, ["192.168.1.6"], "reverse").rule_id == LAN16  # another host
    assert p.evaluate("172.31.11.2", 8081, ["172.31.11.2"], "reverse").rule_id == LOCKED
    p.add_rule(Rule(action="deny", cidr="192.168.1.5/32", id="mine"))
    assert p.evaluate("192.168.1.5", 5432, ["192.168.1.5"], "reverse").rule_id == "mine"
    p = policy([], "deny")
    p.exceptions = [Exception_(host="192.168.1.5", port=5432)]
    d = p.evaluate("192.168.1.5", 5432, ["192.168.1.5"], "reverse")
    assert (d.action, d.reason) == ("deny", "default")  # the exception allows nothing by itself


# ---------------------------------------------------------------- deciding on the name, before DNS
def test_name_first_short_cuts_every_deny_and_ask_whatever_address_rules_there_are():
    p = policy([deny("bad", host="*.evil.example"), allow("ok", host="ok.example"), ask("q", host="q.example")], "ask")
    d = p.evaluate_name("x.evil.example", 443)
    assert (d.action, d.rule_id, d.early) == ("deny", "bad", True)  # never resolved (TG-02)
    assert (p.evaluate_name("new.example", 443).action, p.evaluate_name("new.example", 443).early) == ("ask", True)
    assert (p.evaluate_name("q.example", 443).rule_id, p.evaluate_name("q.example", 443).early) == ("q", True)
    d = p.evaluate_name("ok.example", 443)
    assert (d.action, d.early) == ("allow", False)  # allowed names are resolved, the addresses decide
    # an address deny anywhere (the built-in blocks are such rules) forces no lookup: it can only deny
    p.add_rule(Rule(action="deny", cidr="1.2.3.0/24", id="blk"))
    assert p.evaluate_name("x.evil.example", 443).early and p.evaluate_name("new.example", 443).early
    # an address allow at the TOP forces none either (amendment): it cannot let a name through, so after one
    # approved IP literal the gateway still resolves nothing it denies or has to ask about (ADR-0011)
    p.add_rule(Rule(action="allow", cidr="140.82.112.3/32", port=443, id="ip"))
    for name, action, rule in (
        ("x.evil.example", "deny", "bad"),
        ("new.example", "ask", None),
        ("q.example", "ask", "q"),
    ):
        d = p.evaluate_name(name, 443)
        assert (d.action, d.rule_id, d.early) == (action, rule, True), name
        full = p.evaluate(name, 443, ["140.82.112.3"])  # ... and indeed the address changes nothing
        assert (full.action, full.rule_id) == (action, rule), name
    assert p.evaluate("140.82.112.3", 443, []).rule_id == "ip"
    # the same with an allow for every address, and with an address ask above a name deny
    p = policy([allow("v4", cidr="0.0.0.0/0"), deny("bad", host="bad.example")], "deny")
    assert p.evaluate_name("bad.example", 443).early and p.evaluate_name("other.example", 443).early
    assert p.evaluate("other.example", 443, [PUBLIC]).reason == "default"
    p = policy([ask("ipq", cidr="140.82.112.3/32"), deny("bad", host="bad.example")], "ask")
    assert p.evaluate_name("bad.example", 443).early and p.evaluate_name("new.example", 443).early
    assert p.evaluate("bad.example", 443, ["140.82.112.3"]).rule_id == "bad"
    # the result is the name's alone: address rules are not looked at, an expired name rule is no rule
    p = policy(
        [{**allow("old", host="x.example"), "expires": time.time() - 1}, allow("ip", cidr=PUBLIC + "/32")], "deny"
    )
    d = p.evaluate_name("x.example", 443)
    assert (d.action, d.reason, d.rule_id, d.early) == ("deny", "default", None, True)


def _random_policy(rng: random.Random) -> Policy:
    nets = [
        "8.8.8.0/24",
        "8.8.8.8/32",
        "9.9.9.9/32",
        "192.168.1.0/24",
        "192.168.1.10/32",
        "0.0.0.0/0",
        "2001:4860::/32",
    ]
    hosts = ["a.example", "*.example", "b.test", "*", "*.b.test"]
    rules = []
    for i in range(rng.randint(0, 7)):
        r = {"id": f"r{i}", "action": rng.choice(["allow", "deny", "ask"])}
        if rng.random() < 0.5:
            r["cidr"] = rng.choice(nets)
        else:
            r["host"] = rng.choice(hosts)
        if rng.random() < 0.4:
            r["port"] = rng.choice([443, 80, [80, 443], "400-500"])
        if rng.random() < 0.1:
            r["expires"] = time.time() - 5
        rules.append(r)
    return policy(rules, rng.choice(["allow", "deny", "ask"]), seed=rng.random() < 0.7, locked=["172.31.11.0/24"])


def test_the_name_first_short_cut_is_proven_against_the_full_evaluation():
    """The proof ADR-0019 asks for: whenever `evaluate_name` says the name may be decided before it is
    resolved, the full evaluation gives a result the short cut cannot have changed, for ANY addresses:

      * early `deny`: every address set ends in `deny`.
      * early `ask`: no address set ends in `allow` - nothing is reachable without the human, and after the
        answer the addresses are checked by the full evaluation anyway.

    And an `allow` is never acted on early. 1500 random rule lists, each with every name/port/address mix."""
    rng = random.Random(208)  # noqa: S311 - a reproducible test sequence
    addresses = ["8.8.8.8", "8.8.8.9", "9.9.9.9", "1.1.1.1", "192.168.1.10", "192.168.1.20", "10.0.0.1",
                 "172.31.11.5", "2001:4860::1", "::1"]  # fmt: skip
    sets = [[a] for a in addresses] + [[a, b] for a in addresses[:5] for b in addresses[3:8]]
    early = {"deny": 0, "ask": 0}
    for _ in range(1500):
        p = _random_policy(rng)
        for name in ("a.example", "x.b.test", "other.org"):
            for port in (443, 80, 22):
                pre = p.evaluate_name(name, port)
                if pre.action == "allow":
                    assert not pre.early
                if not pre.early:
                    continue
                early[pre.action] += 1
                for ips in sets:
                    full = p.evaluate(name, port, ips)
                    if pre.action == "deny":
                        assert full.action == "deny", (p.to_dict(), name, port, ips, pre, full)
                    else:
                        assert full.action in ("ask", "deny"), (p.to_dict(), name, port, ips, pre, full)
    assert early["deny"] > 400 and early["ask"] > 400  # the short cut is really exercised


def test_the_short_cut_is_not_needlessly_strict():
    """The other direction, so that the proof above is not satisfied by never short-cutting: a name the list
    denies or asks about is ALWAYS decided early, whatever address rules there are (amendment)."""
    rng = random.Random(19)  # noqa: S311
    for _ in range(1500):
        p = _random_policy(rng)
        for port in (443, 22):
            for name in ("a.example", "other.org"):
                pre = p.evaluate_name(name, port)
                assert pre.early == (pre.action != "allow"), (p.to_dict(), name, port, pre)


# ---------------------------------------------------------------- seeding, restore, order
def test_blocks_are_seeded_once_at_the_bottom_and_deletions_persist():
    p = Policy.from_dict({"default": "ask", "seeded": [], "rules": [allow("a", host="x.example")]})
    added = p.seed_blocks(BUILTIN, ["203.0.113.7/32"])
    assert [r.cidr for r in added] == [*BUILTIN, "203.0.113.7/32"] and p.seeded == [*BUILTIN, "203.0.113.7/32"]
    assert [r.id for r in p.rules][:2] == ["a", block_id(BUILTIN[0])]  # below the operator's rules
    assert all(r.action == "deny" and r.port == "*" and r.expires is None for r in added)
    assert {r.source for r in added[:-1]} == {"builtin"} and added[-1].source == "config"
    assert added[-1].note == "never (gateway config)" and added[0].note == "built-in block"
    assert p.seed_blocks(BUILTIN, ["203.0.113.7/32"]) == []  # once
    # deleted, moved and edited like any rule - and a deleted block stays deleted (also across a save/load)
    assert p.remove_rule(LAN16) and p.remove_rule(block_id("203.0.113.7/32"))
    p = Policy.from_dict(p.to_dict())
    assert p.seed_blocks(BUILTIN, ["203.0.113.7/32"]) == []
    assert p.evaluate("192.168.1.10", 443, []).reason == "default" and p.evaluate("10.0.0.1", 443, []).action == "deny"
    # a `never` entry added to the gateway config later is seeded once, at the very bottom
    added = p.seed_blocks(BUILTIN, ["203.0.113.7/32", "198.51.100.0/25"])
    assert [(r.cidr, r.source) for r in added] == [("198.51.100.0/25", "config")] and p.rules[-1] is added[0]
    # one that left the config is forgotten (its rule stays), so configuring it again seeds it again
    p.remove_rule(block_id("198.51.100.0/25"))
    assert p.seed_blocks(BUILTIN, []) == [] and "198.51.100.0/25" not in p.seeded
    assert [r.cidr for r in p.seed_blocks(BUILTIN, ["198.51.100.0/25"])] == ["198.51.100.0/25"]


def test_restore_adds_back_what_is_missing_or_no_longer_a_block():
    p = policy([allow("a", host="x.example")])
    assert p.restore_blocks(BUILTIN, []) == []  # nothing missing
    p.remove_rule(LAN16)
    p.update_rule(TEN8, {"action": "allow"})  # edited into an allow: no longer the block
    p.update_rule(block_id("127.0.0.0/8"), {"port": 80})  # narrowed to one port: no longer the block
    p.update_rule(block_id("172.16.0.0/12"), {"note": "mine", "group": "lan"})  # still the block
    p.move_rule(block_id("224.0.0.0/4"), "a")  # moved: still the block
    added = p.restore_blocks(BUILTIN, ["203.0.113.7/32"])
    assert [r.cidr for r in added] == ["10.0.0.0/8", "127.0.0.0/8", "192.168.0.0/16", "203.0.113.7/32"]
    assert [r.id for r in added] == [TEN8 + "-2", block_id("127.0.0.0/8") + "-2", LAN16, block_id("203.0.113.7/32")]
    assert p.rules[-4:] == added and "203.0.113.7/32" in p.seeded
    assert p.evaluate("192.168.1.10", 443, []).rule_id == LAN16
    assert p.evaluate("10.0.0.1", 443, []).rule_id == TEN8  # the edited allow is above the restored block
    assert p.restore_blocks(BUILTIN, ["203.0.113.7/32"]) == []


def test_a_seeded_block_whose_action_changes_becomes_your_rule_and_takes_no_time_limit():
    """ADR-0019, amendment: `source: builtin/config` marks the block as it was seeded - an address deny. The
    overview hides those and "remove unused rules" keeps them, so a rule that allows must not carry the mark."""
    p = policy([allow("a", host="x.example")])
    for change in ({"action": "allow"}, {"action": "ask"}):
        q = Policy.from_dict(p.to_dict())
        r = q.update_rule(TEN8, change)
        assert (r.action, r.source, r.id, r.cidr) == (change["action"], "user", TEN8, "10.0.0.0/8")
        assert "source" not in r.to_dict() and q.blocks_missing(BUILTIN, []) == ["10.0.0.0/8"]
        assert q.update_rule(TEN8, {"action": "deny"}).source == "user"  # changed back: still yours, not seeded
        assert q.blocks_missing(BUILTIN, []) == []  # ... but it blocks the range as the seeded block did
    # note, group and port leave it the block it is
    r = p.update_rule(TEN8, {"note": "lab", "group": "lan", "port": 443})
    assert (r.source, r.port) == ("builtin", 443)
    # a time limit is refused: the block would be pruned and, remembered as seeded, never come back
    for rid in (LAN16, TEN8):
        with pytest.raises(ValueError, match=f"rule {rid}: a built-in block takes no time limit. To open the range"):
            p.update_rule(rid, {"expires": time.time() + 3600})
        assert next(r for r in p.rules if r.id == rid).expires is None
    assert p.update_rule(LAN16, {"expires": None}).source == "builtin"
    # ... also in a document (PUT /policy, import, a hand-edited file): refused, not silently dropped
    doc = p.to_dict()
    doc["rules"][-1] = {**doc["rules"][-1], "expires": round(time.time()) + 60}
    with pytest.raises(ValueError, match="a built-in block takes no time limit"):
        Policy.from_dict(doc)
    # a document cannot smuggle the mark onto something that is not an address deny
    for r in (
        {"id": "x", "action": "allow", "cidr": "10.0.0.0/8", "source": "builtin"},
        {"id": "x", "action": "ask", "cidr": "10.0.0.0/8", "source": "config"},
        {"id": "x", "action": "deny", "host": "*.example", "source": "builtin"},
        {"id": "x", "action": "allow", "host": "*", "source": "config"},
    ):
        assert Rule.from_dict(dict(r)).source == "user", r
    for source in SEEDED:
        r = Rule.from_dict({"id": "x", "action": "deny", "cidr": "10.0.0.0/8", "source": source})
        assert r.source == source
    # an operator's rule with a time limit is as before; once the mark is gone a time limit is accepted
    q = Policy.from_dict(p.to_dict())
    q.update_rule(LAN16, {"action": "allow"})
    assert q.update_rule(LAN16, {"expires": time.time() + 60}).source == "user"


@pytest.mark.parametrize("source", ["user", "approval", "learning", "suggestion", "builtin", "config", "preset:dev-basics", "preset:a.b_c-1"])  # fmt: skip
def test_the_known_sources_are_accepted(source):
    assert Rule.from_dict({"id": "x", "action": "deny", "cidr": "10.0.0.0/8", "source": source}).source == source


@pytest.mark.parametrize(
    "source", ["", "admin", "Builtin", "builtin ", "builtin\n", "preset:", "preset:a b", "preset:" + "x" * 65, "user;config", None, 7, ["builtin"]]
)  # fmt: skip
def test_an_unknown_source_is_refused(source):
    with pytest.raises(ValueError, match="rule x: invalid source"):
        Rule.from_dict({"id": "x", "action": "allow", "host": "x.example", "source": source})
    p = policy([allow("a", host="x.example")])
    with pytest.raises(ValueError, match="cannot edit"):  # and it is not editable afterwards
        p.update_rule("a", {"source": "builtin"})


@pytest.mark.parametrize("expires", ["tomorrow", "1700000000", True, False, [1], {"at": 1}])
def test_expires_must_be_a_number_or_null(expires):
    with pytest.raises(ValueError, match="rule x: expires must be a unix time or null"):
        Rule.from_dict({"id": "x", "action": "allow", "host": "x.example", "expires": expires})
    p = policy([allow("a", host="x.example")])
    with pytest.raises(ValueError, match="expires must be a unix time or null"):
        p.update_rule("a", {"expires": expires})
    assert p.rules[0].expires is None


def test_expires_as_a_number_or_null_is_accepted():
    for expires in (None, 0, 1700000000, time.time() + 60.5):
        assert (
            Rule.from_dict({"id": "x", "action": "allow", "host": "x.example", "expires": expires}).expires == expires
        )


def test_what_is_open_inside_the_blocks_and_which_blocks_are_missing():
    p = policy([
        allow("dev", cidr="192.168.1.10/32", port=8123), ask("q", cidr="10.0.0.0/7"), deny("cam", cidr="192.168.1.20/32"),
        allow("pub", cidr=PUBLIC + "/32"), allow("n", host="*"), {**allow("old", cidr="127.0.0.1/32"), "expires": time.time() - 1},
        allow("v6", cidr="fd00::/8"),
    ])  # fmt: skip
    assert p.opened_above(BUILTIN, []) == [
        {"rule": "q", "action": "ask", "cidr": "10.0.0.0/7", "block": "10.0.0.0/8"},  # in the order of the blocks
        {"rule": "dev", "action": "allow", "cidr": "192.168.1.10/32", "block": "192.168.0.0/16"},
        {"rule": "v6", "action": "allow", "cidr": "fd00::/8", "block": "fc00::/7"},
    ]
    assert p.blocks_missing(BUILTIN, ["203.0.113.7/32"]) == ["203.0.113.7/32"]
    # a rule BELOW its block opens nothing and is not listed; a block that is no longer one is not looked at
    p.move_rule("dev", None)
    p.update_rule(TEN8, {"port": 22})
    assert [o["rule"] for o in p.opened_above(BUILTIN, [])] == ["v6"]
    assert p.blocks_missing(BUILTIN, []) == ["10.0.0.0/8"]
    p.remove_rule(LAN16)
    assert p.blocks_missing(BUILTIN, []) == ["10.0.0.0/8", "192.168.0.0/16"]
    assert policy(seed=False).blocks_missing(BUILTIN, []) == BUILTIN and policy().opened_above(BUILTIN, []) == []


def test_move_rule_and_its_validation():
    p = policy([allow("a", host="a.example"), allow("b", host="b.example"), allow("c", host="c.example")], seed=False)
    order = lambda: [r.id for r in p.rules]  # noqa: E731
    assert p.move_rule("c", "a") and order() == ["c", "a", "b"]
    assert p.move_rule("c", "b") and order() == ["a", "c", "b"]
    assert p.move_rule("a", None) and order() == ["c", "b", "a"]  # null: the end of the list
    assert p.move_rule("a", None) and order() == ["c", "b", "a"]
    assert p.move_rule("nope", "a") is False and order() == ["c", "b", "a"]
    for before, error in (
        ("a", "before itself"),
        ("nope", "no rule 'nope'"),
        (LOCKED, "no rule"),
        (3, "rule id or null"),
    ):
        with pytest.raises(ValueError, match=error):
            p.move_rule("a", before)
    assert order() == ["c", "b", "a"]


def test_new_rules_at_the_bottom_stay_above_the_seeded_blocks():
    p = policy([allow("a", host="a.example")])
    p.add_rule(Rule(action="allow", host="learned.example", id="l"), top=False)
    assert [r.id for r in p.rules][:3] == ["a", "l", block_id(BUILTIN[0])]
    p.add_rule(Rule(action="allow", host="top.example", id="t"))
    assert p.rules[0].id == "t"
    with pytest.raises(ValueError, match="already used"):
        p.add_rule(Rule(action="deny", host="x.example", id="a"))


def test_an_address_rule_that_can_never_match_is_found():
    p = policy(
        [
            deny("cam", cidr="192.168.1.10/32"),
            allow("lan", cidr="192.168.1.0/24"),
            allow("dup", cidr="192.168.1.20/32"),  # inside `lan`, an allow: never the first match
            deny("late", cidr="192.168.1.30/32"),  # inside `lan`, a deny: `lan` says the address is open
            deny("cam2", cidr="192.168.1.10/32", port=443),  # covered by `cam`, a deny
            allow("web", cidr="192.168.1.0/25", port=[80, 443]),  # inside `lan`
            allow("other", cidr="192.168.2.0/24"),
            allow("n", host="192.168.1.20"),  # a name rule is never "covered"
            {**allow("tmp", cidr="10.0.0.0/8"), "expires": time.time() + 60},
            allow("ten", cidr="10.1.0.0/16"),  # `tmp` ends by itself: not covered for good
            allow("v6", cidr="fd00::/8"),
            ask("q", cidr="172.16.0.0/16"),
            allow("qa", cidr="172.16.1.0/24"),  # below an ask: still opens the address for a name
            deny("qd", cidr="172.16.2.0/24"),  # below an ask: still blocks it for a name
            ask("qq", cidr="172.16.3.0/24"),  # an ask below an ask never asks
            ask("lq", cidr="192.168.1.40/32"),  # an ask below an allow never asks
        ]
    )
    covered = {r.id: (c.id if (c := p.covered_by(r)) else None) for r in p.rules if r.source == "user"}
    assert covered == {
        "cam": None, "lan": None, "dup": "lan", "late": "lan", "cam2": "cam", "web": "lan", "other": None,
        "n": None, "tmp": None, "ten": None, "v6": None, "q": None, "qa": None, "qd": None, "qq": "q", "lq": "lan",
    }  # fmt: skip
    # the claim is true: a covered rule decides for no address, by literal or behind a name
    user = [r.to_dict() for r in p.rules if r.source == "user"]
    q = policy([allow("name", host="*.example"), *user])
    for rid in ("dup", "late", "cam2", "web", "qq", "lq"):
        without = policy([allow("name", host="*.example"), *[r for r in user if r["id"] != rid]])
        for ip in ("192.168.1.10", "192.168.1.20", "192.168.1.30", "192.168.1.40", "192.168.1.100", "172.16.3.1"):
            for port in (80, 443, 22):
                assert p.evaluate(ip, port, []).rule_id != rid
                assert q.evaluate("x.example", port, [ip]).rule_id != rid
                assert q.evaluate("x.example", port, [ip]).action == without.evaluate("x.example", port, [ip]).action
    assert q.evaluate("x.example", 22, ["192.168.1.30"]).action == "allow"  # `late` blocks nothing: `lan` opened it
    # ... and the rules below the ask are not covered: the ask is skipped for a name, they are what is found
    assert q.evaluate("x.example", 443, ["172.16.1.1"]).action == "allow"
    assert q.evaluate("x.example", 443, ["172.16.2.1"]).rule_id == "qd"
    assert q.evaluate("x.example", 443, ["172.16.4.1"]).rule_id == block_id("172.16.0.0/12")
    assert p.evaluate("172.16.1.1", 443, []).rule_id == "q"  # by literal the ask is the first match
    # an allow below the built-in block that covers it never matched and never will
    p = policy()
    p.add_rule(Rule(action="allow", cidr="192.168.1.10/32", id="low"), top=False)
    p.move_rule("low", None)
    assert p.covered_by(p.rules[-1]).id == LAN16


@pytest.mark.parametrize(
    "inner, outer, within",
    [
        (443, "*", True), ("*", 443, False), (443, [80, 443], True), ([80, 443], 443, False),
        ("8000-8100", "8000-9000", True), ("8000-9001", "8000-9000", False), ([80, "8000-8100"], ["1-100", "8000-8100"], True),
        ("*", "any", True), (None, "*", True),
    ],
)  # fmt: skip
def test_port_coverage(inner, outer, within):
    assert ports_within(inner, outer) is within


# ---------------------------------------------------------------- migration from a pre-0019 policy
OLD = {
    "default": "allow",
    "ask_timeout": 30,
    "hard_deny": ["203.0.113.7/32", "10.0.0.0/8", "198.51.100.0/24"],
    "floor_open": ["192.168.0.0/16", "198.51.100.0/24"],
    "hard_deny_floor": ["junk echoed by an old UI"],
    "rules": [
        {"id": "gh", "action": "allow", "host": "*.github.com"},
        {"id": "d1", "action": "deny", "cidr": "140.82.112.0/20"},
        {"id": "ip", "action": "allow", "cidr": "192.168.1.10/32"},
        {"id": "ip2", "action": "allow", "cidr": "10.0.0.5/32"},
        {"id": "d2", "action": "deny", "cidr": "8.8.8.8/32", "port": 53},
        {"id": "nd", "action": "deny", "host": "bad.example"},
    ],
}


def test_migration_of_a_pre_0019_policy():
    assert (
        is_pre_0019(OLD)
        and is_pre_0019({"default": "ask", "rules": []})
        and is_pre_0019({"seeded": [], "floor_open": []})
    )
    assert not is_pre_0019({"seeded": []})
    new, notes = migrate(OLD, BUILTIN, ["198.18.5.0/24"])
    assert set(new) == {"default", "ask_timeout", "rules", "seeded"}  # hard_deny, floor_open, the echo: gone
    assert (new["default"], new["ask_timeout"]) == ("allow", 30)
    # CIDR deny rules first, in their order; then the block an old address allow reaches into (10/8, for ip2);
    # then the other rules in theirs; then the hard_deny extras
    order = ["d1", "d2", TEN8, "gh", "ip", "ip2", "nd", block_id("203.0.113.7/32")]
    assert [r["id"] for r in new["rules"]] == order
    assert new["rules"][2] == {
        "id": TEN8,
        "action": "deny",
        "cidr": "10.0.0.0/8",
        "source": "builtin",
        "note": "built-in block",
    }
    extra = new["rules"][-1]
    assert extra == {
        "id": block_id("203.0.113.7/32"),
        "action": "deny",
        "cidr": "203.0.113.7/32",
        "note": "was hard_deny",
    }
    # floor_open: the operator had opened 192.168/16 - remembered as seeded, so no block is added for it.
    # 10/8 was an "extra" that is built in anyway; 198.51.100.0/24 is built in and was opened too. The block
    # that was placed at the top is remembered as seeded, so it is not added a second time at the bottom.
    assert new["seeded"] == ["192.168.0.0/16", "198.51.100.0/24", "10.0.0.0/8"]
    p, _ = policy_from_any(OLD, BUILTIN, ["198.18.5.0/24"])
    added = p.seed_blocks(BUILTIN, ["198.18.5.0/24"])
    assert [r.id for r in p.rules][:8] == order
    assert {r.cidr for r in added} == (set(BUILTIN) | {"198.18.5.0/24"}) - set(new["seeded"])
    assert [r.id for r in p.rules].count(TEN8) == 1 and p.blocks_missing(BUILTIN, ["198.18.5.0/24"]) == [
        "192.168.0.0/16",
        "198.51.100.0/24",
    ]
    assert p.rules[-1].cidr == "198.18.5.0/24" and p.rules[-1].source == "config"
    # what was decided before is decided now:
    assert p.evaluate("api.github.com", 443, ["140.82.112.3"]).rule_id == "d1"  # the CIDR deny below the allow won
    assert p.evaluate("nas.example", 443, ["192.168.1.99"]).action == "allow"  # opened range: the mode decides
    assert p.evaluate("x.example", 443, ["203.0.113.7"]).rule_id == block_id("203.0.113.7/32")  # the extra
    assert p.evaluate("x.example", 443, ["10.9.9.9"]).rule_id == TEN8  # still built in
    assert p.evaluate("x.example", 443, ["198.18.5.1"]).rule_id == block_id("198.18.0.0/15")
    # the log says what moved and what changed meaning
    text = "\n".join(notes)
    assert "moved 2 CIDR deny rule(s) to the top: d1, d2" in text
    assert f"hard_deny 203.0.113.7/32 is now deny rule {block_id('203.0.113.7/32')}" in text
    assert "not blocked, as before (floor_open): 192.168.0.0/16, 198.51.100.0/24" in text
    # an address allow inside a range that stays blocked did nothing before and does nothing now: its block
    # stays above it, and the log names the rule and the way to open the address
    assert (
        "NOTE 1 block(s) stay at the top of the list, above rule(s) ip2: these address rules had no effect inside "
        "the blocked ranges and still have none. To open an address, move its rule above the block. "
        "Blocks: 10.0.0.0/8"
    ) in text
    assert "it now decides" not in text
    assert "rule(s) ip2:" in text and "ip," not in text  # 192.168/16 was open: that rule already worked
    assert p.evaluate("10.0.0.5", 22, []).rule_id == TEN8
    assert p.evaluate("nas.example", 22, ["10.0.0.5"]).rule_id == TEN8
    assert p.opened_above(BUILTIN, ["198.18.5.0/24"]) == []  # nothing is open inside a block in force
    assert p.evaluate("192.168.1.10", 22, []).rule_id == "ip"
    # the way the note names: moved above the block, the rule opens its address
    assert p.move_rule("ip2", TEN8) and p.evaluate("10.0.0.5", 22, []).rule_id == "ip2"
    assert p.opened_above(BUILTIN, []) == [
        {"rule": "ip2", "action": "allow", "cidr": "10.0.0.5/32", "block": "10.0.0.0/8"}
    ]
    assert p.move_rule("ip2", "nd")
    # migrating the result again changes nothing
    assert not is_pre_0019(p.to_dict())
    again, notes = policy_from_any(p.to_dict(), BUILTIN, ["198.18.5.0/24"])
    assert notes == [] and again.to_dict() == p.to_dict() and again.seed_blocks(BUILTIN, ["198.18.5.0/24"]) == []


def test_migration_corner_cases_and_fail_closed():
    # nothing to move: no note about moving; a hard_deny extra that floor_open had opened is dropped
    new, notes = migrate(
        {"hard_deny": ["203.0.113.7/32"], "floor_open": ["203.0.113.7/32"], "rules": [{"id": "d", "action": "deny", "cidr": "1.1.1.1/32"}]},
        BUILTIN, [],
    )  # fmt: skip
    assert [r["id"] for r in new["rules"]] == ["d"] and new["seeded"] == []
    assert notes == ["hard_deny 203.0.113.7/32 was opened (floor_open): dropped"]
    # an id that is taken is not reused
    new, _ = migrate(
        {"hard_deny": ["203.0.113.7/32"], "rules": [{"id": block_id("203.0.113.7/32"), "action": "allow", "host": "x"}]},
        BUILTIN, [],
    )  # fmt: skip
    assert [r["id"] for r in new["rules"]] == [block_id("203.0.113.7/32"), block_id("203.0.113.7/32") + "-x"]
    # ... also by a block that is placed at the top: the rule that has its id keeps it
    new, notes = migrate(
        {"rules": [{"id": TEN8, "action": "allow", "cidr": "10.0.0.5/32"}, {"id": "q", "action": "ask", "cidr": "10.0.0.0/7"}]},
        BUILTIN, [],
    )  # fmt: skip
    assert [r["id"] for r in new["rules"]] == [TEN8 + "-x", TEN8, "q"] and new["rules"][0]["cidr"] == "10.0.0.0/8"
    assert f"above rule(s) {TEN8}, q:" in notes[-1] and new["seeded"] == ["10.0.0.0/8"]
    p, _ = policy_from_any({"rules": [{"id": TEN8, "action": "allow", "cidr": "10.0.0.5/32"}]}, BUILTIN, [])
    p.seed_blocks(BUILTIN, [])
    assert p.evaluate("10.0.0.5", 22, []).rule_id == TEN8 + "-x" and p.blocks_missing(BUILTIN, []) == []
    # a config block and a hard_deny extra are kept on top in the same way; an opened range (floor_open) is not
    new, notes = migrate(
        {"hard_deny": ["9.9.9.0/24", "8.8.8.0/24"], "floor_open": ["192.168.0.0/16"], "rules": [
            {"id": "a", "action": "allow", "cidr": "9.9.9.9/32"}, {"id": "b", "action": "ask", "cidr": "198.18.7.7/32"},
            {"id": "c", "action": "allow", "cidr": "192.168.1.1/32"}, {"id": "e", "action": "allow", "cidr": "::/0"},
            {"id": "x", "action": "allow", "cidr": "140.82.112.3/32", "expires": 1},
        ]},
        BUILTIN, ["198.18.7.0/24", "140.82.112.0/20"],
    )  # fmt: skip
    top = [r for r in new["rules"] if r["action"] == "deny"]
    v6 = [c for c in BUILTIN if ":" in c]  # `e` reaches into every IPv6 block
    assert [(r["cidr"], r.get("source")) for r in top] == [
        ("9.9.9.0/24", None), ("198.18.0.0/15", "builtin"), *[(c, "builtin") for c in v6],
        ("198.18.7.0/24", "config"), ("140.82.112.0/20", "config"), ("8.8.8.0/24", None),
    ]  # fmt: skip
    assert [r["id"] for r in new["rules"]][len(top) - 1 : -1] == [
        "a",
        "b",
        "c",
        "e",
        "x",
    ]  # the untouched extra is last
    assert "192.168.0.0/16" in new["seeded"] and "192.168.0.0/16" not in [r["cidr"] for r in top]
    assert notes[-1].startswith(f"NOTE {len(top) - 1} block(s) stay at the top of the list, above rule(s) a, b, e, x:")
    # a rule that cannot be read is reported as that rule, not by the overlap check
    with pytest.raises(ValueError, match="rule bad: invalid cidr 'nope'"):
        policy_from_any({"rules": [{"id": "bad", "action": "allow", "cidr": "nope"}]}, BUILTIN, [])
    # a document with neither rules nor old keys: only the seeding is left to do
    p, notes = policy_from_any({"default": "deny"}, BUILTIN, [])
    assert notes == [] and p.rules == [] and p.seeded == [] and len(p.seed_blocks(BUILTIN, [])) == len(BUILTIN)
    assert policy_from_any(None, BUILTIN, [])[0].default == "ask"
    # what cannot be translated raises (the gateway then stops, or the API answers 400): never a half policy
    for bad, error in (
        ({"hard_deny": ["not-a-cidr"]}, "hard_deny: invalid CIDR"),
        ({"floor_open": "10.0.0.0/8"}, "floor_open: expected a list"),
        ({"rules": {"a": 1}}, "rules: expected a list"),
        ({"rules": ["x"]}, "rules: expected a list"),
        ({"rules": [{"action": "deny", "cidr": "nope"}]}, "invalid cidr"),
        ({"seeded": [], "hard_deny": [], "bogus": 1}, "unknown policy keys"),
        ([1], "expected a mapping"),
    ):
        with pytest.raises(ValueError, match=error):
            policy_from_any(bad, BUILTIN, [])
    # a hand-edited file that has both `seeded` and an old key keeps what it remembers
    new, _ = migrate({"seeded": ["10.0.0.0/8"], "floor_open": ["192.168.0.0/16"]}, BUILTIN, [])
    assert new["seeded"] == ["10.0.0.0/8", "192.168.0.0/16"]


def test_policy_documents_are_strict():
    for bad, error in (
        ({"hard_deny": []}, "unknown policy keys"),  # an old key reaches from_dict only by a bug: refused
        ({"floor_open": []}, "unknown policy keys"),
        ({"seeded": ["x"]}, "seeded: invalid CIDR"),
        ({"rules": "x"}, "rules: expected a list"),
        ("x", "expected a mapping"),
    ):
        with pytest.raises(ValueError, match=error):
            Policy.from_dict(bad)
    p = Policy.from_dict({"seeded": ["10.0.0.1/8"], "rules": [{"id": "a", "action": "deny", "cidr": "10.0.0.1/8"}]})
    assert p.seeded == ["10.0.0.0/8"] and p.rules[0].cidr == "10.0.0.0/8"  # one spelling per range
    assert p.to_dict() == {
        "default": "ask", "ask_timeout": 60, "seeded": ["10.0.0.0/8"],
        "rules": [{"id": "a", "action": "deny", "cidr": "10.0.0.0/8"}],
    }  # fmt: skip
