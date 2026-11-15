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
    is_pre_0019,
    migrate,
    policy_from_any,
    ports_within,
)

BUILTIN = builtin_blocks()
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
    ("... also when it is reached by a name", [allow("dev", cidr="192.168.1.10/32", port=8123)], "ask",
     "ha.lan", 8123, ["192.168.1.10"], "allow", "dev"),
    ("... but not on another port", [allow("dev", cidr="192.168.1.10/32", port=8123)], "ask",
     "192.168.1.10", 22, ["192.168.1.10"], "deny", LAN16),
    ("... and not its neighbour", [allow("dev", cidr="192.168.1.10/32", port=8123)], "ask",
     "192.168.1.11", 8123, ["192.168.1.11"], "deny", LAN16),
    ("an address ask is final too", [ask("dev", cidr="192.168.1.10/32")], "deny",
     "192.168.1.10", 80, ["192.168.1.10"], "ask", "dev"),
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
    # --- name rules: deny is final, allow is not above an address rule
    ("name deny is final", [deny("bad", host="*.evil.example"), allow("a", cidr=PUBLIC + "/32")], "allow",
     "x.evil.example", 443, [PUBLIC], "deny", "bad"),
    ("an address allow above a name deny is the first match", [allow("a", cidr=PUBLIC + "/32"), deny("bad", host="*.evil.example")], "deny",
     "x.evil.example", 443, [PUBLIC], "allow", "a"),
    ("an address deny above a name allow is the first match", [deny("b", cidr=PUBLIC + "/32"), allow("n", host="ok.example")], "allow",
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
    assert (d.action, d.rule_id, d.shadow) == ("allow", "dev", None)
    # an ask rule is "matched", an IP literal has "the address"
    d = policy([ask("n", host="nas.example")]).evaluate("nas.example", 443, ["192.168.1.10"])
    assert d.reason.startswith("name matched by rule n, but it resolves to 192.168.1.10, inside blocked range")
    d = policy([allow("any", host="*")]).evaluate("192.168.1.1", 443, ["192.168.1.1"])
    assert d.reason.startswith("name allowed by rule any, but the address 192.168.1.1 is inside blocked range")
    # nothing is shadowed when a rule simply decides
    assert policy([allow("n", host="nas.example")]).evaluate("nas.example", 443, [PUBLIC]).shadow is None
    assert policy().evaluate("x.example", 443, ["192.168.1.10"]).shadow is None  # no name rule: just the block


def test_below_a_name_rule_only_an_address_deny_counts():
    """The ADR's wording, literally: below a provisional name rule the walk looks only at address `deny`
    rules. An allow for the address that stands BELOW the name rule does not help - and the reason says to
    move it, instead of telling the operator to add what is already there."""
    rules = [allow("n", host="nas.example"), allow("dev", cidr="192.168.1.10/32")]
    d = policy(rules).evaluate("nas.example", 443, ["192.168.1.10"])
    assert d.action == "deny" and d.rule_id == LAN16 and d.shadow["rule"] == "n"
    assert d.reason.endswith("the allow for the address (rule dev) stands below rule n: move it above")
    # by IP literal the same list allows the address (the name rule does not match a literal)
    assert policy(rules).evaluate("192.168.1.10", 443, ["192.168.1.10"]).rule_id == "dev"
    # moved above the name rule it is the first match for the name's address too
    p = policy(rules)
    assert p.move_rule("dev", "n")
    assert p.evaluate("nas.example", 443, ["192.168.1.10"]).rule_id == "dev"
    # an address ask below the name rule does not turn an allowed name into a question either
    d = policy([allow("n", host="x.example"), ask("q", cidr=PUBLIC + "/32")]).evaluate("x.example", 443, [PUBLIC])
    assert (d.action, d.rule_id) == ("allow", "n")


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
def test_name_first_short_cuts_only_where_no_address_can_change_the_result():
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
    # an address allow ABOVE what decides could be the first match for an address: the name alone cannot say
    p.add_rule(Rule(action="allow", cidr="140.82.112.3/32", port=443, id="ip"))
    for name in ("x.evil.example", "new.example", "q.example"):
        d = p.evaluate_name(name, 443)
        assert not d.early, name
        assert p.evaluate(name, 443, ["140.82.112.3"]).rule_id == "ip"  # ... and indeed it decides
    # only for the ports that rule has
    assert p.evaluate_name("x.evil.example", 8443).early and p.evaluate_name("new.example", 8443).early
    # BELOW a name deny it changes nothing: the name rule is the first match for every address
    p = policy([deny("bad", host="*.evil.example"), allow("ip", cidr="140.82.112.3/32")], "deny")
    assert p.evaluate_name("x.evil.example", 443).early
    assert not p.evaluate_name("other.example", 443).early  # the default is below it
    # an address ask above: a deny could become a question (no short cut), a question stays one (short cut)
    p = policy([ask("ipq", cidr="140.82.112.3/32"), deny("bad", host="bad.example")], "ask")
    assert not p.evaluate_name("bad.example", 443).early
    assert p.evaluate_name("new.example", 443).early
    # an expired address allow is no rule
    p = policy([{**allow("old", cidr="140.82.112.3/32"), "expires": time.time() - 1}], "deny")
    assert p.evaluate_name("new.example", 443).early


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
    """The other direction, so that the proof above is not satisfied by never short-cutting: without an
    address allow/ask rule for the port, a name the list denies or asks about is ALWAYS decided early."""
    rng = random.Random(19)  # noqa: S311
    for _ in range(1500):
        p = _random_policy(rng)
        now = time.time()
        for port in (443, 22):
            live = [r for r in p.rules if r.cidr and not r.expired(now) and (r.port == "*" or port == 443)]
            if any(r.action != "deny" for r in live):
                continue
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
            deny("late", cidr="192.168.1.30/32"),  # inside `lan`, a deny: still blocks for a name rule above
            deny("cam2", cidr="192.168.1.10/32", port=443),  # covered by `cam`, a deny
            allow("web", cidr="192.168.1.0/25", port=[80, 443]),  # inside `lan`
            allow("other", cidr="192.168.2.0/24"),
            allow("n", host="192.168.1.20"),  # a name rule is never "covered"
            {**allow("tmp", cidr="10.0.0.0/8"), "expires": time.time() + 60},
            allow("ten", cidr="10.1.0.0/16"),  # `tmp` ends by itself: not covered for good
            allow("v6", cidr="fd00::/8"),
        ]
    )
    covered = {r.id: (c.id if (c := p.covered_by(r)) else None) for r in p.rules if r.source == "user"}
    assert covered == {
        "cam": None, "lan": None, "dup": "lan", "late": None, "cam2": "cam", "web": "lan", "other": None,
        "n": None, "tmp": None, "ten": None, "v6": None,
    }  # fmt: skip
    # the claim is true: a covered rule decides for no address, by literal or behind a name rule
    q = policy([allow("name", host="*"), *[r.to_dict() for r in p.rules if r.source == "user"]])
    for rid in ("dup", "cam2", "web"):
        for ip in ("192.168.1.10", "192.168.1.20", "192.168.1.30", "192.168.1.100", "192.168.1.200"):
            for port in (80, 443, 22):
                assert p.evaluate(ip, port, []).rule_id != rid
                assert q.evaluate("x.example", port, [ip]).rule_id != rid
    assert q.evaluate("x.example", 22, ["192.168.1.30"]).rule_id == "late"  # ... and `late` is not covered
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
    # CIDR deny rules first, in their order; then the other rules in theirs; then the hard_deny extras
    assert [r["id"] for r in new["rules"]] == ["d1", "d2", "gh", "ip", "ip2", "nd", block_id("203.0.113.7/32")]
    extra = new["rules"][-1]
    assert extra == {
        "id": block_id("203.0.113.7/32"),
        "action": "deny",
        "cidr": "203.0.113.7/32",
        "note": "was hard_deny",
    }
    # floor_open: the operator had opened 192.168/16 - remembered as seeded, so no block is added for it.
    # 10/8 was an "extra" that is built in anyway; 198.51.100.0/24 is built in and was opened too.
    assert new["seeded"] == ["192.168.0.0/16", "198.51.100.0/24"]
    p, _ = policy_from_any(OLD, BUILTIN, ["198.18.5.0/24"])
    added = p.seed_blocks(BUILTIN, ["198.18.5.0/24"])
    assert [r.id for r in p.rules][:7] == ["d1", "d2", "gh", "ip", "ip2", "nd", block_id("203.0.113.7/32")]
    assert {r.cidr for r in added} == (set(BUILTIN) | {"198.18.5.0/24"}) - {"192.168.0.0/16", "198.51.100.0/24"}
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
    # an address allow inside a range that stays blocked did nothing before and decides now: named in the log
    assert "NOTE rule ip2 (allow 10.0.0.5/32) had no effect inside the blocked range 10.0.0.0/8" in text
    assert "rule ip " not in text  # 192.168/16 was open: that rule already worked
    assert p.evaluate("10.0.0.5", 22, []).rule_id == "ip2"
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
