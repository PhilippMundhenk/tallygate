"""ADR-0019, amendment: "Nothing that was blocked opens by upgrading" - checked against the old evaluator.

A small reference of the evaluation before ADR-0019 (origin/main: the hard-deny floor first, CIDR deny rules
anywhere, then the rules in order with CIDR allow/ask for IP literals only, then the default) decides many
generated pre-0019 policy documents for many destinations. The same document, migrated and seeded as a gateway
does at its start, must never decide LESS restrictively (allow < ask < deny). More restrictive is allowed: the
migration may close, it must not open.

The generator covers rules that expired and rules with a time limit still running, IPv4 and IPv6 ranges, the
IPv6 forms that carry an IPv4 address (IPv4-mapped, NAT64, 6to4, IPv4-compatible) as destinations, and the
exception of a service port's fixed target (reverse mode)."""

import functools
import ipaddress
import random
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "gateway"))

from egressgw.policy import (
    RANK,
    Exception_,
    builtin_blocks,
    host_matches,
    ip_addr,
    is_ip,
    policy_from_any,
    port_matches,
)

BUILTIN = builtin_blocks()
NOW = time.time()


# ---------------------------------------------------------------- the old evaluator (origin/main), as a reference
@functools.cache
def _net(cidr: str):
    return ipaddress.ip_network(cidr, strict=False)


def _old_matches(rule: dict, host: str, port: int, addrs: list) -> bool:
    if not port_matches(rule.get("port", "*"), port):
        return False
    if rule.get("host"):
        return host_matches(rule["host"], host)
    net = _net(rule["cidr"])
    inside = [a.version == net.version and a in net for a in addrs]
    return bool(inside) and (all(inside) if rule["action"] == "allow" else any(inside))


def old_evaluate(doc: dict, floor: list[str], host: str, port: int, ips: list[str], excepted: bool = False) -> str:
    """What a pre-0019 gateway decided for this document (its `Policy.evaluate`), as an action. `excepted`:
    the destination is the fixed target of a service port with `allow_private`, reached through that port
    (reverse mode) - the old gateway then skipped the whole hard-deny floor for it, and nothing else."""
    literal = is_ip(host)
    addrs = [ip_addr(i) for i in ([*ips, host.strip("[]")] if literal else ips)]
    # 1. the hard-deny floor (built-in + config) and the policy's extras, minus the ranges opened by exact string
    opened = {str(_net(c)) for c in doc.get("floor_open") or []}
    extras = [str(_net(c)) for c in doc.get("hard_deny") or []]
    for cidr in [*floor, *[c for c in extras if c not in floor]]:
        net = _net(cidr)
        if not excepted and cidr not in opened and any(a.version == net.version and a in net for a in addrs):
            return "deny"
    rules = [r for r in doc.get("rules") or [] if not ("expires" in r and r["expires"] <= NOW)]
    # 2. a CIDR deny narrows whatever allowed the destination, wherever it stands in the list (#119)
    for r in rules:
        if r.get("cidr") and r["action"] == "deny" and _old_matches(r, host, port, addrs):
            return "deny"
    # 3. the rules, first match wins; CIDR allow/ask rules apply to IP literals only
    for r in rules:
        if r.get("cidr") and not literal:
            continue
        if _old_matches(r, host, port, addrs):
            return r["action"]
    return doc.get("default", "ask")


def new_evaluate(doc: dict, config: list[str], host: str, port: int, ips: list[str]) -> str:
    """What the gateway decides after the upgrade: the document migrated, the missing blocks seeded."""
    p, _notes = policy_from_any(doc, BUILTIN, config)
    p.seed_blocks(BUILTIN, config)
    return p.evaluate(host, port, ips).action


# ---------------------------------------------------------------- generated documents and destinations
NETS = [
    "0.0.0.0/0", "::/0",  # everything
    "10.0.0.0/8", "192.168.0.0/16", "127.0.0.0/8",  # exactly a built-in block
    "192.168.1.0/24", "192.168.1.10/32", "10.0.0.5/32", "169.254.169.254/32", "fd00::/8",  # inside one
    "10.0.0.0/7", "192.0.0.0/8", "128.0.0.0/1",  # overlapping: partly blocked, partly public
    "8.8.8.0/24", "8.8.8.8/32", "9.9.9.9/32", "9.9.9.0/24", "140.82.112.0/20", "2001:4860::/32",  # public
    "::/96", "64:ff9b::/96", "2002::/16", "64:ff9b::a00:5/128", "fd00::1/128", "2000::/3",  # IPv6, embedded IPv4
]  # fmt: skip
HOSTS = ["a.example", "*.example", "b.test", "*.b.test", "*", "8.8.8.8", "192.168.*"]
PORTS = [443, 80, [80, 443], "400-500", "*"]
EXTRAS = ["9.9.9.0/24", "140.82.112.0/20", "8.8.8.8/32", "192.168.1.0/24", "10.0.0.0/8", "2001:4860::/32", "0.0.0.0/0"]
OPENABLE = ["192.168.0.0/16", "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "fc00::/7", "9.9.9.0/24",
            "192.168.1.0/24", "140.82.112.0/20", "64:ff9b::/96", "::/96", "2002::/16"]  # fmt: skip
CONFIGS = [[], ["9.9.9.0/24"], ["140.82.112.0/20", "198.18.7.0/24"]]

PUBLIC = ["8.8.8.8", "8.8.8.9", "9.9.9.9", "140.82.112.3", "1.1.1.1", "2001:4860::1", "::ffff:8.8.8.8"]
PRIVATE = ["192.168.1.10", "192.168.1.20", "192.168.2.1", "10.0.0.5", "10.9.9.9", "11.0.0.1", "127.0.0.1",
           "169.254.169.254", "fd00::1", "::1", "::ffff:10.0.0.5"]  # fmt: skip
# IPv6 forms that carry an IPv4 address (a blocked one, a public one), and other special IPv6 addresses
EMBEDDED = ["64:ff9b::a00:5", "64:ff9b:1::a00:5", "2002:a00:5::1", "::10.0.0.5", "::ffff:0:10.0.0.5",
            "64:ff9b::808:808", "2002:808:808::1", "fe80::1", "2001:db8::1"]  # fmt: skip
NAMES = ["a.example", "x.example", "b.test", "y.b.test", "other.org"]
ADDRESS_SETS = (
    [[a] for a in [*PUBLIC, *PRIVATE, *EMBEDDED]]
    + [[a, b] for a in PUBLIC[:4] for b in PRIVATE[:5]]  # mixed: a public and a blocked address
    + [[b, a] for a in PUBLIC[:2] for b in PRIVATE[:3]]
    + [[a, b] for a in PUBLIC[:2] for b in EMBEDDED[:5]]
    + [PUBLIC[:2], PUBLIC[2:4], PRIVATE[:2]]
)
BY_NAME = [(n, ips) for n in NAMES for ips in ADDRESS_SETS]
LITERALS = [(a, []) for a in [*PUBLIC, *PRIVATE, *EMBEDDED]] + [
    ("[fd00::1]", []),
    ("[2001:4860::1]", []),
    ("[64:ff9b::a00:5]", []),
    ("[::ffff:10.0.0.5]", []),
]
DESTINATIONS = [*BY_NAME, *LITERALS]


def random_document(rng: random.Random) -> tuple[dict, list[str]]:
    """A pre-0019 policy document (no `seeded`) and the `never` ranges of the gateway config."""
    rules = []
    for i in range(rng.randint(0, 6)):
        r = {"id": f"r{i}", "action": rng.choice(["allow", "deny", "ask"])}
        if rng.random() < 0.6:
            r["cidr"] = rng.choice(NETS)
        else:
            r["host"] = rng.choice(HOSTS)
        if rng.random() < 0.35:
            r["port"] = rng.choice(PORTS)
        x = rng.random()
        if x < 0.08:
            r["expires"] = round(NOW - 60)  # an expired rule is no rule, before and after
        elif x < 0.25:
            r["expires"] = round(NOW + 3600)  # a time limit that is still running: a rule like any other
        rules.append(r)
    doc = {"default": rng.choice(["allow", "deny", "ask"]), "rules": rules}
    if rng.random() < 0.5:
        doc["hard_deny"] = rng.sample(EXTRAS, rng.randint(0, 3))
    if rng.random() < 0.5:
        doc["floor_open"] = rng.sample(OPENABLE, rng.randint(0, 3))
    if rng.random() < 0.1:
        doc["hard_deny_floor"] = ["echoed by an old UI"]
    return doc, rng.choice(CONFIGS)


def less_restrictive(
    doc: dict, config: list[str], dests=DESTINATIONS, ports=(443, 80, 22), reverse: bool = False
) -> list[tuple]:
    """Destinations the migrated policy decides less restrictively than the old one: (host, port, ips, old, new).
    With `reverse` every destination is tried as the fixed target of a service port with `allow_private` on
    443, through that port: the exception from the blocks applies to it on 443 and on no other port."""
    floor = [*dict.fromkeys([*BUILTIN, *config])]
    p, _notes = policy_from_any(doc, BUILTIN, config)
    p.seed_blocks(BUILTIN, config)
    found = []
    for host, ips in dests:
        if reverse:
            host = host.strip("[]")  # a service target is configured without brackets
            p.exceptions = [Exception_(host=host, port=443)]
        for port in ports:
            old = old_evaluate(doc, floor, host, port, ips, excepted=reverse and port == 443)
            new = p.evaluate(host, port, ips, "reverse" if reverse else None).action
            if RANK[new] < RANK[old]:
                found.append((host, port, ips, old, new))
    return found


def minimised(doc: dict, config: list[str], case: tuple, reverse: bool = False) -> dict:
    """The same counterexample with every rule and key removed that it does not need."""
    host, port, ips, _old, _new = case
    still = lambda d: bool(less_restrictive(d, config, [(host, ips)], (port,), reverse))  # noqa: E731
    changed = True
    while changed:
        changed = False
        for i in range(len(doc["rules"])):
            smaller = {**doc, "rules": doc["rules"][:i] + doc["rules"][i + 1 :]}
            if still(smaller):
                doc, changed = smaller, True
                break
        for key in ("hard_deny", "floor_open", "hard_deny_floor"):
            if key in doc and still({k: v for k, v in doc.items() if k != key}):
                doc, changed = {k: v for k, v in doc.items() if k != key}, True
    return doc


def test_the_reference_is_the_old_evaluator():
    """The reference itself, on the cases the old tests held (tests/unit/test_policy.py on origin/main)."""
    floor = BUILTIN
    doc = {"default": "deny", "rules": [{"id": "c", "action": "allow", "cidr": "140.82.112.0/20"}]}
    assert old_evaluate(doc, floor, "140.82.112.3", 443, ["140.82.112.3"]) == "allow"
    assert old_evaluate(doc, floor, "github.com", 443, ["140.82.112.3"]) == "deny"  # a name is never allowed by its IPs
    doc = {"default": "allow", "rules": [{"id": "d", "action": "deny", "cidr": "140.82.112.0/20"}]}
    assert old_evaluate(doc, floor, "github.com", 443, ["8.8.8.8", "140.82.112.3"]) == "deny"  # CIDR deny: any IP
    doc = {
        "default": "ask",
        "rules": [{"id": "a", "action": "allow", "host": "*"}, {"id": "d", "action": "deny", "cidr": "8.8.8.0/24"}],
    }
    assert old_evaluate(doc, floor, "x.example", 443, ["8.8.8.8"]) == "deny"  # ... wherever it stands (#119)
    assert old_evaluate(doc, floor, "x.example", 443, ["192.168.1.1"]) == "deny"  # the floor, before every rule
    assert old_evaluate({**doc, "floor_open": ["192.168.0.0/16"]}, floor, "x.example", 443, ["192.168.1.1"]) == "allow"
    assert old_evaluate({**doc, "floor_open": ["192.168.1.0/24"]}, floor, "x.example", 443, ["192.168.1.1"]) == "deny"
    assert old_evaluate({**doc, "hard_deny": ["9.9.9.0/24"]}, floor, "9.9.9.9", 443, []) == "deny"
    assert old_evaluate(doc, [*floor, "9.9.9.0/24"], "x.example", 443, ["9.9.9.9"]) == "deny"  # `never` of the config
    assert old_evaluate(doc, floor, "x.example", 443, ["1.1.1.1"]) == "allow"
    assert old_evaluate({"default": "ask"}, floor, "x.example", 443, ["1.1.1.1"]) == "ask"


@pytest.mark.parametrize("seed", [208, 211, 20261117])
def test_a_migrated_policy_is_never_less_restrictive_than_the_old_one(seed):
    """250 documents per seed; each with every IP literal and 20 of the names-with-addresses, on three ports.
    Every fourth document is checked through a service port (reverse mode) with the destination as its fixed,
    excepted target."""
    rng = random.Random(seed)  # noqa: S311 - a reproducible test sequence
    worst, checked, opened, reversed_ = None, 0, 0, 0
    for i in range(250):
        doc, config = random_document(rng)
        dests = [*LITERALS, *rng.sample(BY_NAME, 20)]
        reverse = i % 4 == 3
        reversed_ += reverse
        found = less_restrictive(doc, config, dests, reverse=reverse)
        checked += len(dests) * 3
        if found:
            opened += 1
            small = minimised(doc, config, found[0], reverse)
            if worst is None or len(small["rules"]) < len(worst[0]["rules"]):
                worst = (small, config, found[0], reverse)
    assert checked > 38_000 and reversed_ == 62
    assert worst is None, (
        f"{opened} of 250 documents decide less restrictively after the migration. The smallest: document "
        f"{worst[0]} with never={worst[1]}: (host, port, addresses, old, new) = {worst[2]}, reverse mode: {worst[3]}"
    )


def test_the_generator_reaches_what_it_claims_to_cover():
    """Time limits still running, IPv6 ranges, embedded addresses: present in the documents and destinations."""
    rng = random.Random(208)  # noqa: S311
    docs = [random_document(rng)[0] for _ in range(300)]
    rules = [r for d in docs for r in d["rules"]]
    assert (
        sum(r.get("expires", 0) > NOW for r in rules) > 50 and sum(0 < r.get("expires", 0) <= NOW for r in rules) > 20
    )
    assert sum(":" in r.get("cidr", "") for r in rules) > 100
    hosts = {h for h, _ in LITERALS} | {ip for _, ips in BY_NAME for ip in ips}
    assert {"64:ff9b::a00:5", "64:ff9b:1::a00:5", "2002:a00:5::1", "::10.0.0.5", "::ffff:10.0.0.5"} <= hosts


def test_the_reference_knows_the_exception_of_a_service_port():
    """Reverse mode in the old gateway: the fixed target of a service port skipped the hard-deny floor - and
    only that. After the migration the exception skips the seeded blocks - and only those."""
    doc = {"default": "allow", "rules": []}
    assert old_evaluate(doc, BUILTIN, "192.168.1.10", 5432, []) == "deny"
    assert old_evaluate(doc, BUILTIN, "192.168.1.10", 5432, [], excepted=True) == "allow"
    denied = {"default": "allow", "rules": [{"id": "d", "action": "deny", "cidr": "192.168.1.0/24"}]}
    assert old_evaluate(denied, BUILTIN, "192.168.1.10", 5432, [], excepted=True) == "deny"  # a rule is no floor
    for d in (doc, denied):
        assert less_restrictive(d, [], [("192.168.1.10", []), ("db.example", ["192.168.1.10"])], reverse=True) == []
    # an old `hard_deny` extra was part of the floor and skipped by the exception; migrated it is a deny rule of
    # yours, which the exception does not skip: stricter, never looser
    extra = {"default": "allow", "hard_deny": ["9.9.9.0/24"], "rules": []}
    assert old_evaluate(extra, BUILTIN, "9.9.9.9", 443, [], excepted=True) == "allow"
    assert less_restrictive(extra, [], [("9.9.9.9", [])], (443,), reverse=True) == []


def test_the_differential_test_notices_a_migration_that_opens():
    """The check has teeth: seeding every block at the bottom (what the first implementation did) is caught."""
    doc = {"default": "deny", "rules": [{"id": "ip", "action": "allow", "cidr": "10.0.0.5/32"}]}
    assert less_restrictive(doc, []) == []  # as migrated now: the block stays above the old, inert rule
    assert old_evaluate(doc, BUILTIN, "10.0.0.5", 443, []) == "deny"
    p, _ = policy_from_any({**doc, "seeded": []}, BUILTIN, [])  # read as a current document: no migration
    p.seed_blocks(BUILTIN, [])
    assert p.evaluate("10.0.0.5", 443, []).action == "allow"
