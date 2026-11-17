"""ADR-0019, amendment: "Nothing that was blocked opens by upgrading" - checked against the old evaluator.

A small reference of the evaluation before ADR-0019 (origin/main: the hard-deny floor first, CIDR deny rules
anywhere, then the rules in order with CIDR allow/ask for IP literals only, then the default) decides many
generated pre-0019 policy documents for many destinations. The same document, migrated and seeded as a gateway
does at its start, must never decide LESS restrictively (allow < ask < deny). More restrictive is allowed: the
migration may close, it must not open."""

import functools
import ipaddress
import random
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "gateway"))

from egressgw.policy import RANK, builtin_blocks, host_matches, ip_addr, is_ip, policy_from_any, port_matches

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


def old_evaluate(doc: dict, floor: list[str], host: str, port: int, ips: list[str]) -> str:
    """What a pre-0019 gateway decided for this document (its `Policy.evaluate`), as an action."""
    literal = is_ip(host)
    addrs = [ip_addr(i) for i in ([*ips, host.strip("[]")] if literal else ips)]
    # 1. the hard-deny floor (built-in + config) and the policy's extras, minus the ranges opened by exact string
    opened = {str(_net(c)) for c in doc.get("floor_open") or []}
    extras = [str(_net(c)) for c in doc.get("hard_deny") or []]
    for cidr in [*floor, *[c for c in extras if c not in floor]]:
        net = _net(cidr)
        if cidr not in opened and any(a.version == net.version and a in net for a in addrs):
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
]  # fmt: skip
HOSTS = ["a.example", "*.example", "b.test", "*.b.test", "*", "8.8.8.8", "192.168.*"]
PORTS = [443, 80, [80, 443], "400-500", "*"]
EXTRAS = ["9.9.9.0/24", "140.82.112.0/20", "8.8.8.8/32", "192.168.1.0/24", "10.0.0.0/8", "2001:4860::/32", "0.0.0.0/0"]
OPENABLE = ["192.168.0.0/16", "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "fc00::/7", "9.9.9.0/24",
            "192.168.1.0/24", "140.82.112.0/20"]  # fmt: skip
CONFIGS = [[], ["9.9.9.0/24"], ["140.82.112.0/20", "198.18.7.0/24"]]

PUBLIC = ["8.8.8.8", "8.8.8.9", "9.9.9.9", "140.82.112.3", "1.1.1.1", "2001:4860::1"]
PRIVATE = ["192.168.1.10", "192.168.1.20", "192.168.2.1", "10.0.0.5", "10.9.9.9", "11.0.0.1", "127.0.0.1",
           "169.254.169.254", "fd00::1", "::1", "::ffff:10.0.0.5"]  # fmt: skip
NAMES = ["a.example", "x.example", "b.test", "y.b.test", "other.org"]
ADDRESS_SETS = (
    [[a] for a in [*PUBLIC, *PRIVATE]]
    + [[a, b] for a in PUBLIC[:4] for b in PRIVATE[:5]]  # mixed: a public and a blocked address
    + [[b, a] for a in PUBLIC[:2] for b in PRIVATE[:3]]
    + [PUBLIC[:2], PUBLIC[2:4], PRIVATE[:2]]
)
BY_NAME = [(n, ips) for n in NAMES for ips in ADDRESS_SETS]
LITERALS = [(a, []) for a in [*PUBLIC, *PRIVATE]] + [("[fd00::1]", []), ("[2001:4860::1]", [])]
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
        if rng.random() < 0.08:
            r["expires"] = round(NOW - 60)  # an expired rule is no rule, before and after
        rules.append(r)
    doc = {"default": rng.choice(["allow", "deny", "ask"]), "rules": rules}
    if rng.random() < 0.5:
        doc["hard_deny"] = rng.sample(EXTRAS, rng.randint(0, 3))
    if rng.random() < 0.5:
        doc["floor_open"] = rng.sample(OPENABLE, rng.randint(0, 3))
    if rng.random() < 0.1:
        doc["hard_deny_floor"] = ["echoed by an old UI"]
    return doc, rng.choice(CONFIGS)


def less_restrictive(doc: dict, config: list[str], dests=DESTINATIONS, ports=(443, 80, 22)) -> list[tuple]:
    """Destinations the migrated policy decides less restrictively than the old one: (host, port, ips, old, new)."""
    floor = [*dict.fromkeys([*BUILTIN, *config])]
    p, _notes = policy_from_any(doc, BUILTIN, config)
    p.seed_blocks(BUILTIN, config)
    found = []
    for host, ips in dests:
        for port in ports:
            old, new = old_evaluate(doc, floor, host, port, ips), p.evaluate(host, port, ips).action
            if RANK[new] < RANK[old]:
                found.append((host, port, ips, old, new))
    return found


def minimised(doc: dict, config: list[str], case: tuple) -> dict:
    """The same counterexample with every rule and key removed that it does not need."""
    host, port, ips, _old, _new = case
    still = lambda d: bool(less_restrictive(d, config, [(host, ips)], (port,)))  # noqa: E731
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
    """300 documents per seed; each with every IP literal and 25 of the names-with-addresses, on three ports."""
    rng = random.Random(seed)  # noqa: S311 - a reproducible test sequence
    worst, checked, opened = None, 0, 0
    for _ in range(300):
        doc, config = random_document(rng)
        dests = [*LITERALS, *rng.sample(BY_NAME, 25)]
        found = less_restrictive(doc, config, dests)
        checked += len(dests) * 3
        if found:
            opened += 1
            small = minimised(doc, config, found[0])
            if worst is None or len(small["rules"]) < len(worst[0]["rules"]):
                worst = (small, config, found[0])
    assert checked > 30_000
    assert worst is None, (
        f"{opened} of 300 documents decide less restrictively after the migration. The smallest: document "
        f"{worst[0]} with never={worst[1]}: (host, port, addresses, old, new) = {worst[2]}"
    )


def test_the_differential_test_notices_a_migration_that_opens():
    """The check has teeth: seeding every block at the bottom (what the first implementation did) is caught."""
    doc = {"default": "deny", "rules": [{"id": "ip", "action": "allow", "cidr": "10.0.0.5/32"}]}
    assert less_restrictive(doc, []) == []  # as migrated now: the block stays above the old, inert rule
    assert old_evaluate(doc, BUILTIN, "10.0.0.5", 443, []) == "deny"
    p, _ = policy_from_any({**doc, "seeded": []}, BUILTIN, [])  # read as a current document: no migration
    p.seed_blocks(BUILTIN, [])
    assert p.evaluate("10.0.0.5", 443, []).action == "allow"
