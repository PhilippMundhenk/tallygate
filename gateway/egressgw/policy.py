"""Policy engine: pure logic, no I/O besides YAML load/save.

One ordered rule list, first match wins (ADR-0019). For a connection to (host, port) resolving to ips, the
list is walked top to bottom for EACH address, and the connection gets the most restrictive result over all
addresses (deny > ask > allow):

  0. locked ranges (the stack's own networks and the gateway's own listeners): deny, before the list and
     whatever the list says.
  1. an address rule (IP or CIDR) that contains the address (and matches the port) is final: allow, ask, deny.
  2. a name rule (host pattern) that matches the name (and the port): `deny` is final; `allow` / `ask` is
     provisional - the walk continues below it, looking only at address rules with `deny`. If one matches,
     the result is `deny` (a name can never open a blocked range: names are chosen by whoever controls DNS).
  3. nothing matched: the default action (allow | deny | ask).

The built-in blocks (private, loopback, link-local/metadata, ... ranges) and the `never` entries of the gateway
config are ordinary `deny` rules, seeded once at the bottom of the list (`source: builtin` / `config`).

Hostnames are first evaluated *without* resolving them (`evaluate_name`), so names the policy denies or still
has to ask about never reach a DNS resolver (no DNS exfiltration). That decision is only acted on where the
result cannot depend on the addresses (`Decision.early`).
"""

from __future__ import annotations

import fnmatch
import functools
import ipaddress
import re
import time
import uuid
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

import yaml

from egressgw.store import atomic_write

ACTIONS = ("allow", "deny", "ask")
RANK = {"allow": 0, "ask": 1, "deny": 2}  # most restrictive wins over the addresses of one destination
LOCKED = "locked"  # Decision.rule_id of a locked range: not a rule, never editable
# Sources of the seeded blocks (ADR-0019): ordinary deny rules, added once at the bottom of the list.
SEEDED_SOURCES = ("builtin", "config")

DEFAULT_HARD_DENY = [
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.88.99.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "::/96",  # unspecified, loopback and deprecated IPv4-compatible addresses
    "::ffff:0:0/96",
    "64:ff9b::/96",  # NAT64: embeds (possibly private) IPv4 addresses
    "64:ff9b:1::/48",
    "100::/64",
    "2001::/32",  # Teredo
    "2001:db8::/32",
    "2002::/16",  # 6to4: embeds IPv4 addresses
    "fc00::/7",
    "fe80::/10",
    "fec0::/10",
    "ff00::/8",
]
# Loopback, link-local/metadata, unspecified and multicast (formerly the grants' own never list). All of them
# are inside DEFAULT_HARD_DENY today; the union is what is seeded, so neither list can lose a range unnoticed.
DEFAULT_NEVER = ["0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "::/96", "fe80::/10", "ff00::/8"]

_LABEL = re.compile(r"(?!-)[a-z0-9_-]{1,63}(?<!-)")


def valid_hostname(host: str) -> bool:
    """Strict DNS name syntax: ASCII letters/digits/'-'/'_', labels 1..63, total <= 253.
    Non-ASCII (IDN) names must arrive as punycode; anything else is refused before it can be
    resolved or shown to a human in an approval prompt."""
    h = host.lower()
    h = h[:-1] if h.endswith(".") else h
    if not h or len(h) > 253 or not h.isascii():
        return False
    return all(_LABEL.fullmatch(label) for label in h.split("."))


@functools.lru_cache(maxsize=1)
def _psl():
    from publicsuffixlist import PublicSuffixList

    return PublicSuffixList()  # bundled snapshot incl. the PRIVATE section (github.io, s3, ngrok, ...)


def ip_addr(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Parsed address; IPv4-mapped IPv6 (::ffff:a.b.c.d) is normalised to IPv4, so a v4 CIDR covers it."""
    addr = ipaddress.ip_address(value.strip("[]"))
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        return addr.ipv4_mapped
    return addr


_PORT = re.compile(r"(\d{1,5})(?:-(\d{1,5}))?")


def valid_port_spec(spec: Any) -> bool:
    """One port item: 443, "443", "8000-8100" or "*"/"any". Rejects None, bools, floats and typos."""
    if spec in ("*", "any") and isinstance(spec, str):
        return True
    if isinstance(spec, int) and not isinstance(spec, bool):
        return 0 < spec < 65536
    m = _PORT.fullmatch(spec) if isinstance(spec, str) else None
    if not m:
        return False
    lo, hi = int(m.group(1)), int(m.group(2) or m.group(1))
    return 0 < lo <= hi < 65536


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip("[]"))
        return True
    except ValueError:
        return False


SCOPES_NEVER = ("all", "all+lan")  # `all+lan` is read from old files and means the same as `all` now


def parse_never(config: dict) -> tuple[list[str], list[str]]:
    """The `never` ranges of the gateway config: (CIDRs, old spellings that were used).

    `never:` lists ranges as "CIDR" or {range, scope}. Since ADR-0019 they are seeded once as ordinary `deny`
    rules at the bottom of the rule list (`source: config`); the scope `all+lan` and the old keys
    `hard_deny_floor` / `grants_never` are still read and mean the same. A broken entry stops the gateway
    (fail closed)."""
    entries = config.get("never") or []
    if isinstance(entries, (str, dict)) or not isinstance(entries, (list, tuple)):
        raise ValueError("never: expected a list of CIDRs or {range, scope} entries")
    cidrs, old = [], []
    for e in entries:
        cidr, scope = (e, "all") if not isinstance(e, dict) else (e.get("range"), e.get("scope", "all"))
        if isinstance(e, dict) and set(e) - {"range", "scope"}:
            raise ValueError(f"never: unknown keys in {e!r} (range, scope)")
        if scope not in SCOPES_NEVER:
            raise ValueError(f"never: scope must be one of {SCOPES_NEVER}, not {scope!r}")
        if scope == "all+lan" and "scope all+lan" not in old:
            old.append("scope all+lan")
        cidrs.append(cidr)
    old += [k for k in ("hard_deny_floor", "grants_never") if config.get(k)]
    # each old key is checked under its own name, so that an error names the key the operator wrote
    cidrs = parse_cidrs(
        [
            *parse_cidrs(cidrs, "never"),
            *parse_cidrs(config.get("hard_deny_floor") or [], "hard_deny_floor"),
            *parse_cidrs(config.get("grants_never") or [], "grants_never"),
        ],
        "never",
    )
    return cidrs, old


def builtin_blocks() -> list[str]:
    """The built-in blocks: DEFAULT_HARD_DENY and DEFAULT_NEVER as one normalised list."""
    return parse_cidrs([*DEFAULT_HARD_DENY, *DEFAULT_NEVER], "built-in blocks")


def parse_cidrs(values, what: str) -> list[str]:
    """Normalised CIDR strings; a clear error naming the setting for anything that is not a network."""
    if isinstance(values, str) or not isinstance(values, (list, tuple)):
        raise ValueError(f"{what}: expected a list of CIDRs")
    out = []
    for c in values:
        try:
            net = str(ipaddress.ip_network(str(c), strict=False))
        except ValueError as e:
            raise ValueError(f"{what}: invalid CIDR {c!r} ({e})") from None
        if net not in out:
            out.append(net)
    return out


def host_matches(pattern: str, host: str) -> bool:
    """'*' = any; '*.example.com' = example.com and all subdomains; else fnmatch (case-insensitive)."""
    pattern = pattern.lower().rstrip(".")
    host = host.lower().rstrip(".")
    if pattern == "*":
        return True
    if pattern.startswith("*."):
        base = pattern[2:]
        if "*" not in base and "?" not in base:
            return host == base or host.endswith("." + base)
    return fnmatch.fnmatchcase(host, pattern)


def port_matches(spec: Any, port: int) -> bool:
    if spec in (None, "*", "any"):
        return True
    if isinstance(spec, int):
        return spec == port
    if isinstance(spec, str):
        if "-" in spec:
            lo, hi = spec.split("-", 1)
            return int(lo) <= port <= int(hi)
        return int(spec) == port
    if isinstance(spec, (list, tuple)):
        return any(port_matches(s, port) for s in spec)
    return False


def port_ranges(spec: Any) -> list[tuple[int, int]]:
    """A (valid) port spec as inclusive ranges; "*" is everything."""
    if spec in (None, "*", "any"):
        return [(1, 65535)]
    if isinstance(spec, (list, tuple)):
        return [r for s in spec for r in port_ranges(s)]
    if isinstance(spec, str) and "-" in spec:
        lo, hi = spec.split("-", 1)
        return [(int(lo), int(hi))]
    return [(int(spec), int(spec))]


def ports_within(inner: Any, outer: Any) -> bool:
    """True if every port of `inner` is also matched by `outer` (each range inside one range of `outer`)."""
    wide = port_ranges(outer)
    return all(any(lo >= a and hi <= b for a, b in wide) for lo, hi in port_ranges(inner))


@functools.lru_cache(maxsize=4096)
def _net(cidr: str):
    return ipaddress.ip_network(cidr, strict=False)


def in_net(addr, net) -> bool:
    return addr.version == net.version and addr in net


def locked_reason(ip: str, port: int, nets, socks) -> str | None:
    """Why ip:port is locked, or None: inside one of the stack's own networks (`nets`, ip_network objects), or
    one of the gateway's own listeners (`socks`, (ip_network, port))."""
    addr = ip_addr(ip)
    for n in nets:
        if in_net(addr, n):
            return f"locked: {ip} belongs to the tallygate stack itself ({n})"
    for n, p in socks:
        if p == port and in_net(addr, n):
            return f"locked: {ip}:{port} is the gateway itself"
    return None


@dataclass
class Rule:
    action: str
    host: str | None = None
    cidr: str | None = None
    port: Any = "*"
    note: str = ""
    expires: float | None = None  # unix ts, None = permanent
    group: str = ""  # optional named set this rule belongs to (#142), for grouping in the UI
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    source: str = "user"  # user | approval | preset:<name> | learning | suggestion | builtin | config

    def validate(self) -> None:
        if self.action not in ACTIONS:
            raise ValueError(f"rule {self.id}: invalid action {self.action!r}")
        if not self.host and not self.cidr:
            raise ValueError(f"rule {self.id}: needs 'host' or 'cidr'")
        if self.host and self.cidr:
            raise ValueError(f"rule {self.id}: use either 'host' or 'cidr', not both")
        if self.cidr:
            try:
                self.cidr = str(ipaddress.ip_network(str(self.cidr), strict=False))  # one spelling per range
            except ValueError as e:
                raise ValueError(f"rule {self.id}: invalid cidr {self.cidr!r} ({e})") from None
        if not isinstance(self.id, str) or not self.id or self.id == LOCKED:
            raise ValueError(f"invalid rule id {self.id!r}")
        items = self.port if isinstance(self.port, (list, tuple)) else [self.port]
        if not items or not all(valid_port_spec(p) for p in items):
            raise ValueError(f'rule {self.id}: invalid port {self.port!r} (use 443, [80, 443], "8000-8100" or "*")')

    def expired(self, now: float | None = None) -> bool:
        return self.expires is not None and (now or time.time()) >= self.expires

    def contains(self, addr) -> bool:
        """An address rule: is this (parsed) address inside its range? Never true for a name rule."""
        return bool(self.cidr) and in_net(addr, _net(self.cidr))

    def names(self, host: str) -> bool:
        """A name rule: does its host pattern match this name? Never true for an address rule."""
        return bool(self.host) and host_matches(self.host, host)

    def to_dict(self) -> dict:
        d = {"id": self.id, "action": self.action}
        if self.host:
            d["host"] = self.host
        if self.cidr:
            d["cidr"] = self.cidr
        if self.port not in (None, "*"):
            d["port"] = self.port
        if self.note:
            d["note"] = self.note
        if self.expires is not None:
            d["expires"] = round(self.expires)
        if self.group:
            d["group"] = self.group
        if self.source != "user":
            d["source"] = self.source
        return d

    @classmethod
    def from_dict(cls, d: dict) -> Rule:
        known = {"action", "host", "cidr", "port", "note", "expires", "group", "id", "source"}
        unknown = set(d) - known
        if unknown:
            raise ValueError(f"unknown rule keys: {sorted(unknown)}")
        r = cls(**{k: v for k, v in d.items() if k in known})
        r.validate()  # an explicit null port is rejected: it used to mean "all ports"
        return r


@dataclass
class Decision:
    action: str  # allow | deny | ask
    reason: str
    rule_id: str | None = None
    # Set when a name rule allowed (or asked about) the name but an address `deny` rule below it blocked the
    # address: {"rule": the name rule, "address", "by": the blocking rule, "range"} (ADR-0019).
    shadow: dict | None = None
    # Only for `evaluate_name`: True if this result may be acted on before the name is resolved, because no
    # address can change what finally happens to the connection.
    early: bool = False


@dataclass
class Exception_:
    """Exception from the seeded blocks for one service port's fixed target (reverse mode only)."""

    host: str
    port: int


def _why(r: Rule) -> str:
    return f"rule {r.id}" + (f" ({r.note})" if r.note else "")


class Policy:
    def __init__(self) -> None:
        self.default = "ask"
        self.ask_timeout = 60
        self.rules: list[Rule] = []
        # The built-in and config blocks that were seeded as rules once (ADR-0019), by CIDR. A range in this
        # list is not seeded again, so a block the operator deleted stays deleted across restarts.
        self.seeded: list[str] = []
        # Locked, attached by the Gateway and never part of the stored policy: the stack's own networks
        # (ip_network objects) and the gateway's own listeners as (ip_network, port). Denied before the list.
        self.locked_nets: list = []
        self.locked_socks: list = []
        self.exceptions: list[Exception_] = []

    # ---------- evaluation ----------
    def locked(self, ip: str, port: int) -> str | None:
        """Why this address is locked (the stack itself), or None. Checked before the rule list, always."""
        return locked_reason(ip, port, self.locked_nets, self.locked_socks)

    def blocked_by(self, ip: str, port: int, now: float | None = None) -> Rule | None:
        """The first address `deny` rule that contains this address: what blocks an address that only a name
        rule (or a grant target that is only a name) stands for."""
        now, addr = now or time.time(), ip_addr(ip)
        for r in self.rules:
            if r.cidr and r.action == "deny" and not r.expired(now) and port_matches(r.port, port) and r.contains(addr):
                return r
        return None

    def evaluate_name(self, host: str, port: int) -> Decision:
        """What the list says about the *name* alone, before any DNS lookup: the first matching name rule,
        else the default. Address rules cannot be checked yet, so the result is provisional.

        `early` says whether it may be acted on without resolving the name (ADR-0011, ADR-0019):
          * `deny` is early if no address `allow`/`ask` rule for this port stands above what decided: then
            every address ends in `deny` as well (an address rule above is `deny`, the name rule is final).
          * `ask` is early if no address `allow` rule for this port stands above what decided: then no address
            can allow the connection without you, and after your answer the addresses are still checked.
          * `allow` is never early: the name is resolved and `evaluate` decides."""
        now = time.time()
        name = host.lower().rstrip(".")
        opened = asked = False  # an address allow / ask rule for this port seen so far
        for r in self.rules:
            if r.expired(now) or not port_matches(r.port, port):
                continue
            if r.cidr:
                opened = opened or r.action == "allow"
                asked = asked or r.action == "ask"
            elif r.names(name):
                return Decision(r.action, _why(r), r.id, early=self._early(r.action, opened, asked))
        return Decision(self.default, "default", early=self._early(self.default, opened, asked))

    @staticmethod
    def _early(action: str, opened: bool, asked: bool) -> bool:
        if action == "deny":
            return not opened and not asked
        return action == "ask" and not opened

    def evaluate(self, host: str, port: int, ips: list[str], mode: str | None = None) -> Decision:
        """The decision for a destination with its addresses: the list is walked for each address (the literal
        itself for an IP destination), the most restrictive result wins. Without any address there is nothing
        to check and the answer is `deny` (fail closed)."""
        name = host.strip("[]").lower().rstrip(".")
        candidates = list(ips)
        if is_ip(host):
            candidates.append(host.strip("[]"))
        if not candidates:
            return Decision("deny", "no address to check")
        # A service port's fixed target (reverse mode, from the read-only config) is exempt from the seeded
        # blocks, and from nothing else: locked ranges and every other rule apply.
        excepted = mode == "reverse" and any(ex.host.lower() == name and ex.port == port for ex in self.exceptions)
        now = time.time()
        worst: Decision | None = None
        for ip in dict.fromkeys(candidates):
            dec = self._walk(name, ip, port, now, excepted, literal=is_ip(host))
            if worst is None or RANK[dec.action] > RANK[worst.action]:
                worst = dec
            if worst.action == "deny":
                break
        return worst

    def _walk(self, name: str, ip: str, port: int, now: float, excepted: bool, literal: bool) -> Decision:
        """The list for ONE address. See the module docstring; this is the whole evaluation."""
        if why := self.locked(ip, port):
            return Decision("deny", why, LOCKED)
        addr = ip_addr(ip)
        held: Rule | None = None  # the name rule that matched with allow/ask: provisional
        below: Rule | None = None  # an address allow/ask rule for this address that stands below `held`
        for r in self.rules:
            if r.expired(now) or not port_matches(r.port, port):
                continue
            if r.cidr:
                if not r.contains(addr):
                    continue
                if excepted and r.action == "deny" and r.source in SEEDED_SOURCES:
                    continue
                if held is None:
                    return Decision(r.action, _why(r), r.id)  # an address rule: the first match is final
                if r.action == "deny":
                    return self._shadowed(held, r, ip, below, literal)
                below = below or r  # below a name rule only an address `deny` counts
            elif held is None and r.names(name):
                if r.action == "deny":
                    return Decision("deny", _why(r), r.id)  # a name `deny` is final
                held = r
        if held is not None:
            return Decision(held.action, _why(held), held.id)
        return Decision(self.default, "default")

    @staticmethod
    def _shadowed(held: Rule, block: Rule, ip: str, below: Rule | None, literal: bool) -> Decision:
        """A name rule cannot open a blocked range: say so, with the way out (ADR-0019)."""
        verb = "allowed" if held.action == "allow" else "matched"
        what = f"the address {ip} is" if literal else f"it resolves to {ip},"
        way = (
            f"the {below.action} for the address (rule {below.id}) stands below rule {held.id}: move it above"
            if below is not None
            else "add an allow for the address above that rule"
        )
        reason = f"name {verb} by rule {held.id}, but {what} inside blocked range {block.cidr} (rule {block.id}): {way}"
        shadow = {"rule": held.id, "address": ip, "by": block.id, "range": block.cidr}
        return Decision("deny", reason, block.id, shadow=shadow)

    def covered_by(self, rule: Rule) -> Rule | None:
        """The earlier permanent address rule that covers this address rule completely, so that it can never
        decide anything - or None. A `deny` that is only covered by an `allow`/`ask` is not reported: it still
        blocks the address for a name rule above both."""
        if not rule.cidr:
            return None
        net = _net(rule.cidr)
        for r in self.rules:
            if r is rule or r.id == rule.id:
                return None
            if not r.cidr or r.expires is not None:
                continue
            wide = _net(r.cidr)
            if wide.version != net.version or not net.subnet_of(wide) or not ports_within(rule.port, r.port):
                continue
            if r.action == "deny" or rule.action != "deny":
                return r
        return None

    # ---------- mutation ----------
    def prune_expired(self) -> bool:
        before = len(self.rules)
        now = time.time()
        self.rules = [r for r in self.rules if not r.expired(now)]
        return len(self.rules) != before

    def bottom(self) -> int:
        """Where "the bottom" of the operator's rules is: above the run of seeded blocks that ends the list."""
        i = len(self.rules)
        while i and self.rules[i - 1].source in SEEDED_SOURCES:
            i -= 1
        return i

    def add_rule(self, rule: Rule, top: bool = True) -> Rule:
        rule.validate()
        if any(r.id == rule.id for r in self.rules):
            raise ValueError(f"rule id {rule.id} is already used")
        self.rules.insert(0 if top else self.bottom(), rule)
        return rule

    def remove_rule(self, rule_id: str) -> bool:
        before = len(self.rules)
        self.rules = [r for r in self.rules if r.id != rule_id]
        return len(self.rules) != before

    def move_rule(self, rule_id: str, before: str | None) -> bool:
        """Move a rule in front of the rule `before`, or to the very end with None. False if there is no such
        rule; ValueError if `before` is not a rule (or the rule itself)."""
        if before is not None and not isinstance(before, str):
            raise ValueError("before must be a rule id or null (the end of the list)")
        if before == rule_id:
            raise ValueError("a rule cannot be moved before itself")
        rule = next((r for r in self.rules if r.id == rule_id), None)
        if rule is None:
            return False
        if before is not None and not any(r.id == before for r in self.rules):
            raise ValueError(f"no rule {before!r} to move before")
        rest = [r for r in self.rules if r is not rule]
        at = len(rest) if before is None else next(i for i, r in enumerate(rest) if r.id == before)
        rest.insert(at, rule)
        self.rules = rest
        return True

    EDITABLE = ("action", "port", "note", "expires", "group")

    def set_group(self, rule_ids: list[str], group: str) -> list[Rule]:
        """Put several rules in one named set (#142), or clear it with an empty name. Returns the rules that
        changed; a rule id that is not found is skipped. Keeps each rule's position."""
        changed = []
        for rid in rule_ids:
            r = self.update_rule(rid, {"group": str(group)})
            if r is not None:
                changed.append(r)
        return changed

    def update_rule(self, rule_id: str, changes: dict) -> Rule | None:
        """Change an existing rule's action, port, note or expiry in place, keeping its id and position (e.g.
        put a time limit on a permanent rule instead of deleting it). Returns the new rule, or None if there
        is no such rule. What a rule matches (host/cidr) is not editable - that is a different rule."""
        unknown = set(changes) - set(self.EDITABLE)
        if unknown:
            raise ValueError(f"cannot edit {sorted(unknown)}; editable fields: {list(self.EDITABLE)}")
        for i, r in enumerate(self.rules):
            if r.id == rule_id:
                new = replace(r, **changes)
                new.validate()
                self.rules[i] = new
                return new
        return None

    # ---------- the seeded blocks (ADR-0019) ----------
    def seed_blocks(self, builtin: list[str], config: list[str]) -> list[Rule]:
        """Add the built-in and config blocks that were never seeded, as `deny` rules at the bottom, and
        remember them. Returns the rules added. A range that is no longer built in or configured is forgotten
        (its rule stays), so that configuring it again later seeds it again."""
        wanted = [*dict.fromkeys([*builtin, *config])]
        self.seeded = [c for c in self.seeded if c in wanted]
        added = []
        for cidr in wanted:
            if cidr not in self.seeded:
                self.seeded.append(cidr)
                added.append(self._append_block(cidr, "builtin" if cidr in builtin else "config"))
        return added

    def restore_blocks(self, builtin: list[str], config: list[str]) -> list[Rule]:
        """Add back, at the bottom, every built-in or config block that is no longer in force as it was seeded:
        a permanent `deny` for exactly that range on every port. Returns the rules added."""
        added = []
        for cidr in dict.fromkeys([*builtin, *config]):
            present = any(
                r.cidr == cidr and r.action == "deny" and r.expires is None and r.port in (None, "*", "any")
                for r in self.rules
            )
            if not present:
                added.append(self._append_block(cidr, "builtin" if cidr in builtin else "config"))
            if cidr not in self.seeded:
                self.seeded.append(cidr)
        return added

    def _append_block(self, cidr: str, source: str) -> Rule:
        ids = {r.id for r in self.rules}
        rid = base = block_id(cidr)
        n = 1
        while rid in ids:  # the operator edited or re-used the id: the block gets a new one
            n += 1
            rid = f"{base}-{n}"
        note = "built-in block" if source == "builtin" else "never (gateway config)"
        rule = Rule(action="deny", cidr=cidr, id=rid, source=source, note=note)
        rule.validate()
        self.rules.append(rule)
        return rule

    # ---------- serialisation ----------
    def to_dict(self) -> dict:
        return {
            "default": self.default,
            "ask_timeout": self.ask_timeout,
            "seeded": list(self.seeded),
            "rules": [r.to_dict() for r in self.rules],
        }

    @classmethod
    def from_dict(cls, d: dict) -> Policy:
        """A policy in the current form. A pre-0019 document (`hard_deny`, `floor_open`, no `seeded`) is
        translated first, by `migrate`."""
        p = cls()
        d = d or {}
        if not isinstance(d, dict):
            raise ValueError("policy: expected a mapping")
        unknown = set(d) - {"default", "ask_timeout", "seeded", "rules"}
        if unknown:
            raise ValueError(f"unknown policy keys: {sorted(unknown)}")
        p.default = d.get("default", "ask")
        if p.default not in ACTIONS:
            raise ValueError(f"invalid default action {p.default!r}")
        p.ask_timeout = int(d.get("ask_timeout", 60))
        if not 5 <= p.ask_timeout <= 3600:
            raise ValueError("ask_timeout must be 5..3600 seconds")
        p.seeded = parse_cidrs(d.get("seeded") or [], "seeded")
        rules = d.get("rules") or []
        if not isinstance(rules, list) or not all(isinstance(r, dict) for r in rules):
            raise ValueError("rules: expected a list of rules")
        p.rules = [Rule.from_dict(r) for r in rules]
        ids = [r.id for r in p.rules]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate rule ids")
        return p

    @classmethod
    def load(cls, path: Path) -> Policy:
        if not path.exists():
            return cls()
        return cls.from_dict(yaml.safe_load(path.read_text()) or {})

    def save(self, path: Path) -> None:
        atomic_write(path, yaml.safe_dump(self.to_dict(), sort_keys=False))


def block_id(cidr: str) -> str:
    """The id of a seeded block: readable, stable, and safe in a URL path."""
    return "block-" + cidr.replace("/", "_")


OLD_KEYS = ("hard_deny", "floor_open", "hard_deny_floor")


def is_pre_0019(d: dict) -> bool:
    """A policy document from before ADR-0019: it has one of the old keys, or it does not say what was seeded
    (every writer since then stores `seeded`, even when it is empty)."""
    return "seeded" not in d or any(k in d for k in OLD_KEYS)


def migrate(d: dict | None, builtin: list[str], config: list[str]) -> tuple[dict, list[str]]:
    """A pre-0019 policy document in the current form, and what was changed (for the log). Pure; anything it
    cannot translate raises ValueError (the caller fails closed).

      * CIDR `deny` rules move to the top, in their order: they won wherever they stood, and keep winning.
      * `hard_deny` extras become address `deny` rules below the other rules (above the built-in blocks).
      * Ranges in `floor_open` were opened by the operator: they are remembered as seeded without a rule, so
        `Policy.seed_blocks` adds every other built-in and config block at the bottom and leaves these out.
      * `hard_deny`, `floor_open` and the echoed `hard_deny_floor` are dropped."""
    d = dict(d or {})
    if not isinstance(d.get("rules") or [], list) or not all(isinstance(r, dict) for r in d.get("rules") or []):
        raise ValueError("rules: expected a list of rules")
    notes: list[str] = []
    rules = [dict(r) for r in d.get("rules") or []]
    denies = [r for r in rules if r.get("cidr") and r.get("action") == "deny"]
    others = [r for r in rules if not (r.get("cidr") and r.get("action") == "deny")]
    if denies and rules[: len(denies)] != denies:
        notes.append(f"moved {len(denies)} CIDR deny rule(s) to the top: {', '.join(str(r.get('id')) for r in denies)}")
    rules = [*denies, *others]
    opened = parse_cidrs(d.get("floor_open") or [], "floor_open")
    blocks = [*dict.fromkeys([*builtin, *config])]
    ids = {r.get("id") for r in rules}
    for cidr in parse_cidrs(d.get("hard_deny") or [], "hard_deny"):
        if cidr in blocks:
            continue  # the same range is a built-in or config block: seeded as that (unless it was opened)
        if cidr in opened:
            notes.append(f"hard_deny {cidr} was opened (floor_open): dropped")
            continue
        rid = block_id(cidr)
        while rid in ids:
            rid += "-x"
        ids.add(rid)
        rules.append({"id": rid, "action": "deny", "cidr": cidr, "note": "was hard_deny"})
        notes.append(f"hard_deny {cidr} is now deny rule {rid}")
    seeded = [c for c in blocks if c in opened]
    if seeded:
        notes.append(f"not blocked, as before (floor_open): {', '.join(seeded)}")
    seeded = [*dict.fromkeys([*parse_cidrs(d.get("seeded") or [], "seeded"), *seeded])]
    for r in others:
        if not r.get("cidr") or r.get("action") not in ("allow", "ask"):
            continue
        try:
            net = ipaddress.ip_network(str(r["cidr"]), strict=False)
        except ValueError:
            continue  # reported with the rule's id by Rule.validate
        hit = next(
            (c for c in blocks if c not in opened and _net(c).version == net.version and _net(c).overlaps(net)), None
        )
        if hit:
            notes.append(
                f"NOTE rule {r.get('id')} ({r['action']} {r['cidr']}) had no effect inside the blocked range {hit}; "
                "it now decides for these addresses (first match wins). Delete it if that is not wanted"
            )
    out = {k: v for k, v in d.items() if k not in OLD_KEYS}
    out["rules"], out["seeded"] = rules, seeded
    return out, notes


def policy_from_any(d: dict | None, builtin: list[str], config: list[str]) -> tuple[Policy, list[str]]:
    """A validated Policy from a document in the current or a pre-0019 form (API body, import, history
    version), and the migration notes. The caller adopts it, which seeds the blocks that are missing."""
    d = d or {}
    if not isinstance(d, dict):
        raise ValueError("policy: expected a mapping")
    notes: list[str] = []
    if is_pre_0019(d):
        d, notes = migrate(d, builtin, config)
    return Policy.from_dict(d), notes


# ---------- approvals ----------
# Bounds for a caller-supplied approval duration (#173): 1 minute .. 30 days.
TTL_MIN = 60
TTL_MAX = 2_592_000


def clamp_ttl(ttl: Any) -> int:
    """Validate and clamp an approval ttl (whole seconds) to [TTL_MIN, TTL_MAX].

    Only a plain integer is a ttl: bools (a bool is an int subclass), floats, strings and None are garbage
    and raise ValueError, so the API answers them with 400 rather than silently coercing a typo."""
    if not isinstance(ttl, int) or isinstance(ttl, bool):
        raise ValueError("ttl must be an integer number of seconds")
    return max(TTL_MIN, min(TTL_MAX, ttl))


SCOPES = {
    # scope: (action, default ttl seconds or None, host pattern builder, a caller ttl overrides the default)
    "once": ("allow", 120, "exact", False),
    "hour": ("allow", 3600, "exact", False),
    "allow": ("allow", None, "exact", True),  # custom-duration allow: a ttl is required
    "always": ("allow", None, "exact", False),
    "domain": ("allow", None, "domain", False),
    "deny": ("deny", 120, "exact", True),  # temporary deny: ttl optional, defaults to 120 s
    "deny_always": ("deny", None, "exact", False),
}


def registrable_domain(host: str) -> str | None:
    """eTLD+1 per the Public Suffix List *including* its private section, so that e.g.
    'foo.github.io' -> 'foo.github.io' (not 'github.io', which would cover every user's pages).
    None if the host is itself a public suffix or has no registrable part."""
    h = host.lower().rstrip(".")
    if is_ip(h) or not valid_hostname(h):
        return None
    return _psl().privatesuffix(h)


def rule_for_approval(host: str, port: int, scope: str, ttl: int | None = None) -> Rule:
    """The rule a decision installs. `ttl` (seconds) sets a custom lifetime for the scopes that take one
    (`allow`, `deny`); the fixed scopes (`once`, `hour`) and the permanent ones (`always`, `domain`,
    `deny_always`) ignore it. `allow` has no default lifetime and so requires a ttl. A caller ttl is expected
    to be already clamped (`clamp_ttl`); a temporary deny is a normal deny rule with an `expires`, so it
    suppresses re-asking (the rule decides `deny`, not `ask`) until it expires and is pruned."""
    if scope not in SCOPES:
        raise ValueError(f"invalid scope {scope!r}")
    action, default_ttl, kind, ttl_overrides = SCOPES[scope]
    ttl = ttl if (ttl_overrides and ttl is not None) else default_ttl
    if scope == "allow" and ttl is None:
        raise ValueError("scope 'allow' requires a ttl (seconds)")
    if is_ip(host):
        pattern_rule = Rule(action=action, cidr=str(ip_addr(host)), port=port)
    elif kind == "domain":
        base = registrable_domain(host)
        if not base:
            raise ValueError(f"{host!r} has no registrable domain; approve the exact host instead")
        pattern_rule = Rule(action=action, host="*." + base, port=port)
    else:
        pattern_rule = Rule(action=action, host=host.lower(), port=port)
    pattern_rule.source = "approval"
    pattern_rule.note = f"approved via {scope}"
    if ttl:
        pattern_rule.expires = time.time() + ttl
    pattern_rule.validate()
    return pattern_rule


PRESET_META = ("title", "description", "category")
PRESET_CATEGORIES = ("policy", "internet", "template")


def load_preset(path: Path) -> tuple[dict, Policy]:
    """A preset is a policy file with optional metadata for the UI (title, description, category)."""
    d = yaml.safe_load(path.read_text()) or {}
    meta = {k: d.pop(k) for k in PRESET_META if k in d}
    meta.setdefault("title", path.stem)
    meta.setdefault("description", "")
    meta.setdefault("category", "template")
    if meta["category"] not in PRESET_CATEGORIES:
        raise ValueError(f"preset {path.stem}: category must be one of {PRESET_CATEGORIES}")
    return meta, Policy.from_dict(d)
