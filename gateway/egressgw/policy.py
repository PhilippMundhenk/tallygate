"""Policy engine: pure logic, no I/O besides YAML load/save.

Evaluation order for a connection attempt to (host, port) resolving to ips:
  1. hard deny = immutable floor (static config) + policy extras (CIDRs, checked against literal
     and *resolved* IPs) -> deny, never ask, unless a service exception for that exact
     reverse-mode target matches.
  2. rules, first match wins (approvals are inserted at the top).
  3. default action (allow | deny | ask).

Hostnames are first evaluated *without* resolving them (`evaluate_name`), so names the policy
denies or still has to ask about never reach a DNS resolver (no DNS exfiltration).
"""

from __future__ import annotations

import fnmatch
import functools
import ipaddress
import re
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

ACTIONS = ("allow", "deny", "ask")

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


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip("[]"))
        return True
    except ValueError:
        return False


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


@dataclass
class Rule:
    action: str
    host: str | None = None
    cidr: str | None = None
    port: Any = "*"
    note: str = ""
    expires: float | None = None  # unix ts, None = permanent
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    source: str = "user"  # user | approval | preset

    def validate(self) -> None:
        if self.action not in ACTIONS:
            raise ValueError(f"rule {self.id}: invalid action {self.action!r}")
        if not self.host and not self.cidr:
            raise ValueError(f"rule {self.id}: needs 'host' or 'cidr'")
        if self.host and self.cidr:
            raise ValueError(f"rule {self.id}: use either 'host' or 'cidr', not both")
        if self.cidr:
            ipaddress.ip_network(self.cidr, strict=False)
        port_matches(self.port, 1)  # raises on garbage
        for p in self.port if isinstance(self.port, (list, tuple)) else [self.port]:
            for n in str(p).split("-") if p not in (None, "*", "any") else []:
                if not 0 < int(n) < 65536:
                    raise ValueError(f"rule {self.id}: port {p} out of range")

    def expired(self, now: float | None = None) -> bool:
        return self.expires is not None and (now or time.time()) >= self.expires

    def matches(self, host: str, port: int, ips: list[str]) -> bool:
        if not port_matches(self.port, port):
            return False
        if self.host:
            return host_matches(self.host, host)
        net = ipaddress.ip_network(self.cidr, strict=False)
        addrs = [ipaddress.ip_address(i) for i in ips] if ips else []
        if not addrs:
            return False
        if self.action == "allow":
            # allow by CIDR only if *every* resolved address is inside
            return all(a in net for a in addrs)
        return any(a in net for a in addrs)

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
        if self.source != "user":
            d["source"] = self.source
        return d

    @classmethod
    def from_dict(cls, d: dict) -> Rule:
        known = {"action", "host", "cidr", "port", "note", "expires", "id", "source"}
        unknown = set(d) - known
        if unknown:
            raise ValueError(f"unknown rule keys: {sorted(unknown)}")
        r = cls(**{k: v for k, v in d.items() if k in known})
        if r.port is None:
            r.port = "*"
        r.validate()
        return r


@dataclass
class Decision:
    action: str  # allow | deny | ask
    reason: str
    rule_id: str | None = None


@dataclass
class Exception_:
    """Explicit hard-deny exception for one service port's fixed target (reverse mode only)."""

    host: str
    port: int


class Policy:
    def __init__(self) -> None:
        self.default = "ask"
        self.ask_timeout = 60
        # Immutable floor: comes from the static config file, never from the API.
        self.hard_deny_floor: list[str] = list(DEFAULT_HARD_DENY)
        # Extras: editable via the API, can only ADD to the floor.
        self.hard_deny: list[str] = []
        self.rules: list[Rule] = []
        self.exceptions: list[Exception_] = []

    # ---------- evaluation ----------
    def hard_denied(self, host: str, port: int, ips: list[str], mode: str | None = None) -> str | None:
        if mode == "reverse":
            for ex in self.exceptions:
                if ex.host.lower() == host.lower().rstrip(".") and ex.port == port:
                    return None
        nets = [ipaddress.ip_network(c, strict=False) for c in [*self.hard_deny_floor, *self.hard_deny]]
        candidates = list(ips)
        if is_ip(host):
            candidates.append(host.strip("[]"))
        for ip in candidates:
            addr = ipaddress.ip_address(ip)
            # normalise IPv4-mapped IPv6
            if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
                addr = addr.ipv4_mapped
            for n in nets:
                if addr.version == n.version and addr in n:
                    return f"hard-deny {n} ({ip})"
        return None

    def evaluate_name(self, host: str, port: int) -> Decision | None:
        """Decide on the *name* alone, before any DNS lookup. Returns None when a CIDR rule that
        could allow/ask comes first, i.e. the answer genuinely depends on the resolved IPs."""
        now = time.time()
        for r in self.rules:
            if r.expired(now) or not port_matches(r.port, port):
                continue
            if r.host:
                if host_matches(r.host, host):
                    return Decision(r.action, f"rule {r.id}" + (f" ({r.note})" if r.note else ""), r.id)
            elif r.action != "deny":
                return None  # CIDR allow/ask: needs IPs (CIDR deny is re-checked after resolution)
        return Decision(self.default, "default")

    def evaluate(self, host: str, port: int, ips: list[str], mode: str | None = None) -> Decision:
        hd = self.hard_denied(host, port, ips, mode)
        if hd:
            return Decision("deny", hd, "hard_deny")
        now = time.time()
        for r in self.rules:
            if r.expired(now):
                continue
            if r.matches(host, port, ips):
                return Decision(r.action, f"rule {r.id}" + (f" ({r.note})" if r.note else ""), r.id)
        return Decision(self.default, "default")

    # ---------- mutation ----------
    def prune_expired(self) -> bool:
        before = len(self.rules)
        now = time.time()
        self.rules = [r for r in self.rules if not r.expired(now)]
        return len(self.rules) != before

    def add_rule(self, rule: Rule, top: bool = True) -> Rule:
        rule.validate()
        if top:
            self.rules.insert(0, rule)
        else:
            self.rules.append(rule)
        return rule

    def remove_rule(self, rule_id: str) -> bool:
        before = len(self.rules)
        self.rules = [r for r in self.rules if r.id != rule_id]
        return len(self.rules) != before

    # ---------- serialisation ----------
    def to_dict(self) -> dict:
        return {
            "default": self.default,
            "ask_timeout": self.ask_timeout,
            "hard_deny": self.hard_deny,
            "rules": [r.to_dict() for r in self.rules],
        }

    def describe(self) -> dict:
        """API view: the policy plus the read-only floor."""
        return {**self.to_dict(), "hard_deny_floor": self.hard_deny_floor}

    @classmethod
    def from_dict(cls, d: dict) -> Policy:
        p = cls()
        d = d or {}
        d = {k: v for k, v in d.items() if k != "hard_deny_floor"}  # read-only, echoed back by UIs
        unknown = set(d) - {"default", "ask_timeout", "hard_deny", "rules"}
        if unknown:
            raise ValueError(f"unknown policy keys: {sorted(unknown)}")
        p.default = d.get("default", "ask")
        if p.default not in ACTIONS:
            raise ValueError(f"invalid default action {p.default!r}")
        p.ask_timeout = int(d.get("ask_timeout", 60))
        if not 5 <= p.ask_timeout <= 3600:
            raise ValueError("ask_timeout must be 5..3600 seconds")
        floor = {str(ipaddress.ip_network(c, strict=False)) for c in DEFAULT_HARD_DENY}
        extras = []
        for c in d.get("hard_deny") or []:
            net = str(ipaddress.ip_network(str(c), strict=False))
            if net not in floor and net not in extras:
                extras.append(net)
        p.hard_deny = extras
        p.rules = [Rule.from_dict(r) for r in d.get("rules") or []]
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
        tmp = path.with_suffix(".tmp")
        tmp.write_text(yaml.safe_dump(self.to_dict(), sort_keys=False))
        tmp.replace(path)


# ---------- approvals ----------
SCOPES = {
    # scope: (action, ttl seconds or None, host pattern builder)
    "once": ("allow", 120, "exact"),
    "hour": ("allow", 3600, "exact"),
    "always": ("allow", None, "exact"),
    "domain": ("allow", None, "domain"),
    "deny": ("deny", 120, "exact"),
    "deny_always": ("deny", None, "exact"),
}


def registrable_domain(host: str) -> str | None:
    """eTLD+1 per the Public Suffix List *including* its private section, so that e.g.
    'foo.github.io' -> 'foo.github.io' (not 'github.io', which would cover every user's pages).
    None if the host is itself a public suffix or has no registrable part."""
    h = host.lower().rstrip(".")
    if is_ip(h) or not valid_hostname(h):
        return None
    return _psl().privatesuffix(h)


def rule_for_approval(host: str, port: int, scope: str) -> Rule:
    if scope not in SCOPES:
        raise ValueError(f"invalid scope {scope!r}")
    action, ttl, kind = SCOPES[scope]
    if is_ip(host):
        pattern_rule = Rule(action=action, cidr=host.strip("[]"), port=port)
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
