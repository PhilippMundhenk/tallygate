"""Policy engine: pure logic, no I/O besides YAML load/save.

Evaluation order for a connection attempt to (host, port) resolving to ips:
  1. hard_deny (CIDRs, checked against literal and *resolved* IPs) -> deny, never ask,
     unless an explicit service exception matches.
  2. rules, first match wins (approvals are inserted at the top).
  3. default action (allow | deny | ask).
"""

from __future__ import annotations

import fnmatch
import ipaddress
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
    "192.168.0.0/16",
    "198.18.0.0/15",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "::/128",
    "::1/128",
    "::ffff:0:0/96",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
]


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip("[]"))
        return True
    except ValueError:
        return False


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
    """Explicit hard-deny exception (used for service ports to private targets)."""

    host: str
    port: int


class Policy:
    def __init__(self) -> None:
        self.default = "ask"
        self.ask_timeout = 60
        self.hard_deny: list[str] = list(DEFAULT_HARD_DENY)
        self.rules: list[Rule] = []
        self.exceptions: list[Exception_] = []

    # ---------- evaluation ----------
    def hard_denied(self, host: str, port: int, ips: list[str]) -> str | None:
        for ex in self.exceptions:
            if host_matches(ex.host, host) and ex.port == port:
                return None
        nets = [ipaddress.ip_network(c, strict=False) for c in self.hard_deny]
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

    def evaluate(self, host: str, port: int, ips: list[str]) -> Decision:
        hd = self.hard_denied(host, port, ips)
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

    @classmethod
    def from_dict(cls, d: dict) -> Policy:
        p = cls()
        d = d or {}
        unknown = set(d) - {"default", "ask_timeout", "hard_deny", "rules"}
        if unknown:
            raise ValueError(f"unknown policy keys: {sorted(unknown)}")
        p.default = d.get("default", "ask")
        if p.default not in ACTIONS:
            raise ValueError(f"invalid default action {p.default!r}")
        p.ask_timeout = int(d.get("ask_timeout", 60))
        if not 5 <= p.ask_timeout <= 3600:
            raise ValueError("ask_timeout must be 5..3600 seconds")
        if "hard_deny" in d:
            p.hard_deny = [str(c) for c in d["hard_deny"] or []]
        for c in p.hard_deny:
            ipaddress.ip_network(c, strict=False)
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


def registrable_domain(host: str) -> str:
    """Cheap eTLD+1 approximation (handles common 2-level public suffixes)."""
    parts = host.lower().rstrip(".").split(".")
    if len(parts) <= 2:
        return ".".join(parts)
    two_level = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "co.jp", "com.br", "com.cn", "co.nz"}
    if ".".join(parts[-2:]) in two_level and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def rule_for_approval(host: str, port: int, scope: str) -> Rule:
    if scope not in SCOPES:
        raise ValueError(f"invalid scope {scope!r}")
    action, ttl, kind = SCOPES[scope]
    if is_ip(host):
        pattern_rule = Rule(action=action, cidr=host.strip("[]"), port=port)
    elif kind == "domain":
        pattern_rule = Rule(action=action, host="*." + registrable_domain(host), port=port)
    else:
        pattern_rule = Rule(action=action, host=host.lower(), port=port)
    pattern_rule.source = "approval"
    pattern_rule.note = f"approved via {scope}"
    if ttl:
        pattern_rule.expires = time.time() + ttl
    pattern_rule.validate()
    return pattern_rule
