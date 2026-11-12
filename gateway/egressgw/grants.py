"""Grants: named, scoped, time-limited bundles of access that the agent requests and a human approves.

A grant definition (static config or UI) lists targets (host:port + scheme), optional HTTP path
patterns, the access levels it offers (read = GET/HEAD/OPTIONS only, write = everything), whether
targets may be on the LAN (exempt from the hard deny), credential injection and the approval mode per
level. The agent can only *ask* for a defined grant; it can never define or widen one.

Enforcement lives in core.py: an active grant is checked before the normal policy, HTTP(S) targets
are always intercepted so method, path and Host can be enforced on every request, and anything that is
not HTTP on such a target is cut.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import logging
import re
import secrets as _secrets
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from egressgw.policy import ip_addr, is_ip, valid_hostname
from egressgw.store import atomic_write

log = logging.getLogger("egressgw")

LEVELS = ("read", "write")
READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
SCHEMES = ("https", "http", "tcp")
APPROVALS = ("ask", "auto")
# Never reachable, not even through a LAN grant: loopback/link-local/metadata/unspecified/multicast.
DEFAULT_NEVER = ["0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "::/96", "fe80::/10", "ff00::/8"]
MAX_TTL = 7 * 24 * 3600
NAME_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,47}")
# Path tricks that a server might normalise differently than our glob match does.
_BAD_PATH = re.compile(r"(^|/)\.\.?(/|$)|//|\\|%2e|%2f|%5c|%00|[\x00-\x20\x7f]", re.IGNORECASE)


def parse_ttl(v) -> int:
    """'90s', '30m', '4h', '2d' or seconds."""
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return int(v)
    m = re.fullmatch(r"\s*(\d+)\s*([smhd]?)\s*", str(v))
    if not m:
        raise ValueError(f"invalid duration {v!r}")
    return int(m.group(1)) * {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]


def fmt_ttl(s: int) -> str:
    for unit, n in (("d", 86400), ("h", 3600), ("m", 60)):
        if s >= n and s % n == 0:
            return f"{s // n}{unit}"
    return f"{s}s"


def path_ok(path: str, patterns: list[str]) -> bool:
    """True if the request path (without query) is canonical and matches one of the patterns."""
    raw = path.split("?", 1)[0].split("#", 1)[0] or "/"
    if not raw.startswith("/") or _BAD_PATH.search(raw):
        return False
    decoded = urllib.parse.unquote(raw)
    return any(fnmatch.fnmatchcase(decoded, p) for p in patterns)


def _host_ok(h: str) -> bool:
    if h.startswith("*."):
        return valid_hostname(h[2:])
    return is_ip(h) or valid_hostname(h)


def host_match(pattern: str, host: str) -> bool:
    pattern, host = pattern.lower().rstrip("."), host.lower().rstrip(".")
    if pattern.startswith("*."):
        return host.endswith(pattern[1:]) and host != pattern[2:]
    if is_ip(pattern) and is_ip(host):
        return ip_addr(pattern) == ip_addr(host)
    return pattern == host


@dataclass
class Target:
    host: str
    port: int
    scheme: str = "https"
    paths: list[str] = field(default_factory=lambda: ["/*"])
    lan: bool = False
    address: str | None = None
    tls_fingerprint: str | None = None
    tls_verify: bool = True

    @classmethod
    def from_dict(cls, d: dict) -> Target:
        unknown = set(d) - {"host", "port", "scheme", "paths", "lan", "address", "tls_fingerprint", "tls_verify"}
        if unknown:
            raise ValueError(f"unknown target fields: {sorted(unknown)}")
        t = cls(
            host=str(d["host"]).strip().lower().rstrip("."),
            port=int(d["port"]),
            scheme=str(d.get("scheme", "https")).lower(),
            paths=[str(p) for p in (d.get("paths") or ["/*"])],
            lan=bool(d.get("lan", False)),
            address=str(d["address"]).strip() if d.get("address") else None,
            tls_fingerprint=(str(d["tls_fingerprint"]).replace(":", "").lower() if d.get("tls_fingerprint") else None),
            tls_verify=bool(d.get("tls_verify", True)),
        )
        t.validate()
        return t

    def validate(self) -> None:
        if not _host_ok(self.host):
            raise ValueError(f"invalid target host {self.host!r}")
        if not 0 < self.port < 65536:
            raise ValueError(f"invalid port {self.port}")
        if self.scheme not in SCHEMES:
            raise ValueError(f"scheme must be one of {SCHEMES}")
        if self.address and (not is_ip(self.address) or self.host.startswith("*.")):
            raise ValueError("address must be an IP and needs an exact host")
        if self.scheme == "tcp" and (self.paths != ["/*"] or self.tls_fingerprint or not self.tls_verify):
            raise ValueError("tcp targets take no paths/TLS options (traffic is passed through untouched)")
        if self.scheme == "http" and (self.tls_fingerprint or not self.tls_verify):
            raise ValueError("TLS options only apply to https targets")
        if self.tls_fingerprint and not re.fullmatch(r"[0-9a-f]{64}", self.tls_fingerprint):
            raise ValueError("tls_fingerprint must be a SHA-256 fingerprint (64 hex digits, colons allowed)")
        for p in self.paths:
            if not p.startswith("/") or len(p) > 200:
                raise ValueError(f"path pattern must start with '/': {p!r}")

    def matches(self, host: str, port: int) -> bool:
        return port == self.port and host_match(self.host, host)

    def to_dict(self) -> dict:
        d = {"host": self.host, "port": self.port, "scheme": self.scheme}
        if self.scheme != "tcp":
            d["paths"] = self.paths
        if self.lan:
            d["lan"] = True
        if self.address:
            d["address"] = self.address
        if self.tls_fingerprint:
            d["tls_fingerprint"] = self.tls_fingerprint
        if not self.tls_verify:
            d["tls_verify"] = False
        return d

    def label(self) -> str:
        paths = "" if self.scheme == "tcp" or self.paths == ["/*"] else " " + ",".join(self.paths)
        return f"{self.scheme}://{self.host}:{self.port}{paths}{' (LAN)' if self.lan else ''}"


@dataclass
class GrantDef:
    name: str
    description: str
    targets: list[Target]
    levels: list[str]
    approval: dict[str, str]
    default_ttl: int = 3600
    max_ttl: int = 4 * 3600
    inject: list[dict] = field(default_factory=list)
    source: str = "config"

    @classmethod
    def from_dict(cls, name: str, d: dict, source: str) -> GrantDef:
        unknown = set(d) - {
            "name",
            "description",
            "targets",
            "levels",
            "approval",
            "default_ttl",
            "max_ttl",
            "inject",
            "source",
        }
        if unknown:
            raise ValueError(f"grant {name}: unknown fields {sorted(unknown)}")
        levels = [str(lv) for lv in (d.get("levels") or ["read"])]
        appr = d.get("approval", "ask")
        approval = (
            {lv: str(appr) for lv in levels}
            if isinstance(appr, str)
            else {lv: str(appr.get(lv, "ask")) for lv in levels}
        )
        g = cls(
            name=name,
            description=str(d.get("description", ""))[:300],
            targets=[Target.from_dict(t) for t in d.get("targets") or []],
            levels=levels,
            approval=approval,
            default_ttl=parse_ttl(d.get("default_ttl", "1h")),
            max_ttl=parse_ttl(d.get("max_ttl", "4h")),
            inject=[
                {
                    "host": str(i["host"]).lower(),
                    "header": str(i.get("header", "Authorization")),
                    "value": str(i["value"]),
                }
                for i in d.get("inject") or []
            ],
            source=source,
        )
        g.validate()
        return g

    def validate(self) -> None:
        if not NAME_RE.fullmatch(self.name):
            raise ValueError("grant name must match [a-z0-9][a-z0-9_-]{0,47}")
        if not self.targets:
            raise ValueError(f"grant {self.name}: at least one target")
        if not self.levels or any(lv not in LEVELS for lv in self.levels) or len(set(self.levels)) != len(self.levels):
            raise ValueError(f"grant {self.name}: levels must be a subset of {LEVELS}")
        if any(a not in APPROVALS for a in self.approval.values()):
            raise ValueError(f"grant {self.name}: approval must be one of {APPROVALS}")
        if not 60 <= self.default_ttl <= self.max_ttl <= MAX_TTL:
            raise ValueError(f"grant {self.name}: need 1m <= default_ttl <= max_ttl <= 7d")
        if self.source != "config" and (self.inject or any(not t.tls_verify for t in self.targets)):
            # A UI session or the API token must not be able to send stored secrets to a host of its choosing.
            raise ValueError(
                f"grant {self.name}: credential injection and tls_verify: false are only allowed in grants "
                "from the gateway config file"
            )
        if self.levels == ["read"] and all(t.scheme == "tcp" for t in self.targets):
            raise ValueError(f"grant {self.name}: tcp targets cannot be read-only (no protocol visibility)")
        https_hosts = {t.host for t in self.targets if t.scheme == "https" and not t.host.startswith("*.")}
        for i in self.inject:
            if i["host"] not in https_hosts:
                raise ValueError(f"grant {self.name}: inject host {i['host']} must be an exact https target")
            if not re.fullmatch(r"[A-Za-z0-9-]{1,64}", i["header"]):
                raise ValueError(f"grant {self.name}: invalid header name")

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "targets": [t.to_dict() for t in self.targets],
            "levels": self.levels,
            "approval": self.approval,
            "default_ttl": fmt_ttl(self.default_ttl),
            "max_ttl": fmt_ttl(self.max_ttl),
            "inject": self.inject,
            "source": self.source,
        }

    def summary(self) -> dict:
        """What the agent may see: no credentials, no internals."""
        return {
            "name": self.name,
            "description": self.description,
            "levels": self.levels,
            "default_ttl": fmt_ttl(self.default_ttl),
            "max_ttl": fmt_ttl(self.max_ttl),
            "targets": [t.label() for t in self.targets],
        }


@dataclass
class Active:
    id: str
    name: str
    level: str
    created: float
    expires: float
    reason: str
    approved_by: str

    def to_dict(self) -> dict:
        return dict(self.__dict__)


@dataclass
class GrantRequest:
    id: str
    name: str
    level: str
    ttl: int
    reason: str
    client: str
    created: float
    timeout: float
    status: str = "pending"  # pending | approved | denied | expired
    decided_by: str = ""
    grant_id: str = ""
    granted_level: str = ""

    def to_dict(self) -> dict:
        d = dict(self.__dict__)
        d["expires"] = self.created + self.timeout
        d["ttl_label"] = fmt_ttl(self.ttl)
        return d


def clean_reason(text: str) -> str:
    """Agent-written text shown to humans: printable, single line, bounded."""
    text = "".join(c if c.isprintable() else " " for c in str(text or ""))
    return " ".join(text.split())[:300]


class Grants:
    def __init__(self, config: dict, data_dir: Path) -> None:
        self.ui_path = data_dir / "grants.yaml"
        self.never = [ipaddress.ip_network(c, strict=False) for c in config.get("grants_never") or DEFAULT_NEVER]
        # LAN ranges that grants defined in the UI may reach (config-file grants are not limited).
        self.ui_lan_allow = [ipaddress.ip_network(c, strict=False) for c in config.get("grants_lan_allow") or []]
        self.request_timeout = int(config.get("grant_request_timeout", 300))
        self.max_requests = int(config.get("grant_max_pending", 3))
        self.defs: dict[str, GrantDef] = {}
        for name, d in (config.get("grants") or {}).items():
            self.defs[name] = GrantDef.from_dict(name, d or {}, "config")
        if self.ui_path.exists():
            for name, d in (yaml.safe_load(self.ui_path.read_text()) or {}).items():
                if name in self.defs:
                    continue  # config wins
                try:
                    self.defs[name] = GrantDef.from_dict(name, d or {}, "ui")
                except ValueError as e:  # e.g. saved by an older version that allowed inject in UI grants
                    log.error("UI grant %s ignored: %s", name, e)
        self.active: dict[str, Active] = {}
        self.requests: dict[str, GrantRequest] = {}
        # Set by the emergency stop, cleared by the next mode change: while set, "auto" levels need a human.
        # Persisted, so a gateway restart does not quietly turn auto-approval back on.
        self.state_path = data_dir / "grants-state.yaml"
        self.auto_suspended: dict | None = None
        if self.state_path.exists():
            try:
                self.auto_suspended = (yaml.safe_load(self.state_path.read_text()) or {}).get("auto_suspended")
            except (OSError, yaml.YAMLError, AttributeError) as e:  # fail closed: keep auto-approval off
                log.error("%s unreadable (%s): auto-approval stays suspended", self.state_path, e)
                self.auto_suspended = {"since": 0, "by": "unreadable state file"}

    # ---------------------------------------------------------------- auto-approval suspension
    def _save_state(self) -> None:
        atomic_write(self.state_path, yaml.safe_dump({"auto_suspended": self.auto_suspended}, sort_keys=False))

    def suspend_auto(self, by: str) -> None:
        self.auto_suspended = {"since": time.time(), "by": by[:64]}
        self._save_state()

    def resume_auto(self) -> bool:
        """End a suspension; True if one was in effect."""
        if not self.auto_suspended:
            return False
        self.auto_suspended = None
        self._save_state()
        return True

    # ---------------------------------------------------------------- definitions (UI)
    def save_ui(self) -> None:
        data = {
            n: {k: v for k, v in g.to_dict().items() if k not in ("name", "source")}
            for n, g in self.defs.items()
            if g.source == "ui"
        }
        atomic_write(self.ui_path, yaml.safe_dump(data, sort_keys=False))

    def check_ui(self, name: str, d: dict) -> GrantDef:
        """Validate a UI grant definition without storing it."""
        if name in self.defs and self.defs[name].source == "config":
            raise ValueError(f"grant {name} is defined in the config file and cannot be changed in the UI")
        g = GrantDef.from_dict(name, d, "ui")
        for t in g.targets:
            if t.lan and not self.ui_lan_allow:
                raise ValueError("LAN targets in UI grants need grants_lan_allow in the gateway config file")
            if t.lan and t.address and not self._in(t.address, self.ui_lan_allow):
                raise ValueError(f"{t.address} is outside grants_lan_allow")
        return g

    def upsert_ui(self, name: str, d: dict) -> GrantDef:
        g = self.check_ui(name, d)
        self.defs[name] = g
        self.save_ui()
        return g

    def ui_defs(self) -> dict[str, dict]:
        return {n: g.to_dict() for n, g in self.defs.items() if g.source == "ui"}

    def delete_ui(self, name: str) -> None:
        g = self.defs.get(name)
        if not g:
            raise KeyError(name)
        if g.source != "ui":
            raise ValueError("config-file grants cannot be deleted in the UI")
        del self.defs[name]
        for a in [a for a in self.active.values() if a.name == name]:
            del self.active[a.id]
        self.save_ui()

    # ---------------------------------------------------------------- matching
    @staticmethod
    def _in(ip: str, nets) -> bool:
        a = ip_addr(ip)
        return any(a in n for n in nets)

    def match(self, host: str, port: int) -> tuple[Active, GrantDef, Target] | None:
        """Best active grant covering host:port (write beats read)."""
        best = None
        now = time.time()
        for a in self.active.values():
            if a.expires <= now:
                continue
            g = self.defs.get(a.name)
            if not g:
                continue
            for t in g.targets:
                usable = t.matches(host, port) and (a.level == "write" or t.scheme != "tcp")
                if usable and (best is None or (a.level == "write" and best[0].level == "read")):
                    best = (a, g, t)
        return best

    def defined_for(self, host: str, port: int) -> list[str]:
        return sorted(g.name for g in self.defs.values() if any(t.matches(host, port) for t in g.targets))

    def address_problem(self, g: GrantDef, t: Target, ips: list[str]) -> str | None:
        """None if the resolved IPs are acceptable for this target (the hard deny is checked by the caller
        for non-LAN targets)."""
        for ip in ips:
            if self._in(ip, self.never):
                return f"grant {g.name}: {ip} is never reachable"
            if t.lan and g.source == "ui" and not self._in(ip, self.ui_lan_allow):
                return f"grant {g.name}: {ip} is outside grants_lan_allow"
        return None

    # ---------------------------------------------------------------- lifecycle
    def activate(self, name: str, level: str, ttl: int, reason: str, by: str) -> Active:
        g = self.defs[name]
        if level not in g.levels:
            raise ValueError(f"grant {name} has no level {level!r}")
        ttl = max(60, min(int(ttl), g.max_ttl))
        now = time.time()
        for a in self.active.values():
            if a.name == name:  # one active instance per grant: re-approval updates it in place, keeping
                a.level, a.created, a.expires = level, now, now + ttl  # its id, so open connections survive
                a.reason, a.approved_by = clean_reason(reason), by[:64]
                return a
        a = Active(_secrets.token_hex(5), name, level, now, now + ttl, clean_reason(reason), by[:64])
        self.active[a.id] = a
        return a

    def revoke(self, active_id: str) -> Active:
        return self.active.pop(active_id)

    def new_request(self, name: str, level: str, ttl, reason: str, client: str) -> GrantRequest:
        g = self.defs.get(name)
        if not g:
            raise KeyError(name)
        if level not in g.levels:
            raise ValueError(f"grant {name} offers {g.levels}, not {level!r}")
        ttl = g.default_ttl if ttl in (None, "") else parse_ttl(ttl)
        ttl = max(60, min(ttl, g.max_ttl))
        for r in self.requests.values():
            if r.status == "pending" and r.name == name and r.level == level:
                return r  # dedupe
        if sum(r.status == "pending" for r in self.requests.values()) >= self.max_requests:
            raise OverflowError(f"too many pending grant requests (max {self.max_requests})")
        r = GrantRequest(
            _secrets.token_hex(5), name, level, ttl, clean_reason(reason), client, time.time(), self.request_timeout
        )
        self.requests[r.id] = r
        return r

    def prune(self) -> tuple[list[Active], list[GrantRequest]]:
        now = time.time()
        expired = [a for a in self.active.values() if a.expires <= now]
        for a in expired:
            del self.active[a.id]
        timed_out = [r for r in self.requests.values() if r.status == "pending" and r.created + r.timeout <= now]
        for r in timed_out:
            r.status = "expired"
        for rid in [
            rid for rid, r in self.requests.items() if r.status != "pending" and r.created + r.timeout + 3600 < now
        ]:
            del self.requests[rid]  # keep decided requests 1 h for status queries
        return expired, timed_out

    def pending(self) -> list[GrantRequest]:
        return [r for r in self.requests.values() if r.status == "pending"]
