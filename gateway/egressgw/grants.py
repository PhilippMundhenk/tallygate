"""Grants: named, scoped, time-limited bundles of access that the agent requests and a human approves.

A grant definition (static config or UI) lists targets (host:port + scheme), optional HTTP path
patterns, the access levels it offers (read = GET/HEAD/OPTIONS only, write = everything), credential
injection and the approval mode per level. The agent can only *ask* for a defined grant; it can never
define or widen one.

An active grant behaves like rules at the top of the rule list for its targets (ADR-0019): a target with
an IP literal or a fixed `address` is an address rule and may therefore be a local address; a target that
is only a name is a name rule and cannot open a blocked range. The locked ranges (the stack's own networks,
the gateway's own listeners) apply to grants as to everything else.

Enforcement lives in core.py and model.py: an active grant is checked before the rule list, HTTP(S) targets
are always intercepted so method, path and Host can be enforced on every request, and anything that is
not HTTP on such a target is cut.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import logging
import os
import re
import secrets as _secrets
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from egressgw import destinations
from egressgw.policy import ip_addr, is_ip, locked_reason, valid_hostname
from egressgw.store import atomic_write

log = logging.getLogger("egressgw")

LEVELS = ("read", "write")
READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
SCHEMES = ("https", "http", "tcp")
APPROVALS = ("ask", "auto")
MAX_TTL = 7 * 24 * 3600
NAME_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,47}")
# Path tricks that a server might normalise differently than our glob match does.
_BAD_PATH = re.compile(r"(^|/)\.\.?(/|$)|//|\\|[#;]|%2e|%2f|%5c|%23|%3b|%00|[\x00-\x20\x7f]", re.IGNORECASE)


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
    raw = path.split("?", 1)[0] or "/"  # keep `#`/`;`: `_BAD_PATH` refuses them (normalisation tricks)
    if not raw.startswith("/") or _BAD_PATH.search(raw):
        return False
    # Decode to a fixed point: a single unquote lets multiply-encoded traversal (%252e%252e -> %2e%2e)
    # slip past _BAD_PATH while the raw path, forwarded upstream, decodes further to `..` (#111).
    decoded = raw
    for _ in range(3):
        step = urllib.parse.unquote(decoded)
        if step == decoded:
            break
        decoded = step
    else:
        return False  # still changing after three rounds: refuse
    if _BAD_PATH.search(decoded) or "%" in decoded:  # residual %: an encoding we did not fully resolve
        return False
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
    address: str | None = None
    tls_fingerprint: str | None = None
    tls_verify: bool = True

    @classmethod
    def from_dict(cls, d: dict) -> Target:
        # `lan` is read from pre-0019 files and ignored (ADR-0019): what a target may reach follows from
        # whether it names an address, not from a flag.
        unknown = set(d) - {"host", "port", "scheme", "paths", "lan", "address", "tls_fingerprint", "tls_verify"}
        if unknown:
            raise ValueError(f"unknown target fields: {sorted(unknown)}")
        t = cls(
            host=str(d["host"]).strip().lower().rstrip("."),
            port=int(d["port"]),
            scheme=str(d.get("scheme", "https")).lower(),
            paths=[str(p) for p in (d.get("paths") or ["/*"])],
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

    def fixed(self) -> str | None:
        """The address of a target that is an address rule (a fixed `address` or an IP literal as host), or
        None for a target that is only a name (ADR-0019)."""
        if self.address:
            return self.address
        return self.host.strip("[]") if is_ip(self.host) else None

    def to_dict(self) -> dict:
        d = {"host": self.host, "port": self.port, "scheme": self.scheme}
        if self.scheme != "tcp":
            d["paths"] = self.paths
        if self.address:
            d["address"] = self.address
        if self.tls_fingerprint:
            d["tls_fingerprint"] = self.tls_fingerprint
        if not self.tls_verify:
            d["tls_verify"] = False
        return d

    def label(self) -> str:
        paths = "" if self.scheme == "tcp" or self.paths == ["/*"] else " " + ",".join(self.paths)
        return f"{self.scheme}://{self.host}:{self.port}{paths}"


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


NO_INTERNAL_NETS = "GW_TEST_NO_INTERNAL_NETS"  # test/dev switch: start although GW_INTERNAL_NETS is empty


def internal_nets(value: str) -> list:
    """GW_INTERNAL_NETS: the stack's own networks as comma-separated CIDRs (set in compose.yaml). A broken
    entry stops the gateway (fail closed), and so does an empty list, see Grants."""
    nets = []
    for c in (v.strip() for v in value.split(",")):
        if not c:
            continue
        try:
            nets.append(ipaddress.ip_network(c, strict=False))
        except ValueError as e:
            raise ValueError(f"GW_INTERNAL_NETS: invalid CIDR {c!r} ({e})") from None
    return nets


def own_sockets(env) -> list:
    """The gateway's own listeners (management API, grant API, HTTP and SOCKS proxy) as (network, port).
    A listener bound to one address is that address. One bound to every address (or to a name) is reached
    through any local address, so its port is locked on loopback and on the unspecified addresses; the
    gateway's other addresses are inside the stack's own networks."""
    own = []
    for host_var, ports in (
        ("GW_API_HOST", (("GW_API_PORT", "8081"),)),
        ("GW_LISTEN_HOST", (("GW_GRANTS_PORT", "8079"), ("GW_HTTP_PORT", "3128"), ("GW_SOCKS_PORT", "1080"))),
    ):
        host = env.get(host_var) or "127.0.0.1"  # the default the listeners bind to
        if is_ip(host) and not ip_addr(host).is_unspecified:
            nets = [ipaddress.ip_network(str(ip_addr(host)))]
        else:
            nets = [ipaddress.ip_network(c) for c in ("127.0.0.0/8", "0.0.0.0/32", "::1/128", "::/128")]
        own += [(n, int(env.get(var, default))) for var, default in ports for n in nets]
    return own


def clean_reason(text: str) -> str:
    """Agent-written text shown to humans: printable, single line, bounded."""
    text = "".join(c if c.isprintable() else " " for c in str(text or ""))
    return " ".join(text.split())[:300]


def _lan_targets(defs: dict) -> list[tuple[str, dict]]:
    """(grant name, target dict) of every target that still carries the pre-0019 `lan` flag."""
    out = []
    for name, d in (defs or {}).items():
        for t in (d or {}).get("targets") or []:
            if isinstance(t, dict) and t.get("lan"):
                out.append((name, t))
    return out


def _target_key(name: str, t: dict) -> tuple:
    """(grant, host, port) of a raw target as the parsed target spells them."""
    port = t.get("port")
    return name, str(t.get("host", "")).lower().rstrip("."), int(port) if str(port).isdigit() else port


def _lan_notes(where: str, targets: list[tuple[str, dict]]) -> None:
    """Log once what the dropped `lan` flag means for each target (ADR-0019, Migration)."""
    for name, t in targets:
        label = f"grant {name}, target {t.get('host')}:{t.get('port')}"
        if t.get("address") or is_ip(str(t.get("host", ""))):
            log.warning("%s: %s: `lan` is ignored now; the target names an address and keeps working", where, label)
        else:
            log.warning(
                "%s: %s: `lan` is ignored now, and a target that is only a name cannot open a blocked range. "
                "It keeps working for a local address only with a fixed `address`",
                where,
                label,
            )


class Grants:
    def __init__(self, config: dict, data_dir: Path) -> None:
        self.ui_path = data_dir / "grants.yaml"
        # Locked (ADR-0019): the stack's own networks and the gateway's own listeners are never reachable,
        # through a grant or anything else. The Gateway attaches them to the policy, which checks them before
        # the rule list; they are kept here because they come from the environment, as the grants do.
        self.internal = internal_nets(os.environ.get("GW_INTERNAL_NETS", ""))
        if not self.internal:
            # Fatal (#232): raised like an invalid entry, so the gateway does not start (addon.py refuses every
            # connection and mitmdump exits). A gateway run outside the compose stack (the test suite,
            # development) has no networks of a stack to lock and says so with GW_TEST_NO_INTERNAL_NETS=1.
            if os.environ.get(NO_INTERNAL_NETS) != "1":
                raise ValueError(
                    "GW_INTERNAL_NETS is empty: no network of the stack would be locked, and only the built-in "
                    "blocks, which can be deleted, would keep the agent away from the control plane and the "
                    "gateway API. Set it to the stack's networks as compose.yaml does: a compose.yaml that is "
                    f"older than the images lacks it. (Tests and development only: {NO_INTERNAL_NETS}=1)"
                )
            log.warning(
                "%s is set - GW_INTERNAL_NETS is empty and no network of the stack is locked (test only)",
                NO_INTERNAL_NETS,
            )
        self.own = own_sockets(os.environ)
        if config.get("grants_lan_allow"):
            log.warning(
                "gateway config: grants_lan_allow is ignored since ADR-0019: a grant target with an IP or a fixed "
                "`address` may be a local address, one that is only a name may not"
            )
        self.request_timeout = int(config.get("grant_request_timeout", 300))
        self.max_requests = int(config.get("grant_max_pending", 3))
        self.defs: dict[str, GrantDef] = {}
        self._had_lan = {_target_key(n, t) for n, t in _lan_targets(config.get("grants") or {})}
        _lan_notes("gateway config", _lan_targets(config.get("grants") or {}))
        for name, d in (config.get("grants") or {}).items():
            self.defs[name] = GrantDef.from_dict(name, d or {}, "config")
        if self.ui_path.exists():
            text = self.ui_path.read_text()
            raw = yaml.safe_load(text) or {}
            old_form = "destinations" not in raw and bool(raw)  # a pre-0014 {name: def} file
            file_defs = destinations.grants_from_file(raw)  # a file that cannot be read stops the gateway
            lan = _lan_targets(file_defs)
            self._had_lan |= {_target_key(n, t) for n, t in lan}
            for name, d in file_defs.items():
                if name in self.defs:
                    continue  # config wins
                try:
                    self.defs[name] = GrantDef.from_dict(name, d or {}, "ui")
                except ValueError as e:  # e.g. saved by an older version that allowed inject in UI grants
                    log.error("UI grant %s ignored: %s", name, e)
            for suffix, needed in ((".pre-0014", old_form), (".pre-0019", bool(lan))):
                if needed:  # migrate once: keep the old file next to the new one, then rewrite it
                    backup = self.ui_path.with_suffix(self.ui_path.suffix + suffix)
                    if not backup.exists():
                        atomic_write(backup, text)
            if old_form or lan:
                _lan_notes(str(self.ui_path), lan)
                self.save_ui()
                log.warning("migrated %s (the old file is kept next to it as *.pre-0014 / *.pre-0019)", self.ui_path)
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

    def local_notes(self, policy, never: list[str] | tuple = ()) -> list[str]:
        """For the upgrade to ADR-0019: grant targets that name an address which was refused before and is
        reachable now while the grant is active. That is an address inside a blocked range without the old
        `lan` flag, and - with or without it - an address in the old never list (`never`: the built-in one and
        the entries of the gateway config), which no grant could reach. Locked addresses stay refused and are
        not named. Nothing is changed here - the operator is told, once, in the log."""
        out = []
        nets = [ipaddress.ip_network(c, strict=False) for c in never]
        for g in self.defs.values():
            for t in g.targets:
                ip = t.fixed()
                if not ip or policy.locked(ip, t.port):
                    continue
                addr = ip_addr(ip)
                if (g.name, t.host.lower().rstrip("."), t.port) in self._had_lan and not any(
                    addr.version == n.version and addr in n for n in nets
                ):
                    continue
                if block := policy.blocked_by(ip, t.port):
                    auto = [lv for lv, how in g.approval.items() if how == "auto"]
                    out.append(
                        f"NOTE grant {g.name}: target {t.host}:{t.port} names the address {ip} inside blocked range "
                        f"{block.cidr}. It was refused before; now it is reachable while the grant is active"
                        + (f" (approval for {', '.join(auto)} is automatic)" if auto else "")
                        + ". Delete the target if that is not wanted"
                    )
        return out

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
        ui = {n: g for n, g in self.defs.items() if g.source == "ui"}
        atomic_write(self.ui_path, yaml.safe_dump(destinations.grants_to_file(ui), sort_keys=False))

    def check_ui(self, name: str, d: dict) -> GrantDef:
        """Validate a UI grant definition without storing it. A target that names a locked address is refused
        here already; whether a target that is only a name resolves into a blocked range is checked by the
        Gateway (`check_grant`), which can resolve it."""
        if name in self.defs and self.defs[name].source == "config":
            raise ValueError(f"grant {name} is defined in the config file and cannot be changed in the UI")
        g = GrantDef.from_dict(name, d, "ui")
        for t in g.targets:
            if (ip := t.fixed()) and (why := locked_reason(ip, t.port, self.internal, self.own)):
                raise ValueError(f"grant {name}: {why}")
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
