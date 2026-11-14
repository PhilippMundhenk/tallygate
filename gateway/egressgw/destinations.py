"""The one destination model as a data format (ADR-0014, step 1).

Rules, read-only hosts, credential injection, repository limits and grants describe the same thing: what the
agent may do at a destination, when, and how. A `Destination` is one entry with a `match` and properties;
`translate(gw)` lists a gateway's current configuration and state as `Destination`s, so that the file format,
the converter, the API and the UI can all speak one model.

This module is **data only**. It defines the entries and reads a running `Gateway` into them; it decides
nothing. The evaluation path still lives in `model.Access`, which reads the old split structures directly.
A later step switches `Access` to read a `Model`; until then `translate` is exercised only by tests and the
converter, so introducing it cannot change enforcement.

How today's mechanisms map (ADR-0014 §1):

| Today | Destination field |
|---|---|
| rule `allow`/`ask`/`deny` (host or cidr, port) | `match`, `access` |
| the mode | `Model.default` (the final `match: {host: "*"}` entry, kept as `default` for readability) |
| grant | `access: request` plus `request` (name, levels, approval, durations) and the target's `scheme`/`paths`/`lan`/`address`/`tls` |
| `readonly` entry, grant level `read` | `methods` (+ `read_paths` for POSTs that only read) |
| `github_repos` | `repos` (the repository matcher of `github.RepoScope` applies to the host) |
| `inject`, grant `inject` | `credentials` |
| `never`, `grants_never`, `GW_INTERNAL_NETS` | `Model.never` (one additive list with a scope per entry) |

One matcher is used for every entry: `*.example.com` means the domain and its subdomains, as in rules today.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from egressgw.policy import Rule, valid_port_spec

if TYPE_CHECKING:
    from egressgw.core import Gateway

ACCESS = ("allow", "ask", "deny", "request")
# how a destination limits request methods (ADR-0014 §1 `methods`):
#   all            - no method limit
#   read           - only GET/HEAD/OPTIONS, no protocol upgrade (a grant's read level)
#   no-writes      - PUT/PATCH/DELETE refused, POST allowed (a read-only host, post_is_write off)
#   no-writes+post - PUT/PATCH/DELETE and POST refused, except POSTs on `read_paths` (post_is_write on)
METHODS = ("all", "read", "no-writes", "no-writes+post")


@dataclass
class Match:
    """What a destination matches: a host pattern or a CIDR, and a port spec (as in rules today)."""

    host: str | None = None
    cidr: str | None = None
    port: Any = "*"  # 443, [80, 443], "8000-8100" or "*"

    def validate(self) -> None:
        if not self.host and not self.cidr:
            raise ValueError("match needs 'host' or 'cidr'")
        if self.host and self.cidr:
            raise ValueError("match takes either 'host' or 'cidr', not both")
        items = self.port if isinstance(self.port, (list, tuple)) else [self.port]
        if not items or not all(valid_port_spec(p) for p in items):
            raise ValueError(f'invalid port {self.port!r} (use 443, [80, 443], "8000-8100" or "*")')

    def to_dict(self) -> dict:
        d: dict = {"host": self.host} if self.host else {"cidr": self.cidr}
        if self.port not in (None, "*"):
            d["port"] = self.port
        return d

    @classmethod
    def from_dict(cls, d: dict) -> Match:
        unknown = set(d) - {"host", "cidr", "port"}
        if unknown:
            raise ValueError(f"unknown match keys: {sorted(unknown)}")
        m = cls(host=d.get("host"), cidr=d.get("cidr"), port=d.get("port", "*"))
        m.validate()
        return m


@dataclass
class Request:
    """The `request` flow of a destination with `access: request` (today: a grant definition): the agent asks,
    a human (or `auto`) approves a level for a while, and it ends by itself."""

    name: str
    levels: list[str] = field(default_factory=lambda: ["read"])
    approval: dict[str, str] = field(default_factory=dict)
    default_ttl: int = 3600
    max_ttl: int = 4 * 3600

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "levels": list(self.levels),
            "approval": dict(self.approval),
            "default_ttl": self.default_ttl,
            "max_ttl": self.max_ttl,
        }

    @classmethod
    def from_dict(cls, d: dict) -> Request:
        unknown = set(d) - {"name", "levels", "approval", "default_ttl", "max_ttl"}
        if unknown:
            raise ValueError(f"unknown request keys: {sorted(unknown)}")
        return cls(
            name=str(d["name"]),
            levels=[str(lv) for lv in d.get("levels") or ["read"]],
            approval={str(k): str(v) for k, v in (d.get("approval") or {}).items()},
            default_ttl=int(d.get("default_ttl", 3600)),
            max_ttl=int(d.get("max_ttl", 4 * 3600)),
        )


@dataclass
class Destination:
    """One destination: a `match` and the properties that apply there. A properties-only entry (read-only,
    credentials, repository limits) has `access = None`: it adds limits to whatever host matches, it does not
    decide access by itself - exactly as `readonly`/`inject`/`github_repos` do today."""

    match: Match
    access: str | None = None  # allow | ask | deny | request | None (properties only)
    methods: str = "all"
    paths: list[str] | None = None  # None = every path
    read_paths: tuple[str, ...] = ()  # POSTs that only read (readonly `read_posts`)
    credentials: tuple[tuple[str, str], ...] = ()  # (header, value template) added after stripping
    repos: bool = False  # the github_repos repository matcher applies to this host
    request: Request | None = None  # set iff access == "request"
    scheme: str | None = None  # a request target's scheme (http | https | tcp)
    lan: bool = False  # exempt from the `all`-scope never floor, this target only
    address: str | None = None  # pinned IP of a request target
    tls_fingerprint: str | None = None
    tls_verify: bool = True
    note: str = ""
    expires: float | None = None  # unix ts, None = permanent
    id: str = ""
    source: str = "file"  # file | user | approval | preset | grant | config

    # Properties that can hand out secrets or open the local network (ADR-0014 §4): only the read-only config
    # file may set them. The API/UI may add entries and narrow them, never set these.
    FILE_ONLY = ("credentials", "lan", "tls_verify")

    def validate(self) -> None:
        self.match.validate()
        if self.access is not None and self.access not in ACCESS:
            raise ValueError(f"invalid access {self.access!r} (one of {list(ACCESS)} or null)")
        if self.methods not in METHODS:
            raise ValueError(f"invalid methods {self.methods!r} (one of {list(METHODS)})")
        if (self.access == "request") != (self.request is not None):
            raise ValueError("'request' is set exactly when access == 'request'")
        if self.scheme is not None and self.scheme not in ("http", "https", "tcp"):
            raise ValueError(f"invalid scheme {self.scheme!r}")

    def file_only_set(self) -> list[str]:
        """The file-only properties this entry sets, so a loader can reject them from the API/UI (§4)."""
        out = []
        if self.credentials:
            out.append("credentials")
        if self.lan:
            out.append("lan")
        if not self.tls_verify:
            out.append("tls.verify: false")
        return out

    def to_dict(self) -> dict:
        d: dict = {"match": self.match.to_dict()}
        if self.access is not None:
            d["access"] = self.access
        if self.methods != "all":
            d["methods"] = self.methods
        if self.paths is not None:
            d["paths"] = list(self.paths)
        if self.read_paths:
            d["read_paths"] = list(self.read_paths)
        if self.credentials:
            d["credentials"] = [{"header": h, "value": v} for h, v in self.credentials]
        if self.repos:
            d["repos"] = True
        if self.request is not None:
            d["request"] = self.request.to_dict()
        if self.scheme is not None:
            d["scheme"] = self.scheme
        if self.lan:
            d["lan"] = True
        if self.address:
            d["address"] = self.address
        if self.tls_fingerprint or not self.tls_verify:
            d["tls"] = {"fingerprint": self.tls_fingerprint, "verify": self.tls_verify}
        if self.note:
            d["note"] = self.note
        if self.expires is not None:
            d["expires"] = round(self.expires)
        if self.id:
            d["id"] = self.id
        if self.source != "file":
            d["source"] = self.source
        return d

    @classmethod
    def from_dict(cls, d: dict) -> Destination:
        known = {
            "match", "access", "methods", "paths", "read_paths", "credentials", "repos",
            "request", "scheme", "lan", "address", "tls", "note", "expires", "id", "source",
        }  # fmt: skip
        unknown = set(d) - known
        if unknown:
            raise ValueError(f"unknown destination keys: {sorted(unknown)}")
        if "match" not in d:
            raise ValueError("destination needs a 'match'")
        tls = d.get("tls") or {}
        if set(tls) - {"fingerprint", "verify"}:
            raise ValueError(f"unknown tls keys: {sorted(set(tls) - {'fingerprint', 'verify'})}")
        creds = tuple((str(c.get("header", "Authorization")), str(c["value"])) for c in (d.get("credentials") or []))
        dest = cls(
            match=Match.from_dict(d["match"]),
            access=d.get("access"),
            methods=str(d.get("methods", "all")),
            paths=[str(p) for p in d["paths"]] if d.get("paths") is not None else None,
            read_paths=tuple(str(p) for p in d.get("read_paths") or ()),
            credentials=creds,
            repos=bool(d.get("repos", False)),
            request=Request.from_dict(d["request"]) if d.get("request") is not None else None,
            scheme=d.get("scheme"),
            lan=bool(d.get("lan", False)),
            address=str(d["address"]) if d.get("address") else None,
            tls_fingerprint=(str(tls["fingerprint"]) if tls.get("fingerprint") else None),
            tls_verify=bool(tls.get("verify", True)),
            note=str(d.get("note", "")),
            expires=d.get("expires"),
            id=str(d.get("id", "")),
            source=str(d.get("source", "file")),
        )
        dest.validate()
        return dest


@dataclass
class Model:
    """A whole configuration as destinations: the ordered entries, the mode (the final `*` entry), and the
    one never-reachable list."""

    destinations: list[Destination] = field(default_factory=list)
    default: str = "ask"  # the mode
    never: list[dict] = field(default_factory=list)  # [{range, scope}] with scope all | all+lan

    def to_dict(self) -> dict:
        return {
            "default": self.default,
            "destinations": [d.to_dict() for d in self.destinations],
            "never": list(self.never),
        }


def _readonly_methods(post_is_write: bool) -> str:
    return "no-writes+post" if post_is_write else "no-writes"


def translate(gw: Gateway) -> Model:
    """List a running gateway's configuration and state as one ordered destination model (ADR-0014 §1).

    Access entries (rules, grants) keep their order; property entries (read-only, credentials, repositories)
    are listed after them, as they apply on top of whatever access matched - the same layering the current
    `Access.host_limits` does. Nothing here decides; it only mirrors the live structures into the model."""
    dests: list[Destination] = []

    # Access: the rules, in order. Their source (user/approval/preset) is kept.
    for r in gw.policy.rules:
        dests.append(
            Destination(
                match=Match(host=r.host, cidr=r.cidr, port=r.port),
                access=r.action,
                note=r.note,
                expires=r.expires,
                id=r.id,
                source=r.source,
            )
        )

    # Access: grants become `access: request` destinations, one per target.
    for g in gw.grants.defs.values():
        for t in g.targets:
            creds = tuple(
                (i.get("header", "Authorization"), i["value"])
                for i in g.inject
                if i["host"] == t.host and t.scheme == "https"
            )
            dests.append(
                Destination(
                    match=Match(host=t.host, port=t.port),
                    access="request",
                    request=Request(g.name, list(g.levels), dict(g.approval), g.default_ttl, g.max_ttl),
                    paths=None if t.scheme == "tcp" else list(t.paths),
                    credentials=creds,
                    scheme=t.scheme,
                    lan=t.lan,
                    address=t.address,
                    tls_fingerprint=t.tls_fingerprint,
                    tls_verify=t.tls_verify,
                    note=g.description,
                    source=g.source,
                )
            )

    # Properties only, from the read-only config file: read-only hosts, repositories, credentials.
    dests += file_destinations(gw)

    return Model(destinations=dests, default=gw.policy.default, never=_never(gw))


def file_destinations(gw: Gateway) -> list[Destination]:
    """The properties-only destinations from the read-only gateway config (read-only hosts, repository scope,
    credentials). They carry no `access`: they add limits to whatever host matches, as `readonly`/`inject`/
    `github_repos` do today. The config is read-only at runtime, so this is stable and can be built once."""
    dests: list[Destination] = []
    for ro in gw.readonly:
        dests.append(
            Destination(
                match=Match(host=ro.host),
                methods=_readonly_methods(ro.post_is_write),
                read_paths=tuple(ro.read_posts),
                source="file",
            )
        )
    if gw.github.patterns:
        for host in sorted(gw.github.hosts):
            dests.append(Destination(match=Match(host=host), repos=True, source="file"))
    for i in gw.inject:
        header = i.get("header", "Authorization")
        dests.append(
            Destination(
                match=Match(host=i["host"].lower().rstrip(".")),
                credentials=((header, i["value"]),),
                source="file",
            )
        )
    return dests


def _never(gw: Gateway) -> list[dict]:
    """The never-reachable ranges as one additive list with a scope each (ADR-0014 §3). `all` ranges (the
    policy's `hard_deny`) may be exempted by a `lan: true` target; `all+lan` ranges cannot: those are the
    built-in LAN floor plus its configured additions (`gw.grants.never`) and the stack's own networks
    (`gw.grants.internal`, today `GW_INTERNAL_NETS`)."""
    out = [{"range": c, "scope": "all"} for c in gw.policy.hard_deny]
    out += [{"range": str(n), "scope": "all+lan"} for n in gw.grants.never]
    out += [{"range": str(n), "scope": "all+lan"} for n in gw.grants.internal]
    return out


def from_rules(rules: list[Rule]) -> list[Destination]:
    """The access destinations for a list of rules (used by tests and the converter)."""
    return [
        Destination(
            match=Match(host=r.host, cidr=r.cidr, port=r.port),
            access=r.action,
            note=r.note,
            expires=r.expires,
            id=r.id,
            source=r.source,
        )
        for r in rules
    ]
