"""One destination model and one evaluation path (ADR-0014).

Rules, read-only hosts, credential injection, repository limits and grants all answer the same question:
what may the agent do at this destination, now? Here they are properties of one thing.

- A `Verdict` is what was decided for one upstream connection: the checked name (or IP literal) and, if a
  grant carries the connection, which one.
- `Limits` are everything that applies to single requests on that connection, whatever defined it: the
  scheme and Host it must use, the paths, the methods, the credentials that are stripped and added.

What is answered here and nowhere else:

- `Access.on_name` / `Access.on_addresses`: the decision for a connection, on the name before it is resolved
  and again with its addresses (hard deny, rules, the mode, learning mode); `Access.grant_for` and
  `Access.grant_problem` for a connection an active grant carries.
- `Access.tls`: is the connection intercepted, passed through, or refused? It follows from the limits
  (anything with limits is intercepted), and a destination that has limits cannot be reached around them by
  its IP address.
- `Access.check`: may this request go out, and with which headers?

The module has no I/O and does not know mitmproxy: `core.py` resolves names, asks you, turns flows into `Req`
and applies the outcome.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from egressgw.grants import READ_METHODS, Target, path_ok
from egressgw.learning import REASON as LEARNING
from egressgw.policy import Decision, ip_addr, is_ip, valid_hostname
from egressgw.store import render

if TYPE_CHECKING:
    from egressgw.core import Gateway

WRITE_METHODS = frozenset({"PUT", "PATCH", "DELETE"})

INTERCEPT = "intercept"
PASSTHROUGH = "passthrough"


@dataclass(frozen=True)
class Verdict:
    """What was decided for one upstream connection that is allowed."""

    host: str  # the checked name (lower case, no trailing dot) or the IP literal
    port: int
    grant: str | None = None  # id of the active grant that carries the connection
    target: Target | None = None  # that grant's target


@dataclass(frozen=True)
class Req:
    """The parts of an HTTP request the limits look at."""

    method: str
    scheme: str
    path: str
    host_header: str | None  # the Host header or :authority as sent, None if absent
    pretty_host: str  # mitmproxy's pretty_host: the Host header if present, else the URL host
    connection: str = ""  # the Connection header (for "upgrade")


@dataclass
class Limits:
    """Everything that applies to single requests at one destination."""

    host: str
    grant: str | None = None  # name of the grant, for the messages
    gone: bool = False  # the grant has ended: nothing passes any more
    raw: bool = False  # raw TCP: no request is looked at
    https_only: bool = False  # plain HTTP is refused
    host_required: bool = False  # the Host must be the destination even when the header is absent
    paths: list[str] | None = None
    read_level: bool = False  # only GET/HEAD/OPTIONS, no protocol upgrade (a grant's read level)
    no_writes: bool = False  # PUT/PATCH/DELETE refused (a read-only host)
    post_is_write: bool = False
    read_posts: tuple[str, ...] = ()
    repos: bool = False  # the repository limits of github_repos apply
    strip: tuple[str, ...] = ()  # the agent's own headers that are removed
    add: tuple[tuple[str, str], ...] = ()  # (header, value template) added after stripping
    add_needs_https_host: bool = False  # add only over TLS and only if the Host is the destination

    @property
    def any(self) -> bool:
        """True if single requests have to be looked at: the connection is intercepted."""
        return bool(
            self.grant or self.paths or self.read_level or self.no_writes or self.repos or self.strip or self.add
        )


@dataclass
class Outcome:
    refuse: str | None = None
    strip: tuple[str, ...] = ()
    add: list[tuple[str, str]] = field(default_factory=list)  # (header, rendered value)


class Access:
    """The model over a gateway's configuration and state. It reads them and decides; it changes nothing."""

    def __init__(self, gw: Gateway) -> None:
        self.gw = gw

    # ---------------------------------------------------------------- the connection
    @staticmethod
    def checked_name(host: str) -> str | None:
        """The name as rules and prompts use it (punycode, lower case, no trailing dot), or None if it is not a
        valid host name. mitmproxy hands IDNs over decoded."""
        if not host.isascii():
            try:
                host = host.encode("idna").decode("ascii")
            except UnicodeError:
                return None
        return host.lower().rstrip(".") if valid_hostname(host) else None

    def on_name(self, host: str, port: int) -> Decision:
        """The decision on the name alone, before any lookup: denied and not-yet-approved names are never
        resolved. Learning mode replaces the mode when no rule matched and no grant is defined for it."""
        dec = self.gw.policy.evaluate_name(host, port)
        if dec.rule_id is None and not self.grant_hint(host, port) and self.gw.learning.covers(port):
            return Decision("allow", LEARNING)
        return dec

    def on_addresses(self, host: str, port: int, ips: list[str], proto: str = "", learning: bool = False) -> Decision:
        """The decision with the addresses: hard deny, CIDR deny rules, the rules, the mode. With `learning`
        (the name was let through by learning mode) learning mode replaces the mode again; the hard deny and
        every rule still decide first."""
        dec = self.gw.policy.evaluate(host, port, ips, proto)
        if learning and dec.rule_id is None and self.gw.learning.covers(port):
            return Decision("allow", LEARNING)
        return dec

    def grant_for(self, host: str, port: int):
        """(active, definition, target) of the grant that carries a connection to host:port, or None.
        Grants only ADD access: a name the rules already allow uses the rules, except for a LAN target, which
        the rules can never reach (hard deny), e.g. with the `open` preset active. IP literals always use it."""
        m = self.gw.grants.match(host, port)
        if m and not m[2].lan and not is_ip(host) and self.gw.policy.evaluate_name(host, port).action == "allow":
            return None
        return m

    def grant_hint(self, host: str, port: int) -> str | None:
        names = self.gw.grants.defined_for(host, port)
        return f"available via grant {', '.join(names)} (agent: tallygate request {names[0]})" if names else None

    def request_without_verdict(self, host: str, port: int, scheme: str) -> tuple[Verdict | None, str | None]:
        """A request on a connection that has no stored verdict: a plain-HTTP proxy request (its hooks run
        before the server connection exists). The destination is the request's own host, which the agent
        chose, so it is re-authorised here rather than trusted (#137). Returns (verdict, None), or (None,
        reason) to refuse."""
        if scheme == "https":
            # A legitimate https request arrives through a CONNECT tunnel, where server_connect has gated the
            # destination and stored a verdict, and TLS is intercepted or bound to the SNI. No verdict here
            # means an absolute-form `https://` proxy request, which skips all of that and would be checked
            # against the host it names rather than the connection's checked target (#137).
            return None, "https over the plain proxy must use CONNECT"
        m = self.grant_for(host, port)
        return (Verdict(host, port, m[0].id, m[2]) if m else Verdict(host, port)), None

    @staticmethod
    def grant_addresses(t: Target, host: str) -> list[str] | None:
        """The addresses of a grant target that need no lookup (a pinned address, an IP literal), else None."""
        if t.address:
            return [t.address]
        if is_ip(host):
            return [host.strip("[]")]
        return None

    def grant_problem(self, g, t: Target, host: str, port: int, ips: list[str]) -> str | None:
        """Why a grant connection to these addresses is refused, or None: never-reachable ranges for grants,
        `grants_lan_allow` for UI grants, and for a target without `lan` the hard deny as for any connection."""
        problem = self.gw.grants.address_problem(g, t, ips)
        if not problem and not t.lan:
            problem = self.gw.policy.hard_denied(host, port, ips)
        if not problem and not ips:
            problem = "no address"
        return problem

    # ---------------------------------------------------------------- limits of a destination
    def host_limits(self, host: str) -> Limits:
        """The limits a destination has by itself (from the read-only gateway config): read-only, credentials,
        repositories. `host` is a checked name; an IP literal has none. Decided from the destination model
        (`gw.file_model`), not from the config lists directly (ADR-0014)."""
        from egressgw import decide  # local: decide imports Limits from this module

        return decide.host_limits(self.gw.file_model, host, self.gw.strip_headers)

    def grant_limits(self, v: Verdict, now: float | None = None) -> Limits:
        """The limits of a connection carried by a grant: the target's scheme and paths, the level that was
        approved, the grant's credentials; plus the repository limits of the host, which a grant never widens."""
        gw, t = self.gw, v.target
        if t.scheme == "tcp":
            return Limits(host=v.host, raw=True)
        a = gw.grants.active.get(v.grant)
        g = gw.grants.defs.get(a.name) if a else None
        if a is None or g is None or a.expires <= (now or time.time()):
            return Limits(host=v.host, grant="?", gone=True)
        lim = Limits(host=v.host, grant=g.name, https_only=t.scheme == "https", host_required=True, paths=t.paths)
        lim.read_level = a.level == "read"
        lim.repos = gw.github.applies(v.host)
        rules = [i for i in g.inject if i["host"] == v.host and t.scheme == "https"]
        if rules or v.host in gw.inject_hosts:  # never forward the agent's own credentials to these hosts
            own = [i.get("header", "Authorization") for i in gw.inject if i["host"].lower().rstrip(".") == v.host]
            lim.strip = tuple(dict.fromkeys([*gw.strip_headers, *own, *(i["header"] for i in rules)]))
            lim.add = tuple((i["header"], i["value"]) for i in rules)
        return lim

    def limits(self, v: Verdict, now: float | None = None) -> Limits:
        return self.grant_limits(v, now) if v.grant else self.host_limits(v.host)

    def intercepted(self, host: str) -> bool:
        """A destination with limits of its own is always intercepted, whatever the client's SNI says."""
        return self.host_limits(host).any

    # ---------------------------------------------------------------- TLS: intercept, pass through or refuse
    def tls(self, v: Verdict | None, sni: str) -> tuple[str, str | None]:
        """(INTERCEPT | PASSTHROUGH, None), or (PASSTHROUGH, reason) when the passthrough must be refused."""
        if v is None:
            return PASSTHROUGH, "TLS without a checked destination"
        if v.grant:
            # http(s) grant targets are always intercepted so that every request is checked; tcp is raw
            return (PASSTHROUGH if v.target.scheme == "tcp" else INTERCEPT), None
        if self.intercepted(v.host):
            return INTERCEPT, None
        return PASSTHROUGH, self.passthrough_problem(v.host, v.port, sni)

    def passthrough_problem(self, host: str, port: int, sni: str) -> str | None:
        """Why TLS to `host` must not be passed through with this SNI, or None (ADR-0013).
        - name: the SNI must be that name. A missing SNI, another name or an ECH outer name is refused.
        - IP literal: an address of a destination that has limits is refused (reach it by name, where the
          limits apply). Otherwise no SNI is normal, and an SNI name passes only if the rules allow that name
          by itself on this port and it has no limits of its own."""
        if not is_ip(host):
            return None if sni == host else f"TLS SNI {sni or '(none)'} does not match the checked name {host}"
        if self.gw._is_intercept_ip(host):
            return f"IP {host} is an intercepted host; reach it by name, not by IP literal"
        if not sni or (is_ip(sni) and ip_addr(sni) == ip_addr(host)):
            return None
        if valid_hostname(sni) and self.gw.policy.evaluate_name(sni, port).action == "allow":
            if self.intercepted(sni):
                return f"TLS SNI {sni} names an intercepted host; reach it by name, not by IP literal"
            return None
        return f"TLS SNI {sni} on IP {host} is not allowed by the rules"

    # ---------------------------------------------------------------- raw traffic on a connection
    def raw_problem(self, v: Verdict | None) -> str | None:
        """Non-HTTP traffic on the connection: only a tcp grant target carries it. (Connections without a
        grant are not intercepted, so mitmproxy never reports raw traffic for them.)"""
        if v and v.grant and v.target.scheme != "tcp":
            return "non-HTTP traffic to an HTTP grant target"
        return None

    def grant_live(self, v: Verdict | None, now: float | None = None) -> bool:
        """True while the grant carrying this connection is still active (not revoked or expired)."""
        if not v or not v.grant:
            return True  # not a grant connection: nothing to end
        a = self.gw.grants.active.get(v.grant)
        return a is not None and a.expires > (now or time.time())

    def websocket_problem(self, v: Verdict | None) -> str | None:
        if v and v.grant:
            a = self.gw.grants.active.get(v.grant)
            if a is not None and a.level == "read":
                return "websocket on a read-only grant"
        return None

    # ---------------------------------------------------------------- one check for every request
    def check(self, v: Verdict, r: Req, now: float | None = None) -> Outcome:
        """May this request go out on the connection decided by `v`, and with which headers?"""
        lim = self.limits(v, now)
        if lim.raw:
            return Outcome()
        if lim.gone:
            return Outcome("grant expired or revoked")
        if lim.https_only and r.scheme != "https":
            return Outcome("plain HTTP to an https grant target")
        sent = r.pretty_host.lower().rstrip(".")
        if lim.host_required:
            if sent != lim.host:
                return Outcome("Host header does not match the granted target")
        elif r.host_header and not _same_host(sent.strip("[]"), lim.host):
            # On a shared CDN or virtual-host server the Host picks the site: another name would reach a
            # destination nobody checked (#57). Without a Host the upstream serves its default site.
            return Outcome("Host header does not match the checked target")
        if lim.paths is not None and not path_ok(r.path, lim.paths):
            return Outcome(f"path not covered by grant {lim.grant}")
        method = r.method.upper()
        if lim.read_level and (method not in READ_METHODS or "upgrade" in r.connection.lower()):
            return Outcome(f"grant {lim.grant} is read-only")
        if lim.no_writes and (
            is_write(method, r.path, lim.post_is_write, lim.read_posts) or "upgrade" in r.connection.lower()
        ):
            # a WebSocket or other protocol upgrade on a read-only host is a channel the gateway cannot inspect
            return Outcome("read-only host")
        if lim.repos and (why := self.gw.github.check(lim.host, r.method, r.path)):
            return Outcome(why)  # another repository: refused before it reaches GitHub, before any token is added
        out = Outcome(strip=lim.strip)
        if lim.add and (not lim.add_needs_https_host or (r.scheme == "https" and sent == lim.host)):
            for header, template in lim.add:
                value = render(template, self.gw.secrets)
                if value is not None:  # secret not configured: the request goes out without credentials
                    out.add.append((header, value))
        return out


def is_write(method: str, path: str, post_is_write: bool, read_posts) -> bool:
    """A request that a read-only destination refuses: PUT, PATCH, DELETE, and POST where it counts as a write
    (except on the `read_posts` paths: POSTs that only read, e.g. a search or a batch lookup)."""
    method = method.upper()
    return method in WRITE_METHODS or (method == "POST" and post_is_write and not path_ok(path, list(read_posts)))


def _same_host(sent: str, host: str) -> bool:
    host = host.strip("[]")
    return sent == host or (is_ip(sent) and is_ip(host) and ip_addr(sent) == ip_addr(host))
