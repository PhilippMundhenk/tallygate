"""mitmproxy addon: single enforcement point for all egress.

Every upstream connection (HTTP proxy CONNECT, plain HTTP, SOCKS5, reverse:tcp service
ports) passes through `server_connect`, where the policy is evaluated on the requested
host:port *and* its resolved IPs. Hostnames are decided on the name first and only resolved
once the policy (or a human) allows them, so denied/pending names never leak through DNS.
Allowed hostnames are pinned to the checked IP to defeat DNS rebinding. TLS is passed through
untouched when its SNI matches the checked name, except for hosts configured for credential injection
or read-only access, which are intercepted (the agent never sees injected secrets; its own credentials
for those hosts are stripped). HTTP requests must name the checked target in their Host header.
"""

from __future__ import annotations

import asyncio
import contextlib
import functools
import inspect
import logging
import os
import socket
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from mitmproxy import ctx, dns, http, tls
from mitmproxy.net.dns import response_codes
from mitmproxy.proxy import server_hooks

from egressgw import api, destinations
from egressgw.activity import Activity
from egressgw.availability import Availability, Unavailable
from egressgw.github import RepoScope
from egressgw.grants import Grants
from egressgw.history import PolicyHistory
from egressgw.learning import REASON as LEARNING
from egressgw.learning import Learning, parse_ports
from egressgw.model import INTERCEPT, Access, Req, Verdict
from egressgw.policy import (
    DEFAULT_HARD_DENY,
    Decision,
    Exception_,
    Policy,
    ip_addr,
    is_ip,
    load_preset,
    parse_cidrs,
    parse_never,
    registrable_domain,
    rule_for_approval,
    valid_hostname,
)
from egressgw.readonly import parse_readonly
from egressgw.store import EventLog, Secrets

log = logging.getLogger("egressgw")

DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
CONFIG_PATH = Path(os.environ.get("GW_CONFIG", DATA_DIR / "config.yaml"))
PRESET_DIR = Path(os.environ.get("PRESET_DIR", Path(__file__).resolve().parent.parent / "presets"))
CA_EXPORT = Path(os.environ.get("CA_EXPORT_DIR", "/ca"))
NEG_CACHE_SECONDS = 60
DUP_WINDOW = 2.0  # identical events within this window are counted, not stored (log-flood protection)
# TEST ONLY: "name=ip,name=ip" static resolution used by the e2e test-suite instead of /etc/hosts.
# Never set this in production; the gateway logs a loud warning when it is active.
STATIC_HOSTS = dict(kv.split("=", 1) for kv in os.environ.get("GW_TEST_STATIC_HOSTS", "").split(",") if "=" in kv)
# TEST ONLY: the configured hard_deny_floor replaces the built-in list (the e2e upstreams live on 127.0.0.1).
FLOOR_REPLACE = os.environ.get("GW_TEST_FLOOR_REPLACE") == "1"


def fail_closed(hook):
    """mitmproxy only logs an exception raised in an addon hook and then carries on, i.e. the connection
    would go out unchecked. Every hook is therefore wrapped: any error refuses the connection or flow."""

    def refuse(self, data) -> None:
        log.exception("%s failed - refusing the connection (fail closed)", hook.__name__)
        if isinstance(data, server_hooks.ServerConnectionHookData):
            data.server.error = "egress policy: internal error (fail closed)"
        elif isinstance(data, tls.ClientHelloData):
            data.ignore_connection = False  # no passthrough; the TLS handshakes are then failed on purpose
            with contextlib.suppress(Exception):
                self.tls_refused.add(data.context.server.id)
        elif getattr(data, "killable", False):
            data.kill()  # http/tcp/websocket/dns flows

    if inspect.iscoroutinefunction(hook):

        @functools.wraps(hook)
        async def wrapper(self, data):
            try:
                return await hook(self, data)
            except Exception:  # noqa: BLE001 - any error must refuse, never pass traffic through
                refuse(self, data)

    else:

        @functools.wraps(hook)
        def wrapper(self, data):
            try:
                return hook(self, data)
            except Exception:  # noqa: BLE001 - any error must refuse, never pass traffic through
                refuse(self, data)

    return wrapper


def _refusing_tls(server_side: bool):
    """A TLS connection object that cannot complete a handshake (no certificate, no SNI): used to refuse
    a TLS connection from the TLS hooks, which offer no other way to close it."""
    from OpenSSL import SSL

    conn = SSL.Connection(SSL.Context(SSL.TLS_METHOD))
    if server_side:
        conn.set_accept_state()
    else:
        conn.set_connect_state()
    return conn


def _body_buffered(req: http.Request) -> bool:
    """True if mitmproxy reads this request's whole body before forwarding it, so that a 403 can be sent
    instead. Bodies over stream_large_bodies (already marked `stream`) and bodies of unknown size (chunked,
    HTTP/2 without Content-Length) may be streamed upstream before the `request` hook."""
    if req.stream or "transfer-encoding" in req.headers:
        return False
    length = req.headers.get("content-length")
    if length is None:
        return req.http_version.startswith("HTTP/1")  # HTTP/1 without either header has no body
    return length.strip().isdigit()


@dataclass
class Pending:
    host: str
    port: int
    ips: list[str]
    proto: str
    client: str
    timeout: int
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:10])
    created: float = field(default_factory=time.time)
    attempts: int = 1
    future: asyncio.Future | None = None
    context: list = field(default_factory=list)  # what the agent said it was doing (#74): a claim, untrusted

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "host": self.host,
            "domain": None if is_ip(self.host) else registrable_domain(self.host),
            "idn": any(label.startswith("xn--") for label in self.host.split(".")),
            "port": self.port,
            "ips": self.ips,
            "proto": self.proto,
            "client": self.client,
            "created": self.created,
            "expires": self.created + self.timeout,
            "attempts": self.attempts,
            "context": self.context,
        }


class Gateway:
    def __init__(self) -> None:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        self.config = yaml.safe_load(CONFIG_PATH.read_text()) if CONFIG_PATH.exists() else {}
        self.config = self.config or {}
        self._read_destinations()  # ADR-0014: a `destinations:` block feeds the old keys the parsers expect
        self.policy_path = DATA_DIR / "policy.yaml"
        # The hard-deny floor comes only from the (read-only mounted) static config, never from the API:
        # the built-in list plus `hard_deny_floor`. Validated here: a broken entry must stop the gateway.
        # `never` in the config (ADR-0014; the old keys hard_deny_floor and grants_never are still read). Every
        # range closes all connections; the `all+lan` ones also close LAN grant targets (see Grants).
        every, lan, self.old_never_keys = parse_never(self.config)
        configured = parse_cidrs([*every, *lan], "never")
        builtin = [] if FLOOR_REPLACE and configured else DEFAULT_HARD_DENY
        self.hard_deny_floor = parse_cidrs([*builtin, *configured], "never")
        self.floor_configured = [c for c in configured if c not in builtin]  # for the "never reachable" view
        self.history = PolicyHistory(DATA_DIR / "policy-history.db", int(self.config.get("policy_history_keep", 500)))
        if not self.policy_path.exists():
            initial = self.config.get("initial_preset", "baseline")
            preset = PRESET_DIR / f"{initial}.yaml"
            self.policy = load_preset(preset)[1] if preset.exists() else Policy()
            self.policy.save(self.policy_path)
            what = f"initial policy (preset {initial})"
        else:
            self.policy = Policy.load(self.policy_path)
            what = (
                "policy.yaml changed while the gateway was stopped"
                if self.history.latest
                else "policy at gateway start"
            )
        self.adopt(self.policy)
        self._history("gateway", what)  # nothing is stored when it equals the latest version
        self.events = EventLog(
            DATA_DIR / "events.db",
            int(self.config.get("log_keep_days", 30)),
            int(self.config.get("log_max_events", 500_000)),
        )
        self.secrets = Secrets(DATA_DIR / "secrets.json")
        self.learning = Learning(
            self.events.db,
            parse_ports(self.config.get("learning_ports", [80, 443])),
            int(self.config.get("learning_max_minutes", 120)),
        )
        self.inject = [dict(i) for i in self.config.get("inject") or []]
        self.inject_hosts = {i["host"].lower().rstrip(".") for i in self.inject}
        self.readonly = parse_readonly(self.config.get("readonly") or [])
        self.github = RepoScope(self.config)  # github_repos (#78); an invalid entry stops the gateway
        self.strip_headers = [str(h) for h in self.config.get("inject_strip_headers") or ["Authorization", "Cookie"]]
        # the read-only config's destination properties as one model (ADR-0014); built once, the config does
        # not change at runtime. A destination's own request limits are decided from this (decide.host_limits).
        self.file_model = destinations.file_destinations(self.readonly, self.github, self.inject)
        self.max_pending = int(self.config.get("max_pending", 10))
        # rule usage (#70): matches per rule id since the last flush to the event log, as [count, last ts]
        self.hits: dict[str, list] = {}
        self.stale_days = int(self.config.get("rule_stale_days", 30))
        self.suggest_min = int(self.config.get("suggest_min_approvals", 3))
        self.suggest_days = int(self.config.get("suggest_window_days", 7))
        self._dups: dict[tuple, list] = {}
        self.grants = Grants(self.config, DATA_DIR)
        self.availability = Availability(self.config, DATA_DIR)
        self.activity = Activity()
        self._unavailable = self.availability.mode()[0]  # last state seen by availability_tick
        self._grant_events: dict[str, asyncio.Event] = {}
        self.pending: dict[tuple[str, int], Pending] = {}
        self.neg_cache: dict[tuple[str, int], float] = {}
        # server connection ids whose TLS is refused (SNI does not match the checked name): both handshakes fail
        self.tls_refused: set[str] = set()
        # What was decided per upstream connection (server connection id -> Verdict), and the one model that
        # says what follows from it: interception, and what each request may do (ADR-0014, model.py).
        self.verdicts: dict[str, Verdict] = {}
        self.access = Access(self)
        # IPs the configured intercept hosts (inject / read-only / scoped GitHub) resolve to. Interception is
        # keyed on the NAME, so an IP-literal connection to one of these would skip credential strip/injection
        # and the read-only check, with no SNI needed (#108, no-SNI variant). Such connections are refused so
        # the agent must use the name. Filled proactively, on a timer, and as intercept hosts are used by name.
        self.intercept_ips: set = set()
        self.subscribers: set[asyncio.Queue] = set()
        self.api_token = os.environ.get("GW_API_TOKEN", "")
        self._tasks: list[asyncio.Task] = []

    def _read_destinations(self) -> None:
        """ADR-0014 §5: a `destinations:` block in the gateway config is an alternative to the old property
        keys. It is translated in memory into those keys (`readonly`/`inject`/`github_*`/`grants`) so the
        rest of the gateway is unchanged. To keep the meaning unambiguous it may not be mixed with them; a
        broken entry stops the gateway (fail closed), as the old keys do. `python -m egressgw.convert` writes
        a config in this form."""
        entries = self.config.get("destinations")
        if not entries:
            return
        clash = [k for k in destinations.CONFIG_KEYS if self.config.get(k)]
        if clash:
            raise ValueError(
                f"`destinations:` cannot be combined with the old keys {clash}; convert the whole file "
                "(python -m egressgw.convert <config>)"
            )
        if not isinstance(entries, list):
            raise ValueError("destinations: expected a list of entries")
        dests = [destinations.Destination.from_dict(e) for e in entries]
        self.config.update(destinations.destinations_to_config(dests))
        del self.config["destinations"]

    def adopt(self, policy: Policy) -> Policy:
        """Attach the static parts (floor, service exceptions) to a policy loaded from file/API."""
        policy.use_floor(self.hard_deny_floor)
        self.policy = policy
        self._apply_service_exceptions()
        return policy

    def never_reachable(self) -> list[dict]:
        """Every range that is never reachable, from all the places that define one, for one view in the UI.
        `scope` is "all" (every connection; a LAN grant target may be exempt) or "all+lan" (LAN grant targets
        included). Read-only: this reports what is enforced, it decides nothing."""
        own = set(self.floor_configured)
        lan = {str(n) for n in self.grants.never}
        floor = set(self.hard_deny_floor)

        def row(cidr: str, source: str) -> dict:
            return {"range": cidr, "source": source, "scope": "all+lan" if cidr in lan else "all"}

        out = [row(c, "config" if c in own else "builtin") for c in self.hard_deny_floor]
        configured_lan = {str(n) for n in self.grants.never_configured}
        out += [  # closed for grants although not in the floor (only with the test-only floor switch)
            {"range": str(n), "source": "config" if str(n) in configured_lan else "builtin", "scope": "all+lan"}
            for n in self.grants.never
            if str(n) not in floor
        ]
        out += [{"range": c, "source": "policy", "scope": "all"} for c in self.policy.hard_deny]
        out += [{"range": str(n), "source": "stack", "scope": "all+lan"} for n in self.grants.internal]
        out += [
            {"range": f"{ip}:{port}", "source": "listener", "scope": "all+lan"}
            for ip, port in sorted(self.grants.own, key=lambda s: (str(s[0]), s[1]))
        ]
        return out

    def _apply_service_exceptions(self) -> None:
        self.policy.exceptions = []
        for s in self.config.get("services") or []:
            if s.get("allow_private"):
                host, port = s["target"].rsplit(":", 1)
                self.policy.exceptions.append(Exception_(host=host.strip("[]"), port=int(port)))

    # ------------------------------------------------------------------ lifecycle
    async def running(self) -> None:
        if STATIC_HOSTS:
            log.warning("GW_TEST_STATIC_HOSTS is set - test-only name resolution is ACTIVE: %s", STATIC_HOSTS)
        if FLOOR_REPLACE:
            log.warning("GW_TEST_FLOOR_REPLACE is set - the built-in hard-deny floor is NOT active (test only)")
        if self.old_never_keys:
            log.warning(
                "gateway config: %s still work, but are read as `never` now; see docs/configuration.md "
                "(python -m egressgw.convert prints the file in the new form)",
                " and ".join(self.old_never_keys),
            )
        if len(self.api_token) < 24:
            log.warning("GW_API_TOKEN missing or shorter than 24 chars - API disabled")
        else:
            host = os.environ.get("GW_API_HOST", "127.0.0.1")
            port = int(os.environ.get("GW_API_PORT", "8081"))
            await api.start(self, host, port)
            log.warning("egressgw API listening on %s:%s", host, port)
        from egressgw import agentapi

        ahost = os.environ.get("GW_LISTEN_HOST", "127.0.0.1")
        aport = int(os.environ.get("GW_GRANTS_PORT", "8079"))
        await agentapi.start(self, ahost, aport)
        log.warning("grant request API for the agent listening on %s:%s", ahost, aport)
        self._export_ca()
        await self._refresh_intercept_ips()  # know the intercept hosts' IPs before the first connection
        self._tasks.append(asyncio.create_task(self._housekeeping()))

    def done(self) -> None:
        for t in self._tasks:
            t.cancel()

    def _export_ca(self) -> None:
        src = Path(ctx.options.confdir).expanduser() / "mitmproxy-ca-cert.pem"
        try:
            CA_EXPORT.mkdir(parents=True, exist_ok=True)
            (CA_EXPORT / "egress-gw-ca.pem").write_bytes(src.read_bytes())
        except OSError as e:
            log.warning("could not export CA cert: %s", e)

    async def _housekeeping(self) -> None:
        last_ip_refresh = time.monotonic()
        while True:
            await asyncio.sleep(15)
            try:
                self._housekeep()
                if time.monotonic() - last_ip_refresh > 600:  # re-resolve intercept hosts (CDN IPs rotate)
                    last_ip_refresh = time.monotonic()
                    await self._refresh_intercept_ips()
            except Exception:  # keep the loop alive; the error is logged
                log.exception("housekeeping failed")

    def _housekeep(self) -> None:
        if self.policy.prune_expired():
            self.save_policy("gateway", "expired rules removed")
        now = time.time()
        self.neg_cache = {k: v for k, v in self.neg_cache.items() if v > now}
        self._flush_dups(now)
        self.flush_hits()
        if self.learning.expired():
            self.end_learning("gateway", "time is up")
        self.events.enforce_cap()
        expired, timed_out = self.grants.prune()
        for a in expired:
            self.record(kind="grant", host=a.name, action="expired", reason=f"grant {a.name} ({a.level}) expired")
        for r in timed_out:
            self.record(kind="grant", host=r.name, action="deny", reason=f"grant request {r.id} timed out")
            self._grant_resolved(r)
        if expired:
            self.publish({"type": "grants"})
        self.availability_tick(now)

    # ------------------------------------------------------------------ availability (#73)
    def availability_tick(self, now: float | None = None) -> None:
        """Called by housekeeping and after every change: when nobody can answer any more, what is waiting
        is denied; when the operator is back (or periodically while away), the digest goes out."""
        now = time.time() if now is None else now
        if self.availability.expire_away(now):
            self.record(kind="admin", action="availability", reason="away period ended")
        mode = self.availability.mode(now)[0]
        was, self._unavailable = self._unavailable, mode
        if mode != "available" and was == "available":
            self._deny_waiting(self.availability.blocking(now) or mode)
            self.publish({"type": "availability"})
        elif mode == "available" and was != "available":
            self._digest("away ended" if was == "away" else "quiet hours ended")
            self.publish({"type": "availability"})
        elif mode != was:  # quiet hours <-> away
            self.publish({"type": "availability"})
        elif self.availability.digest_due(now):
            self._digest("while away")

    def _deny_waiting(self, why: str) -> None:
        """Deny held connections and grant requests that wait for a human: nobody will answer them."""
        for key, p in list(self.pending.items()):
            if self.pending.pop(key, None) is not p:
                continue
            self.availability.note("conn", p.host, p.port, why)
            if p.future is not None and not p.future.done():
                p.future.set_result(Decision("deny", why))
            self.publish({"type": "resolved", "id": p.id, "action": "deny", "reason": why.split(":", 1)[0]})
        for r in self.grants.pending():
            self.availability.note("grant", r.name, 0, why)
            r.status, r.decided_by = "denied", "availability"
            self.record(kind="grant", host=r.name, action="deny", reason=f"grant request for {r.name}: {why}")
            self._grant_resolved(r)

    def _digest(self, why: str) -> None:
        items, dropped = self.availability.take()
        if items or dropped:
            self.publish({"type": "digest", "why": why, "items": items, "more": dropped})

    # ------------------------------------------------------------------ events
    def publish(self, ev: dict) -> None:
        for q in list(self.subscribers):
            with contextlib.suppress(asyncio.QueueFull):
                q.put_nowait(ev)

    def record(self, **ev) -> dict | None:
        """Store + publish an event. Identical connection/DNS events inside DUP_WINDOW are only
        counted (a looping or hostile agent cannot fill the disk or drown the live log)."""
        if ev.get("kind") in ("conn", "dns"):
            key = (
                ev.get("kind"),
                ev.get("proto"),
                ev.get("client"),
                ev.get("host"),
                ev.get("port"),
                ev.get("action"),
                ev.get("reason"),
            )
            now = time.time()
            seen = self._dups.get(key)
            if seen and now - seen[0] < DUP_WINDOW:
                seen[1] += 1
                return None
            if seen and seen[1]:
                self._emit_repeats(seen[2], seen[1])  # not flushed by housekeeping yet: don't lose the count
            self._dups[key] = [now, 0, ev]
        ev = self.events.add(ev)
        self.publish({"type": "event", "event": ev})
        return ev

    def _flush_dups(self, now: float) -> None:
        for key, (ts, count, ev) in list(self._dups.items()):
            if now - ts >= DUP_WINDOW:
                del self._dups[key]
                if count:
                    self._emit_repeats(ev, count)

    def _emit_repeats(self, ev: dict, count: int) -> None:
        rep = {k: v for k, v in ev.items() if k not in ("id", "ts")}
        rep["reason"] = f"{ev.get('reason')} (repeated {count}x)"
        self.publish({"type": "event", "event": self.events.add(rep)})

    def _hit(self, dec: Decision) -> None:
        """Count a match of a rule (hot path: one dict update, flushed to the event log by housekeeping)."""
        if dec.rule_id and dec.rule_id != "hard_deny":
            h = self.hits.get(dec.rule_id)
            if h is None:
                self.hits[dec.rule_id] = [1, time.time()]
            else:
                h[0] += 1
                h[1] = time.time()

    def flush_hits(self) -> None:
        hits, self.hits = self.hits, {}
        self.events.flush_hits(hits, [r.id for r in self.policy.rules])

    def start_learning(self, minutes, ports, by: str) -> dict:
        s = self.learning.start(minutes, ports, by)
        until = time.strftime("%H:%M", time.localtime(s["until"]))
        self.record(
            kind="admin", action="learning", reason=f"learning mode on until {until}, ports {s['ports']}, by {by}"
        )
        self.publish({"type": "learning"})
        return s

    def end_learning(self, by: str, why: str) -> dict | None:
        s = self.learning.end(by, why)
        if s:
            self.record(kind="admin", action="learning", reason=f"learning mode ended: {why} ({by})")
            self.publish({"type": "learning"})
        return s

    def save_policy(self, by: str = "api", what: str = "policy changed") -> None:
        self.policy.save(self.policy_path)
        self._history(by, what)
        self.publish({"type": "policy"})

    def _history(self, by: str, what: str) -> None:
        """Keep the saved policy as a version. Best effort: the policy itself is already saved, and a broken
        history must not break approvals or the emergency stop."""
        try:
            self.history.record(self.policy.to_dict(), by, what)
        except Exception:
            log.exception("policy history: version not stored")

    # ------------------------------------------------------------------ decisions
    async def resolve(self, host: str, port: int) -> list[str]:
        if is_ip(host):
            return [host.strip("[]")]
        if host.lower() in STATIC_HOSTS:
            return [STATIC_HOSTS[host.lower()]]
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        ips: list[str] = []
        for fam, *_rest, sockaddr in infos:
            if fam in (socket.AF_INET, socket.AF_INET6) and sockaddr[0] not in ips:
                ips.append(sockaddr[0])
        return ips

    async def decide(
        self, host: str, port: int, ips: list[str], proto: str, client: str, learning: bool = False
    ) -> Decision:
        """Full decision with known IPs (the model), asking you if it says `ask`."""
        dec = self.access.on_addresses(host, port, ips, proto, learning)
        if dec.action != "ask":
            return dec
        return await self.ask(host, port, ips, proto, client)

    async def ask(self, host: str, port: int, ips: list[str], proto: str, client: str) -> Decision:
        key = (host.lower(), port)
        if why := self.availability.blocking():
            # Nobody can answer (away / quiet hours): refuse at once instead of holding the connection, and
            # remember it for the digest. Never allowed automatically (fail closed).
            self.availability.note("conn", host.lower(), port, why)
            return Decision("deny", why)
        if self.neg_cache.get(key, 0) > time.time():
            return Decision("deny", "approval timed out recently")
        p = self.pending.get(key)
        if p is None and len(self.pending) >= self.max_pending:
            # Approval flooding guard: a hostile agent cannot bury the human in prompts.
            return Decision("deny", f"too many pending approvals (max_pending={self.max_pending})")
        if p is None:
            p = Pending(
                host=host.lower(),
                port=port,
                ips=ips,
                proto=proto,
                client=client,
                timeout=self.policy.ask_timeout,
                context=self.activity.recent(client),
            )
            self.record(  # first: if the log cannot be written, nothing is left pending
                kind="ask",
                proto=proto,
                client=client,
                host=host,
                port=port,
                ips=ips,
                action="ask",
                reason="awaiting approval",
                extra={"pending_id": p.id, "context": p.context} if p.context else {"pending_id": p.id},
            )
            p.future = asyncio.get_running_loop().create_future()
            self.pending[key] = p
            self.publish({"type": "ask", "pending": p.to_dict()})
        else:
            p.attempts += 1
        try:
            return await asyncio.wait_for(asyncio.shield(p.future), timeout=p.timeout - (time.time() - p.created))
        except TimeoutError:
            if self.pending.pop(key, None) is p:
                self.neg_cache[key] = time.time() + NEG_CACHE_SECONDS
                if not p.future.done():
                    p.future.set_result(Decision("deny", "approval timed out"))
                self.publish({"type": "resolved", "id": p.id, "action": "deny", "reason": "timeout"})
            return p.future.result()

    def answer(self, pending_id: str, scope: str, by: str) -> dict:
        for key, p in list(self.pending.items()):
            if p.id == pending_id:
                rule = rule_for_approval(p.host, p.port, scope)
                self.policy.add_rule(rule, top=True)
                self.save_policy(by, f"approval {scope} for {p.host}:{p.port}")
                dec = Decision(rule.action, f"{scope} by {by}", rule.id)
                del self.pending[key]
                if not p.future.done():
                    p.future.set_result(dec)
                self.publish({"type": "resolved", "id": p.id, "action": rule.action, "scope": scope, "by": by})
                try:  # for rule suggestions; the decision itself is already made
                    self.events.add_approval(p.host, p.port, scope, by)
                except Exception:
                    log.exception("approval not stored for rule suggestions")
                return {"rule": rule.to_dict()}
        raise KeyError(pending_id)

    # ------------------------------------------------------------------ mitmproxy hooks
    # ------------------------------------------------------------------ grants
    def _grant_resolved(self, r) -> None:
        self.publish({"type": "grant_resolved", "request": r.to_dict()})
        self.publish({"type": "grants"})
        ev = self._grant_events.pop(r.id, None)
        if ev:
            ev.set()

    def request_grant(self, name: str, level: str, ttl, reason: str, client: str):
        """Called by the agent API. Returns the request (auto-approved levels are active immediately)."""
        g = self.grants.defs.get(name)
        if not g:
            raise KeyError(name)
        if g.approval.get(level) == "auto" and not self.grants.auto_suspended:  # emergency stop suspends it
            r = self.grants.new_request(name, level, ttl, reason, client)
            self._approve(r, level, "auto")
            return r
        if why := self.availability.blocking():
            self.availability.note("grant", name, 0, why)
            self.record(kind="grant", client=client, host=name, action="deny", reason=f"grant {name} ({level}): {why}")
            raise Unavailable(why)
        r = self.grants.new_request(name, level, ttl, reason, client)
        if r.id not in self._grant_events:
            self._grant_events[r.id] = asyncio.Event()
            self.record(
                kind="grant",
                client=client,
                host=name,
                action="ask",
                reason=f"agent requests grant {name} ({level}, {r.ttl // 60} min): {r.reason}",
            )
            self.publish({"type": "grant_request", "request": r.to_dict(), "grant": g.summary()})
        return r

    def _approve(self, r, level: str, by: str, ttl: int | None = None):
        a = self.grants.activate(r.name, level, ttl or r.ttl, r.reason, by)
        r.status, r.decided_by, r.grant_id, r.granted_level = "approved", by, a.id, level
        self.record(
            kind="grant",
            host=r.name,
            action="allow",
            reason=f"grant {r.name} ({level}) active until {time.strftime('%H:%M', time.localtime(a.expires))} by {by}",
        )
        self._grant_resolved(r)
        return a

    def decide_grant(self, rid: str, decision: str, by: str, ttl=None) -> dict:
        r = self.grants.requests.get(rid)
        if not r or r.status != "pending":
            raise KeyError(rid)
        g = self.grants.defs.get(r.name)
        if decision == "deny" or not g:
            r.status, r.decided_by = "denied", by
            self.record(kind="grant", host=r.name, action="deny", reason=f"grant request for {r.name} denied by {by}")
            self._grant_resolved(r)
            return r.to_dict()
        level = "read" if decision == "read" else r.level
        if level not in g.levels:
            raise ValueError(f"grant {g.name} has no {level} level")
        from egressgw.grants import parse_ttl

        self._approve(r, level, by, parse_ttl(ttl) if ttl else None)
        return r.to_dict()

    def activate_grant(self, name: str, level: str, ttl, by: str) -> dict:
        from egressgw.grants import parse_ttl

        g = self.grants.defs[name]
        a = self.grants.activate(name, level, parse_ttl(ttl) if ttl else g.default_ttl, "activated by admin", by)
        self.record(kind="grant", host=name, action="allow", reason=f"grant {name} ({level}) activated by {by}")
        self.publish({"type": "grants"})
        return a.to_dict()

    def revoke_grant(self, active_id: str, by: str) -> dict:
        a = self.grants.revoke(active_id)
        self.record(kind="grant", host=a.name, action="deny", reason=f"grant {a.name} revoked by {by}")
        self.publish({"type": "grants"})
        return a.to_dict()

    async def wait_grant(self, rid: str, timeout: float) -> None:
        ev = self._grant_events.get(rid)
        if ev:
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(ev.wait(), timeout)

    async def _grant_connect(self, data, host: str, port: int, proto: str, client: str, block) -> bool:
        """Handle a connection covered by an active grant. Returns True if handled (allowed or blocked)."""
        m = self.access.grant_for(host, port)
        if not m:
            return False
        a, g, t = m
        ips = self.access.grant_addresses(t, host)
        if ips is None:
            try:
                ips = await self.resolve(host, port)
            except OSError as e:
                block(f"dns failure: {e}")
                return True
        if problem := self.access.grant_problem(g, t, host, port, ips):
            block(problem, ips)
            return True
        self.record(
            kind="conn",
            proto=proto,
            client=client,
            host=host,
            port=port,
            ips=ips,
            action="allow",
            reason=f"grant {g.name} ({a.level})",
        )
        self.verdicts[data.server.id] = Verdict(host, port, a.id, t)
        data.server.address = (ips[0], port)
        if t.scheme == "https" and not is_ip(host):
            data.server.sni = host
        return True

    @fail_closed
    async def server_connect(self, data: server_hooks.ServerConnectionHookData) -> None:
        if data.server.address is None:
            data.server.error = "egress policy: no destination"
            return
        host, port = data.server.address
        host = str(host)
        proto = getattr(data.client.proxy_mode, "type_name", "?")
        client = data.client.peername[0] if data.client.peername else "?"

        def block(reason: str, ips: list[str] | None = None) -> None:
            data.server.error = f"egress policy: blocked ({reason})"  # first: recording may fail
            self.record(
                kind="conn", proto=proto, client=client, host=host, port=port, ips=ips, action="deny", reason=reason
            )

        if is_ip(host):
            if await self._grant_connect(data, host, port, proto, client, block):
                return
            ips = [host.strip("[]")]
            if hint := self.access.grant_hint(host, port):
                dec = self.access.on_addresses(host, port, ips, proto)
                if dec.action != "allow":
                    self._hit(dec)
                    return block(f"{dec.reason}; {hint}", ips)
            dec = await self.decide(host, port, ips, proto, client)
        else:
            name = self.access.checked_name(host)
            if name is None:
                return block("invalid hostname")
            host = name
            if await self._grant_connect(data, host, port, proto, client, block):
                return
            # 1) decide on the name alone: denied / not-yet-approved names are never resolved
            pre = self.access.on_name(host, port)
            hint = self.access.grant_hint(host, port)
            if hint and pre.action != "allow":
                self._hit(pre)
                return block(f"{pre.reason}; {hint}")
            if pre.action == "ask":
                pre = await self.ask(host, port, [], proto, client)
            if pre.action != "allow":
                self._hit(pre)
                return block(f"{pre.reason} (not resolved)")
            # 2) resolve and re-check with IPs (hard deny, CIDR rules); pin to the checked IP
            try:
                ips = await self.resolve(host, port)
            except OSError as e:
                return block(f"dns failure: {e}")
            if not ips:
                return block("no address")
            dec = await self.decide(host, port, ips, proto, client, learning=pre.reason == LEARNING)
        reason = dec.reason
        self._hit(dec)
        if dec.action != "allow":
            data.server.error = f"egress policy: blocked ({dec.reason})"
            if hint := self.access.grant_hint(host, port):
                reason = f"{reason}; {hint}"
        self.record(
            kind="conn", proto=proto, client=client, host=host, port=port, ips=ips, action=dec.action, reason=reason
        )
        if dec.action != "allow":
            return
        self.verdicts[data.server.id] = Verdict(host, port)
        # Pin to the checked address (anti DNS-rebinding: no second resolution after the decision).
        # For intercepted hosts the upstream SNI is set explicitly, so the upstream certificate is
        # still verified against the hostname, not the IP.
        if not is_ip(host):
            data.server.address = (ips[0], port)
            if self.access.intercepted(host):
                data.server.sni = host
                self._note_intercept_ips(ips)  # record the IPs so an IP-literal route to them is refused

    def _intercept_names(self) -> set[str]:
        """Exact (resolvable) host names that are intercepted; wildcards and IP literals are skipped."""
        names = set(self.inject_hosts) | {r.host for r in self.readonly}
        if self.github.patterns:  # GitHub hosts are intercepted only when repo-scoping is active
            names |= set(self.github.hosts)
        return {n for n in names if n and "*" not in n and not is_ip(n) and valid_hostname(n)}

    def _note_intercept_ips(self, ips: list[str]) -> None:
        with contextlib.suppress(ValueError):
            self.intercept_ips.update(ip_addr(i) for i in ips)
        if len(self.intercept_ips) > 4096:  # bound memory under CDN IP churn; the next refresh rebuilds it
            self.intercept_ips = set()

    def _is_intercept_ip(self, host: str) -> bool:
        try:
            return ip_addr(host) in self.intercept_ips
        except ValueError:
            return False

    async def _refresh_intercept_ips(self) -> None:
        """Resolve the configured intercept host names so an IP-literal connection to one can be refused."""
        found: set = set()
        for name in self._intercept_names():
            try:
                for ip in await self.resolve(name, 443):
                    with contextlib.suppress(ValueError):
                        found.add(ip_addr(ip))
            except OSError:
                continue  # transient DNS failure: keep what we have and try again next cycle
        self.intercept_ips |= found

    @fail_closed
    def server_disconnected(self, data: server_hooks.ServerConnectionHookData) -> None:
        self.verdicts.pop(data.server.id, None)
        self.tls_refused.discard(data.server.id)

    @fail_closed
    def server_connect_error(self, data: server_hooks.ServerConnectionHookData) -> None:
        # an allowed connection whose upstream connect fails never gets server_disconnected
        self.server_disconnected(data)

    @fail_closed
    def tls_clienthello(self, data: tls.ClientHelloData) -> None:
        sid = data.context.server.id
        v = self.verdicts.get(sid)
        sni = (getattr(data.client_hello, "sni", None) or "").lower().rstrip(".")
        mode, why = self.access.tls(v, sni)
        if mode == INTERCEPT:
            # A destination with limits (credentials, read-only, repositories, a grant) is always intercepted,
            # whatever the SNI says: its requests are checked one by one. The upstream SNI is the checked name.
            return
        if why:
            # No passthrough: on a shared CDN, the SNI picks the site (domain fronting). Both TLS handshakes
            # are failed on purpose in tls_start_client/tls_start_server.
            self.tls_refused.add(sid)
            client = data.context.client.peername[0] if data.context.client.peername else "?"
            port = data.context.server.address[1] if data.context.server.address else 0
            host = v.host if v else "?"
            self.record(kind="conn", proto="tls", client=client, host=host, port=port, action="deny", reason=why)
            return
        data.ignore_connection = True  # end-to-end TLS, untouched

    @fail_closed
    def tls_start_client(self, data: tls.TlsData) -> None:
        if data.context.server.id in self.tls_refused:
            data.ssl_conn = _refusing_tls(server_side=True)

    @fail_closed
    def tls_start_server(self, data: tls.TlsData) -> None:
        """Per-target upstream TLS for grant targets: pinned leaf fingerprint (self-signed LAN services)
        or, if explicitly configured, no verification."""
        if data.context.server.id in self.tls_refused:
            data.ssl_conn = _refusing_tls(server_side=False)  # no SNI, no data: the handshake cannot succeed
            return
        v = self.verdicts.get(data.context.server.id)
        t = v.target if v else None
        if t is None or (not t.tls_fingerprint and t.tls_verify):
            return
        if data.ssl_conn is None:  # script addons run before the built-in TlsConfig: let it build the
            tlsconfig = ctx.master.addons.get("tlsconfig")  # connection, then adjust verification
            tlsconfig.tls_start_server(data)
        if t.tls_fingerprint:
            from cryptography.hazmat.primitives import hashes
            from OpenSSL import SSL

            want = t.tls_fingerprint

            def verify(_conn, cert, _errno, depth, _ok) -> bool:
                if depth > 0:
                    return True  # chain is irrelevant: the leaf itself is pinned
                return cert.to_cryptography().fingerprint(hashes.SHA256()).hex() == want

            data.ssl_conn.set_verify(SSL.VERIFY_PEER, verify)
        elif not t.tls_verify:
            from OpenSSL import SSL

            data.ssl_conn.set_verify(SSL.VERIFY_NONE, None)

    @fail_closed
    def tcp_start(self, flow) -> None:
        v = self.verdicts.get(flow.server_conn.id)
        if why := self.access.raw_problem(v):
            self._refuse_raw(flow, v, why)

    @fail_closed
    def websocket_start(self, flow: http.HTTPFlow) -> None:
        v = self.verdicts.get(flow.server_conn.id)
        if why := self.access.websocket_problem(v):
            self._refuse_raw(flow, v, why)

    @fail_closed
    def tcp_message(self, flow) -> None:
        # A raw tunnel stays open after its grant is revoked or expires; cut it on the next message, so no
        # more data flows once the grant has ended (#137). Killing it here, inside a message hook, closes it.
        v = self.verdicts.get(flow.server_conn.id)
        if v and v.grant and not self.access.grant_live(v):
            self._refuse_raw(flow, v, "grant ended: tunnel closed")

    @fail_closed
    def websocket_message(self, flow: http.HTTPFlow) -> None:
        v = self.verdicts.get(flow.server_conn.id)
        if v and v.grant and not self.access.grant_live(v):
            self._refuse_raw(flow, v, "grant ended: websocket closed")

    def _refuse_raw(self, flow, v: Verdict, reason: str) -> None:
        flow.kill()
        self.record(
            kind="conn",
            proto="grant",
            client=flow.client_conn.peername[0] if flow.client_conn.peername else "?",
            host=v.host,
            port=v.port,
            action="deny",
            reason=reason,
        )

    def _checks(self, flow: http.HTTPFlow) -> tuple[str, int, str] | None:
        """The one check for every request: asks the model, then strips and adds the credentials it names.
        Returns (host, port, reason) to refuse the request, or None."""
        req = flow.request
        v, refuse = self._verdict_for(flow)
        if refuse:
            return (req.host or "?").lower().rstrip("."), req.port, refuse
        out = self.access.check(
            v,
            Req(req.method, req.scheme, req.path, req.host_header, req.pretty_host, req.headers.get("connection", "")),
        )
        if out.refuse:
            return v.host, (v.port if v.grant else req.port), out.refuse
        for name in out.strip:
            req.headers.pop(name, None)
        for name, value in out.add:
            req.headers[name] = value
        return None

    def _verdict_for(self, flow: http.HTTPFlow) -> tuple[Verdict | None, str | None]:
        """(verdict, None), or (None, reason) to refuse. A request on a connection with a stored verdict is
        checked against it. A request with none - a plain-HTTP proxy request (its hooks run before the server
        connection exists), or an absolute-form https proxy request - is re-authorised on its own destination
        rather than trusted (#137)."""
        v = self.verdicts.get(flow.server_conn.id)
        if v is not None:
            return v, None
        host = (flow.request.host or "").lower().rstrip(".")
        return self.access.request_without_verdict(host, flow.request.port, flow.request.scheme)

    def _enforce(self, flow: http.HTTPFlow, early: bool) -> None:
        refusal = self._checks(flow)
        if refusal is None:
            return
        host, port, why = refusal
        req = flow.request
        if req.stream or (early and not _body_buffered(req)):
            # A response cannot replace a streamed body: mitmproxy refuses to combine the two, and a body
            # that grows past stream_large_bodies later would be streamed. Cut the request instead.
            flow.kill()
        else:
            flow.response = http.Response.make(403, f"egress policy: {why}\n".encode(), {"Content-Type": "text/plain"})
        self.record(
            kind="conn",
            proto="http",
            client=flow.client_conn.peername[0] if flow.client_conn.peername else "?",
            host=host,
            port=port,
            action="deny",
            reason=f"{why}: {req.method} {req.path[:120]}",
        )

    @fail_closed
    def requestheaders(self, flow: http.HTTPFlow) -> None:
        """First line: runs before anything is sent upstream. Bodies larger than stream_large_bodies are
        streamed right after this hook, so the `request` hook would come too late for them."""
        self._enforce(flow, early=True)

    @fail_closed
    def request(self, flow: http.HTTPFlow) -> None:
        """Second line, with the complete request. A response set here means: refused in requestheaders."""
        if flow.response is None:
            self._enforce(flow, early=False)

    @fail_closed
    def dns_request(self, flow: dns.DNSFlow) -> None:
        flow.response = flow.request.fail(response_codes.NXDOMAIN)
        q = flow.request.question
        name = q.name if q else "?"
        client = flow.client_conn.peername[0] if flow.client_conn.peername else "?"
        self.record(
            kind="dns",
            proto="dns",
            client=client,
            host=name,
            port=53,
            action="deny",
            reason="agent DNS is disabled (NXDOMAIN); use the proxy",
        )
