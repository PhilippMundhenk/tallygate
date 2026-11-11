"""mitmproxy addon: single enforcement point for all egress.

Every upstream connection (HTTP proxy CONNECT, plain HTTP, SOCKS5, reverse:tcp service
ports) passes through `server_connect`, where the policy is evaluated on the requested
host:port *and* its resolved IPs. Hostnames are decided on the name first and only resolved
once the policy (or a human) allows them, so denied/pending names never leak through DNS.
Allowed hostnames are pinned to the checked IP to defeat DNS rebinding. TLS is passed through
untouched, except for hosts configured for credential injection or read-only access, which are
intercepted (the agent never sees injected secrets; its own credentials for those hosts are
stripped).
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

from egressgw import api
from egressgw.grants import READ_METHODS, GrantDef, Grants, Target, path_ok
from egressgw.policy import (
    DEFAULT_HARD_DENY,
    Decision,
    Exception_,
    Policy,
    is_ip,
    parse_cidrs,
    registrable_domain,
    rule_for_approval,
    valid_hostname,
)
from egressgw.store import EventLog, Secrets, render

log = logging.getLogger("egressgw")

DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
CONFIG_PATH = Path(os.environ.get("GW_CONFIG", DATA_DIR / "config.yaml"))
PRESET_DIR = Path(os.environ.get("PRESET_DIR", Path(__file__).resolve().parent.parent / "presets"))
CA_EXPORT = Path(os.environ.get("CA_EXPORT_DIR", "/ca"))
NEG_CACHE_SECONDS = 60
DUP_WINDOW = 2.0  # identical events within this window are counted, not stored (log-flood protection)
WRITE_METHODS = frozenset({"PUT", "PATCH", "DELETE"})
# TEST ONLY: "name=ip,name=ip" static resolution used by the e2e test-suite instead of /etc/hosts.
# Never set this in production; the gateway logs a loud warning when it is active.
STATIC_HOSTS = dict(kv.split("=", 1) for kv in os.environ.get("GW_TEST_STATIC_HOSTS", "").split(",") if "=" in kv)


def fail_closed(hook):
    """mitmproxy only logs an exception raised in an addon hook and then carries on, i.e. the connection
    would go out unchecked. Every hook is therefore wrapped: any error refuses the connection or flow."""

    def refuse(data) -> None:
        log.exception("%s failed - refusing the connection (fail closed)", hook.__name__)
        if isinstance(data, server_hooks.ServerConnectionHookData):
            data.server.error = "egress policy: internal error (fail closed)"
        elif isinstance(data, tls.ClientHelloData):
            data.ignore_connection = False  # intercept: the per-request checks still apply
        elif getattr(data, "killable", False):
            data.kill()  # http/tcp/websocket/dns flows

    if inspect.iscoroutinefunction(hook):

        @functools.wraps(hook)
        async def wrapper(self, data):
            try:
                return await hook(self, data)
            except Exception:  # noqa: BLE001 - any error must refuse, never pass traffic through
                refuse(data)

    else:

        @functools.wraps(hook)
        def wrapper(self, data):
            try:
                return hook(self, data)
            except Exception:  # noqa: BLE001 - any error must refuse, never pass traffic through
                refuse(data)

    return wrapper


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
        }


class Gateway:
    def __init__(self) -> None:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        self.config = yaml.safe_load(CONFIG_PATH.read_text()) if CONFIG_PATH.exists() else {}
        self.config = self.config or {}
        self.policy_path = DATA_DIR / "policy.yaml"
        # The hard-deny floor comes only from the (read-only mounted) static config, never from the API.
        # Validated here: a broken entry must stop the gateway, not fail per connection.
        self.hard_deny_floor = parse_cidrs(self.config.get("hard_deny_floor") or DEFAULT_HARD_DENY, "hard_deny_floor")
        if not self.policy_path.exists():
            preset = PRESET_DIR / f"{self.config.get('initial_preset', 'baseline')}.yaml"
            self.policy = Policy.load(preset) if preset.exists() else Policy()
            self.policy.save(self.policy_path)
        else:
            self.policy = Policy.load(self.policy_path)
        self.adopt(self.policy)
        self.events = EventLog(
            DATA_DIR / "events.db",
            int(self.config.get("log_keep_days", 30)),
            int(self.config.get("log_max_events", 500_000)),
        )
        self.secrets = Secrets(DATA_DIR / "secrets.json")
        self.inject = [dict(i) for i in self.config.get("inject") or []]
        self.inject_hosts = {i["host"].lower() for i in self.inject}
        self.readonly_hosts = {str(h).lower() for h in self.config.get("readonly") or []}
        self.intercept_hosts = self.inject_hosts | self.readonly_hosts
        self.strip_headers = [str(h) for h in self.config.get("inject_strip_headers") or ["Authorization", "Cookie"]]
        self.max_pending = int(self.config.get("max_pending", 10))
        self._dups: dict[tuple, list] = {}
        self.grants = Grants(self.config, DATA_DIR)
        # server connection id -> (active grant id, host the agent asked for, target)
        self.conn_grant: dict[str, tuple[str, str, Target]] = {}
        self._grant_events: dict[str, asyncio.Event] = {}
        self.pending: dict[tuple[str, int], Pending] = {}
        self.neg_cache: dict[tuple[str, int], float] = {}
        self.orig_host: dict[str, str] = {}
        self.subscribers: set[asyncio.Queue] = set()
        self.api_token = os.environ.get("GW_API_TOKEN", "")
        self._tasks: list[asyncio.Task] = []

    def adopt(self, policy: Policy) -> Policy:
        """Attach the static parts (floor, service exceptions) to a policy loaded from file/API."""
        policy.hard_deny_floor = self.hard_deny_floor
        self.policy = policy
        self._apply_service_exceptions()
        return policy

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
        while True:
            await asyncio.sleep(15)
            try:
                self._housekeep()
            except Exception:  # keep the loop alive; the error is logged
                log.exception("housekeeping failed")

    def _housekeep(self) -> None:
        if self.policy.prune_expired():
            self.save_policy()
        now = time.time()
        self.neg_cache = {k: v for k, v in self.neg_cache.items() if v > now}
        self._flush_dups(now)
        self.events.enforce_cap()
        expired, timed_out = self.grants.prune()
        for a in expired:
            self.record(kind="grant", host=a.name, action="expired", reason=f"grant {a.name} ({a.level}) expired")
        for r in timed_out:
            self.record(kind="grant", host=r.name, action="deny", reason=f"grant request {r.id} timed out")
            self._grant_resolved(r)
        if expired:
            self.publish({"type": "grants"})

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
            self._dups[key] = [now, 0, ev]
        ev = self.events.add(ev)
        self.publish({"type": "event", "event": ev})
        return ev

    def _flush_dups(self, now: float) -> None:
        for key, (ts, count, ev) in list(self._dups.items()):
            if now - ts >= DUP_WINDOW:
                del self._dups[key]
                if count:
                    rep = {k: v for k, v in ev.items() if k not in ("id", "ts")}
                    rep["reason"] = f"{ev.get('reason')} (repeated {count}x)"
                    self.publish({"type": "event", "event": self.events.add(rep)})

    def save_policy(self) -> None:
        self.policy.save(self.policy_path)
        self.publish({"type": "policy"})

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

    async def decide(self, host: str, port: int, ips: list[str], proto: str, client: str) -> Decision:
        """Full decision with known IPs (hard deny, rules, default; asks if needed)."""
        dec = self.policy.evaluate(host, port, ips, proto)
        if dec.action != "ask":
            return dec
        return await self.ask(host, port, ips, proto, client)

    async def ask(self, host: str, port: int, ips: list[str], proto: str, client: str) -> Decision:
        key = (host.lower(), port)
        if self.neg_cache.get(key, 0) > time.time():
            return Decision("deny", "approval timed out recently")
        p = self.pending.get(key)
        if p is None and len(self.pending) >= self.max_pending:
            # Approval flooding guard: a hostile agent cannot bury the human in prompts.
            return Decision("deny", f"too many pending approvals (max_pending={self.max_pending})")
        if p is None:
            p = Pending(
                host=host.lower(), port=port, ips=ips, proto=proto, client=client, timeout=self.policy.ask_timeout
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
                extra={"pending_id": p.id},
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
                self.save_policy()
                dec = Decision(rule.action, f"{scope} by {by}", rule.id)
                del self.pending[key]
                if not p.future.done():
                    p.future.set_result(dec)
                self.publish({"type": "resolved", "id": p.id, "action": rule.action, "scope": scope, "by": by})
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
        if g.approval.get(level) == "auto":
            r = self.grants.new_request(name, level, ttl, reason, client)
            self._approve(r, level, "auto")
            return r
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
        m = self._grant_match(host, port)
        if not m:
            return False
        a, g, t = m
        if t.address:
            ips = [t.address]
        elif is_ip(host):
            ips = [host.strip("[]")]
        else:
            try:
                ips = await self.resolve(host, port)
            except OSError as e:
                block(f"dns failure: {e}")
                return True
        problem = self.grants.address_problem(g, t, ips)
        if not problem and not t.lan:
            problem = self.policy.hard_denied(host, port, ips)
        if problem or not ips:
            block(problem or "no address", ips)
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
        self.conn_grant[data.server.id] = (a.id, host, t)
        self.orig_host[data.server.id] = host
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
            if hint := self._grant_hint(host, port):
                dec = self.policy.evaluate(host, port, ips, proto)
                if dec.action != "allow":
                    return block(f"{dec.reason}; {hint}", ips)
            dec = await self.decide(host, port, ips, proto, client)
        else:
            if not host.isascii():  # mitmproxy hands us IDNs decoded; prompts and rules use punycode
                try:
                    host = host.encode("idna").decode("ascii")
                except UnicodeError:
                    return block("invalid hostname")
            if not valid_hostname(host):
                return block("invalid hostname")
            host = host.lower().rstrip(".")
            if await self._grant_connect(data, host, port, proto, client, block):
                return
            # 1) decide on the name alone: denied / not-yet-approved names are never resolved
            pre = self.policy.evaluate_name(host, port)
            hint = self._grant_hint(host, port)
            if hint and (pre is None or pre.action != "allow"):
                return block(f"{pre.reason if pre else 'not allowed'}; {hint}")
            if pre is not None and pre.action == "ask":
                pre = await self.ask(host, port, [], proto, client)
            if pre is not None and pre.action == "deny":
                return block(f"{pre.reason} (not resolved)")
            # 2) resolve and re-check with IPs (hard deny, CIDR rules); pin to the checked IP
            try:
                ips = await self.resolve(host, port)
            except OSError as e:
                return block(f"dns failure: {e}")
            if not ips:
                return block("no address")
            dec = await self.decide(host, port, ips, proto, client)
        reason = dec.reason
        if dec.action != "allow":
            data.server.error = f"egress policy: blocked ({dec.reason})"
            if hint := self._grant_hint(host, port):
                reason = f"{reason}; {hint}"
        self.record(
            kind="conn", proto=proto, client=client, host=host, port=port, ips=ips, action=dec.action, reason=reason
        )
        if dec.action != "allow":
            return
        self.orig_host[data.server.id] = host
        # Pin to the checked address (anti DNS-rebinding: no second resolution after the decision).
        # For intercepted hosts the upstream SNI is set explicitly, so the upstream certificate is
        # still verified against the hostname, not the IP.
        if not is_ip(host):
            data.server.address = (ips[0], port)
            if host in self.intercept_hosts:
                data.server.sni = host

    def _grant_match(self, host: str, port: int):
        """Active grant for host:port - unless the policy already allows the name: grants only ADD
        access, they never narrow what the rules allow."""
        m = self.grants.match(host, port)
        if m and not is_ip(host):
            pre = self.policy.evaluate_name(host, port)
            if pre is not None and pre.action == "allow":
                return None
        return m

    def _grant_hint(self, host: str, port: int) -> str | None:
        names = self.grants.defined_for(host, port)
        return f"available via grant {', '.join(names)} (agent: tallygate request {names[0]})" if names else None

    @fail_closed
    def server_disconnected(self, data: server_hooks.ServerConnectionHookData) -> None:
        self.orig_host.pop(data.server.id, None)
        self.conn_grant.pop(data.server.id, None)

    @fail_closed
    def tls_clienthello(self, data: tls.ClientHelloData) -> None:
        b = self.conn_grant.get(data.context.server.id)
        if b:
            # http(s) grant targets are ALWAYS intercepted so method/path/Host can be enforced; tcp
            # targets are passed through untouched.
            if b[2].scheme == "tcp":
                data.ignore_connection = True
            return
        orig = self.orig_host.get(data.context.server.id)
        sni = (data.client_hello.sni or "").lower()
        if orig and orig in self.intercept_hosts and sni == orig:
            return  # intercept: credential injection and/or read-only enforcement
        data.ignore_connection = True  # end-to-end TLS, untouched

    @fail_closed
    def tls_start_server(self, data: tls.TlsData) -> None:
        """Per-target upstream TLS for grant targets: pinned leaf fingerprint (self-signed LAN services)
        or, if explicitly configured, no verification."""
        b = self.conn_grant.get(data.context.server.id)
        if not b or (not b[2].tls_fingerprint and b[2].tls_verify):
            return
        if data.ssl_conn is None:  # script addons run before the built-in TlsConfig: let it build the
            tlsconfig = ctx.master.addons.get("tlsconfig")  # connection, then adjust verification
            tlsconfig.tls_start_server(data)
        t = b[2]
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
        b = self.conn_grant.get(flow.server_conn.id)
        if b and b[2].scheme != "tcp":
            self._grant_refuse_raw(flow, b, "non-HTTP traffic to an HTTP grant target")

    @fail_closed
    def websocket_start(self, flow: http.HTTPFlow) -> None:
        b = self.conn_grant.get(flow.server_conn.id)
        if b and (a := self.grants.active.get(b[0])) is not None and a.level == "read":
            self._grant_refuse_raw(flow, b, "websocket on a read-only grant")

    def _grant_refuse_raw(self, flow, b, reason: str) -> None:
        flow.kill()
        self.record(
            kind="conn",
            proto="grant",
            client=flow.client_conn.peername[0] if flow.client_conn.peername else "?",
            host=b[1],
            port=b[2].port,
            action="deny",
            reason=reason,
        )

    def _grant_request(self, flow: http.HTTPFlow) -> bool:
        """Enforce an active grant on an HTTP request. Returns True if the request was handled."""
        b = self.conn_grant.get(flow.server_conn.id)
        if b is None and flow.request.scheme == "http" and not self.orig_host.get(flow.server_conn.id):
            # plain-HTTP proxy request: this hook runs before the server connection exists
            m = self._grant_match(flow.request.host.lower().rstrip("."), flow.request.port)
            if m and m[2].scheme == "http":
                b = (m[0].id, flow.request.host.lower().rstrip("."), m[2])
        if b is None:
            return False
        aid, host, t = b
        if t.scheme == "tcp":
            return True  # tcp grants pass traffic through untouched (mitmproxy may still parse HTTP)
        a = self.grants.active.get(aid)
        g: GrantDef | None = self.grants.defs.get(a.name) if a else None
        req = flow.request
        client = flow.client_conn.peername[0] if flow.client_conn.peername else "?"

        def refuse(why: str) -> bool:
            flow.response = http.Response.make(403, f"egress policy: {why}\n".encode(), {"Content-Type": "text/plain"})
            self.record(
                kind="conn",
                proto="http",
                client=client,
                host=host,
                port=t.port,
                action="deny",
                reason=f"{why}: {req.method} {req.path[:120]}",
            )
            return True

        if a is None or g is None or a.expires <= time.time():
            return refuse("grant expired or revoked")
        if t.scheme == "https" and req.scheme != "https":
            return refuse("plain HTTP to an https grant target")
        if req.pretty_host.lower().rstrip(".") != host:
            return refuse("Host header does not match the granted target")
        if not path_ok(req.path, t.paths):
            return refuse(f"path not covered by grant {g.name}")
        if a.level == "read" and (
            req.method.upper() not in READ_METHODS or "upgrade" in req.headers.get("connection", "").lower()
        ):
            return refuse(f"grant {g.name} is read-only")
        rules = [i for i in g.inject if i["host"] == host and t.scheme == "https"]
        if rules:
            for name in {*self.strip_headers, *(i["header"] for i in rules)}:
                req.headers.pop(name, None)
            for i in rules:
                value = render(i["value"], self.secrets)
                if value is not None:
                    req.headers[i["header"]] = value
        return True

    @fail_closed
    def request(self, flow: http.HTTPFlow) -> None:
        if self._grant_request(flow):
            return
        # The real destination: the connection's checked target (TLS) or the absolute-form URL host
        # (plain HTTP proxy requests, whose server connection is opened after this hook).
        target = (self.orig_host.get(flow.server_conn.id) or flow.request.host or "").lower().rstrip(".")
        if target in self.readonly_hosts and flow.request.method.upper() in WRITE_METHODS:
            flow.response = http.Response.make(403, b"egress policy: read-only host\n", {"Content-Type": "text/plain"})
            self.record(
                kind="conn",
                proto="http",
                client=flow.client_conn.peername[0] if flow.client_conn.peername else "?",
                host=target,
                port=flow.request.port,
                action="deny",
                reason=f"read-only host: {flow.request.method} refused",
            )
            return
        if target not in self.inject_hosts:
            return
        # Never forward the agent's own credentials to an injection host: otherwise it could act as
        # (and exfiltrate to) an account of its choosing, e.g. when no secret is configured yet.
        for rule in self.inject:
            if rule["host"].lower() == target:
                flow.request.headers.pop(rule.get("header", "Authorization"), None)
        for name in self.strip_headers:
            flow.request.headers.pop(name, None)
        host = flow.request.pretty_host.lower().rstrip(".")
        if flow.request.scheme != "https" or host != target:
            return  # inject only over TLS and only if Host/:authority matches the checked target
        for rule in self.inject:
            if rule["host"].lower() != target:
                continue
            value = render(rule["value"], self.secrets)
            if value is not None:  # secret not configured: request goes out without credentials
                flow.request.headers[rule.get("header", "Authorization")] = value

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
