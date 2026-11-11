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
from egressgw.policy import (
    DEFAULT_HARD_DENY,
    Decision,
    Exception_,
    Policy,
    is_ip,
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
        self.hard_deny_floor = [str(c) for c in self.config.get("hard_deny_floor") or DEFAULT_HARD_DENY]
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
            if self.policy.prune_expired():
                self.save_policy()
            now = time.time()
            self.neg_cache = {k: v for k, v in self.neg_cache.items() if v > now}
            self._flush_dups(now)
            self.events.enforce_cap()

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
            p.future = asyncio.get_running_loop().create_future()
            self.pending[key] = p
            self.record(
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
    async def server_connect(self, data: server_hooks.ServerConnectionHookData) -> None:
        if data.server.address is None:
            data.server.error = "egress policy: no destination"
            return
        host, port = data.server.address
        host = str(host)
        proto = getattr(data.client.proxy_mode, "type_name", "?")
        client = data.client.peername[0] if data.client.peername else "?"

        def block(reason: str, ips: list[str] | None = None) -> None:
            self.record(
                kind="conn", proto=proto, client=client, host=host, port=port, ips=ips, action="deny", reason=reason
            )
            data.server.error = f"egress policy: blocked ({reason})"

        if is_ip(host):
            ips = [host.strip("[]")]
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
            # 1) decide on the name alone: denied / not-yet-approved names are never resolved
            pre = self.policy.evaluate_name(host, port)
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
        self.record(
            kind="conn", proto=proto, client=client, host=host, port=port, ips=ips, action=dec.action, reason=dec.reason
        )
        if dec.action != "allow":
            data.server.error = f"egress policy: blocked ({dec.reason})"
            return
        self.orig_host[data.server.id] = host
        # Pin to the checked address (anti DNS-rebinding: no second resolution after the decision).
        # For intercepted hosts the upstream SNI is set explicitly, so the upstream certificate is
        # still verified against the hostname, not the IP.
        if not is_ip(host):
            data.server.address = (ips[0], port)
            if host in self.intercept_hosts:
                data.server.sni = host

    def server_disconnected(self, data: server_hooks.ServerConnectionHookData) -> None:
        self.orig_host.pop(data.server.id, None)

    def tls_clienthello(self, data: tls.ClientHelloData) -> None:
        orig = self.orig_host.get(data.context.server.id)
        sni = (data.client_hello.sni or "").lower()
        if orig and orig in self.intercept_hosts and sni == orig:
            return  # intercept: credential injection and/or read-only enforcement
        data.ignore_connection = True  # end-to-end TLS, untouched

    def request(self, flow: http.HTTPFlow) -> None:
        # The real destination: the connection's checked target (TLS) or the absolute-form URL host
        # (plain HTTP proxy requests, whose server connection is opened after this hook).
        target = (self.orig_host.get(flow.server_conn.id) or flow.request.host or "").lower().rstrip(".")
        if target in self.readonly_hosts and flow.request.method.upper() in WRITE_METHODS:
            self.record(
                kind="conn",
                proto="http",
                client=flow.client_conn.peername[0] if flow.client_conn.peername else "?",
                host=target,
                port=flow.request.port,
                action="deny",
                reason=f"read-only host: {flow.request.method} refused",
            )
            flow.response = http.Response.make(403, b"egress policy: read-only host\n", {"Content-Type": "text/plain"})
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

    def dns_request(self, flow: dns.DNSFlow) -> None:
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
        flow.response = flow.request.fail(response_codes.NXDOMAIN)
