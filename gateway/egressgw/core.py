"""mitmproxy addon: single enforcement point for all egress.

Every upstream connection (HTTP proxy CONNECT, plain HTTP, SOCKS5, reverse:tcp service
ports) passes through `server_connect`, where the policy is evaluated on the requested
host:port *and* its resolved IPs. Allowed hostnames are pinned to the checked IP to defeat
DNS rebinding. TLS is passed through untouched, except for hosts configured for credential
injection, which are intercepted to add the auth header (the agent never sees the secret).
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
from egressgw.policy import Decision, Exception_, Policy, is_ip, rule_for_approval
from egressgw.store import EventLog, Secrets, render

log = logging.getLogger("egressgw")

DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
CONFIG_PATH = Path(os.environ.get("GW_CONFIG", DATA_DIR / "config.yaml"))
PRESET_DIR = Path(os.environ.get("PRESET_DIR", Path(__file__).resolve().parent.parent / "presets"))
CA_EXPORT = Path(os.environ.get("CA_EXPORT_DIR", "/ca"))
NEG_CACHE_SECONDS = 60
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
        if not self.policy_path.exists():
            preset = PRESET_DIR / f"{self.config.get('initial_preset', 'baseline')}.yaml"
            self.policy = Policy.load(preset) if preset.exists() else Policy()
            self.policy.save(self.policy_path)
        else:
            self.policy = Policy.load(self.policy_path)
        self._apply_service_exceptions()
        self.events = EventLog(DATA_DIR / "events.db", int(self.config.get("log_keep_days", 30)))
        self.secrets = Secrets(DATA_DIR / "secrets.json")
        self.inject = [dict(i) for i in self.config.get("inject") or []]
        self.inject_hosts = {i["host"].lower() for i in self.inject}
        self.pending: dict[tuple[str, int], Pending] = {}
        self.neg_cache: dict[tuple[str, int], float] = {}
        self.orig_host: dict[str, str] = {}
        self.subscribers: set[asyncio.Queue] = set()
        self.api_token = os.environ.get("GW_API_TOKEN", "")
        self._tasks: list[asyncio.Task] = []

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

    # ------------------------------------------------------------------ events
    def publish(self, ev: dict) -> None:
        for q in list(self.subscribers):
            with contextlib.suppress(asyncio.QueueFull):
                q.put_nowait(ev)

    def record(self, **ev) -> dict:
        ev = self.events.add(ev)
        self.publish({"type": "event", "event": ev})
        return ev

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
        dec = self.policy.evaluate(host, port, ips)
        if dec.action != "ask":
            return dec
        key = (host.lower(), port)
        if self.neg_cache.get(key, 0) > time.time():
            return Decision("deny", "approval timed out recently")
        p = self.pending.get(key)
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
        try:
            ips = await self.resolve(host, port)
        except OSError as e:
            self.record(
                kind="conn", proto=proto, client=client, host=host, port=port, action="deny", reason=f"dns failure: {e}"
            )
            data.server.error = f"egress policy: cannot resolve {host}"
            return
        dec = await self.decide(host, port, ips, proto, client)
        self.record(
            kind="conn", proto=proto, client=client, host=host, port=port, ips=ips, action=dec.action, reason=dec.reason
        )
        if dec.action != "allow":
            data.server.error = f"egress policy: blocked ({dec.reason})"
            return
        self.orig_host[data.server.id] = host.lower()
        # Pin to the checked address (anti DNS-rebinding: no second resolution after the decision).
        # For intercepted (injection) hosts the upstream SNI is set explicitly, so the upstream
        # certificate is still verified against the hostname, not the IP.
        if not is_ip(host) and ips:
            data.server.address = (ips[0], port)
            if host.lower() in self.inject_hosts:
                data.server.sni = host.lower()

    def server_disconnected(self, data: server_hooks.ServerConnectionHookData) -> None:
        self.orig_host.pop(data.server.id, None)

    def tls_clienthello(self, data: tls.ClientHelloData) -> None:
        orig = self.orig_host.get(data.context.server.id)
        sni = (data.client_hello.sni or "").lower()
        if orig and orig in self.inject_hosts and sni == orig:
            return  # intercept: we will inject credentials
        data.ignore_connection = True  # end-to-end TLS, untouched

    def request(self, flow: http.HTTPFlow) -> None:
        if flow.request.scheme != "https" or not self.inject:
            return
        host = flow.request.pretty_host.lower()
        if self.orig_host.get(flow.server_conn.id) != host or host not in self.inject_hosts:
            return
        for rule in self.inject:
            if rule["host"].lower() != host:
                continue
            value = render(rule["value"], self.secrets)
            header = rule.get("header", "Authorization")
            if value is None:
                continue  # secret not configured: leave request as-is
            flow.request.headers[header] = value

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
