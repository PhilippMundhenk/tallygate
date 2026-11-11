"""Internal management API. Listens on the control network only; bearer-token protected."""

from __future__ import annotations

import asyncio
import hmac
import json
import time
from typing import TYPE_CHECKING

from aiohttp import web

from egressgw.policy import SCOPES, Policy, Rule, is_ip, valid_hostname

if TYPE_CHECKING:
    from egressgw.core import Gateway


def _json(data, status: int = 200) -> web.Response:
    return web.json_response(data, status=status)


def build_app(gw: Gateway) -> web.Application:
    @web.middleware
    async def auth(request: web.Request, handler):
        if request.path == "/health":
            return await handler(request)
        hdr = request.headers.get("Authorization", "")
        if not hmac.compare_digest(hdr.encode(), f"Bearer {gw.api_token}".encode()):
            return _json({"error": "unauthorized"}, 401)
        try:
            return await handler(request)
        except (ValueError, KeyError, TypeError) as e:
            return _json({"error": str(e)}, 400)

    routes = web.RouteTableDef()

    @routes.get("/health")
    async def health(_):
        return _json({"ok": True})

    @routes.get("/policy")
    async def get_policy(_):
        return _json(gw.policy.describe())

    @routes.put("/policy")
    async def put_policy(request):
        gw.adopt(Policy.from_dict(await request.json()))  # floor + service exceptions stay as configured
        gw.save_policy()
        gw.record(kind="admin", action="policy", reason="policy replaced via API")
        return _json(gw.policy.describe())

    @routes.post("/rules")
    async def add_rule(request):
        body = await request.json()
        top = bool(body.pop("top", True))
        rule = gw.policy.add_rule(Rule.from_dict(body), top=top)
        gw.save_policy()
        gw.record(kind="admin", action="rule+", host=rule.host or rule.cidr, reason=json.dumps(rule.to_dict()))
        return _json(rule.to_dict(), 201)

    @routes.delete("/rules/{rid}")
    async def del_rule(request):
        rid = request.match_info["rid"]
        if not gw.policy.remove_rule(rid):
            return _json({"error": "not found"}, 404)
        gw.save_policy()
        gw.record(kind="admin", action="rule-", reason=f"rule {rid} removed")
        return _json({"ok": True})

    @routes.post("/presets/{name}")
    async def apply_preset(request):
        """Merge a preset's rules on top (e.g. 'setup' for temporary login access)."""
        name = request.match_info["name"]
        if not name.isidentifier():
            return _json({"error": "bad preset"}, 400)
        from egressgw.core import PRESET_DIR

        path = PRESET_DIR / f"{name}.yaml"
        if not path.exists():
            return _json({"error": "unknown preset"}, 404)
        preset = Policy.load(path)
        ttl = (await request.json()).get("ttl") if request.can_read_body else None
        added = []
        for r in reversed(preset.rules):
            r.source = "preset"
            r.note = (r.note + " " if r.note else "") + f"[{name}]"
            if ttl:
                r.expires = time.time() + int(ttl)
            gw.policy.remove_rule(r.id)
            gw.policy.add_rule(r, top=True)
            added.append(r.id)
        gw.save_policy()
        gw.record(kind="admin", action="preset", reason=f"preset {name} applied ({len(added)} rules, ttl={ttl})")
        return _json({"added": added})

    @routes.get("/presets")
    async def list_presets(_):
        from egressgw.core import PRESET_DIR

        return _json(sorted(p.stem for p in PRESET_DIR.glob("*.yaml")))

    @routes.get("/pending")
    async def pending(_):
        return _json([p.to_dict() for p in gw.pending.values()])

    @routes.post("/pending/{pid}/decide")
    async def decide(request):
        body = await request.json()
        scope = body.get("scope")
        if scope not in SCOPES:
            return _json({"error": f"scope must be one of {list(SCOPES)}"}, 400)
        try:
            res = gw.answer(request.match_info["pid"], scope, str(body.get("by", "api"))[:64])
        except KeyError:
            return _json({"error": "no such pending request (already decided or timed out)"}, 404)
        return _json(res)

    @routes.post("/test")
    async def test(request):
        body = await request.json()
        host, port = str(body["host"]).strip(), int(body.get("port", 443))
        if not is_ip(host):
            if not valid_hostname(host):
                return _json({"action": "deny", "reason": "invalid hostname", "ips": []})
            pre = gw.policy.evaluate_name(host, port)
            if pre is not None and pre.action != "allow":
                return _json(
                    {"action": pre.action, "reason": pre.reason + " (not resolved)", "rule_id": pre.rule_id, "ips": []}
                )
        try:
            ips = await gw.resolve(host, port)
        except OSError as e:
            return _json({"action": "deny", "reason": f"dns failure: {e}", "ips": []})
        d = gw.policy.evaluate(host, port, ips)
        return _json({"action": d.action, "reason": d.reason, "rule_id": d.rule_id, "ips": ips})

    @routes.get("/events")
    async def events(request):
        q = request.query
        return _json(
            gw.events.recent(int(q.get("limit", 200)), int(q["before"]) if q.get("before") else None, q.get("q"))
        )

    @routes.get("/stream")
    async def stream(request):
        resp = web.StreamResponse(headers={"Content-Type": "text/event-stream", "Cache-Control": "no-cache"})
        await resp.prepare(request)
        queue: asyncio.Queue = asyncio.Queue(maxsize=1000)
        gw.subscribers.add(queue)
        try:
            await resp.write(b": connected\n\n")
            while True:
                try:
                    ev = await asyncio.wait_for(queue.get(), timeout=20)
                    await resp.write(f"data: {json.dumps(ev)}\n\n".encode())
                except TimeoutError:
                    await resp.write(b": ping\n\n")
        except (ConnectionResetError, asyncio.CancelledError):
            pass
        finally:
            gw.subscribers.discard(queue)
        return resp

    @routes.get("/secrets")
    async def secrets(_):
        return _json({"names": gw.secrets.names()})

    @routes.put("/secrets/{name}")
    async def set_secret(request):
        body = await request.json()
        name = request.match_info["name"]
        gw.secrets.set(name, body.get("value") or None)
        gw.record(kind="admin", action="secret", reason=f"secret {name} {'set' if body.get('value') else 'removed'}")
        return _json({"names": gw.secrets.names()})

    @routes.get("/info")
    async def info(_):
        from egressgw.core import CA_EXPORT

        ca = CA_EXPORT / "egress-gw-ca.pem"
        return _json(
            {
                "inject_hosts": sorted(gw.inject_hosts),
                "inject_secrets_needed": sorted({s for i in gw.inject for s in _secret_names(i["value"])}),
                "services": gw.config.get("services") or [],
                "ca_pem": ca.read_text() if ca.exists() else None,
                "pending": len(gw.pending),
            }
        )

    app = web.Application(middlewares=[auth], client_max_size=1024 * 1024)
    app.add_routes(routes)
    return app


def _secret_names(template: str) -> set[str]:
    import re

    return set(re.findall(r"\$\{([a-z0-9_]+)\}", template))


async def start(gw: Gateway, host: str, port: int) -> web.AppRunner:
    runner = web.AppRunner(build_app(gw), access_log=None)
    await runner.setup()
    await web.TCPSite(runner, host, port).start()
    return runner
