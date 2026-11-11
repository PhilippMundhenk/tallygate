"""Grant request API for the agent (listens on the agent network, no authentication).

Deliberately tiny: the agent can list the grants that exist, ask for one with a reason, and poll the
outcome. It cannot define, widen, approve or revoke anything, and sees no credentials or internals.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from aiohttp import web

if TYPE_CHECKING:
    from egressgw.core import Gateway


def build_app(gw: Gateway) -> web.Application:
    rate = int(gw.config.get("grant_api_rate", 30))  # requests/minute, all endpoints: the agent is untrusted
    hits: list[float] = []

    @web.middleware
    async def limit(request: web.Request, handler):
        now = time.time()
        hits[:] = [t for t in hits if now - t < 60]
        if len(hits) >= rate:
            return web.json_response({"error": "rate limited"}, status=429)
        hits.append(now)
        try:
            return await handler(request)
        except KeyError as e:
            return web.json_response({"error": f"unknown: {e}"}, status=404)
        except OverflowError as e:
            return web.json_response({"error": str(e)}, status=429)
        except (ValueError, TypeError) as e:
            return web.json_response({"error": str(e)}, status=400)

    routes = web.RouteTableDef()

    @routes.get("/v1/grants")
    async def catalog(_):
        active = {a.name: a for a in gw.grants.active.values() if a.expires > time.time()}
        out = []
        for g in gw.grants.defs.values():
            d = g.summary()
            if g.name in active:
                d["active"] = {"level": active[g.name].level, "expires": int(active[g.name].expires)}
            out.append(d)
        return web.json_response({"grants": out})

    @routes.post("/v1/grants/{name}/request")
    async def request_grant(request: web.Request):
        body = await request.json()
        if not isinstance(body, dict):
            raise ValueError("JSON object expected")
        r = gw.request_grant(
            request.match_info["name"],
            str(body.get("level", "read")),
            body.get("ttl"),
            str(body.get("reason", "")),
            request.remote or "?",
        )
        return web.json_response(_public(r), status=202 if r.status == "pending" else 200)

    @routes.get("/v1/requests/{rid}")
    async def status(request: web.Request):
        rid = request.match_info["rid"]
        if rid not in gw.grants.requests:
            raise KeyError(rid)
        wait = min(max(float(request.query.get("wait", 0)), 0), 55)
        if wait and gw.grants.requests[rid].status == "pending":
            await gw.wait_grant(rid, wait)
        return web.json_response(_public(gw.grants.requests[rid]))

    app = web.Application(middlewares=[limit], client_max_size=4096)
    app.add_routes(routes)
    return app


def _public(r) -> dict:
    d = {"id": r.id, "grant": r.name, "level": r.level, "status": r.status, "ttl": r.ttl}
    if r.status == "approved":
        d["granted_level"] = r.granted_level
    return d


async def start(gw: Gateway, host: str, port: int) -> web.AppRunner:
    runner = web.AppRunner(build_app(gw), access_log=None)
    await runner.setup()
    await web.TCPSite(runner, host, port).start()
    return runner
