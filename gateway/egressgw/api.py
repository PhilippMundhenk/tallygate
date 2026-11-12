"""Internal management API. Listens on the control network only; bearer-token protected."""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import json
import time
from typing import TYPE_CHECKING

from aiohttp import web

from egressgw import history, usage
from egressgw.policy import ACTIONS, SCOPES, Decision, Policy, Rule, is_ip, load_preset, valid_hostname

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
        old = gw.policy.default
        gw.adopt(Policy.from_dict(await request.json()))  # floor + service exceptions stay as configured
        gw.save_policy(_by(request), "policy replaced")
        gw.record(kind="admin", action="policy", reason="policy replaced via API" + _mode_changed(gw, old))
        return _json(gw.policy.describe())

    @routes.patch("/policy")
    async def patch_policy(request):
        """Change only the mode and/or the approval timeout; the rules stay as they are on the server."""
        body = await request.json()
        if not isinstance(body, dict) or not body:
            raise ValueError("expected an object with default and/or ask_timeout")
        unknown = set(body) - {"default", "ask_timeout"}
        if unknown:
            raise ValueError(f"PATCH /policy changes only default and ask_timeout, not {sorted(unknown)}")
        default = body.get("default", gw.policy.default)
        if default not in ACTIONS:
            raise ValueError(f"default must be one of {list(ACTIONS)}")
        timeout = body.get("ask_timeout", gw.policy.ask_timeout)
        if isinstance(timeout, bool) or not isinstance(timeout, int) or not 5 <= timeout <= 3600:
            raise ValueError("ask_timeout must be a whole number of seconds, 5..3600")
        old = gw.policy.default
        gw.policy.default, gw.policy.ask_timeout = default, timeout
        gw.save_policy(_by(request), f"mode {default}, approval timeout {timeout} s")
        reason = f"mode {default}, approval timeout {timeout} s via API" + _mode_changed(gw, old)
        gw.record(kind="admin", action="policy", reason=reason)
        return _json(gw.policy.describe())

    @routes.post("/emergency-stop")
    async def emergency_stop_route(request):
        body = (await request.json()) if request.can_read_body else {}
        by = str(body.get("by", "api") if isinstance(body, dict) else "api")[:64]
        return _json(emergency_stop(gw, by))

    @routes.post("/rules")
    async def add_rule(request):
        body = await request.json()
        top = bool(body.pop("top", True))
        rule = gw.policy.add_rule(Rule.from_dict(body), top=top)
        gw.save_policy(_by(request), f"rule {rule.id} added ({rule.action} {rule.host or rule.cidr})")
        gw.record(kind="admin", action="rule+", host=rule.host or rule.cidr, reason=json.dumps(rule.to_dict()))
        return _json(rule.to_dict(), 201)

    @routes.delete("/rules/{rid}")
    async def del_rule(request):
        rid = request.match_info["rid"]
        if not gw.policy.remove_rule(rid):
            return _json({"error": "not found"}, 404)
        gw.save_policy(_by(request), f"rule {rid} removed")
        gw.record(kind="admin", action="rule-", reason=f"rule {rid} removed")
        return _json({"ok": True})

    @routes.post("/presets/{name}")
    async def apply_preset(request):
        """Insert a template's rules on top, as `<preset>:<id>` tagged `preset:<name>`, optionally with a TTL.
        Applying again replaces the template's own earlier rules (with the new TTL); rules from any other
        source are never taken over."""
        name = request.match_info["name"]
        if not name.isidentifier():
            return _json({"error": "bad preset"}, 400)
        from egressgw.core import PRESET_DIR

        path = PRESET_DIR / f"{name}.yaml"
        if not path.exists():
            return _json({"error": "unknown preset"}, 404)
        meta, preset = load_preset(path)
        if meta["category"] == "policy":
            return _json(
                {
                    "error": f"preset {name} is a whole policy (with its own default): replace the policy with it instead"
                },
                400,
            )
        ttl = (await request.json()).get("ttl") if request.can_read_body else None
        expires = int(time.time() + int(ttl)) if ttl else None  # stored as whole seconds
        source = f"preset:{name}"
        for r in preset.rules:
            r.id, r.source, r.expires = f"{name}:{r.id}", source, expires
        ids = {r.id for r in preset.rules}
        taken = sorted(r.id for r in gw.policy.rules if r.id in ids and r.source != source)
        if taken:
            return _json({"error": f"rule ids already used by other rules: {', '.join(taken)}"}, 409)
        gw.policy.rules = [r for r in gw.policy.rules if r.source != source]  # its own earlier rules
        for r in reversed(preset.rules):
            gw.policy.add_rule(r, top=True)
        gw.save_policy(_by(request), f"template {name} applied")
        gw.record(kind="admin", action="preset", reason=f"preset {name} applied ({len(ids)} rules, ttl={ttl})")
        return _json({"added": [r.id for r in preset.rules], "expires": expires})

    @routes.delete("/presets/{name}")
    async def undo_preset(request):
        """Remove the rules a preset added (rules tagged preset:<name>)."""
        name = request.match_info["name"]
        if not name.isidentifier():
            return _json({"error": "bad preset"}, 400)
        removed = [r.id for r in gw.policy.rules if r.source == f"preset:{name}"]
        for rid in removed:
            gw.policy.remove_rule(rid)
        if removed:
            gw.save_policy(_by(request), f"template {name} undone")
        gw.record(kind="admin", action="preset", reason=f"preset {name} undone ({len(removed)} rules)")
        return _json({"removed": removed})

    @routes.get("/presets")
    async def list_presets(request):
        """Preset names; with ?details=1 also title, description, category and rules (for the UI)."""
        from egressgw.core import PRESET_DIR

        paths = sorted(PRESET_DIR.glob("*.yaml"))
        if request.query.get("details") != "1":
            return _json([p.stem for p in paths])
        out = []
        for p in paths:
            meta, pol = load_preset(p)
            out.append({"name": p.stem, **meta, "default": pol.default, "rules": [r.to_dict() for r in pol.rules]})
        return _json(out)

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
            if pre.action != "allow":
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

    # ---------------------------------------------------------------- rule usage and suggestions (#70)
    @routes.get("/rules/stats")
    async def rule_stats(_):
        rules = usage.rule_usage(gw.policy, gw.events.hit_stats(), gw.hits, time.time(), gw.stale_days)
        return _json({"rules": rules, "stale_days": gw.stale_days})

    @routes.post("/rules/cleanup")
    async def rule_cleanup(request):
        """Remove the given rules, but only those that are still unused (checked again here)."""
        body = await request.json()
        ids = body.get("ids") if isinstance(body, dict) else None
        if not isinstance(ids, list) or not all(isinstance(i, str) for i in ids):
            raise ValueError("expected {ids: [rule ids]}")
        rules = usage.rule_usage(gw.policy, gw.events.hit_stats(), gw.hits, time.time(), gw.stale_days)
        stale = {r["id"] for r in rules if r["stale"]}
        removed = [i for i in dict.fromkeys(ids) if i in stale]
        for rid in removed:
            gw.policy.remove_rule(rid)
        if removed:
            gw.save_policy(_by(request), f"unused rules removed: {', '.join(removed)}")
            gw.record(kind="admin", action="rule-", reason=f"unused rules removed: {', '.join(removed)}")
        return _json({"removed": removed, "kept": [i for i in ids if i not in removed]})

    def _suggestions() -> list[dict]:
        since = time.time() - gw.suggest_days * 86400
        return usage.suggestions(gw.events.approvals_since(since), gw.policy, gw.events.dismissed(), gw.suggest_min)

    @routes.get("/suggestions")
    async def suggestions(_):
        return _json({"suggestions": _suggestions(), "min_approvals": gw.suggest_min, "window_days": gw.suggest_days})

    @routes.post("/suggestions/accept")
    async def accept_suggestion(request):
        """Add the permanent rule of a current suggestion (built here, not taken from the request)."""
        key = str((await request.json()).get("key", ""))
        s = next((s for s in _suggestions() if s["key"] == key), None)
        if s is None:
            return _json({"error": "no such suggestion (already accepted or dismissed?)"}, 404)
        note = f"suggested: approved {s['count']}x in {gw.suggest_days} days"
        rule = gw.policy.add_rule(Rule(**s["rule"], note=note, source="suggestion"))
        gw.save_policy(_by(request), f"suggestion accepted: rule {rule.id} (allow {rule.host})")
        gw.record(kind="admin", action="rule+", host=rule.host, reason=json.dumps(rule.to_dict()))
        return _json(rule.to_dict(), 201)

    @routes.post("/suggestions/dismiss")
    async def dismiss_suggestion(request):
        key = str((await request.json()).get("key", ""))
        if not key:
            raise ValueError("expected {key}")
        gw.events.dismiss(key)
        return _json({"dismissed": key})

    # ---------------------------------------------------------------- policy history, export, import
    @routes.get("/policy/history")
    async def policy_history(request):
        q = request.query
        before = int(q["before"]) if q.get("before") else None
        return _json({"versions": gw.history.versions(int(q.get("limit", 100)), before), "keep": gw.history.keep})

    def _version(vid: str) -> dict:
        v = gw.history.get(int(vid))
        if v is None:
            raise KeyError(f"no policy version {vid}")
        return v

    @routes.get("/policy/history/{vid:[0-9]+}")
    async def policy_version(request):
        try:
            return _json(_version(request.match_info["vid"]))
        except KeyError as e:
            return _json({"error": e.args[0]}, 404)

    @routes.get("/policy/diff")
    async def policy_diff(request):
        """Changes from version `from` to version `to` (default: the policy in force now)."""
        q = request.query
        if not q.get("from"):
            raise ValueError("from (a version id) is required")
        try:
            old = _version(q["from"])["policy"]
            new = gw.policy.to_dict() if q.get("to", "current") == "current" else _version(q["to"])["policy"]
        except KeyError as e:
            return _json({"error": e.args[0]}, 404)
        return _json(history.diff(old, new))

    @routes.post("/policy/history/{vid:[0-9]+}/restore")
    async def policy_restore(request):
        vid = request.match_info["vid"]
        try:
            v = _version(vid)
        except KeyError as e:
            return _json({"error": e.args[0]}, 404)
        old = gw.policy.default
        gw.adopt(Policy.from_dict(v["policy"]))  # validated like PUT /policy; the floor stays as configured
        gw.save_policy(_by(request), f"version {vid} restored")
        gw.record(kind="admin", action="policy", reason=f"policy version {vid} restored" + _mode_changed(gw, old))
        return _json(gw.policy.describe())

    @routes.get("/policy/export")
    async def policy_export(_):
        name = time.strftime("tallygate-policy-%Y%m%d-%H%M.yaml", time.gmtime())
        return _json({"filename": name, "yaml": history.export_doc(gw.policy.to_dict(), gw.grants.ui_defs())})

    @routes.post("/policy/import")
    async def policy_import(request):
        """Validate an export (like PUT /policy and PUT /grants) and show what it would change; with
        `apply: true` replace the policy and add or replace the UI grants it contains. All or nothing."""
        body = await request.json()
        if not isinstance(body, dict):
            raise ValueError("expected {yaml, apply}")
        pol_d, grants_d, warnings = history.parse_import(body.get("yaml"))
        new = Policy.from_dict(pol_d)
        checked = {n: gw.grants.check_ui(n, d) for n, d in grants_d.items()}
        result = {
            "diff": history.diff(gw.policy.to_dict(), new.to_dict()),
            "grants": {
                "added": sorted(n for n in checked if n not in gw.grants.defs),
                "changed": sorted(
                    n for n, g in checked.items() if n in gw.grants.defs and gw.grants.defs[n].to_dict() != g.to_dict()
                ),
            },
            "warnings": warnings,
            "applied": False,
        }
        if body.get("apply") is True:
            old = gw.policy.default
            gw.adopt(new)
            gw.save_policy(_by(request), "policy imported")
            for n, d in grants_d.items():
                gw.grants.upsert_ui(n, d)
            note = _mode_changed(gw, old)
            gw.record(kind="admin", action="policy", reason=f"policy imported ({len(checked)} UI grants)" + note)
            if checked:
                gw.publish({"type": "grants"})
            result["applied"] = True
        return _json(result)

    # ---------------------------------------------------------------- grants (admin)
    @routes.get("/grants")
    async def grants(_):
        g = gw.grants
        needed = {}
        for d in g.defs.values():
            missing = sorted({n for i in d.inject for n in _secret_names(i["value"])} - set(gw.secrets.names()))
            if missing:
                needed[d.name] = missing
        return _json(
            {
                "defs": [d.to_dict() for d in g.defs.values()],
                "active": [a.to_dict() for a in g.active.values() if a.expires > time.time()],
                "requests": [r.to_dict() for r in g.pending()],
                "lan_allow_ui": [str(n) for n in g.ui_lan_allow],
                "missing_secrets": needed,
                "auto_suspended": g.auto_suspended,
            }
        )

    @routes.put("/grants/{name}")
    async def put_grant(request):
        name = request.match_info["name"]
        d = gw.grants.upsert_ui(name, await request.json())
        gw.record(kind="admin", action="grant", host=name, reason=f"grant {name} defined/changed via API")
        gw.publish({"type": "grants"})
        return _json(d.to_dict())

    @routes.delete("/grants/{name}")
    async def delete_grant(request):
        name = request.match_info["name"]
        gw.grants.delete_ui(name)
        gw.record(kind="admin", action="grant", host=name, reason=f"grant {name} deleted via API")
        gw.publish({"type": "grants"})
        return _json({"deleted": name})

    @routes.post("/grants/{name}/activate")
    async def activate_grant(request):
        body = await request.json()
        return _json(
            gw.activate_grant(
                request.match_info["name"],
                str(body.get("level", "read")),
                body.get("ttl"),
                str(body.get("by", "api"))[:64],
            )
        )

    @routes.delete("/active-grants/{aid}")
    async def revoke_grant(request):
        by = request.query.get("by", "api")[:64]
        return _json(gw.revoke_grant(request.match_info["aid"], by))

    @routes.post("/grant-requests/{rid}/decide")
    async def decide_grant(request):
        body = await request.json()
        decision = str(body.get("decision", ""))
        if decision not in ("approve", "read", "deny"):
            raise ValueError("decision must be approve | read | deny")
        return _json(
            gw.decide_grant(request.match_info["rid"], decision, str(body.get("by", "api"))[:64], body.get("ttl"))
        )

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


def _by(request: web.Request) -> str:
    """Who made a change, for the policy history: the control plane sets it to the session user."""
    return request.headers.get("X-Tallygate-By", "")[:64] or "api"


def _mode_changed(gw: Gateway, old: str) -> str:
    """A mode change ends an auto-approval suspension left by the emergency stop. Returns a note for the log."""
    if gw.policy.default != old and gw.grants.resume_auto():
        return "; grant auto-approval resumed"
    return ""


def _step(steps: list, name: str, fn) -> None:
    """Run one emergency-stop step; a failure is reported and does not stop the steps after it."""
    try:
        res = fn() or {}
        steps.append({"step": name, "ok": not res.get("errors"), **res})
    except Exception as e:  # noqa: BLE001 - best effort: every later step must still run
        steps.append({"step": name, "ok": False, "errors": [f"{type(e).__name__}: {e}"]})


def emergency_stop(gw: Gateway, by: str) -> dict:
    """Best effort, most important first: suspend auto-approval, revoke grants, deny what is pending,
    remove internet shortcuts, mode deny. Every step runs even if an earlier one failed."""
    steps: list[dict] = []
    reason = f"emergency stop by {by}"

    def revoke() -> dict:
        done, errors = [], []
        for a in list(gw.grants.active.values()):
            try:
                gw.revoke_grant(a.id, by)
                done.append(a.name)
            except Exception as e:  # noqa: BLE001
                errors.append(f"{a.name}: {e}")
        return {"revoked": done, "errors": errors}

    def deny_asks() -> dict:
        denied = []
        for key, p in list(gw.pending.items()):
            if gw.pending.pop(key, None) is not p:
                continue
            if p.future is not None and not p.future.done():
                p.future.set_result(Decision("deny", reason))
            gw.publish({"type": "resolved", "id": p.id, "action": "deny", "scope": "deny", "by": by})
            denied.append(f"{p.host}:{p.port}")
        return {"denied": denied}

    def deny_grant_requests() -> dict:
        denied, errors = [], []
        for r in gw.grants.pending():
            try:
                gw.decide_grant(r.id, "deny", by)
                denied.append(r.name)
            except Exception as e:  # noqa: BLE001
                errors.append(f"{r.name}: {e}")
        return {"denied": denied, "errors": errors}

    def remove_internet() -> dict:
        from egressgw.core import PRESET_DIR

        sources, ids, errors = set(), set(), []
        for path in sorted(PRESET_DIR.glob("*.yaml")):
            try:
                meta, pol = load_preset(path)
            except Exception as e:  # noqa: BLE001
                errors.append(f"preset {path.stem}: {e}")
                continue
            if meta["category"] == "internet":
                sources.add(f"preset:{path.stem}")
                ids |= {r.id for r in pol.rules}
        if not sources:
            errors.append(f"no internet presets found in {PRESET_DIR}")
        removed = [r.id for r in gw.policy.rules if r.source in sources or (r.id in ids and r.action == "allow")]
        for rid in removed:
            gw.policy.remove_rule(rid)
        if removed:
            gw.save_policy(by, "emergency stop: internet shortcuts removed")
        return {"removed": removed, "errors": errors}

    def mode_deny() -> dict:
        old = gw.policy.default
        gw.policy.default = "deny"
        gw.save_policy(by, "emergency stop: mode deny")
        return {"previous": old}

    _step(steps, "suspend_auto_approval", lambda: gw.grants.suspend_auto(by))
    _step(steps, "revoke_grants", revoke)
    _step(steps, "deny_pending", deny_asks)
    _step(steps, "deny_grant_requests", deny_grant_requests)
    _step(steps, "remove_internet_presets", remove_internet)
    _step(steps, "mode_deny", mode_deny)
    ok = all(s["ok"] for s in steps)
    counts = ", ".join(
        f"{s['step']}: {len(v)}" for s in steps for k, v in s.items() if k in ("revoked", "denied", "removed")
    )
    failed = [s["step"] for s in steps if not s["ok"]]
    with contextlib.suppress(Exception):  # the stop itself has happened; a log failure must not hide that
        gw.record(
            kind="admin",
            action="emergency-stop",
            reason=f"{reason} ({counts}; " + ("complete)" if ok else f"failed: {', '.join(failed)})"),
        )
    return {"ok": ok, "steps": steps}


def _secret_names(template: str) -> set[str]:
    import re

    return set(re.findall(r"\$\{([a-z0-9_]+)\}", template))


async def start(gw: Gateway, host: str, port: int) -> web.AppRunner:
    runner = web.AppRunner(build_app(gw), access_log=None)
    await runner.setup()
    await web.TCPSite(runner, host, port).start()
    return runner
