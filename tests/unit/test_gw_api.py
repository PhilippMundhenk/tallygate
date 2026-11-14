"""Management API and agent grant API in-process (aiohttp test client against a real Gateway object)."""

import asyncio
import sys
import time
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "gateway"))

pytest.importorskip("mitmproxy")
pytest.importorskip("aiohttp")

from aiohttp.test_utils import TestClient, TestServer

from egressgw import agentapi, api, core

TOKEN = "t" * 32
PRESETS = Path(__file__).resolve().parents[2] / "gateway" / "presets"


@pytest.fixture
def gw(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "DATA_DIR", tmp_path)
    monkeypatch.setattr(core, "CONFIG_PATH", tmp_path / "config.yaml")
    monkeypatch.setattr(core, "PRESET_DIR", PRESETS)
    monkeypatch.setattr(core, "CA_EXPORT", tmp_path / "ca")
    monkeypatch.setattr(core, "STATIC_HOSTS", {})
    (tmp_path / "config.yaml").write_text(
        yaml.safe_dump(
            {
                "inject": [{"host": "api.example", "value": "Bearer ${tok}"}],
                "services": [{"listen": 5432, "target": "db.example:5432"}],
                "grants": {
                    "nas": {"targets": [{"host": "nas.example", "port": 443}], "levels": ["write"]},
                    "auto": {"targets": [{"host": "a.example", "port": 443}], "approval": "auto"},
                },
                "grant_max_pending": 1,
            }
        )
    )
    (tmp_path / "policy.yaml").write_text(
        yaml.safe_dump({"default": "ask", "rules": [{"id": "ok", "action": "allow", "host": "ok.example"}]})
    )
    g = core.Gateway()
    g.api_token = TOKEN
    return g


def call(app, method, path, body=None, auth=True, headers=None):
    async def go():
        async with TestClient(TestServer(app)) as c:
            h = {"Authorization": f"Bearer {TOKEN}"} if auth else {}
            r = await c.request(method, path, json=body, headers={**h, **(headers or {})})
            return r.status, await r.json()

    return asyncio.run(go())


def admin(gw, method, path, body=None, auth=True):
    return call(api.build_app(gw), method, path, body, auth)


def test_token_required_except_for_health(gw):
    assert admin(gw, "GET", "/health", auth=False) == (200, {"ok": True})
    assert admin(gw, "GET", "/policy", auth=False)[0] == 401
    gw.api_token = ""  # an empty token never matches "Bearer "
    assert call(api.build_app(gw), "GET", "/policy", headers={"Authorization": "Bearer "}, auth=False)[0] == 401


def test_destinations_crud_for_rules_and_grants(gw):
    # ADR-0014: one CRUD surface. An access destination is a rule; a request destination is a grant.
    status, d = admin(
        gw, "POST", "/destinations", {"match": {"host": "shop.example"}, "access": "allow", "group": "shops"}
    )
    assert status == 201 and d["access"] == "allow" and d["group"] == "shops" and d["match"]["host"] == "shop.example"
    rid = d["id"]
    assert gw.policy.rules[0].id == rid and gw.policy.rules[0].group == "shops"

    # edit it (a destination dict; the editable fields are mapped to the rule)
    status, d2 = admin(gw, "PATCH", f"/destinations/{rid}", {"access": "deny", "match": {"port": 443}, "note": "n"})
    assert status == 200 and d2["access"] == "deny"
    assert gw.policy.rules[0].action == "deny" and gw.policy.rules[0].note == "n" and gw.policy.rules[0].port == 443

    # a request destination becomes a UI grant, addressed by grant:<name>
    req = {
        "match": {"host": "ha.example", "port": 443}, "access": "request", "scheme": "https",
        "request": {"name": "ha", "levels": ["read", "write"], "approval": {"read": "ask", "write": "ask"}, "default_ttl": 3600, "max_ttl": 14400},
    }  # fmt: skip
    status, g = admin(gw, "POST", "/destinations", req)
    assert status == 201 and g["id"] == "grant:ha" and "ha" in gw.grants.defs and gw.grants.defs["ha"].source == "ui"

    # group + delete through the same surface
    admin(gw, "POST", "/destinations/group", {"ids": [rid, "grant:ha"], "group": "set"})  # grant id skipped
    assert gw.policy.rules[0].group == "set"
    assert admin(gw, "DELETE", f"/destinations/{rid}") == (200, {"ok": True})
    assert admin(gw, "DELETE", "/destinations/grant:ha") == (200, {"ok": True}) and "ha" not in gw.grants.defs
    assert admin(gw, "DELETE", "/destinations/nope")[0] == 404
    assert admin(gw, "DELETE", "/destinations/grant:nope")[0] == 404
    assert admin(gw, "POST", "/destinations", {"match": {"host": "x"}})[0] == 400  # no access -> error, not 500


def test_destinations_api_cannot_set_file_only_grant_properties(gw):
    # ADR-0014 trust split (#137): the API/UI may not set credentials, lan (outside lan_allow) or
    # tls_verify:false, and may not change a config-file grant. Only the read-only config file may.
    base = {"targets": [{"host": "x.example", "port": 443}], "levels": ["read"], "approval": {"read": "ask"}}
    creds = {**base, "inject": [{"host": "x.example", "header": "Authorization", "value": "Bearer ${tok}"}]}
    assert admin(gw, "PUT", "/destinations/grant/withcreds", creds)[0] == 400  # credential injection is file-only
    noverify = {
        "targets": [{"host": "x.example", "port": 443, "tls_verify": False}],
        "levels": ["read"],
        "approval": {"read": "ask"},
    }
    assert admin(gw, "PUT", "/destinations/grant/noverify", noverify)[0] == 400  # disabling TLS verify is file-only
    lanone = {
        "targets": [{"host": "x.example", "port": 443, "lan": True}],
        "levels": ["read"],
        "approval": {"read": "ask"},
    }
    assert admin(gw, "PUT", "/destinations/grant/lanone", lanone)[0] == 400  # LAN needs lan_allow in the config
    assert admin(gw, "PUT", "/destinations/grant/nas", base)[0] == 400  # nas is a config-file grant, read-only here
    assert admin(gw, "PUT", "/destinations/grant/ok2", base)[0] == 200 and gw.grants.defs["ok2"].source == "ui"
    # the same credential injection smuggled through POST /destinations (a single-target request) is refused too
    bad = {
        "match": {"host": "x.example", "port": 443}, "access": "request", "scheme": "https",
        "credentials": [{"header": "Authorization", "value": "Bearer ${tok}"}],
        "request": {"name": "viapost", "levels": ["read"], "approval": {"read": "ask"}, "default_ttl": 3600, "max_ttl": 14400},
    }  # fmt: skip
    assert admin(gw, "POST", "/destinations", bad)[0] == 400


def test_settings_get_and_patch(gw):
    # ADR-0015: behaviour settings editable in the UI, trust-critical stays file-only.
    status, s = admin(gw, "GET", "/settings")
    assert status == 200 and set(s) == {"values", "defaults", "restart_keys"}
    assert s["values"]["rule_stale_days"] == 30 and "log_keep_days" in s["restart_keys"]
    status, after = admin(gw, "PATCH", "/settings", {"rule_stale_days": 45, "log_keep_days": 14})
    assert status == 200 and after["values"]["rule_stale_days"] == 45 and after["restart_needed"] == ["log_keep_days"]
    assert gw.stale_days == 45  # applied live
    assert admin(gw, "PATCH", "/settings", {"inject": []})[0] == 400  # trust-critical refused, not 500
    assert admin(gw, "PATCH", "/settings", {"grant_max_pending": 0})[0] == 400  # out of range
    assert admin(gw, "PATCH", "/settings", {"grant_max_pending": 9})[0] == 200
    assert gw.grants.max_requests == 9  # applied live to the grant flow


def test_model_endpoint_returns_the_whole_destination_model(gw):
    status, model = admin(gw, "GET", "/model")
    assert status == 200 and set(model) == {"default", "destinations", "never"}
    assert model["default"] == gw.policy.default
    accesses = [d for d in model["destinations"] if d.get("access")]
    assert any(d["match"].get("host") == "ok.example" and d["access"] == "allow" for d in accesses)


def test_preset_names_are_checked(gw):
    assert admin(gw, "POST", "/presets/..%2Fpolicy")[0] in (400, 404)
    assert admin(gw, "POST", "/presets/not-an-identifier") == (400, {"error": "bad preset"})
    assert admin(gw, "DELETE", "/presets/not-an-identifier") == (400, {"error": "bad preset"})
    assert admin(gw, "POST", "/presets/doesnotexist") == (404, {"error": "unknown preset"})
    names = admin(gw, "GET", "/presets")[1]
    assert "baseline" in names
    details = admin(gw, "GET", "/presets?details=1")[1]
    assert {d["name"] for d in details} == set(names) and all("rules" in d for d in details)


def test_pending_decisions(gw):
    assert admin(gw, "POST", "/pending/x/decide", {"scope": "forever"})[0] == 400
    assert admin(gw, "POST", "/pending/x/decide", {"scope": "once"})[0] == 404


def decide(gw, host, port, body):
    """Insert a pending request (with a future bound to the running loop) and POST a decision for it.
    Returns (status, response, pending)."""

    async def go():
        app = api.build_app(gw)
        async with TestClient(TestServer(app)) as c:
            p = core.Pending(
                host=host, port=port, ips=[], proto="http", client="c", timeout=60,
                future=asyncio.get_running_loop().create_future(),
            )  # fmt: skip
            gw.pending[(host, port)] = p
            r = await c.request(
                "POST", f"/pending/{p.id}/decide", json=body, headers={"Authorization": f"Bearer {TOKEN}"}
            )
            return r.status, await r.json(), p

    return asyncio.run(go())


def test_decide_custom_allow_ttl_installs_a_temporary_rule(gw):
    before = time.time()
    status, res, p = decide(gw, "shop.example", 443, {"scope": "allow", "ttl": 1800})
    assert status == 200 and res["rule"]["action"] == "allow" and res["rule"]["host"] == "shop.example"
    rule = gw.policy.rules[0]  # approvals go on top, and are listed/revocable like any other rule
    assert rule.id == res["rule"]["id"] and rule.source == "approval"
    assert rule.expires is not None and 1800 - 2 <= rule.expires - before <= 1800 + 2
    assert p.future.result().action == "allow"


def test_decide_allow_ttl_is_clamped_and_requires_a_ttl(gw):
    before = time.time()
    status, res, _ = decide(gw, "shop.example", 443, {"scope": "allow", "ttl": 1})  # below the 60 s floor
    assert status == 200 and 60 - 2 <= gw.policy.rules[0].expires - before <= 60 + 2
    status, res, _ = decide(gw, "two.example", 443, {"scope": "allow", "ttl": 99_999_999})  # above 30 days
    assert status == 200 and gw.policy.rules[0].expires - before <= 2_592_000 + 2
    # "allow" with no ttl is rejected (the custom-duration scope needs a duration)
    status, res, _ = decide(gw, "three.example", 443, {"scope": "allow"})
    assert status == 400 and "ttl" in res["error"]


def test_decide_rejects_garbage_ttl_with_400(gw):
    for bad in ("3600", 3600.5, True):
        status, res, _ = decide(gw, "bad.example", 443, {"scope": "allow", "ttl": bad})
        assert status == 400 and "ttl must be an integer" in res["error"]
    assert gw.policy.rules[0].id == "ok"  # nothing was installed by the rejected calls


def test_decide_temporary_deny_suppresses_reask_then_asks_again(gw):
    before = time.time()
    status, res, _ = decide(gw, "block.example", 443, {"scope": "deny", "ttl": 600})
    assert status == 200 and res["rule"]["action"] == "deny"
    rule = gw.policy.rules[0]
    assert rule.expires is not None and 600 - 2 <= rule.expires - before <= 600 + 2
    # while live, the destination is denied (not re-asked); after expiry it may be asked again
    assert gw.policy.evaluate_name("block.example", 443).action == "deny"
    rule.expires = time.time() - 1
    assert gw.policy.evaluate_name("block.example", 443).action == "ask"


def test_decide_backward_compatible_scopes_still_work(gw):
    status, res, _ = decide(gw, "a.example", 443, {"scope": "once"})  # no ttl field at all
    assert status == 200 and res["rule"]["expires"] - time.time() <= 122
    status, res, _ = decide(gw, "b.example", 443, {"scope": "always"})
    assert status == 200 and "expires" not in res["rule"]
    status, res, _ = decide(gw, "c.github.com", 443, {"scope": "domain"})
    assert status == 200 and res["rule"]["host"] == "*.github.com" and "expires" not in res["rule"]
    status, res, _ = decide(gw, "d.example", 443, {"scope": "deny_always"})
    assert status == 200 and res["rule"]["action"] == "deny" and "expires" not in res["rule"]
    status, res, _ = decide(gw, "e.example", 443, {"scope": "deny"})  # plain deny keeps the 120 s default
    assert status == 200 and res["rule"]["expires"] - time.time() <= 122


def test_policy_test_endpoint_never_resolves_names_that_are_not_allowed(gw, monkeypatch):
    resolved = []

    async def resolve(host, port):
        resolved.append(host)
        raise OSError("nxdomain")

    monkeypatch.setattr(gw, "resolve", resolve)
    assert admin(gw, "POST", "/test", {"host": "bad_name-"})[1]["reason"] == "invalid hostname"
    body = admin(gw, "POST", "/test", {"host": "unknown.example"})[1]
    assert body["action"] == "ask" and body["reason"] == "default (not resolved)" and resolved == []
    body = admin(gw, "POST", "/test", {"host": "ok.example", "port": 443})[1]
    assert body == {"action": "deny", "reason": "dns failure: nxdomain", "ips": []} and resolved == ["ok.example"]
    body = admin(gw, "POST", "/test", {"host": "10.0.0.1"})[1]  # IP literals skip the name check
    assert body["action"] == "deny" and resolved[-1] == "10.0.0.1"


def test_policy_test_endpoint_with_ips(gw):
    body = admin(gw, "POST", "/test", {"host": "192.168.1.1", "port": 80})[1]
    assert body["action"] == "deny" and body["rule_id"] == "hard_deny" and body["ips"] == ["192.168.1.1"]
    assert admin(gw, "POST", "/test", {})[0] == 400  # missing host


def test_grant_decision_must_be_known(gw):
    r = gw.request_grant("nas", "write", None, "", "c")
    assert admin(gw, "POST", f"/grant-requests/{r.id}/decide", {"decision": "maybe"})[0] == 400
    assert r.status == "pending"
    status, body = admin(gw, "POST", f"/grant-requests/{r.id}/decide", {"decision": "approve", "ttl": "2h"})
    assert status == 200 and body["status"] == "approved"


def test_never_reachable_lists_every_source(tmp_path, monkeypatch, gw):
    # one read-only list for the UI. The fixture's gateway has no extra configuration.
    status, rows = admin(gw, "GET", "/never-reachable")
    assert status == 200 and {r["source"] for r in rows} == {"builtin"}
    assert {"range": "10.0.0.0/8", "source": "builtin", "scope": "all"} in rows
    assert {"range": "127.0.0.0/8", "source": "builtin", "scope": "all+lan"} in rows  # closed for LAN grants too
    assert admin(gw, "GET", "/never-reachable", auth=False)[0] == 401

    cfg = {
        "never": ["8.8.8.0/24", {"range": "192.168.50.0/24", "scope": "all+lan"}],
        "hard_deny_floor": ["10.0.0.0/8", "8.8.4.0/24"],  # old keys: still read
        "grants_never": ["192.168.60.0/24"],
    }
    (tmp_path / "config.yaml").write_text(yaml.safe_dump(cfg))
    (tmp_path / "policy.yaml").write_text(yaml.safe_dump({"default": "ask", "hard_deny": ["9.9.9.9/32"]}))
    monkeypatch.setenv("GW_INTERNAL_NETS", "172.31.11.0/24")
    monkeypatch.setenv("GW_API_HOST", "172.31.11.2")
    monkeypatch.setenv("GW_API_PORT", "8081")
    monkeypatch.delenv("GW_LISTEN_HOST", raising=False)
    g = core.Gateway()
    assert g.old_never_keys == ["hard_deny_floor", "grants_never"]
    rows = g.never_reachable()
    cfg_rows = {r["range"]: r["scope"] for r in rows if r["source"] == "config"}
    assert cfg_rows == {
        "8.8.8.0/24": "all",
        "8.8.4.0/24": "all",
        "192.168.50.0/24": "all+lan",
        "192.168.60.0/24": "all+lan",
    }
    assert rows.count({"range": "10.0.0.0/8", "source": "builtin", "scope": "all"}) == 1  # listed once, as built in
    assert [r["range"] for r in rows if r["source"] == "policy"] == ["9.9.9.9/32"]
    assert {r["range"]: r["scope"] for r in rows if r["source"] in ("stack", "listener")} == {
        "172.31.11.0/24": "all+lan",
        "172.31.11.2:8081": "all+lan",
    }
    assert len({r["range"] for r in rows}) == len(rows)  # every range once
    # an all+lan range closes every connection too, and every grant
    assert g.policy.hard_denied("x", 443, ["192.168.60.5"]) and g.policy.hard_denied("x", 443, ["8.8.8.8"])
    assert [str(n) for n in g.grants.never_configured] == ["192.168.50.0/24", "192.168.60.0/24"]


@pytest.mark.parametrize(
    "never, error",
    [
        ("10.0.0.0/8", "expected a list"),
        ([{"range": "10.0.0.0/8", "scope": "lan"}], "scope must be one of"),
        ([{"range": "10.0.0.0/8", "why": "x"}], "unknown keys"),
        (["not-a-cidr"], "invalid CIDR"),
    ],
)
def test_a_broken_never_entry_stops_the_gateway(tmp_path, gw, never, error):
    (tmp_path / "config.yaml").write_text(yaml.safe_dump({"never": never}))
    with pytest.raises(ValueError, match=error):
        core.Gateway()


def test_a_broken_old_key_is_named_in_the_error(tmp_path, gw):
    for key in ("hard_deny_floor", "grants_never"):
        (tmp_path / "config.yaml").write_text(yaml.safe_dump({key: ["10.0.0.0/33"]}))
        with pytest.raises(ValueError, match=f"^{key}: invalid CIDR"):
            core.Gateway()


def test_info_reports_injection_services_and_ca(gw):
    status, body = admin(gw, "GET", "/info")
    assert status == 200 and body["ca_pem"] is None
    assert body["inject_hosts"] == ["api.example"] and body["inject_secrets_needed"] == ["tok"]
    assert body["services"][0]["target"] == "db.example:5432" and body["pending"] == 0
    (core.CA_EXPORT).mkdir()
    (core.CA_EXPORT / "egress-gw-ca.pem").write_text("PEM")
    assert admin(gw, "GET", "/info")[1]["ca_pem"] == "PEM"


# ------------------------------------------------------------------ agent API
def agent(gw, method, path, body=None):
    return call(agentapi.build_app(gw), method, path, body, auth=False)


def test_agent_request_body_must_be_an_object(gw):
    assert agent(gw, "POST", "/v1/grants/nas/request", ["write"]) == (400, {"error": "JSON object expected"})


def test_agent_pending_cap_is_429_and_unknown_ids_404(gw):
    assert agent(gw, "POST", "/v1/grants/nas/request", {"level": "write"})[0] == 202
    assert agent(gw, "POST", "/v1/grants/nas/request", {"level": "write"})[0] == 202  # deduplicated
    gw.grants.defs["nas2"] = gw.grants.defs["nas"]
    status, body = agent(gw, "POST", "/v1/grants/nas2/request", {"level": "write"})
    assert status == 429 and "too many pending" in body["error"]
    assert agent(gw, "GET", "/v1/requests/nope")[0] == 404
    assert agent(gw, "POST", "/v1/grants/nope/request", {})[0] == 404


def test_agent_auto_approved_grant_is_active_at_once(gw):
    status, body = agent(gw, "POST", "/v1/grants/auto/request", {"reason": "x"})
    assert status == 200 and body["status"] == "approved" and body["granted_level"] == "read"
    catalog = agent(gw, "GET", "/v1/grants")[1]["grants"]
    assert next(g for g in catalog if g["name"] == "auto")["active"]["level"] == "read"
    status, polled = agent(gw, "GET", f"/v1/requests/{body['id']}?wait=5")
    assert status == 200 and polled["status"] == "approved"
