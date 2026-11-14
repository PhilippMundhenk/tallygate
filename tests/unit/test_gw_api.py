"""Management API and agent grant API in-process (aiohttp test client against a real Gateway object)."""

import asyncio
import sys
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


def test_rules_add_validate_and_delete(gw):
    status, rule = admin(gw, "POST", "/rules", {"action": "deny", "host": "bad.example", "top": False})
    assert status == 201 and gw.policy.rules[-1].id == rule["id"]
    assert admin(gw, "POST", "/rules", {"action": "allow"})[0] == 400  # validation error, not 500
    assert gw.events.recent(1)[0]["action"] == "rule+"
    assert admin(gw, "DELETE", f"/rules/{rule['id']}") == (200, {"ok": True})
    assert admin(gw, "DELETE", f"/rules/{rule['id']}")[0] == 404
    assert "bad.example" not in (core.DATA_DIR / "policy.yaml").read_text()


def test_rule_edit_in_place(gw):
    # #141: PATCH changes an existing rule's action/port/note/expiry, keeping its id.
    status, rule = admin(gw, "PATCH", "/rules/ok", {"action": "deny", "expires": 2000000000, "note": "limited"})
    assert status == 200 and rule["id"] == "ok"
    assert (rule["action"], rule["expires"], rule["note"]) == ("deny", 2000000000, "limited")
    assert gw.policy.rules[0].id == "ok" and gw.policy.rules[0].action == "deny"
    assert gw.events.recent(1)[0]["action"] == "rule~"
    assert "limited" in (core.DATA_DIR / "policy.yaml").read_text()  # persisted
    assert admin(gw, "PATCH", "/rules/nope", {"note": "x"})[0] == 404  # no such rule
    assert admin(gw, "PATCH", "/rules/ok", {"host": "elsewhere.example"})[0] == 400  # host is not editable
    assert admin(gw, "PATCH", "/rules/ok", {"action": "permit"})[0] == 400  # still validated


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
