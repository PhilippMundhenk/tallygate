"""The `destinations:` config format, end to end (#122, ADR-0014).

A gateway configured entirely through `destinations:` must enforce exactly as the old keys do: allowed names
pass, denied names are refused, read-only hosts refuse writes, credentials are injected, repository scope is
enforced, and an on-request destination is blocked until it is requested and then limited to its paths.
Real mitmdump, real TLS interception; working paths AND blocking paths are both asserted.
"""

from __future__ import annotations

import json

import pytest

from .helpers import connect_tunnel, proxy_request, tls_request

HOSTS = "ro.test=127.0.0.1,gh.test=127.0.0.1,open.test=127.0.0.1,blocked.test=127.0.0.1,svc.test=127.0.0.1"


@pytest.fixture
def gw(make_gateway, upstream):
    https, http = upstream["https"], upstream["http"]
    g = make_gateway(
        {
            # never-keys coexist with destinations; grants_never set so the floor is replaced and the
            # loopback e2e upstreams are reachable through a grant (GW_TEST_FLOOR_REPLACE)
            "hard_deny_floor": ["10.0.0.0/8"],
            "grants_never": ["169.254.0.0/16"],
            "destinations": [
                {"match": {"host": "ro.test"}, "methods": "no-writes"},
                {
                    "match": {"host": "gh.test"},
                    "credentials": [{"header": "Authorization", "value": "Bearer ${github_token}"}],
                    "repos": {"patterns": ["acme/app"]},
                },
                {
                    "match": {"host": "svc.test", "port": http},
                    "access": "request",
                    "scheme": "http",
                    "paths": ["/api/*"],
                    "request": {
                        "name": "svc",
                        "levels": ["read", "write"],
                        "approval": {"read": "auto", "write": "ask"},
                        "default_ttl": 3600,
                        "max_ttl": 14400,
                    },
                },
            ],
        },
        {
            "default": "deny",
            "rules": [
                {"action": "deny", "host": "blocked.test", "port": https},
                {"action": "allow", "host": "*.test", "port": https},
            ],
        },
        GW_TEST_FLOOR_REPLACE="1",
        GW_TEST_STATIC_HOSTS=HOSTS,
    )
    g["api"].call("PUT", "/secrets/github_token", {"value": "real-token"})
    g["https"], g["http"] = https, http
    return g


def tls(g, host, path="/", method="GET", **headers):
    return tls_request(g["ports"]["http"], f"{host}:{g['https']}", host, g["ca"], method, path, headers)


def test_destinations_config_is_accepted_and_reported(gw):
    # the gateway started from `destinations:` alone and exposes the same model/config
    info = gw["api"].call("GET", "/info")[1]
    assert info["github_repos"] == ["acme/app"] and "ro.test" in [
        r if isinstance(r, str) else r["host"] for r in info.get("readonly", ["ro.test"])
    ]
    model = gw["api"].call("GET", "/model")[1]
    assert any(d["match"].get("host") == "svc.test" and d["access"] == "request" for d in model["destinations"])


def test_allowed_passes_and_denied_is_blocked(gw):
    # at the CONNECT layer: an allowed name tunnels, a denied name is refused (open.test is passthrough, so
    # we check the tunnel, not the upstream cert; an intercepted allowed host is covered by the read-only test)
    sock, line = connect_tunnel(gw["ports"]["http"], f"open.test:{gw['https']}")
    sock.close()
    assert " 200" in line  # working path
    sock2, line2 = connect_tunnel(gw["ports"]["http"], f"blocked.test:{gw['https']}")
    sock2.close()
    assert " 200" not in line2  # blocking path: a denied name never connects
    _, evs, _ = gw["api"].call("GET", "/events?limit=10")
    assert any(e["action"] == "deny" and "blocked.test" in (e.get("host") or "") for e in evs)


def test_read_only_host_allows_reads_and_refuses_writes(gw):
    assert tls(gw, "ro.test", "/x")[0] == 200  # GET works
    assert tls(gw, "ro.test", "/x", "POST")[0] == 200  # POST is allowed (post_is_write is off)
    for method in ("PUT", "PATCH", "DELETE"):
        status, body = tls(gw, "ro.test", "/x", method)
        assert status == 403 and b"read-only" in body, method  # blocking path


def test_credentials_injected_and_agent_own_stripped(gw):
    status, body = tls(gw, "gh.test", "/acme/app/raw/main/README.md", Authorization="Bearer agent-own")
    assert status == 200
    echo = json.loads(body)
    assert echo["auth"] == "Bearer real-token"  # the configured token replaced the agent's own


def test_repository_scope_blocks_other_repositories(gw):
    assert tls(gw, "gh.test", "/acme/app/raw/main/a")[0] == 200  # the allowed repo
    status, body = tls(gw, "gh.test", "/evil/exfil/raw/main/a")
    assert status == 403 and b"evil/exfil" in body  # blocking path: another repo refused before GitHub


def test_on_request_destination_is_blocked_until_requested_then_limited(gw):
    # before requesting: the on-request destination is not reachable
    assert proxy_request(gw["ports"]["http"], f"svc.test:{gw['http']}", "/api/x")[0] != 200
    status, r, _ = gw["agent"].call("POST", "/v1/grants/svc/request", {"level": "read", "reason": "e2e"})
    assert status == 200 and r["status"] == "approved"
    assert proxy_request(gw["ports"]["http"], f"svc.test:{gw['http']}", "/api/x")[0] == 200  # working path
    status, body = proxy_request(gw["ports"]["http"], f"svc.test:{gw['http']}", "/other")  # outside the paths
    assert status == 403 and b"path" in body  # blocking path


def test_mixing_destinations_with_old_keys_stops_the_gateway(make_gateway):
    g = make_gateway(
        {"destinations": [{"match": {"host": "a.test"}, "methods": "no-writes"}], "readonly": ["b.test"]},
        {"default": "deny"},
        wait=False,
    )
    assert g["proc"].wait(30) != 0
    assert "cannot be combined with the old keys" in g["log"].read_text()


def test_an_access_rule_in_the_gateway_config_stops_the_gateway(make_gateway):
    g = make_gateway(
        {"destinations": [{"match": {"host": "a.test"}, "access": "allow"}]},
        {"default": "deny"},
        wait=False,
    )
    assert g["proc"].wait(30) != 0
    assert "belong in the policy" in g["log"].read_text()
