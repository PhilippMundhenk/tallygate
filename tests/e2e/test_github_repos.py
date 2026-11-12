"""GitHub access per repository end to end (#78): other repositories are refused before they reach GitHub.

gh.test plays github.com (git/web paths, and /api/v3 like GitHub Enterprise); other.test is a GitHub host
without credential injection (passthrough before, intercepted and checked with github_repos)."""

from __future__ import annotations

import json

import pytest

from .helpers import tls_request

HOSTS = "gh.test=127.0.0.1,other.test=127.0.0.1"


@pytest.fixture
def gw(make_gateway, upstream):
    port = upstream["https"]
    g = make_gateway(
        {
            "hard_deny_floor": ["10.0.0.0/8"],
            "inject": [{"host": "gh.test", "header": "Authorization", "value": "Bearer ${github_token}"}],
            "github_hosts": ["gh.test", "other.test"],
            "github_repos": ["acme/app", "tools/*"],
        },
        {"default": "deny", "rules": [{"action": "allow", "host": "*.test", "port": port}]},
        GW_TEST_FLOOR_REPLACE="1",
        GW_TEST_STATIC_HOSTS=HOSTS,
    )
    g["api"].call("PUT", "/secrets/github_token", {"value": "real-token"})
    g["port"] = port
    return g


def req(g, path, method="GET", host="gh.test", **headers):
    status, body = tls_request(g["ports"]["http"], f"{host}:{g['port']}", host, g["ca"], method, path, headers)
    return status, body


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/acme/app.git/info/refs?service=git-receive-pack"),
        ("POST", "/acme/app.git/git-receive-pack"),
        ("GET", "/tools/lib/archive/main.tar.gz"),
        ("GET", "/api/v3/repos/acme/app/pulls"),
        ("GET", "/api/v3/user"),
    ],
)
def test_allowed_repositories_get_the_token(gw, method, path):
    status, body = req(gw, path, method, Authorization="Bearer agent-own")
    assert status == 200
    echo = json.loads(body)
    assert echo["auth"] == "Bearer real-token" and echo["path"] == path


@pytest.mark.parametrize(
    ("method", "path", "why"),
    [
        ("POST", "/evil/exfil.git/git-receive-pack", "repository evil/exfil is not in github_repos"),
        ("GET", "/acme/other/archive/main.zip", "repository acme/other is not in github_repos"),
        ("GET", "/acme/app/../../evil/x", "non-canonical path"),
        ("POST", "/api/v3/user/repos", "only /repos/"),
        ("POST", "/api/graphql", "GraphQL"),
    ],
)
def test_other_repositories_are_refused_before_github(gw, method, path, why):
    status, body = req(gw, path, method)
    assert status == 403 and why in body.decode()
    _, evs, _ = gw["api"].call("GET", "/events?limit=5")
    assert any(why in e["reason"] and e["action"] == "deny" for e in evs)


def test_a_github_host_without_injection_is_checked_too(gw):
    status, body = req(gw, "/acme/app/raw/main/README.md", host="other.test")
    assert status == 200 and json.loads(body)["auth"] is None  # intercepted, no token there
    assert req(gw, "/evil/x/raw/main/a", host="other.test")[0] == 403
    assert gw["api"].call("GET", "/info")[1]["github_repos"] == ["acme/app", "tools/*"]


def test_invalid_github_repos_stop_the_gateway(make_gateway):
    g = make_gateway({"github_repos": ["not a repo"]}, {"default": "deny"}, wait=False)
    assert g["proc"].wait(30) != 0
    assert "github_repos: invalid entry" in g["log"].read_text()
