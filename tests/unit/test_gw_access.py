"""One read-only view of what the agent may do where (#121): gateway/egressgw/access.py."""

import sys
import time
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "gateway"))

pytest.importorskip("mitmproxy")

from egressgw import access, core

CONFIG = {
    "inject": [{"host": "github.example", "value": "Bearer ${t}"}, {"host": "api.github.example", "value": "x"}],
    "readonly": ["npm.example", {"host": "*.oci.example", "post_is_write": True, "read_posts": ["/q/*"]}],
    "github_repos": ["me/app"],
    "github_hosts": ["github.example"],
    "grants": {
        "ha": {
            "targets": [{"host": "ha.lan", "port": 8123, "scheme": "http", "paths": ["/api/*"], "lan": True}],
            "levels": ["read", "write"],
        },
        "sec": {
            "targets": [{"host": "npm.example", "port": 443}],
            "inject": [{"host": "npm.example", "value": "Bearer ${n}"}],
            "approval": "auto",
        },
        "ssh": {"targets": [{"host": "nas.lan", "port": 22, "scheme": "tcp", "lan": True}], "levels": ["write"]},
    },
}
POLICY = {
    "default": "deny",
    "rules": [
        {"id": "gh", "action": "allow", "host": "github.example", "port": 443, "note": "git"},
        {"id": "npm", "action": "allow", "host": "npm.example", "port": [80, 443]},
        {"id": "cdn", "action": "allow", "host": "*.cdn.example"},
        {"id": "bad", "action": "deny", "cidr": "198.18.0.0/15", "port": "8000-8100"},
        {"id": "old", "action": "allow", "host": "gone.example", "expires": 1},
    ],
}


@pytest.fixture
def gw(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "DATA_DIR", tmp_path)
    monkeypatch.setattr(core, "CONFIG_PATH", tmp_path / "config.yaml")
    monkeypatch.setattr(core, "STATIC_HOSTS", {})
    (tmp_path / "config.yaml").write_text(yaml.safe_dump(CONFIG))
    (tmp_path / "policy.yaml").write_text(yaml.safe_dump(POLICY))
    return core.Gateway()


def by_host(view):
    return {(r["host"], r["port"]): r for r in view["rows"]}


def test_each_destination_once_with_everything_that_applies(gw):
    view = access.overview(gw)
    rows = by_host(view)
    assert view["default"] == "deny" and view["last_used_days"] == 30
    assert [r["host"] for r in view["rows"]][:4] == ["github.example", "npm.example", "*.cdn.example", "198.18.0.0/15"]
    assert ("gone.example", "*") not in rows  # an expired rule decides nothing

    gh = rows["github.example", "443"]  # rule + credentials + repository limit on one row
    assert gh["access"] == "allow" and gh["rule"] == {
        "id": "gh",
        "position": 1,
        "note": "git",
        "expires": None,
        "source": "user",
    }
    assert gh["credentials"] is True and gh["repos"] == ["me/app"] and gh["read_only"] is None and gh["grants"] == []

    npm = rows["npm.example", "80,443"]  # rule + read-only + a grant whose target the rule covers
    assert npm["access"] == "allow" and npm["read_only"] == {"post_is_write": False, "read_posts": []}
    assert [g["name"] for g in npm["grants"]] == ["sec"] and npm["grants"][0]["credentials"] is True
    assert npm["grants"][0]["paths"] is None and npm["grants"][0]["active"] is None

    assert rows["*.cdn.example", "*"]["access"] == "allow" and rows["198.18.0.0/15", "8000-8100"]["access"] == "deny"

    api = rows["api.github.example", "443"]  # credentials, but no rule names it: what the rules decide now
    assert api["access"] == "deny" and api["rule"] is None and api["credentials"] is True
    oci = rows["*.oci.example", "443"]  # a pattern cannot be evaluated: no access stated
    assert oci["access"] is None and oci["read_only"] == {"post_is_write": True, "read_posts": ["/q/*"]}

    ha = rows["ha.lan", "8123"]  # reachable only on request
    assert ha["access"] == "request" and ha["rule"] is None
    assert ha["grants"] == [
        {
            "name": "ha",
            "levels": ["read", "write"],
            "lan": True,
            "scheme": "http",
            "paths": ["/api/*"],
            "credentials": False,
            "active": None,
        }
    ]
    assert rows["nas.lan", "22"]["grants"][0]["scheme"] == "tcp" and rows["nas.lan", "22"]["grants"][0]["paths"] is None


def test_effective_row_names_the_rule_that_decides(gw):
    from egressgw.policy import Rule

    gw.policy.rules = [Rule(action="allow", host="*.github.example", id="wild"), *gw.policy.rules]
    api = by_host(access.overview(gw))["api.github.example", "443"]
    assert api["access"] == "allow" and api["rule"]["id"] == "wild" and api["rule"]["position"] == 1


def test_active_grants_and_last_use(gw):
    a = gw.grants.activate("ha", "read", 600, "why", "me")
    now = time.time()
    for host, port, action in (
        ("github.example", 443, "allow"),
        ("x.cdn.example", 8443, "allow"),
        ("npm.example", 8080, "allow"),
        ("npm.example", 443, "deny"),
    ):
        gw.events.add({"kind": "conn", "host": host, "port": port, "action": action, "ts": now - 60})
    gw.events.add({"kind": "conn", "host": "github.example", "port": 443, "action": "allow", "ts": now - 40 * 86400})
    rows = by_host(access.overview(gw))
    assert rows["ha.lan", "8123"]["grants"][0]["active"] == {"level": "read", "expires": a.expires}
    assert rows["github.example", "443"]["last_used"] == pytest.approx(now - 60)
    assert rows["*.cdn.example", "*"]["last_used"] == pytest.approx(now - 60)  # a pattern: any host it covers
    assert rows["npm.example", "80,443"]["last_used"] is None  # another port, and a denied attempt: not "used"
    assert rows["198.18.0.0/15", "8000-8100"]["last_used"] is None and rows["nas.lan", "22"]["last_used"] is None
