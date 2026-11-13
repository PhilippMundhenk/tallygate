"""ADR-0014: one model for what applies to a connection and its requests (gateway/egressgw/model.py)."""

import sys
import time
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "gateway"))

pytest.importorskip("mitmproxy")

from egressgw import core
from egressgw.model import INTERCEPT, PASSTHROUGH, Req, Verdict

CONFIG = {
    "inject": [{"host": "api.example", "header": "X-Token", "value": "Bearer ${tok}"}],
    "inject_strip_headers": ["Authorization", "Cookie"],
    "readonly": ["ro.example", {"host": "*.oci.example", "post_is_write": True, "read_posts": ["/q/*"]}],
    "github_repos": ["me/app"],
    "github_hosts": ["git.example"],
    "grants": {
        "ha": {
            "targets": [{"host": "ha.example", "port": 443, "paths": ["/api/*"]}],
            "levels": ["read", "write"],
            "inject": [{"host": "ha.example", "header": "X-HA", "value": "${tok}"}],
        },
        "plain": {"targets": [{"host": "plain.example", "port": 80, "scheme": "http"}], "levels": ["write"]},
        "ssh": {"targets": [{"host": "nas.example", "port": 22, "scheme": "tcp"}], "levels": ["write"]},
        "api": {"targets": [{"host": "api.example", "port": 443}], "levels": ["write"]},
    },
}
POLICY = {
    "default": "deny",
    "rules": [
        {"id": "ok", "action": "allow", "host": "ok.example"},
        {"id": "api", "action": "allow", "host": "api.example"},
    ],
}


@pytest.fixture
def gw(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "DATA_DIR", tmp_path)
    monkeypatch.setattr(core, "CONFIG_PATH", tmp_path / "config.yaml")
    monkeypatch.setattr(core, "STATIC_HOSTS", {})
    (tmp_path / "config.yaml").write_text(yaml.safe_dump(CONFIG))
    (tmp_path / "policy.yaml").write_text(yaml.safe_dump(POLICY))
    g = core.Gateway()
    g.secrets.set("tok", "s3cret")
    return g


def req(method="GET", path="/", host="ok.example", scheme="https", header=True, connection=""):
    return Req(method, scheme, path, host if header else None, host, connection)


def grant(gw, name, level="write"):
    a = gw.grants.activate(name, level, 600, "", "t")
    t = gw.grants.defs[name].targets[0]
    return Verdict(t.host, t.port, a.id, t)


# ---------------------------------------------------------------- limits decide interception
def test_a_destination_with_limits_is_intercepted_and_one_without_is_not(gw):
    m = gw.access
    assert not m.host_limits("ok.example").any and not m.intercepted("ok.example")
    for host in ("ro.example", "x.oci.example", "api.example", "git.example"):  # read-only, credentials, repositories
        assert m.intercepted(host), host
    assert m.tls(Verdict("ok.example", 443), "ok.example") == (PASSTHROUGH, None)
    assert m.tls(Verdict("ro.example", 443), "") == (INTERCEPT, None)  # whatever the SNI says
    assert m.tls(grant(gw, "ha"), "") == (INTERCEPT, None)  # every request of a grant is checked
    assert m.tls(grant(gw, "ssh"), "") == (PASSTHROUGH, None)  # raw TCP
    assert m.tls(None, "ok.example") == (PASSTHROUGH, "TLS without a checked destination")


def test_passthrough_needs_the_checked_name_and_never_goes_around_limits(gw):
    m = gw.access
    assert m.passthrough_problem("ok.example", 443, "front.example") == (
        "TLS SNI front.example does not match the checked name ok.example"
    )
    assert "(none)" in m.passthrough_problem("ok.example", 443, "")
    ip = "192.0.2.1"
    assert m.passthrough_problem(ip, 443, "") is None and m.passthrough_problem(ip, 443, ip) is None
    assert m.passthrough_problem(ip, 443, "ok.example") is None  # the rules allow that name by itself
    assert m.passthrough_problem(ip, 443, "api.example") == (
        "TLS SNI api.example names an intercepted host; reach it by name, not by IP literal"
    )
    assert (
        m.passthrough_problem(ip, 443, "other.example")
        == "TLS SNI other.example on IP 192.0.2.1 is not allowed by the rules"
    )
    gw._note_intercept_ips([ip])  # the address of a destination with limits: no SNI does not help
    for sni in ("", ip, "ok.example"):
        assert (
            m.passthrough_problem(ip, 443, sni)
            == f"IP {ip} is an intercepted host; reach it by name, not by IP literal"
        )


# ---------------------------------------------------------------- one check for every request
def test_host_binding(gw):
    v = Verdict("ok.example", 443)
    assert gw.access.check(v, req()).refuse is None
    assert gw.access.check(v, req(host="evil.example")).refuse == "Host header does not match the checked target"
    assert gw.access.check(v, req(host="evil.example", header=False)).refuse is None  # no Host: the default site
    assert gw.access.check(Verdict("192.0.2.1", 80), req(host="[192.0.2.1]", scheme="http")).refuse is None


def test_read_only_hosts(gw):
    ro, oci = Verdict("ro.example", 443), Verdict("x.oci.example", 443)
    check = gw.access.check
    assert check(ro, req("GET", host="ro.example")).refuse is None
    assert check(ro, req("POST", host="ro.example")).refuse is None  # POST is a write only where configured
    for method in ("PUT", "PATCH", "DELETE", "put"):
        assert check(ro, req(method, host="ro.example")).refuse == "read-only host"
    assert check(oci, req("POST", "/v2/upload", host="x.oci.example")).refuse == "read-only host"
    assert check(oci, req("POST", "/q/search", host="x.oci.example")).refuse is None  # a POST that only reads


def test_credentials_are_stripped_always_and_added_only_to_the_destination_over_tls(gw):
    v = Verdict("api.example", 443)
    out = gw.access.check(v, req(host="api.example"))
    assert out.refuse is None and out.strip == ("X-Token", "Authorization", "Cookie")
    assert out.add == [("X-Token", "Bearer s3cret")]
    assert gw.access.check(v, req(host="api.example", scheme="http")).add == []  # never in clear text
    plain = gw.access.check(v, req(host="api.example", scheme="http"))
    assert plain.strip == out.strip  # the agent's own credentials are removed all the same
    gw.secrets.set("tok", None)
    assert gw.access.check(v, req(host="api.example")).add == []  # no secret yet: no credentials at all
    assert gw.access.check(Verdict("ok.example", 443), req()).strip == ()


def test_repository_limits(gw):
    v = Verdict("git.example", 443)
    assert gw.access.check(v, req(path="/me/app.git/info/refs", host="git.example")).refuse is None
    assert gw.access.check(v, req(path="/other/repo", host="git.example")).refuse is not None  # another repository


def test_a_grant_is_the_same_check_with_its_own_limits(gw):
    check = gw.access.check
    ha = grant(gw, "ha", "read")
    ok = check(ha, req(path="/api/states", host="ha.example"))
    assert ok.refuse is None and ok.add == [("X-HA", "s3cret")] and set(ok.strip) == {"Authorization", "Cookie", "X-HA"}
    assert (
        check(ha, req(path="/api/x", host="ha.example", scheme="http")).refuse == "plain HTTP to an https grant target"
    )
    assert check(ha, req(path="/api/x", host="evil.example")).refuse == "Host header does not match the granted target"
    assert check(ha, req(path="/api/x", host="evil.example", header=False)).refuse is not None  # required either way
    assert check(ha, req(path="/admin", host="ha.example")).refuse == "path not covered by grant ha"
    assert check(ha, req("POST", "/api/x", host="ha.example")).refuse == "grant ha is read-only"
    assert (
        check(ha, req(path="/api/x", host="ha.example", connection="keep-alive, Upgrade")).refuse
        == "grant ha is read-only"
    )
    assert check(grant(gw, "ha", "write"), req("POST", "/api/x", host="ha.example")).refuse is None
    assert check(grant(gw, "plain"), req("PUT", host="plain.example", scheme="http")).refuse is None
    assert check(grant(gw, "ssh"), req(host="whatever")).refuse is None  # raw: no request is looked at
    api = check(grant(gw, "api"), req(host="api.example"))  # a grant to a credentials host: stripped, none of its own
    assert api.refuse is None and "X-Token" in api.strip and api.add == []


def test_an_ended_grant_lets_nothing_through(gw):
    v = grant(gw, "ha")
    r = req(path="/api/x", host="ha.example")
    assert gw.access.check(v, r, now=time.time() + 601).refuse == "grant expired or revoked"
    gw.grants.revoke(v.grant)
    assert gw.access.check(v, r).refuse == "grant expired or revoked"
    del gw.grants.defs["ha"]
    assert gw.access.limits(v).gone


def test_raw_traffic_and_websockets(gw):
    m = gw.access
    assert m.raw_problem(grant(gw, "ha")) == "non-HTTP traffic to an HTTP grant target"
    assert m.raw_problem(grant(gw, "ssh")) is None and m.raw_problem(Verdict("ok.example", 443)) is None
    assert m.raw_problem(None) is None and m.websocket_problem(None) is None
    assert m.websocket_problem(grant(gw, "ha", "read")) == "websocket on a read-only grant"
    assert m.websocket_problem(grant(gw, "ha", "write")) is None
    assert m.websocket_problem(Verdict("ok.example", 443)) is None
