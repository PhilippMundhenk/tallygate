"""egress-gw end-to-end: policy enforcement on every protocol path, approvals, injection, DNS."""

from __future__ import annotations

import json
import threading
import time

import pytest

from .conftest import free_port
from .helpers import connect_tunnel, dns_rcode, http_via_proxy, https_via_proxy, plain_http, socks5_http


def last_events(gw, n=10):
    status, data, _ = gw["api"].call("GET", f"/events?limit={n}")
    assert status == 200
    return data


def wait_pending(gw, port, timeout=4.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        _, pend, _ = gw["api"].call("GET", "/pending")
        match = [p for p in pend if p["port"] == port]
        if match:
            return match[0]
        time.sleep(0.1)
    raise AssertionError(f"no pending request for port {port}")


def in_thread(fn, *args):
    result = {}
    t = threading.Thread(target=lambda: result.setdefault("r", fn(*args)))
    t.start()
    return t, result


# ---------------------------------------------------------------- allow / deny
def test_allowed_by_cidr_rule(gateway, upstream):
    status, body = http_via_proxy(gateway["ports"]["http"], f"http://127.0.0.1:{upstream['http']}/hello")
    assert status == 200 and json.loads(body)["path"] == "/hello"


def test_hard_deny_on_resolved_private_ip_is_immediate(gateway):
    t0 = time.time()
    status, _ = http_via_proxy(gateway["ports"]["http"], "http://lan.test/")
    assert status == 502 and time.time() - t0 < 2  # never asked
    ev = last_events(gateway, 1)[0]
    assert ev["host"] == "lan.test" and ev["action"] == "deny" and "hard-deny" in ev["reason"]


def test_hard_deny_literal_ip_via_connect(gateway):
    _, line = connect_tunnel(gateway["ports"]["http"], "10.1.2.3:22")
    assert " 200" not in line


# ---------------------------------------------------------------- human in the loop
def test_ask_then_approve_releases_held_connection(gateway, upstream):
    port = upstream["http2"]
    t, res = in_thread(http_via_proxy, gateway["ports"]["http"], f"http://127.0.0.1:{port}/held")
    pending = wait_pending(gateway, port)
    assert pending["host"] == "127.0.0.1" and pending["ips"] == ["127.0.0.1"]
    status, data, _ = gateway["api"].call("POST", f"/pending/{pending['id']}/decide", {"scope": "once", "by": "e2e"})
    assert status == 200 and data["rule"]["expires"]
    t.join(10)
    assert res["r"][0] == 200 and json.loads(res["r"][1])["path"] == "/held"
    # the approval created a temporary rule at the top -> next request passes without asking
    status, _ = http_via_proxy(gateway["ports"]["http"], f"http://127.0.0.1:{port}/again")
    assert status == 200


def test_ask_timeout_denies_and_negative_cache(gateway):
    port = free_port()
    t0 = time.time()
    status, _ = http_via_proxy(gateway["ports"]["http"], f"http://127.0.0.1:{port}/")
    assert status == 502 and 4 <= time.time() - t0 < 9  # ask_timeout = 5
    t0 = time.time()
    status, _ = http_via_proxy(gateway["ports"]["http"], f"http://127.0.0.1:{port}/")
    assert status == 502 and time.time() - t0 < 2  # negative cache: no second prompt
    reasons = [e["reason"] for e in last_events(gateway, 3)]
    assert "approval timed out recently" in reasons and "approval timed out" in reasons


def test_concurrent_requests_share_one_prompt(gateway):
    port = free_port()
    threads = [in_thread(http_via_proxy, gateway["ports"]["http"], f"http://127.0.0.1:{port}/{i}")[0] for i in range(3)]
    p = wait_pending(gateway, port)
    time.sleep(0.5)
    _, pend, _ = gateway["api"].call("GET", "/pending")
    assert len([x for x in pend if x["port"] == port]) == 1
    gateway["api"].call("POST", f"/pending/{p['id']}/decide", {"scope": "deny", "by": "e2e"})
    for t in threads:
        t.join(10)


def test_block_forever_creates_permanent_deny(gateway):
    port = free_port()
    t, _ = in_thread(http_via_proxy, gateway["ports"]["http"], f"http://127.0.0.1:{port}/")
    p = wait_pending(gateway, port)
    _, data, _ = gateway["api"].call("POST", f"/pending/{p['id']}/decide", {"scope": "deny_always", "by": "e2e"})
    t.join(10)
    assert data["rule"]["action"] == "deny" and "expires" not in data["rule"]
    _, pol, _ = gateway["api"].call("GET", "/policy")
    assert pol["rules"][0]["id"] == data["rule"]["id"]


# ---------------------------------------------------------------- credential injection
def test_injection_only_with_secret_and_matching_connect_and_sni(gateway, upstream):
    target = f"gh.test:{upstream['https']}"
    hdr = {"Authorization": "token placeholder"}
    gateway["api"].call("PUT", "/secrets/github_token", {"value": ""})
    _, body = https_via_proxy(gateway["ports"]["http"], target, "gh.test", "/a", gateway["ca"], hdr)
    assert json.loads(body)["auth"] == "token placeholder"  # no secret yet -> untouched

    gateway["api"].call("PUT", "/secrets/github_token", {"value": "ghp_E2E"})
    _, body = https_via_proxy(gateway["ports"]["http"], target, "gh.test", "/b", gateway["ca"], hdr)
    assert json.loads(body)["auth"] == "Bearer ghp_E2E"


def test_sni_spoofing_does_not_get_the_token(gateway, upstream):
    """CONNECT to another (allowed) host but claim SNI gh.test: must be passed through, never injected."""
    gateway["api"].call("PUT", "/secrets/github_token", {"value": "ghp_E2E"})
    status, body = https_via_proxy(
        gateway["ports"]["http"],
        f"other.test:{upstream['https']}",
        "gh.test",
        "/spoof",
        str(upstream["cert"]),
        {"Authorization": "token placeholder"},
    )
    assert status == 200 and json.loads(body)["auth"] == "token placeholder"


def test_intercepted_upstream_certificate_is_still_verified(gateway, upstream):
    """badcert.test is an injection host, but the upstream cert is only valid for gh.test/other.test:
    the gateway must refuse to talk to it (and therefore never send the token)."""
    gateway["api"].call("PUT", "/secrets/github_token", {"value": "ghp_E2E"})
    try:
        status, body = https_via_proxy(
            gateway["ports"]["http"], f"badcert.test:{upstream['https']}", "badcert.test", "/x", gateway["ca"], {}
        )
    except OSError:
        return  # connection aborted: fine
    assert status != 200 and b"ghp_E2E" not in body


def test_secrets_are_never_returned(gateway):
    gateway["api"].call("PUT", "/secrets/github_token", {"value": "ghp_E2E"})
    _, data, _ = gateway["api"].call("GET", "/secrets")
    assert data == {"names": ["github_token"]}
    assert "ghp_E2E" not in json.dumps(last_events(gateway, 50))


# ---------------------------------------------------------------- other protocols
def test_socks5_allowed_and_denied(gateway, upstream):
    status, body = socks5_http(gateway["ports"]["socks"], "127.0.0.1", upstream["http"], "/socks")
    assert status == 200 and json.loads(body)["path"] == "/socks"
    with pytest.raises(ConnectionRefusedError):
        socks5_http(gateway["ports"]["socks"], "lan.test", 80, "/")


def test_service_port_forwards_under_policy(gateway):
    status, body = plain_http(gateway["ports"]["svc"], "/svc")
    assert status == 200 and json.loads(body)["path"] == "/svc"
    assert last_events(gateway, 1)[0]["proto"] == "reverse"


def test_dns_is_always_nxdomain_and_logged(gateway):
    assert dns_rcode(gateway["ports"]["dns"], "exfil.example.com") == 3
    ev = last_events(gateway, 1)[0]
    assert ev["kind"] == "dns" and ev["host"] == "exfil.example.com"


# ---------------------------------------------------------------- management API
def test_api_requires_token(gateway):
    from .helpers import Api

    anon = Api(gateway["api"].base)
    assert anon.call("GET", "/policy")[0] == 401
    assert anon.call("GET", "/health")[0] == 200


def test_policy_validation_rejects_garbage(gateway):
    status, data, _ = gateway["api"].call("PUT", "/policy", {"default": "maybe"})
    assert status == 400 and "invalid default" in data["error"]
    status, _, _ = gateway["api"].call("POST", "/rules", {"action": "allow"})
    assert status == 400


def test_dry_run_test_endpoint(gateway):
    _, data, _ = gateway["api"].call("POST", "/test", {"host": "lan.test", "port": 443})
    assert data["action"] == "deny" and data["rule_id"] == "hard_deny"


def test_preset_with_ttl(gateway):
    status, data, _ = gateway["api"].call("POST", "/presets/open", {"ttl": 60})
    assert status == 200 and data["added"] == ["open-https"]
    _, pol, _ = gateway["api"].call("GET", "/policy")
    rule = next(r for r in pol["rules"] if r["id"] == "open-https")
    assert rule["expires"] - time.time() <= 61
    gateway["api"].call("DELETE", "/rules/open-https")
