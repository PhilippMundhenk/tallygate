"""egress-gw end-to-end: policy enforcement on every protocol path, approvals, injection, DNS."""

from __future__ import annotations

import contextlib
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
    """lan.test is allowed by name but resolves to a private IP: denied at once, never asked."""
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
    assert json.loads(body)["auth"] is None  # no secret yet -> agent credentials stripped (TG-05)

    gateway["api"].call("PUT", "/secrets/github_token", {"value": "ghp_E2E"})
    _, body = https_via_proxy(gateway["ports"]["http"], target, "gh.test", "/b", gateway["ca"], hdr)
    assert json.loads(body)["auth"] == "Bearer ghp_E2E"


def test_sni_spoofing_does_not_get_the_token(gateway, upstream):
    """CONNECT to another (allowed) host but claim SNI gh.test: never injected, and since #57 not passed
    through either (the SNI must match the checked name)."""
    import ssl

    gateway["api"].call("PUT", "/secrets/github_token", {"value": "ghp_E2E"})
    with pytest.raises((OSError, ssl.SSLError)):
        https_via_proxy(
            gateway["ports"]["http"],
            f"other.test:{upstream['https']}",
            "gh.test",
            "/spoof",
            str(upstream["cert"]),
            {"Authorization": "token placeholder"},
        )


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


def test_preset_ttl_does_not_demote_permanent_rules(gateway):
    """#15: re-applying a preset with a TTL turned its permanent rules (e.g. `anthropic`) into expiring ones."""
    api = gateway["api"]
    api.call("POST", "/presets/lockdown", {})
    api.call("POST", "/presets/lockdown", {"ttl": 60})
    _, pol, _ = api.call("GET", "/policy")
    rules = {r["id"]: r for r in pol["rules"]}
    assert "expires" not in rules["anthropic"] and "expires" not in rules["claude-ai"]
    for rid in ("anthropic", "claude-ai"):
        api.call("DELETE", f"/rules/{rid}")


# ---------------------------------------------------------------- security review regressions
def test_denied_names_are_never_resolved(gateway):
    """TG-02: a name the policy denies must not reach a resolver (DNS exfiltration)."""
    _, line = connect_tunnel(gateway["ports"]["http"], "c2VjcmV0.x.denied.test:443")
    assert " 200" not in line
    ev = last_events(gateway, 1)[0]
    assert ev["host"] == "c2vjcmv0.x.denied.test" and "not resolved" in ev["reason"] and ev["ips"] == []


def test_unknown_names_are_asked_before_resolution(gateway):
    port = 4441
    t, res = in_thread(connect_tunnel, gateway["ports"]["http"], f"unresolved-name.test:{port}")
    p = wait_pending(gateway, port)
    assert p["ips"] == [] and p["domain"] == "unresolved-name.test"
    gateway["api"].call("POST", f"/pending/{p['id']}/decide", {"scope": "deny", "by": "e2e"})
    t.join(10)
    assert " 200" not in res["r"][1]


def test_invalid_hostnames_are_refused(gateway):
    """TG-10: garbage / spoofy names never reach DNS or a human prompt."""
    for host in ("bad-.test", "a..b.test", "x" * 70 + ".test"):
        _, line = connect_tunnel(gateway["ports"]["http"], f"{host}:443")
        assert " 200" not in line
    _, pend, _ = gateway["api"].call("GET", "/pending")
    assert pend == []
    assert last_events(gateway, 1)[0]["reason"] == "invalid hostname"


def test_pending_approvals_are_capped(gateway):
    """TG-08: max_pending=3 in the test config; the 4th distinct request is denied immediately."""
    threads = [in_thread(connect_tunnel, gateway["ports"]["http"], f"flood{i}.test:{4450 + i}") for i in range(3)]
    for i in range(3):
        wait_pending(gateway, 4450 + i)
    t0 = time.time()
    _, line = connect_tunnel(gateway["ports"]["http"], "flood9.test:4459")
    assert " 200" not in line and time.time() - t0 < 2
    assert "too many pending" in last_events(gateway, 1)[0]["reason"]
    _, pend, _ = gateway["api"].call("GET", "/pending")
    for p in pend:
        gateway["api"].call("POST", f"/pending/{p['id']}/decide", {"scope": "deny", "by": "e2e"})
    for t, _ in threads:
        t.join(10)


def test_agent_credentials_never_reach_injection_hosts(gateway, upstream):
    """TG-05: Authorization/Cookie from the agent are stripped even when no secret is configured."""
    gateway["api"].call("PUT", "/secrets/github_token", {"value": ""})
    hdr = {"Authorization": "token ghp_ATTACKER", "Cookie": "user_session=attacker"}
    _, body = https_via_proxy(
        gateway["ports"]["http"], f"gh.test:{upstream['https']}", "gh.test", "/c", gateway["ca"], hdr
    )
    assert json.loads(body)["auth"] is None
    gateway["api"].call("PUT", "/secrets/github_token", {"value": "ghp_E2E"})
    _, body = https_via_proxy(
        gateway["ports"]["http"], f"gh.test:{upstream['https']}", "gh.test", "/c", gateway["ca"], hdr
    )
    assert json.loads(body)["auth"] == "Bearer ghp_E2E"


def test_readonly_hosts_refuse_writes(gateway, upstream):
    """TG-11: e.g. `npm publish` as an exfiltration path."""
    target = f"ro.test:{upstream['https']}"
    status, _ = https_via_proxy(gateway["ports"]["http"], target, "ro.test", "/pkg", gateway["ca"])
    assert status == 200
    raw, line = connect_tunnel(gateway["ports"]["http"], target)
    assert " 200" in line
    import ssl

    ctx = ssl.create_default_context(cafile=gateway["ca"])
    with ctx.wrap_socket(raw, server_hostname="ro.test") as tls:
        tls.sendall(b"PUT /pkg HTTP/1.1\r\nHost: ro.test\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
        data = b""
        while chunk := tls.recv(4096):
            data += chunk
    assert data.startswith(b"HTTP/1.1 403") and b"read-only" in data


def test_identical_events_are_coalesced(gateway):
    """TG-09: a flood of identical events is stored once plus a 'repeated Nx' summary."""
    for _ in range(25):
        dns_rcode(gateway["ports"]["dns"], "flood.example.com")
    rows = [e for e in last_events(gateway, 50) if e["host"] == "flood.example.com"]
    assert len(rows) == 1
    time.sleep(17)  # housekeeping flushes the counter
    rows = [e for e in last_events(gateway, 50) if e["host"] == "flood.example.com"]
    assert any("repeated" in e["reason"] for e in rows)


def test_hard_deny_floor_is_not_editable_via_api(gateway):
    """TG-03"""
    _, pol, _ = gateway["api"].call("GET", "/policy")
    pol["hard_deny"] = []
    gateway["api"].call("PUT", "/policy", pol)
    _, pol, _ = gateway["api"].call("GET", "/policy")
    assert "192.168.0.0/16" in pol["hard_deny_floor"]
    _, data, _ = gateway["api"].call("POST", "/test", {"host": "lan.test", "port": 443})
    assert data["action"] == "deny" and data["rule_id"] == "hard_deny"


def test_secret_with_crlf_is_rejected(gateway):
    status, _, _ = gateway["api"].call("PUT", "/secrets/github_token", {"value": "x\r\nX-Evil: 1"})
    assert status == 400


def test_punycode_names_are_flagged_in_prompts(gateway):
    """TG-10: IDN names arrive as punycode and are flagged for the human."""
    port = 4470
    t, _res = in_thread(connect_tunnel, gateway["ports"]["http"], f"xn--gthub-cta.com:{port}")
    p = wait_pending(gateway, port)
    assert p["host"] == "xn--gthub-cta.com" and p["idn"] is True
    gateway["api"].call("POST", f"/pending/{p['id']}/decide", {"scope": "deny", "by": "e2e"})
    t.join(10)


def _tls_any_sni(proxy_port, target, sni, method="GET", headers=None) -> bytes:
    """CONNECT + TLS with an arbitrary (or no) SNI; the certificate is not checked. Returns the raw response."""
    import ssl

    raw, line = connect_tunnel(proxy_port, target)
    assert " 200" in line
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    hdrs = {"Host": target.split(":")[0], "Connection": "close", "Content-Length": "0", **(headers or {})}
    data = b""
    with ctx.wrap_socket(raw, server_hostname=sni) as tls:
        tls.sendall((f"{method} /x HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in hdrs.items()) + "\r\n").encode())
        with contextlib.suppress(OSError):
            while chunk := tls.recv(65536):
                data += chunk
    return data


@pytest.mark.parametrize("sni", [None, "gh.test.", "other.test", "GH.TEST"])
def test_inject_host_is_intercepted_whatever_the_sni(gateway, upstream, sni):
    """#9: without a matching SNI the TLS was passed through, and the agent's own token reached the host."""
    gateway["api"].call("PUT", "/secrets/github_token", {"value": "ghp_E2E"})
    target = f"gh.test:{upstream['https']}"
    data = _tls_any_sni(gateway["ports"]["http"], target, sni, headers={"Authorization": "token AGENT"})
    assert json.loads(data.partition(b"\r\n\r\n")[2])["auth"] == "Bearer ghp_E2E"  # stripped, then injected


@pytest.mark.parametrize("sni", [None, "ro.test.", "other.test"])
def test_readonly_host_is_intercepted_whatever_the_sni(gateway, upstream, sni):
    data = _tls_any_sni(gateway["ports"]["http"], f"ro.test:{upstream['https']}", sni, method="PUT")
    assert data.startswith(b"HTTP/1.1 403") and b"read-only" in data


def test_preset_details_and_undo(gateway):
    """#34: templates carry metadata for the UI, their rules are tagged, and undo removes exactly them."""
    api = gateway["api"]
    _, names, _ = api.call("GET", "/presets")
    assert {"python", "node", "internet", "open", "baseline"} <= set(names)
    _, details, _ = api.call("GET", "/presets?details=1")
    py = next(p for p in details if p["name"] == "python")
    assert py["category"] == "template" and py["title"] and {r["host"] for r in py["rules"]} >= {"pypi.org"}
    _, before, _ = api.call("GET", "/policy")
    status, data, _ = api.call("POST", "/presets/python", {"ttl": 600})
    assert status == 200 and set(data["added"]) == {"py-pypi", "py-files"}
    _, pol, _ = api.call("GET", "/policy")
    tagged = [r for r in pol["rules"] if r.get("source") == "preset:python"]
    assert {r["id"] for r in tagged} == {"py-pypi", "py-files"} and all(r["expires"] for r in tagged)
    status, data, _ = api.call("DELETE", "/presets/python")
    assert status == 200 and set(data["removed"]) == {"py-pypi", "py-files"}
    _, after, _ = api.call("GET", "/policy")
    assert [r["id"] for r in after["rules"]] == [r["id"] for r in before["rules"]]  # nothing else touched
    assert api.call("DELETE", "/presets/no-such")[0] == 400
    assert api.call("DELETE", "/presets/nosuch")[1] == {"removed": []}
