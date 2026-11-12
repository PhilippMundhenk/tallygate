"""Gateway decisions and hooks in-process, with real mitmproxy flow/connection objects.

Covers the paths the e2e harness cannot reach reliably (DNS failures, IDNA errors, exceptions inside
hooks, housekeeping) - each test checks the security decision, not just that the code runs."""

import asyncio
import logging
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "gateway"))

pytest.importorskip("mitmproxy")

from mitmproxy import tls
from mitmproxy.proxy import server_hooks
from mitmproxy.test import tflow, tutils

from egressgw import core
from egressgw.grants import Target


@pytest.fixture
def make(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "DATA_DIR", tmp_path)
    monkeypatch.setattr(core, "CONFIG_PATH", tmp_path / "config.yaml")
    monkeypatch.setattr(core, "STATIC_HOSTS", {})

    def factory(config: dict | None = None, policy: dict | None = None) -> core.Gateway:
        (tmp_path / "config.yaml").write_text(yaml.safe_dump(config or {}))
        (tmp_path / "policy.yaml").write_text(yaml.safe_dump(policy or {"default": "deny"}))
        return core.Gateway()

    return factory


def connect_data(host, port=443, mode="regular") -> server_hooks.ServerConnectionHookData:
    server = tflow.tserver_conn()
    server.address = (host, port) if host is not None else None
    client = tflow.tclient_conn()
    return server_hooks.ServerConnectionHookData(server=server, client=client)


def connect(gw, host, port=443):
    data = connect_data(host, port)
    asyncio.run(gw.server_connect(data))
    return data


def last_event(gw) -> dict:
    return gw.events.recent(1)[0]


GRANTS = {
    "nas": {"targets": [{"host": "nas.example", "port": 443}], "levels": ["read", "write"]},
    "pinned": {"targets": [{"host": "cam.example", "port": 443, "address": "203.0.113.7", "lan": True}]},
    "ipgrant": {"targets": [{"host": "198.51.100.9", "port": 8443, "lan": True}]},
    "wonly": {"targets": [{"host": "w.example", "port": 443}], "levels": ["write"]},
}


# ------------------------------------------------------------------ fail closed
def test_error_in_server_connect_refuses_the_connection(make, monkeypatch):
    gw = make()
    monkeypatch.setattr(gw.policy, "evaluate_name", lambda *a: 1 / 0)
    data = connect(gw, "x.example")
    assert data.server.error == "egress policy: internal error (fail closed)"


def test_error_in_tls_clienthello_refuses_the_tls(make):
    gw = make()
    data = tls.ClientHelloData(context=SimpleNamespace(), client_hello=None, ignore_connection=True)  # no .server
    gw.tls_clienthello(data)
    assert data.ignore_connection is False  # never passed through
    data = tls.ClientHelloData(context=SimpleNamespace(server=SimpleNamespace(id="s1")), client_hello=None)
    gw.tls_clienthello(data)  # client_hello None: fails after the server id is known
    assert data.ignore_connection is False and "s1" in gw.tls_refused


def test_error_in_request_kills_the_flow(make, monkeypatch):
    gw = make()
    monkeypatch.setattr(gw, "_checks", lambda f: 1 / 0)
    flow = tflow.tflow()
    gw.request(flow)
    assert not flow.killable  # killed


def test_error_on_an_unkillable_object_is_only_logged(make, caplog):
    gw = make()
    with caplog.at_level(logging.ERROR, "egressgw"):
        gw.websocket_start(SimpleNamespace())  # no server_conn attribute
    assert "websocket_start failed - refusing the connection" in caplog.text


# ------------------------------------------------------------------ static config
def test_service_exception_only_for_allow_private_services(make):
    gw = make(
        {
            "services": [
                {"listen": 1, "target": "192.168.1.10:5432", "allow_private": True},
                {"listen": 2, "target": "[fd00::5]:80", "allow_private": True},
                {"listen": 3, "target": "192.168.1.11:22"},
            ]
        }
    )
    assert [(e.host, e.port) for e in gw.policy.exceptions] == [("192.168.1.10", 5432), ("fd00::5", 80)]
    ev = gw.policy.evaluate
    assert ev("192.168.1.10", 5432, ["192.168.1.10"], "reverse").action == "deny"  # default deny, not hard deny
    assert ev("192.168.1.10", 5432, ["192.168.1.10"], "reverse").reason == "default"
    assert ev("192.168.1.10", 5432, ["192.168.1.10"], "regular").rule_id == "hard_deny"
    assert ev("192.168.1.11", 22, ["192.168.1.11"], "reverse").rule_id == "hard_deny"
    gw.adopt(core.Policy())  # a policy replaced via the API keeps the configured exceptions
    assert len(gw.policy.exceptions) == 2


# ------------------------------------------------------------------ housekeeping
def test_housekeeping_loop_survives_errors(make, monkeypatch, caplog):
    gw = make()
    calls = []

    async def fake_sleep(_):
        calls.append(1)
        if len(calls) > 2:
            raise asyncio.CancelledError

    monkeypatch.setattr(core.asyncio, "sleep", fake_sleep)
    monkeypatch.setattr(gw, "_housekeep", lambda: 1 / 0)
    with caplog.at_level(logging.ERROR, "egressgw"), pytest.raises(asyncio.CancelledError):
        asyncio.run(gw._housekeeping())
    assert len(calls) == 3 and caplog.text.count("housekeeping failed") == 2


def test_housekeeping_expires_grants_and_times_out_requests(make):
    gw = make({"grants": GRANTS})
    q = asyncio.Queue()
    gw.subscribers.add(q)
    a = gw.grants.activate("nas", "read", 600, "", "t")
    r = gw.request_grant("wonly", "write", None, "deploy", "10.0.0.2")
    assert r.status == "pending" and r.id in gw._grant_events
    waiter = gw._grant_events[r.id]
    a.expires = time.time() - 1
    r.created -= r.timeout + 1
    gw.neg_cache[("old.example", 443)] = time.time() - 1
    gw._housekeep()
    assert gw.grants.active == {} and r.status == "expired"
    assert waiter.is_set() and r.id not in gw._grant_events  # a long-polling agent is woken up
    assert gw.neg_cache == {}
    reasons = [e["reason"] for e in gw.events.recent(5)]
    assert f"grant request {r.id} timed out" in reasons and "grant nas (read) expired" in reasons
    types = [q.get_nowait()["type"] for _ in range(q.qsize())]
    assert "grant_resolved" in types and types[-1] == "grants"


def test_housekeeping_prunes_expired_rules_and_saves(make, tmp_path):
    gw = make(
        policy={"default": "deny", "rules": [{"id": "old", "action": "allow", "host": "a.example", "expires": 1}]}
    )
    gw._housekeep()
    assert gw.policy.rules == [] and "old" not in (tmp_path / "policy.yaml").read_text()


# ------------------------------------------------------------------ resolve / approvals
def test_resolve_ip_literals_and_real_names(make):
    gw = make()
    assert asyncio.run(gw.resolve("[2001:db8::1]", 443)) == ["2001:db8::1"]
    ips = asyncio.run(gw.resolve("localhost", 80))
    assert ips and len(ips) == len(set(ips)) and set(ips) <= {"127.0.0.1", "::1"}


def test_answer_and_grant_decisions_for_unknown_ids(make):
    gw = make({"grants": GRANTS})
    with pytest.raises(KeyError):
        gw.answer("nope", "once", "t")
    with pytest.raises(KeyError):
        gw.decide_grant("nope", "approve", "t")
    r = gw.request_grant("wonly", "write", None, "", "c")
    with pytest.raises(ValueError, match="has no read level"):
        gw.decide_grant(r.id, "read", "t")  # cannot downgrade to a level the grant does not offer
    assert r.status == "pending"
    gw.decide_grant(r.id, "deny", "admin")
    with pytest.raises(KeyError):
        gw.decide_grant(r.id, "approve", "admin")  # already decided
    with pytest.raises(KeyError):
        gw.request_grant("nope", "read", None, "", "c")


def test_grant_request_for_a_removed_definition_is_denied(make):
    gw = make({"grants": GRANTS})
    r = gw.request_grant("nas", "write", "2h", "", "c")
    del gw.grants.defs["nas"]
    assert gw.decide_grant(r.id, "approve", "admin")["status"] == "denied"
    assert gw.grants.active == {}


# ------------------------------------------------------------------ server_connect
def test_no_destination_is_refused(make):
    data = connect(make(), None)
    assert data.server.error == "egress policy: no destination"


def test_undecodable_idn_is_refused(make):
    gw = make(policy={"default": "allow"})
    data = connect(gw, "a" * 70 + "ü.example")  # label too long for IDNA
    assert data.server.error == "egress policy: blocked (invalid hostname)"
    assert last_event(gw)["action"] == "deny"


def test_idn_is_checked_as_punycode(make, monkeypatch):
    gw = make(policy={"default": "deny", "rules": [{"id": "idn", "action": "deny", "host": "xn--bcher-kva.example"}]})
    data = connect(gw, "bücher.example")
    assert "rule idn" in data.server.error and last_event(gw)["host"] == "xn--bcher-kva.example"


def test_dns_failure_and_empty_answer_are_refused(make, monkeypatch):
    gw = make(policy={"default": "allow"})

    async def fail(host, port):
        raise OSError("no such host")

    monkeypatch.setattr(gw, "resolve", fail)
    assert connect(gw, "a.example").server.error == "egress policy: blocked (dns failure: no such host)"

    async def empty(host, port):
        return []

    monkeypatch.setattr(gw, "resolve", empty)
    data = connect(gw, "b.example")
    assert data.server.error == "egress policy: blocked (no address)" and data.server.address == ("b.example", 443)


def test_allowed_name_is_pinned_to_the_checked_ip(make, monkeypatch):
    gw = make({"inject": [{"host": "api.example", "value": "x"}]}, {"default": "allow"})

    async def resolve(host, port):
        return ["93.184.216.34"]

    monkeypatch.setattr(gw, "resolve", resolve)
    data = connect(gw, "API.example.")
    assert data.server.error is None and data.server.address == ("93.184.216.34", 443)
    assert data.server.sni == "api.example"  # intercepted host: upstream cert checked against the name
    assert gw.orig_host[data.server.id] == "api.example"


def test_ip_literal_with_a_grant_hint_is_refused_without_asking(make):
    gw = make({"grants": GRANTS}, {"default": "ask"})
    data = connect(gw, "198.51.100.9", 8443)
    assert "available via grant ipgrant" in data.server.error
    assert gw.pending == {}  # no approval prompt for something a grant covers


def test_grant_on_an_ip_literal_target(make):
    gw = make({"grants": GRANTS}, {"default": "deny"})
    gw.grants.activate("ipgrant", "read", 600, "", "t")
    data = connect(gw, "198.51.100.9", 8443)
    assert data.server.error is None and data.server.address == ("198.51.100.9", 8443)
    assert gw.conn_grant[data.server.id][1] == "198.51.100.9"


def test_grant_with_a_fixed_address_is_never_resolved(make, monkeypatch):
    gw = make({"grants": GRANTS})
    gw.grants.activate("pinned", "read", 600, "", "t")

    async def must_not_resolve(host, port):
        raise AssertionError("resolved")

    monkeypatch.setattr(gw, "resolve", must_not_resolve)
    data = connect(gw, "cam.example")
    assert data.server.address == ("203.0.113.7", 443) and data.server.sni == "cam.example"


def test_grant_dns_failure_is_refused(make, monkeypatch):
    gw = make({"grants": GRANTS})
    gw.grants.activate("nas", "read", 600, "", "t")

    async def fail(host, port):
        raise OSError("timeout")

    monkeypatch.setattr(gw, "resolve", fail)
    data = connect(gw, "nas.example")
    assert data.server.error == "egress policy: blocked (dns failure: timeout)"
    assert data.server.id not in gw.conn_grant


def test_non_lan_grant_still_honours_the_hard_deny(make, monkeypatch):
    gw = make({"grants": GRANTS})
    gw.grants.activate("nas", "read", 600, "", "t")

    async def private(host, port):
        return ["10.1.2.3"]

    monkeypatch.setattr(gw, "resolve", private)
    data = connect(gw, "nas.example")
    assert "hard-deny 10.0.0.0/8" in data.server.error


# ------------------------------------------------------------------ TLS
def grant_conn(gw, target: Target, level="write", name="nas") -> str:
    a = gw.grants.activate(name, level, 600, "", "t")
    sid = "srv-1"
    gw.conn_grant[sid] = (a.id, target.host, target)
    return sid


def test_tcp_grant_targets_are_passed_through_http_ones_intercepted(make):
    gw = make({"grants": GRANTS})
    for scheme, ignored in (("tcp", True), ("https", False)):
        sid = grant_conn(gw, Target(host="nas.example", port=443, scheme=scheme))
        data = tls.ClientHelloData(context=SimpleNamespace(server=SimpleNamespace(id=sid)), client_hello=None)
        gw.tls_clienthello(data)
        assert data.ignore_connection is ignored


class FakeSSLConn:
    def set_verify(self, mode, cb):
        self.mode, self.cb = mode, cb


def tls_data(sid):
    return SimpleNamespace(context=SimpleNamespace(server=SimpleNamespace(id=sid)), ssl_conn=FakeSSLConn())


def self_signed():
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "nas.example")])
    now = datetime.datetime.now(datetime.UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )


def test_pinned_fingerprint_checks_the_leaf_only(make):
    from cryptography.hazmat.primitives import hashes
    from OpenSSL import SSL, crypto

    cert = self_signed()
    leaf = crypto.X509.from_cryptography(cert)
    gw = make({"grants": GRANTS})
    good = Target(host="nas.example", port=443, tls_fingerprint=cert.fingerprint(hashes.SHA256()).hex())
    data = tls_data(grant_conn(gw, good))
    gw.tls_start_server(data)
    assert data.ssl_conn.mode == SSL.VERIFY_PEER
    assert data.ssl_conn.cb(None, leaf, 0, 0, 0) is True
    assert data.ssl_conn.cb(None, leaf, 0, 1, 0) is True  # intermediates/CA are irrelevant
    bad = Target(host="nas.example", port=443, tls_fingerprint="00" * 32)
    data = tls_data(grant_conn(gw, bad))
    gw.tls_start_server(data)
    assert data.ssl_conn.cb(None, leaf, 0, 0, 1) is False  # even if the chain itself verified


def test_tls_verify_false_disables_verification_only_for_that_target(make):
    from OpenSSL import SSL

    gw = make({"grants": GRANTS})
    data = tls_data(grant_conn(gw, Target(host="nas.example", port=443, tls_verify=False)))
    gw.tls_start_server(data)
    assert data.ssl_conn.mode == SSL.VERIFY_NONE
    for sid in (grant_conn(gw, Target(host="nas.example", port=443)), "not-a-grant"):
        data = tls_data(sid)
        gw.tls_start_server(data)
        assert not hasattr(data.ssl_conn, "mode")  # default verification untouched


# ------------------------------------------------------------------ SNI binding (#57)
def hello(gw, orig, sni, sid="srv-9", port=443):
    if orig is not None:
        gw.orig_host[sid] = orig
    ctx = SimpleNamespace(
        server=SimpleNamespace(id=sid, address=("192.0.2.1", port)), client=SimpleNamespace(peername=("10.0.0.5", 1))
    )
    data = tls.ClientHelloData(context=ctx, client_hello=SimpleNamespace(sni=sni))
    gw.tls_clienthello(data)
    return data


def test_tls_passes_through_only_with_the_checked_sni(make):
    gw = make(policy={"default": "deny", "rules": [{"id": "a", "action": "allow", "host": "ok.example", "port": 443}]})
    cases = [
        ("ok.example", "OK.example.", True),
        ("ok.example", "front.example", False),
        ("ok.example", None, False),
        (None, "ok.example", False),  # no checked destination
        ("192.0.2.1", None, True),  # IP literal without SNI: normal
        ("192.0.2.1", "192.0.2.1", True),
        ("192.0.2.1", "ok.example", True),  # the rules allow this name by itself
        ("192.0.2.1", "front.example", False),
        ("192.0.2.1", "bad_name", False),
    ]
    for i, (orig, sni, passed) in enumerate(cases):
        data = hello(gw, orig, sni, sid=f"s{i}")
        assert data.ignore_connection is passed, (orig, sni)
        assert (f"s{i}" in gw.tls_refused) is not passed
    assert last_event(gw)["reason"] == "TLS SNI bad_name on IP 192.0.2.1 is not allowed by the rules"


def test_refused_tls_fails_both_handshakes_and_is_forgotten_on_disconnect(make):
    gw = make()
    hello(gw, "ok.example", "front.example", sid="s1")
    for hook in (gw.tls_start_client, gw.tls_start_server):
        data = SimpleNamespace(context=SimpleNamespace(server=SimpleNamespace(id="s1")), ssl_conn=None)
        hook(data)
        assert data.ssl_conn is not None  # a connection that cannot complete a handshake
    data = SimpleNamespace(context=SimpleNamespace(server=SimpleNamespace(id="other")), ssl_conn=None)
    gw.tls_start_client(data)
    assert data.ssl_conn is None  # untouched: mitmproxy's TlsConfig builds it
    gw.server_disconnected(SimpleNamespace(server=SimpleNamespace(id="s1")))
    assert "s1" not in gw.tls_refused


def test_host_binding(make):
    gw = make()
    for host, target, refused in (
        ("a.example", "a.example", False),
        ("A.EXAMPLE.", "a.example", False),
        ("b.example", "a.example", True),
        ("[::1]:80", "::1", False),
        ("[0:0::1]", "::1", False),
        ("192.0.2.1", "a.example", True),
    ):
        req = tutils.treq(host=target)
        req.headers["Host"] = host
        assert (gw._host_binding(req, target) is not None) is refused, host
    req = tutils.treq()
    req.headers.pop("Host", None)
    assert gw._host_binding(req, "a.example") is None  # no Host: the upstream's default site


# ------------------------------------------------------------------ websocket / http
def test_websocket_refused_on_read_grants_only(make):
    gw = make({"grants": GRANTS})
    t = Target(host="nas.example", port=443)
    for level, killed in (("read", True), ("write", False)):
        flow = tflow.twebsocketflow()
        a = gw.grants.activate("nas", level, 600, "", "t")
        gw.conn_grant[flow.server_conn.id] = (a.id, "nas.example", t)
        gw.websocket_start(flow)
        assert (not flow.killable) is killed
    ev = gw.events.recent(5)
    assert any(e["reason"] == "websocket on a read-only grant" for e in ev)


def grant_flow(gw, level="read", **req):
    flow = tflow.tflow(req=tutils.treq(scheme="https", host="nas.example", port=443, path="/x", **req))
    flow.request.headers["Host"] = "nas.example"
    a = gw.grants.activate("nas", level, 600, "", "t")
    gw.conn_grant[flow.server_conn.id] = (a.id, "nas.example", Target(host="nas.example", port=443))
    return flow, a


def test_expired_or_revoked_grant_refuses_requests_on_open_connections(make):
    gw = make({"grants": GRANTS})
    flow, a = grant_flow(gw)
    a.expires = time.time() - 1
    gw.request(flow)
    assert flow.response.status_code == 403 and b"grant expired or revoked" in flow.response.content
    flow, a = grant_flow(gw)
    gw.grants.revoke(a.id)
    gw.request(flow)
    assert flow.response.status_code == 403


def test_read_grant_allows_get_and_refuses_writes(make):
    gw = make({"grants": GRANTS})
    flow, _ = grant_flow(gw, method=b"GET")
    gw.request(flow)
    assert flow.response is None
    flow, _ = grant_flow(gw, method=b"POST")
    gw.request(flow)
    assert flow.response.status_code == 403 and b"read-only" in flow.response.content


def inject_gw(make):
    gw = make({"inject": [{"host": "api.example", "header": "Authorization", "value": "Bearer ${tok}"}]})
    gw.secrets.set("tok", "s3cret")
    return gw


def agent_flow(scheme: str, host_header: str):
    flow = tflow.tflow(req=tutils.treq(scheme=scheme, host="api.example", port=443, path="/"))
    flow.request.headers["Host"] = host_header
    flow.request.headers["Authorization"] = "Bearer agent-own"
    flow.request.headers["Cookie"] = "session=agent"
    return flow


def test_injection_only_over_tls_and_only_for_the_checked_host(make):
    gw = inject_gw(make)
    flow = agent_flow("https", "api.example")
    gw.request(flow)
    assert flow.request.headers["Authorization"] == "Bearer s3cret" and "Cookie" not in flow.request.headers
    flow = agent_flow("http", "api.example")
    gw.request(flow)
    # the agent's own credentials are stripped, and the secret never goes out in clear text
    assert "Authorization" not in flow.request.headers and "Cookie" not in flow.request.headers
    flow = agent_flow("https", "evil.example")
    gw.request(flow)
    assert flow.response.status_code == 403  # another Host is refused outright (#57)


def test_injection_without_a_configured_secret_sends_no_credentials(make):
    gw = make({"inject": [{"host": "api.example", "value": "Bearer ${tok}"}, {"host": "other.example", "value": "x"}]})
    flow = agent_flow("https", "api.example")
    gw.request(flow)
    assert "Authorization" not in flow.request.headers


# ------------------------------------------------------------------ requestheaders (#56)
def ro_flow(method=b"PUT", http_version=b"HTTP/1.1", **headers):
    flow = tflow.tflow(
        req=tutils.treq(method=method, host="ro.example", port=443, path="/pkg", http_version=http_version)
    )
    flow.request.headers.clear()
    flow.request.headers["Host"] = "ro.example"
    for k, v in headers.items():
        flow.request.headers[k.replace("_", "-")] = v
    return flow


def test_requestheaders_refuses_small_bodies_with_a_403(make):
    gw = make({"readonly": ["ro.example"]})
    for flow in (ro_flow(content_length="2"), ro_flow()):  # sized body, HTTP/1 without a body
        gw.requestheaders(flow)
        assert flow.response.status_code == 403 and flow.killable
        assert last_event(gw)["reason"] == "read-only host: PUT /pkg"
        refused = flow.response
        gw.request(flow)  # already refused: the second line leaves it alone
        assert flow.response is refused


def test_requestheaders_kills_streamed_or_unsized_bodies(make):
    """mitmproxy streams bodies over stream_large_bodies right after requestheaders: a 403 cannot replace them."""
    gw = make({"readonly": ["ro.example"]})
    streamed = ro_flow(content_length="2000000")
    streamed.request.stream = True
    flows = (streamed, ro_flow(transfer_encoding="chunked"), ro_flow(http_version=b"HTTP/2.0"))
    for flow in flows:
        gw.requestheaders(flow)
        assert flow.response is None and not flow.killable
    assert last_event(gw)["action"] == "deny"


def test_request_kills_a_refused_flow_whose_body_was_already_streamed(make):
    gw = make({"readonly": ["ro.example"]})
    flow = ro_flow(content_length="2000000")
    flow.request.stream = True
    gw.request(flow)
    assert flow.response is None and not flow.killable


def test_requestheaders_strips_agent_credentials_before_streaming(make):
    gw = inject_gw(make)
    flow = agent_flow("https", "api.example")
    flow.request.stream = True
    gw.requestheaders(flow)
    assert flow.request.headers["Authorization"] == "Bearer s3cret" and "Cookie" not in flow.request.headers
    assert flow.killable


def test_dns_requests_are_answered_nxdomain_and_logged(make):
    gw = make()
    flow = tflow.tdnsflow()
    gw.dns_request(flow)
    assert flow.response.response_code == 3  # NXDOMAIN
    assert last_event(gw)["reason"] == "agent DNS is disabled (NXDOMAIN); use the proxy"
