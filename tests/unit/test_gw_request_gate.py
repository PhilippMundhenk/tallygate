"""#236: a request is checked against its own destination, and bound to the upstream connection that carries
it. In-process, with real mitmproxy flow and connection objects: the request gate for a plain-HTTP proxy
request (`Access.request_without_verdict`, `Gateway._verdict_for`), what `server_connect` records about the
connections it allows, and the check when the response arrives."""

import asyncio
import sys
import time
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "gateway"))

pytest.importorskip("mitmproxy")

from mitmproxy.proxy import server_hooks
from mitmproxy.test import tflow, tutils

from egressgw import core
from egressgw.grants import Target
from egressgw.model import Req, Verdict, _same_authority

PUBLIC = "93.184.216.34"
GRANTS = {
    "nas": {
        "targets": [{"host": "nas.example", "port": 8080, "scheme": "http", "paths": ["/api/*"]}],
        "levels": ["read", "write"],
    },
    "cam": {
        "targets": [{"host": "cam.example", "port": 8080, "scheme": "http", "address": "192.168.1.8"}],
        "levels": ["read"],
    },
    "ip": {"targets": [{"host": "192.168.1.9", "port": 8080, "scheme": "http"}], "levels": ["read", "write"]},
}
RULES = [
    {"id": "a", "action": "allow", "host": "a.example"},
    {"id": "no", "action": "deny", "host": "no.example"},
    {"id": "q", "action": "ask", "host": "q.example"},
    {"id": "ip", "action": "allow", "cidr": f"{PUBLIC}/32"},
    {"id": "qip", "action": "ask", "cidr": "93.184.216.35/32"},
]


@pytest.fixture
def gw(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "DATA_DIR", tmp_path)
    monkeypatch.setattr(core, "CONFIG_PATH", tmp_path / "config.yaml")
    monkeypatch.setattr(core, "STATIC_HOSTS", {})
    monkeypatch.setenv("GW_INTERNAL_NETS", "172.31.10.0/24")
    (tmp_path / "config.yaml").write_text(yaml.safe_dump({"grants": GRANTS}))
    (tmp_path / "policy.yaml").write_text(yaml.safe_dump({"default": "deny", "ask_timeout": 5, "rules": RULES}))
    g = core.Gateway()

    async def resolve(host, port):
        return [host.strip("[]")] if core.is_ip(host) else [PUBLIC]

    g.resolve = resolve
    return g


def open_conn(gw, client, host, port=8080):
    """One upstream connection of `client` through the real hook."""
    server = tflow.tserver_conn()
    server.address = (host, port)
    server.error = None
    data = server_hooks.ServerConnectionHookData(server=server, client=client)
    asyncio.run(gw.server_connect(data))
    return data


def plain(client, host, port=8080, method=b"GET", path=b"/api/x", **headers):
    """A plain-HTTP proxy request as the request hooks see it: no upstream connection assigned yet."""
    flow = tflow.tflow(req=tutils.treq(method=method, scheme=b"http", host=host, port=port, path=path))
    flow.client_conn = client
    flow.request.headers.clear()
    flow.request.headers["Host"] = f"{host}:{port}"
    for k, v in headers.items():
        flow.request.headers[k.replace("_", "-")] = v
    return flow


def refusal(flow) -> str:
    assert flow.response is not None and flow.response.status_code == 403
    return flow.response.text.removeprefix("egress policy: ").strip()


# ------------------------------------------------------------------ the model: the request's own destination
def test_the_request_gate_decides_a_name_on_the_name(gw):
    gate = gw.access.request_without_verdict
    assert gate("a.example", 80, "http") == (Verdict("a.example", 80), None)
    assert gate("A.Example.", 80, "http")[0].host == "a.example"
    assert gate("bücher.example", 80, "http")[0].host == "xn--bcher-kva.example"  # as the rules name it
    assert gate("no.example", 80, "http") == (Verdict("no.example", 80), "rule no")
    v, problem = gate("q.example", 80, "http")
    assert v == Verdict("q.example", 80) and problem.startswith("rule q: needs your approval, which is not asked")
    assert gate("other.example", 80, "http")[1] == "default"
    assert gate("bad name.example", 80, "http") == (Verdict("bad name.example", 80), "invalid hostname")
    assert gate("192.168.1.1.", 80, "http")[1] == "invalid hostname"  # an address written like a name
    assert gate("a.example", 443, "https") == (None, "https over the plain proxy must use CONNECT")


def test_the_request_gate_walks_the_list_for_an_ip_literal(gw):
    gate = gw.access.request_without_verdict
    assert gate(PUBLIC, 80, "http") == (Verdict(PUBLIC, 80), None)
    assert gate("93.184.216.35", 80, "http")[1].startswith("rule qip: needs your approval")
    assert gate("93.184.216.36", 80, "http")[1] == "default"
    assert "block-192.168.0.0_16" in gate("192.168.1.1", 80, "http")[1]  # a blocked range
    assert "locked: " in gate("172.31.10.5", 80, "http")[1]  # the stack itself
    assert "block-" in gate("[::ffff:192.168.1.1]", 80, "http")[1]


def test_the_request_gate_gives_a_grant_target_its_grant(gw):
    gate = gw.access.request_without_verdict
    assert gate("nas.example", 8080, "http")[1] == "default; available via grant nas (agent: tallygate request nas)"
    a = gw.grants.activate("nas", "read", 600, "", "t")
    v, problem = gate("nas.example", 8080, "http")
    assert problem is None and v.grant == a.id and v.target.paths == ["/api/*"]
    # an IP literal that is a grant's target: the grant, with its limits
    assert "available via grant ip" in gate("192.168.1.9", 8080, "http")[1]
    b = gw.grants.activate("ip", "read", 600, "", "t")
    v, problem = gate("192.168.1.9", 8080, "http")
    assert problem is None and v.grant == b.id
    assert gate("192.168.1.9", 8081, "http")[1].startswith("inside blocked range") is False  # another port:
    assert "block-192.168.0.0_16" in gate("192.168.1.9", 8081, "http")[1]  # ... the block


def test_the_address_of_a_grant_target_is_reached_by_its_name(gw):
    hint = gw.access.grant_address_hint
    assert hint("192.168.1.8", 8080) is None  # not active
    a = gw.grants.activate("cam", "read", 600, "", "t")
    why = "192.168.1.8 is the address of cam.example (grant cam): reach a grant target by its name"
    assert hint("192.168.1.8", 8080) == why and hint("[::ffff:192.168.1.8]", 8080) is not None
    assert hint("192.168.1.8", 8081) is None and hint("192.168.1.7", 8080) is None and hint("cam.example", 8080) is None
    v, problem = gw.access.request_without_verdict("192.168.1.8", 8080, "http")
    assert v.grant is None and problem.endswith(why) and "block-192.168.0.0_16" in problem
    # a rule for the address itself opens it: grants only add access
    gw.policy.add_rule(
        core.Policy.from_dict({"rules": [{"action": "allow", "cidr": "192.168.1.8/32"}]}).rules[0], top=True
    )
    assert gw.access.request_without_verdict("192.168.1.8", 8080, "http") == (Verdict("192.168.1.8", 8080), None)
    # an expired grant, a grant whose definition is gone, a target that is an IP literal itself
    a.expires = time.time() - 1
    assert hint("192.168.1.8", 8080) is None
    a.expires = time.time() + 60
    del gw.grants.defs["cam"]
    gw.grants.activate("ip", "read", 600, "", "t")
    assert hint("192.168.1.8", 8080) is None and hint("192.168.1.9", 8080) is None


def test_server_connect_refuses_the_address_of_a_grant_target_without_asking(gw):
    gw.policy.default = "ask"
    gw.grants.activate("cam", "read", 600, "", "t")
    gw.policy.rules = [r for r in gw.policy.rules if r.cidr != "192.168.0.0/16"]  # not blocked: it would be asked
    data = open_conn(gw, tflow.tclient_conn(), "192.168.1.8")
    assert "default; 192.168.1.8 is the address of cam.example (grant cam)" in data.server.error
    assert gw.pending == {} and data.server.id not in gw.verdicts
    assert open_conn(gw, tflow.tclient_conn(), "cam.example").server.error is None  # by its name: the grant


# ------------------------------------------------------------------ the model: the request line names a server too
def test_the_authority_of_a_request_line_is_bound_to_the_checked_target(gw):
    for authority, ok in (
        ("a.example", True),
        ("A.Example.:8080", True),
        ("a.example:8081", False),
        ("b.example:8080", False),
        ("b.example", False),
        ("[::1]:8080", False),
    ):
        assert _same_authority(authority, "a.example", 8080) is ok, authority
    assert _same_authority("[::1]:8080", "::1", 8080) and _same_authority("[0:0::1]", "::1", 8080)
    assert not _same_authority("[::1]:80", "::1", 8080)

    def check(v, target):
        return gw.access.check(v, Req("GET", "http", "/api/x", v.host, v.host, "", target)).refuse

    v = Verdict("a.example", 8080)
    assert check(v, "") is None and check(v, "a.example:8080") is None
    assert check(v, "b.example:8080") == "request target does not match the checked target"
    a = gw.grants.activate("nas", "read", 600, "", "t")
    v = Verdict("nas.example", 8080, a.id, gw.grants.defs["nas"].targets[0])
    assert check(v, "nas.example:8080") is None
    assert check(v, "other.example:8080") == "request target does not match the granted target"


def test_only_an_http1_request_line_is_looked_at(gw):
    """HTTP/2 has no request line: its :authority is the Host, which is checked as that."""
    client = tflow.tclient_conn()
    data = open_conn(gw, client, "a.example")
    for version, refused in ((b"HTTP/1.1", True), (b"HTTP/2.0", False)):
        flow = tflow.tflow(req=tutils.treq(host="a.example", port=8080, http_version=version, authority=b"b.example"))
        flow.client_conn, flow.server_conn = client, data.server
        flow.request.headers.clear()
        flow.request.headers["Host"] = "a.example"
        if version == b"HTTP/2.0":
            flow.request.authority = "a.example"
        gw.request(flow)
        assert (flow.response is not None) is refused, version
    assert gw.events.recent(1)[0]["reason"].startswith("request target does not match the checked target")


# ------------------------------------------------------------------ what server_connect keeps
def test_allowed_connections_are_kept_per_client_until_they_close(gw, monkeypatch):
    client, other = tflow.tclient_conn(), tflow.tclient_conn()
    d1, d2 = open_conn(gw, client, "a.example"), open_conn(gw, client, PUBLIC)
    open_conn(gw, other, PUBLIC)
    refused = open_conn(gw, client, "no.example")
    assert refused.server.error and refused.server.id not in gw.upstreams
    up = gw.upstreams[d1.server.id]
    assert (up.client, up.verdict, up.address) == (client.id, Verdict("a.example", 8080), (PUBLIC, 8080))
    assert gw.upstreams[d2.server.id].seq == up.seq + 1 and set(gw.pool) == {client.id, other.id}
    # mitmproxy reuses by the address: both connections of this client go to it, the other client's does not
    assert [u.verdict.host for u in gw._pooled(client.id, PUBLIC, 8080)] == ["a.example", PUBLIC]
    assert len(gw._pooled(client.id, f"[::ffff:{PUBLIC}]", 8080)) == 2  # compared by value: never fewer
    assert gw._pooled(client.id, PUBLIC, 8081) == [] and gw._pooled(client.id, "a.example", 8080) == []
    assert gw._pooled("nobody", PUBLIC, 8080) == []
    # closed: out of the pool at once, but what it was checked for is kept for a response still on its way
    gw.server_disconnected(d1)
    gw.server_disconnected(d1)  # a connect error reports the same connection again
    assert d1.server.id in gw.upstreams and list(gw.pool[client.id]) == [d2.server.id]
    monkeypatch.setattr(core, "UPSTREAMS_KEPT", 1)
    gw.server_disconnected(d2)
    assert client.id not in gw.pool and d1.server.id not in gw.upstreams and d2.server.id in gw.upstreams
    gw.server_disconnected(refused)  # never admitted: nothing to forget
    assert list(gw._closed) == [d2.server.id]


def test_addresses_are_compared_by_value():
    key = core._addr_key
    assert key("::ffff:192.0.2.1", 80) == key("192.0.2.1", 80) == key("[::FFFF:192.0.2.1]", 80)
    assert key("A.Example.", 80) == key("a.example", 80) != key("a.example", 81)
    assert key("0:0::1", 80) == key("::1", 80) != key("::2", 80)


# ------------------------------------------------------------------ the gate: which connection carries the request
def test_a_request_for_a_new_connection_is_handed_to_server_connect(gw):
    """No open connection goes where the request names: mitmproxy opens one, and server_connect decides it,
    whatever the gate thinks of the destination (it denies it, it would ask, it knows nothing yet)."""
    client = tflow.tclient_conn()
    for host in ("a.example", "no.example", "q.example", "192.168.1.1", PUBLIC):
        flow = plain(client, host)
        gw.requestheaders(flow)
        gw.request(flow)
        assert flow.response is None and flow.killable, host
        gate = flow.metadata[core.GATED]
        assert (gate.host, gate.port, gate.grant, gate.reuse) == (host, 8080, None, False)
    assert set(gw.gated[client.id]) == {
        core._addr_key(h, 8080) for h in ("a.example", "no.example", "q.example", "192.168.1.1", PUBLIC)
    }
    gw.client_disconnected(client)
    assert gw.gated == {}
    flow = plain(client, "a.example", scheme=None)
    flow.request.scheme = "https"
    gw.requestheaders(flow)
    assert refusal(flow) == "https over the plain proxy must use CONNECT" and core.GATED not in flow.metadata


def test_a_request_never_rides_a_connection_that_was_checked_for_another_destination(gw):
    client = tflow.tclient_conn()
    a = gw.grants.activate("nas", "read", 600, "", "t")
    assert open_conn(gw, client, "nas.example").server.error is None  # pinned to PUBLIC:8080, carried by the grant
    for method, path in ((b"DELETE", b"/secret/wipe"), (b"GET", b"/api/x")):
        flow = plain(client, PUBLIC, method=method, path=path)
        gw.requestheaders(flow)
        assert refusal(flow) == f"request for {PUBLIC}:8080 on a connection that was checked for nas.example:8080"
    ev = gw.events.recent(1)[0]
    assert (ev["host"], ev["port"], ev["action"]) == (PUBLIC, 8080, "deny") and ev["reason"].endswith(": GET /api/x")
    # the destination is decided too: here the list does not allow the address by itself
    assert open_conn(gw, client, "a.example", 9000).server.error is None
    flow = plain(client, "93.184.216.36", 9000)
    gw.requestheaders(flow)
    assert core.GATED in flow.metadata  # another address: a new connection
    gw.policy.rules = [r for r in gw.policy.rules if r.id != "ip"]
    flow = plain(client, PUBLIC, 9000)
    gw.requestheaders(flow)
    assert refusal(flow) == (
        f"request for {PUBLIC}:9000 on a connection that was checked for a.example:9000; {PUBLIC}:9000 itself: default"
    )
    # a body that may be streamed cannot be answered: the flow is killed
    flow = plain(client, PUBLIC, transfer_encoding="chunked")
    gw.requestheaders(flow)
    assert flow.response is None and not flow.killable and a.id in gw.grants.active


def test_a_connection_that_was_checked_for_the_destination_carries_the_request_with_its_verdict(gw):
    client = tflow.tclient_conn()
    data = open_conn(gw, client, PUBLIC)
    flow = plain(client, PUBLIC)
    gw.requestheaders(flow)
    gw.request(flow)
    assert flow.response is None
    gate = flow.metadata[core.GATED]
    assert gate.reuse and gate.seq == gw.upstreams[data.server.id].seq and client.id not in gw.gated
    # the rule is gone: the list would deny it, or ask - and nobody is asked for a request
    gw.policy.rules = [r for r in gw.policy.rules if r.id != "ip"]
    flow = plain(client, PUBLIC)
    gw.requestheaders(flow)
    assert refusal(flow) == f"{PUBLIC}:8080 is not allowed on this connection any more: default"
    gw.policy.default = "ask"
    flow = plain(client, PUBLIC)
    gw.requestheaders(flow)
    assert "needs your approval, which is not asked for on an open connection" in refusal(flow) and gw.pending == {}


def test_a_grant_connection_to_an_ip_literal_keeps_the_grant_on_every_request(gw):
    client = tflow.tclient_conn()
    a = gw.grants.activate("ip", "read", 600, "", "t")
    data = open_conn(gw, client, "192.168.1.9")
    assert data.server.error is None and gw.verdicts[data.server.id].grant == a.id
    flow = plain(client, "192.168.1.9")
    gw.requestheaders(flow)
    assert flow.response is None and flow.metadata[core.GATED].grant == a.id
    flow = plain(client, "192.168.1.9", method=b"POST")
    gw.requestheaders(flow)
    assert refusal(flow) == "grant ip is read-only"
    # another grant instance carries the destination now (revoked and approved again): not this connection
    gw.grants.revoke(a.id)
    b = gw.grants.activate("ip", "read", 600, "", "t")
    assert b.id != a.id
    flow = plain(client, "192.168.1.9")
    gw.requestheaders(flow)
    assert refusal(flow) == "the grants for 192.168.1.9:8080 changed: use a new connection"
    gw.grants.revoke(b.id)
    flow = plain(client, "192.168.1.9")
    gw.requestheaders(flow)
    assert refusal(flow).startswith("192.168.1.9:8080 is not allowed on this connection any more: ")


# ------------------------------------------------------------------ the connection that is opened for a request
def test_server_connect_refuses_when_the_grants_changed_since_the_request_was_checked(gw):
    """The gate checked the request against the limits it found. If the connection is then carried by another
    grant, or by none, the request was checked against the wrong limits."""
    client = tflow.tclient_conn()
    changed = "the grants for this destination changed while the request was checked: send it again"
    # checked without a grant (the rules allow the name), connected under a grant
    gw.policy.add_rule(
        core.Policy.from_dict({"rules": [{"action": "allow", "host": "cam.example"}]}).rules[0], top=True
    )
    gw.requestheaders(plain(client, "cam.example"))
    assert gw.gated[client.id] == {core._addr_key("cam.example", 8080): None}
    gw.grants.activate("cam", "read", 600, "", "t")  # a fixed address: the grant carries it, not the rule
    data = open_conn(gw, client, "cam.example")
    assert changed in data.server.error and data.server.id not in gw.verdicts and gw.gated[client.id] == {}
    assert open_conn(gw, client, "cam.example").server.error is None  # sent again: checked and connected alike
    # checked under a grant, connected without it
    a = gw.grants.activate("nas", "read", 600, "", "t")
    gw.policy.add_rule(
        core.Policy.from_dict({"rules": [{"action": "allow", "cidr": f"{PUBLIC}/32"}]}).rules[0], top=True
    )
    flow = plain(client, "nas.example")
    gw.requestheaders(flow)
    assert flow.metadata[core.GATED].grant == a.id
    gw.grants.revoke(a.id)
    gw.policy.add_rule(
        core.Policy.from_dict({"rules": [{"action": "allow", "host": "nas.example"}]}).rules[0], top=True
    )
    data = open_conn(gw, client, "nas.example")
    assert changed in data.server.error and gw.events.recent(1)[0]["reason"].startswith(changed)
    # a connection nobody announced (a CONNECT tunnel) and one that is as announced are not touched
    assert open_conn(gw, client, "nas.example").server.error is None
    gw.requestheaders(plain(client, "a.example"))
    assert open_conn(gw, client, "a.example").server.error is None and gw.gated[client.id] == {}


# ------------------------------------------------------------------ the connection that carried it
def responded(gw, flow, data):
    """The response arrives on the connection of `data`: what the last line does with it."""
    flow.server_conn = data.server
    gw.responseheaders(flow)
    return None if flow.killable else gw.events.recent(1)[0]["reason"]


def test_the_response_is_withheld_if_the_connection_was_not_checked_for_the_request(gw):
    client = tflow.tclient_conn()
    old = open_conn(gw, client, "a.example", 9000)
    # as it should be: checked, then a connection was opened for it
    flow = plain(client, "a.example")
    gw.requestheaders(flow)
    assert responded(gw, flow, open_conn(gw, client, "a.example")) is None
    # ... also when that connection has closed in the meantime
    flow = plain(client, "a.example")
    gw.requestheaders(flow)
    data = open_conn(gw, client, "a.example")
    gw.server_disconnected(data)
    assert responded(gw, flow, data) is None
    # a connection that was checked for another destination
    flow = plain(client, "a.example")
    gw.requestheaders(flow)
    why = responded(gw, flow, open_conn(gw, client, PUBLIC))
    assert why == (
        f"response withheld: request for a.example:8080 on a connection that was checked for {PUBLIC}:8080: GET /api/x"
    )
    # a connection for this destination that was already open when the request was checked, unseen by the gate
    flow = plain(client, "a.example", 9000)
    gw.requestheaders(flow)
    assert flow.metadata[core.GATED].reuse is False
    assert "on a connection that was open before it was checked" in responded(gw, flow, old)
    # a connection the gateway knows nothing about
    flow = plain(client, "a.example")
    gw.requestheaders(flow)
    unknown = server_hooks.ServerConnectionHookData(server=tflow.tserver_conn(), client=client)
    assert "the connection was not checked" in responded(gw, flow, unknown)
    # another grant than the one the request was checked with
    a = gw.grants.activate("nas", "read", 600, "", "t")
    data = open_conn(gw, client, "nas.example")
    flow = plain(client, "nas.example")
    gw.requestheaders(flow)
    gw.upstreams[data.server.id].verdict = Verdict("nas.example", 8080, "another", Target("nas.example", 8080))
    assert a.id == flow.metadata[core.GATED].grant and "was checked for nas.example:8080" in responded(gw, flow, data)


def test_requests_the_gateway_answered_and_tunnelled_requests_are_left_alone(gw):
    client = tflow.tclient_conn()
    # refused by the gate after it was noted for a new connection: the 403 is ours, no connection carries it
    gw.grants.activate("nas", "read", 600, "", "t")
    flow = plain(client, "nas.example", path=b"/admin")
    gw.requestheaders(flow)
    assert refusal(flow) == "path not covered by grant nas" and core.GATED not in flow.metadata
    gw.responseheaders(flow)
    assert flow.killable
    # a request in a tunnel has the connection's verdict from the start: nothing is noted, nothing compared
    data = open_conn(gw, client, "a.example")
    flow = plain(client, "a.example")
    flow.server_conn = data.server
    gw.requestheaders(flow)
    gw.responseheaders(flow)
    assert flow.response is None and flow.killable and core.GATED not in flow.metadata


def test_a_streamed_request_is_checked_against_the_connection_it_got(gw):
    """Headers checked, connection opened, body streamed: the `request` hook then sees the connection."""
    client = tflow.tclient_conn()
    flow = plain(client, "a.example", content_length="2000000")
    flow.request.stream = True
    gw.requestheaders(flow)
    flow.server_conn = open_conn(gw, client, "a.example").server
    gw.request(flow)
    assert flow.killable and flow.response is None
    flow = plain(client, "a.example", content_length="2000000")
    flow.request.stream = True
    gw.requestheaders(flow)
    flow.server_conn = open_conn(gw, client, PUBLIC).server
    gw.request(flow)
    assert not flow.killable
    assert gw.events.recent(1)[0]["reason"].startswith(
        "request for a.example:8080 on a connection that was checked for"
    )
