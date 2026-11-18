"""Security review of v0.4.0, #236: every request is checked against its own destination, also on a connection
that is already open.

mitmproxy keeps the upstream connections of one client connection and reuses one whose address equals the
host and port a plain-HTTP proxy request names, without `server_connect`. After one allowed request to a name,
a request that named the pinned address rode that connection and skipped the grant's limits and the blocked
ranges. The tests talk to the real gateway process over raw sockets (the keep-alive sequence matters) and to
upstreams that keep every byte they received, so "refused" always also means "nothing reached the upstream".
"""

from __future__ import annotations

import json
import socket
import ssl
import struct
import threading
import time

import pytest
import yaml

from .conftest import start_gateway
from .helpers import TIMEOUT, connect_tunnel


# ---------------------------------------------------------------- an upstream that remembers what it received
class Upstream:
    """A keep-alive HTTP/1.1 server on raw sockets. `conns` holds the bytes of every accepted connection; the
    answer to a request says which connection carried it."""

    def __init__(self, bind: str = "127.0.0.1") -> None:
        self.sock = socket.create_server((bind, 0))
        self.port = self.sock.getsockname()[1]
        self.conns: list[bytearray] = []
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self) -> None:
        while True:
            conn, _ = self.sock.accept()
            self.conns.append(bytearray())
            threading.Thread(target=self._serve, args=(conn, len(self.conns) - 1), daemon=True).start()

    def _serve(self, conn: socket.socket, n: int) -> None:
        buf, done = self.conns[n], 0
        with conn:
            while True:
                try:
                    chunk = conn.recv(65536)
                except OSError:
                    return
                if not chunk:
                    return
                buf += chunk
                while (end := buf.find(b"\r\n\r\n", done)) >= 0:
                    line, *lines = bytes(buf[done:end]).decode("latin1").split("\r\n")
                    headers = {k.lower(): v.strip() for k, _, v in (h.partition(":") for h in lines)}
                    length = int(headers.get("content-length", 0))
                    if len(buf) < end + 4 + length:
                        break
                    done = end + 4 + length
                    method, target, _ = line.split(" ", 2)
                    body = json.dumps(
                        {
                            "method": method,
                            "target": target,
                            "host": headers.get("host"),
                            "auth": headers.get("authorization"),
                            "conn": n,
                        }
                    ).encode()
                    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body) + body)

    @property
    def received(self) -> bytes:
        return b"".join(bytes(c) for c in self.conns)

    def requests(self) -> list[str]:
        """The request lines that arrived, in order of connection."""
        return [
            line.decode("latin1")
            for line in self.received.split(b"\r\n")
            if line.endswith((b" HTTP/1.1", b" HTTP/1.0"))
        ]


class H2Upstream:
    """An HTTP/2 server over TLS (ALPN h2). mitmproxy offers the agent HTTP/2 only if the upstream speaks it.
    `seen` holds (connection, :authority, :path) of every request that arrived."""

    def __init__(self, cert, key) -> None:
        self.sock = socket.create_server(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.seen: list[tuple[int, str, str]] = []
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(str(cert), str(key))
        self.ctx.set_alpn_protocols(["h2"])
        self.accepted = 0
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self) -> None:
        while True:
            raw, _ = self.sock.accept()
            self.accepted += 1
            threading.Thread(target=self._serve, args=(raw, self.accepted - 1), daemon=True).start()

    def _serve(self, raw: socket.socket, n: int) -> None:
        import h2.config
        import h2.connection
        import h2.events

        try:
            with self.ctx.wrap_socket(raw, server_side=True) as s:
                conn = h2.connection.H2Connection(h2.config.H2Configuration(client_side=False))
                conn.initiate_connection()
                s.sendall(conn.data_to_send())
                while data := s.recv(65536):
                    for ev in conn.receive_data(data):
                        if isinstance(ev, h2.events.RequestReceived):
                            head = {k.decode(): v.decode() for k, v in ev.headers}
                            self.seen.append((n, head[":authority"], head[":path"]))
                            body = json.dumps({"authority": head[":authority"], "path": head[":path"]}).encode()
                            conn.send_headers(ev.stream_id, [(":status", "200")])
                            conn.send_data(ev.stream_id, body, end_stream=True)
                    s.sendall(conn.data_to_send())
        except (OSError, ssl.SSLError):
            return


# ---------------------------------------------------------------- clients
def read_response(s) -> tuple[int, bytes]:
    """One response from a keep-alive connection: (status, body), or (0, b"") if the connection was closed."""
    buf = b""
    try:
        while b"\r\n\r\n" not in buf:
            chunk = s.recv(65536)
            if not chunk:
                return 0, buf
            buf += chunk
        head, rest = buf.split(b"\r\n\r\n", 1)
        length = 0
        for line in head.split(b"\r\n")[1:]:
            if line.lower().startswith(b"content-length:"):
                length = int(line.split(b":")[1])
        while len(rest) < length:
            chunk = s.recv(65536)
            if not chunk:
                break
            rest += chunk
    except (OSError, ssl.SSLError):
        return 0, buf
    return int(head.split()[1]), rest


def send(s, method: str, target: str, host: str, headers: dict | None = None, body: bytes = b"") -> None:
    hdrs = {"Host": host, "Content-Length": str(len(body)), **(headers or {})}
    head = f"{method} {target} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in hdrs.items()) + "\r\n"
    s.sendall(head.encode() + body)


def ask(s, method: str, target: str, host: str, **kw) -> tuple[int, bytes]:
    send(s, method, target, host, **kw)
    return read_response(s)


def get(s, hostport: str, path: str = "/", method: str = "GET", **kw) -> tuple[int, bytes]:
    """A plain-HTTP proxy request (absolute-form) on an open connection to the proxy."""
    return ask(s, method, f"http://{hostport}{path}", hostport, **kw)


def proxy(gw) -> socket.socket:
    return socket.create_connection(("127.0.0.1", gw["ports"]["http"]), timeout=TIMEOUT)


def settled(up: Upstream) -> bytes:
    """What the upstream has received, after giving a request that should not arrive the time to arrive."""
    time.sleep(0.3)
    return up.received


def events(gw, n: int = 40) -> list[dict]:
    return gw["api"].call("GET", f"/events?limit={n}")[1]


def grant(gw, name: str) -> None:
    status, r, _ = gw["agent"].call("POST", f"/v1/grants/{name}/request", {"level": "read", "reason": "e2e"})
    assert status == 200 and r["status"] == "approved", r


def revoke(gw, name: str) -> None:
    for a in gw["api"].call("GET", "/grants")[1]["active"]:
        if a["name"] == name:
            assert gw["api"].call("DELETE", f"/active-grants/{a['id']}?by=e2e")[0] == 200


def pending(gw, port: int, timeout: float = 5.0) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        match = [p for p in gw["api"].call("GET", "/pending")[1] if p["port"] == port]
        if match:
            return match[0]
        time.sleep(0.1)
    raise AssertionError(f"no pending request for port {port}")


# ---------------------------------------------------------------- one gateway for the module
@pytest.fixture(scope="module")
def ups(upstream):
    """The upstreams, one port per case so that the rules of one case do not open another. 127.0.0.2 plays a
    device on the LAN: it is inside a seeded block."""
    names = ("shared", "both", "svc", "pin", "ask", "askip", "ws")
    http = {**{n: Upstream() for n in names}, "lan": Upstream("127.0.0.2"), "lit": Upstream("127.0.0.2")}
    return {**http, "h2": H2Upstream(upstream["cert"], upstream["cert"].with_suffix(".key"))}


@pytest.fixture(scope="module")
def gw(tmp_path_factory, upstream, ups):
    def http_grant(host: str, up: str, **more) -> dict:
        target = {"host": host, "port": ups[up].port, "scheme": "http", "paths": ["/api/*"], **more}
        return {"targets": [target], "levels": ["read"], "approval": "auto"}

    tls = upstream["keepalive_tls"]
    config = {
        "hard_deny_floor": ["127.0.0.2/32"],
        "inject": [{"host": "gh.test", "header": "Authorization", "value": "Bearer ${github_token}"}],
        "grants": {
            "svc": http_grant("svc.test", "svc"),  # a name
            "ws": http_grant("svc.test", "ws"),
            "pin": http_grant("pin.test", "pin", address="127.0.0.1"),  # a name with a fixed address
            "lan": http_grant("lanecho.test", "lan", address="127.0.0.2"),  # ... inside a blocked range
            "lit": http_grant("127.0.0.2", "lit"),  # an IP literal
        },
    }
    policy = {
        "default": "deny",
        "ask_timeout": 8,
        "rules": [
            {"id": "a", "action": "allow", "host": "a.test", "port": [ups["shared"].port, ups["both"].port]},
            {"id": "ip", "action": "allow", "cidr": "127.0.0.1/32", "port": ups["both"].port},
            {"id": "q", "action": "ask", "host": "asked.test", "port": ups["ask"].port},
            {"id": "qip", "action": "ask", "cidr": "127.0.0.1/32", "port": ups["askip"].port},
            {"id": "gh", "action": "allow", "host": "gh.test", "port": [tls, ups["h2"].port]},
            {"id": "other", "action": "allow", "host": "other.test", "port": [tls, ups["h2"].port]},
        ],
    }
    data = tmp_path_factory.mktemp("gw-236")
    (data / "config.yaml").write_text(yaml.safe_dump(config))
    (data / "policy.yaml").write_text(yaml.safe_dump(policy))
    names = ("a.test", "b.test", "svc.test", "pin.test", "asked.test", "gh.test", "other.test")
    proc, gw = start_gateway(
        data,
        upstream,
        GW_TEST_FLOOR_REPLACE="1",
        GW_TEST_STATIC_HOSTS=",".join(f"{n}=127.0.0.1" for n in names) + ",lanecho.test=127.0.0.2",
    )
    assert gw["api"].call("PUT", "/secrets/github_token", {"value": "s3cr3t"})[0] == 200
    try:
        yield gw
    finally:
        proc.terminate()
        proc.wait(10)


# ---------------------------------------------------------------- the three proofs of concept of the review
def test_a_read_grant_on_paths_is_not_left_by_naming_the_pinned_address(gw, ups):
    """PoC 1 (test_c1d): a read-only grant for /api/* on a name with a fixed address. The second request on the
    same connection names the address: DELETE on another path went out, with no check at all."""
    up, port = ups["pin"], ups["pin"].port
    grant(gw, "pin")
    with proxy(gw) as s:
        status, body = get(s, f"pin.test:{port}", "/api/ok")
        assert status == 200 and json.loads(body)["host"] == f"pin.test:{port}"
        status, body = get(s, f"127.0.0.1:{port}", "/secret/wipe", "DELETE")
        assert status == 403, (status, body)
        assert b"on a connection that was checked for pin.test" in body
        assert b"reach a grant target by its name" in body
        # the connection to the proxy is still usable, and the grant still works on it
        assert get(s, f"pin.test:{port}", "/api/again")[0] == 200
    assert up.requests() == ["GET /api/ok HTTP/1.1", "GET /api/again HTTP/1.1"]
    assert b"DELETE" not in settled(up) and b"wipe" not in up.received
    ev = next(e for e in events(gw) if e["action"] == "deny" and e["port"] == port)
    assert ev["host"] == "127.0.0.1" and "DELETE /secret/wipe" in ev["reason"]


def test_a_grant_on_a_name_is_not_left_by_naming_the_address_it_resolved_to(gw, ups):
    """PoC 2 (test_c1c): the same with a target that is only a name; the address is the one it resolved to."""
    up, port = ups["svc"], ups["svc"].port
    grant(gw, "svc")
    with proxy(gw) as s:
        assert get(s, f"svc.test:{port}", "/api/ok")[0] == 200
        for method, path in (("DELETE", "/secret/wipe"), ("POST", "/api/x"), ("GET", "/api/ok")):
            status, body = get(s, f"127.0.0.1:{port}", path, method)
            assert status == 403 and b"on a connection that was checked for svc.test" in body, (method, body)
    assert settled(up).count(b"HTTP/1.1\r\n") == 1 and up.requests() == ["GET /api/ok HTTP/1.1"]


def test_a_blocked_range_is_not_reached_through_a_grant_connection(gw, ups):
    """PoC 3 (test_c1b, test_c1_grant_limits_keepalive): the grant target names a device inside a blocked
    range. On the grant's connection a request that named the address reached the device with any method and
    path. The controls show that only the reuse opened it."""
    up, port = ups["lan"], ups["lan"].port
    literal, name = f"127.0.0.2:{port}", f"lanecho.test:{port}"
    revoke(gw, "lan")
    with proxy(gw) as s:
        assert get(s, literal, "/admin", "POST")[0] == 502  # no grant: the block
    grant(gw, "lan")
    with proxy(gw) as s:
        status, body = get(s, name, "/admin", "POST")  # the grant's own limits on a new connection
        assert status == 403 and b"path not covered by grant lan" in body
    with proxy(gw) as s:
        status, body = get(s, literal, "/admin", "POST")  # the address on a new connection: the block
        assert status == 502 and b"reach a grant target by its name" in body
    with proxy(gw) as s:
        assert get(s, name, "/api/x")[0] == 200
        status, body = get(s, literal, "/admin/wipe", "DELETE")
        assert status == 403 and b"checked for lanecho.test" in body and b"inside blocked range" not in body
        assert b"rule block-127.0.0.2_32" in body  # the request's own destination was decided: the block
        status, body = get(s, literal, "/api/x")  # also what the grant would allow by name
        assert status == 403
    assert up.requests() == ["GET /api/x HTTP/1.1"] and b"DELETE" not in settled(up)


def test_a_streamed_request_is_cut_before_anything_reaches_the_upstream(gw, ups):
    """A body of unknown length is streamed upstream right after the headers were checked, so the request is
    refused at the headers: not one byte of it arrives."""
    up, port = ups["pin"], ups["pin"].port
    grant(gw, "pin")
    with proxy(gw) as s:
        assert get(s, f"pin.test:{port}", "/api/first")[0] == 200
        before = settled(up)
        s.sendall(
            f"POST http://127.0.0.1:{port}/secret/upload HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
            "Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n".encode()
        )
        assert read_response(s)[0] in (0, 403)
        assert settled(up) == before


def test_a_websocket_upgrade_does_not_ride_a_grant_connection(gw, ups):
    up, port = ups["ws"], ups["ws"].port
    grant(gw, "ws")
    upgrade = {"Connection": "Upgrade", "Upgrade": "websocket", "Sec-WebSocket-Version": "13"}
    upgrade["Sec-WebSocket-Key"] = "dGhlIHNhbXBsZSBub25jZQ=="
    with proxy(gw) as s:
        assert get(s, f"svc.test:{port}", "/api/ok")[0] == 200
        status, body = get(s, f"127.0.0.1:{port}", "/api/socket", headers=upgrade)
        assert status == 403 and b"checked for svc.test" in body
        status, body = get(s, f"svc.test:{port}", "/api/socket", headers=upgrade)  # by name: the read level
        assert status == 403 and b"grant ws is read-only" in body
    assert settled(up).count(b"HTTP/1.1\r\n") == 1


# ---------------------------------------------------------------- what must keep working
def test_keep_alive_to_one_destination_still_works(gw, ups):
    """Several requests to the same destination on one connection to the proxy. An IP literal uses ONE upstream
    connection for all of them (the pool), a name gets a new one per request, each decided by server_connect
    (mitmproxy looks for the name, and the connection is pinned to the address): unchanged by #236."""
    up, port = ups["both"], ups["both"].port
    with proxy(gw) as s:
        by_ip = [json.loads(get(s, f"127.0.0.1:{port}", f"/ip{i}")[1])["conn"] for i in range(4)]
    with proxy(gw) as s:
        replies = [get(s, f"a.test:{port}", f"/name{i}") for i in range(3)]
    assert len(set(by_ip)) == 1
    assert [st for st, _ in replies] == [200, 200, 200]
    assert [r.split()[1] for r in up.requests()] == ["/ip0", "/ip1", "/ip2", "/ip3", "/name0", "/name1", "/name2"]


def test_the_first_request_to_an_ask_destination_prompts_once_and_passes_after_approval(gw, ups):
    """The request hooks run before the connection is opened. They must not refuse what `server_connect` will
    ask about: one prompt, and the held request goes out when it is approved."""
    up, port = ups["ask"], ups["ask"].port
    with proxy(gw) as s:
        send(s, "GET", f"http://asked.test:{port}/held", f"asked.test:{port}")
        p = pending(gw, port)
        assert p["host"] == "asked.test" and up.received == b""
        assert gw["api"].call("POST", f"/pending/{p['id']}/decide", {"scope": "hour", "by": "e2e"})[0] == 200
        status, body = read_response(s)
        assert status == 200 and json.loads(body)["target"] == "/held"
        assert get(s, f"asked.test:{port}", "/again")[0] == 200  # the same connection, the rule of the approval
    asks = [e for e in events(gw, 100) if e["kind"] == "ask" and e["port"] == port]
    assert len(asks) == 1 and gw["api"].call("GET", "/pending")[1] == []


def test_no_prompt_for_a_request_on_an_open_connection(gw, ups):
    """An IP literal that the rules ask about, approved once. Its connection is reused. When the approval is
    gone, the next request on that connection would need a prompt, which a request hook cannot ask: it is
    refused, and a new connection asks again."""
    up, port = ups["askip"], ups["askip"].port
    hp = f"127.0.0.1:{port}"
    with proxy(gw) as s:
        send(s, "GET", f"http://{hp}/one", hp)
        p = pending(gw, port)
        status, res, _ = gw["api"].call("POST", f"/pending/{p['id']}/decide", {"scope": "once", "by": "e2e"})
        assert status == 200 and read_response(s)[0] == 200
        status, body = get(s, hp, "/two")  # the approval's rule still stands: the open connection carries it
        assert status == 200 and json.loads(body)["conn"] == 0
        assert gw["api"].call("DELETE", f"/destinations/{res['rule']['id']}")[0] == 200
        status, body = get(s, hp, "/three")
        assert status == 403 and b"is not allowed on this connection any more" in body
        assert b"needs your approval, which is not asked for on an open connection" in body
        assert gw["api"].call("GET", "/pending")[1] == []
    assert [r.split()[1] for r in up.requests()] == ["/one", "/two"]
    with proxy(gw) as s:  # a new connection is asked about
        send(s, "GET", f"http://{hp}/four", hp)
        p = pending(gw, port)
        gw["api"].call("POST", f"/pending/{p['id']}/decide", {"scope": "deny", "by": "e2e"})
        assert read_response(s)[0] == 502
    assert b"/three" not in settled(up) and b"/four" not in up.received


# ---------------------------------------------------------------- rules: two names on one address
def test_a_name_and_its_address_do_not_share_a_connection(gw, ups):
    """Both are allowed here, each by its own rule. The connection that was checked for the name still does
    not carry the request that names the address: what was checked is what is sent."""
    up, port = ups["both"], ups["both"].port
    before = len(up.requests())
    with proxy(gw) as s:
        assert get(s, f"a.test:{port}", "/by-name")[0] == 200
        status, body = get(s, f"127.0.0.1:{port}", "/by-address")
        assert (
            status == 403
            and body
            == (
                f"egress policy: request for 127.0.0.1:{port} on a connection that was checked for a.test:{port}\n"
            ).encode()
        )
    with proxy(gw) as s:  # on its own connection it is allowed
        assert get(s, f"127.0.0.1:{port}", "/by-address-alone")[0] == 200
    assert [r.split()[1] for r in up.requests()[before:]] == ["/by-name", "/by-address-alone"]


def test_another_name_on_the_same_address_does_not_ride_the_connection(gw, ups):
    """a.test is allowed, b.test is not, both are served by the same address. Nothing for b.test goes out on
    the connection that was opened for a.test, however the request names it."""
    up, port = ups["shared"], ups["shared"].port
    a, b = f"a.test:{port}", f"b.test:{port}"
    with proxy(gw) as s:
        assert get(s, a, "/a")[0] == 200
        status, body = ask(s, "GET", f"http://{a}/host-b", b)  # the Host header picks the site
        assert status == 403 and b"Host header does not match the checked target" in body
        status, body = get(s, f"127.0.0.1:{port}", "/address", headers={"Host": b})  # by the pinned address
        assert status == 403 and b"on a connection that was checked for a.test" in body
        assert get(s, a, "/a2")[0] == 200
        status, body = get(s, b, "/b")  # by its name: a new connection, which the rules refuse
        assert status == 502 and b"egress policy: blocked (default (not resolved))" in body
    assert [r.split()[1] for r in up.requests()] == ["/a", "/a2"] and b"b.test" not in settled(up)


# ---------------------------------------------------------------- grants that end while a connection is open
def test_a_revoked_grant_ends_on_an_open_connection_too(gw, ups):
    up, port = ups["svc"], ups["svc"].port
    before = len(up.requests())
    grant(gw, "svc")
    with proxy(gw) as s:
        assert get(s, f"svc.test:{port}", "/api/one")[0] == 200
        revoke(gw, "svc")
        status, body = get(s, f"svc.test:{port}", "/api/two")
        assert status == 502 and b"available via grant svc" in body
    assert [r.split()[1] for r in up.requests()[before:]] == ["/api/one"] and b"/api/two" not in settled(up)


def test_a_grant_for_an_ip_literal_keeps_its_limits_on_the_reused_connection(gw, ups):
    """The one case in which a grant's connection is reused: the target is an IP literal, so the request names
    what was checked. Every request on it is held to the grant, and to the grant being active."""
    up, port = ups["lit"], ups["lit"].port
    hp = f"127.0.0.2:{port}"
    grant(gw, "lit")
    with proxy(gw) as s:
        first, second = get(s, hp, "/api/one"), get(s, hp, "/api/two")
        assert first[0] == second[0] == 200 and json.loads(first[1])["conn"] == json.loads(second[1])["conn"]
        status, body = get(s, hp, "/api/three", "POST")
        assert status == 403 and b"grant lit is read-only" in body
        status, body = get(s, hp, "/other")
        assert status == 403 and b"path not covered by grant lit" in body
        revoke(gw, "lit")
        status, body = get(s, hp, "/api/four")
        assert status == 403 and b"is not allowed on this connection any more" in body, body
    assert [r.split()[1] for r in up.requests()] == ["/api/one", "/api/two"] and b"four" not in settled(up)


# ---------------------------------------------------------------- the other paths: one connection, one target
def _bound_to_a(s, up: Upstream, port: int) -> None:
    """Plain HTTP on a connection that was opened for a.test (a CONNECT tunnel, SOCKS5): every request is
    checked against that target, by its Host and by the authority in its request line."""
    a, b = f"a.test:{port}", f"b.test:{port}"
    assert ask(s, "GET", "/one", a)[0] == 200
    status, body = ask(s, "GET", "/host-b", b)
    assert status == 403 and b"Host header does not match the checked target" in body
    status, body = ask(s, "GET", f"http://{b}/target-b", a)  # absolute-form: a server uses it before the Host
    assert status == 403 and b"request target does not match the checked target" in body
    status, body = ask(s, "GET", f"http://a.test:{port + 1}/port", a)
    assert status == 403 and b"request target does not match the checked target" in body
    status, body = ask(s, "GET", f"http://{a}/absolute", a)  # naming the checked target is fine
    assert status == 200 and json.loads(body)["host"] == a
    assert ask(s, "GET", "/two", a)[0] == 200
    assert b"b.test" not in settled(up) and b"/port" not in up.received


def test_requests_in_a_connect_tunnel_stay_bound_to_its_target(gw, ups):
    up, port = ups["shared"], ups["shared"].port
    s, line = connect_tunnel(gw["ports"]["http"], f"a.test:{port}")
    assert " 200" in line
    with s:
        _bound_to_a(s, up, port)


def test_requests_over_socks5_stay_bound_to_its_target(gw, ups):
    up, port = ups["shared"], ups["shared"].port
    with socket.create_connection(("127.0.0.1", gw["ports"]["socks"]), timeout=TIMEOUT) as s:
        s.sendall(b"\x05\x01\x00")
        assert s.recv(2) == b"\x05\x00"
        s.sendall(b"\x05\x01\x00\x03" + bytes([len("a.test")]) + b"a.test" + struct.pack(">H", port))
        assert s.recv(10)[1] == 0
        _bound_to_a(s, up, port)


def _tls_tunnel(gw, target: str, sni: str, alpn: list[str] | None = None) -> ssl.SSLSocket:
    raw, line = connect_tunnel(gw["ports"]["http"], target)
    assert " 200" in line
    ctx = ssl.create_default_context(cafile=gw["ca"])
    if alpn:
        ctx.set_alpn_protocols(alpn)
    return ctx.wrap_socket(raw, server_hostname=sni)


def test_requests_on_an_intercepted_tls_connection_stay_bound_to_its_target(gw, upstream):
    port = upstream["keepalive_tls"]
    gh, other = f"gh.test:{port}", f"other.test:{port}"
    with _tls_tunnel(gw, gh, "gh.test") as s:
        status, body = ask(s, "GET", "/one", gh)
        assert status == 200 and json.loads(body)["auth"] == "Bearer s3cr3t"
        status, body = ask(s, "GET", "/host-other", other)  # other.test is allowed too, by its own rule
        assert status == 403 and b"Host header does not match the checked target" in body
        status, body = ask(s, "GET", f"https://{other}/target-other", gh)
        assert status == 403 and b"request target does not match the checked target" in body
        status, body = ask(s, "GET", "/two", gh)  # the connection is reused for what it was checked for
        assert status == 200 and json.loads(body)["path"] == "/two"


def test_http2_streams_on_one_connection_stay_bound_to_its_target(gw, ups):
    """HTTP/2 on both sides, one TLS connection, several streams: each stream's :authority is checked like the
    Host of an HTTP/1 request, and the streams that pass share the one upstream connection."""
    import h2.connection
    import h2.events

    up, port = ups["h2"], ups["h2"].port
    with _tls_tunnel(gw, f"gh.test:{port}", "gh.test", ["h2"]) as s:
        assert s.selected_alpn_protocol() == "h2"
        conn = h2.connection.H2Connection()
        conn.initiate_connection()

        def stream(sid: int, authority: str, path: str, *more: tuple[str, str]) -> tuple[int, bytes]:
            head = [(":method", "GET"), (":authority", authority), (":scheme", "https"), (":path", path)]
            conn.send_headers(sid, [*head, *more], end_stream=True)
            s.sendall(conn.data_to_send())
            status, body = 0, b""
            while True:
                data = s.recv(65536)
                assert data, "connection closed"
                for ev in conn.receive_data(data):
                    if isinstance(ev, h2.events.ResponseReceived) and ev.stream_id == sid:
                        status = int(dict(ev.headers)[b":status"])
                    elif isinstance(ev, h2.events.DataReceived) and ev.stream_id == sid:
                        body += ev.data
                        conn.acknowledge_received_data(ev.flow_controlled_length, sid)
                    elif isinstance(ev, h2.events.StreamEnded) and ev.stream_id == sid:
                        s.sendall(conn.data_to_send())
                        return status, body
                    elif isinstance(ev, h2.events.StreamReset) and ev.stream_id == sid:
                        return 0, body
                s.sendall(conn.data_to_send())

        gh = f"gh.test:{port}"
        status, body = stream(1, gh, "/h2-one")
        assert status == 200 and json.loads(body) == {"authority": gh, "path": "/h2-one"}
        # other.test is allowed by its own rule, but not on this connection
        status, body = stream(3, f"other.test:{port}", "/h2-other", ("content-length", "0"))
        assert status == 403 and b"Host header does not match the checked target" in body
        # without a length the body could be streamed, so the stream is reset instead of answered
        assert stream(5, f"127.0.0.1:{port}", "/h2-address") == (0, b"")
        assert stream(7, gh, "/h2-two")[0] == 200
    assert up.seen == [(0, gh, "/h2-one"), (0, gh, "/h2-two")]
