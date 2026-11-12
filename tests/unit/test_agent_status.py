"""agent/status.py: status JSON and the isolation self-test of the setup wizard, against local fakes
(a fake /proc, a fake CONNECT proxy with a TLS upstream, a UDP responder) instead of the real network."""

import datetime
import importlib.util
import json
import socket
import ssl
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

STATUS = Path(__file__).resolve().parents[2] / "agent" / "status.py"
NO_PROXY = urllib.request.build_opener(urllib.request.ProxyHandler({}))


@pytest.fixture
def st(monkeypatch):
    for v in ("HTTPS_PROXY", "https_proxy", "SELFTEST_BLOCKED_PROBES", "NODE_EXTRA_CA_CERTS", "STATUS_PORT"):
        monkeypatch.delenv(v, raising=False)
    spec = importlib.util.spec_from_file_location("agent_status", STATUS)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    monkeypatch.setattr(mod, "TIMEOUT", 2)
    return mod


# ---------------------------------------------------------------- status
def test_sh_returns_stripped_stdout_and_never_raises(st, monkeypatch):
    assert st.sh(sys.executable, "-c", "print('  1.2.3 (Claude Code)  ')") == "1.2.3 (Claude Code)"
    assert st.sh("/nonexistent/claude", "--version") == ""  # OSError

    def hang(*a, **k):
        raise subprocess.TimeoutExpired(a[0], 10)

    monkeypatch.setattr(st.subprocess, "run", hang)
    assert st.sh("claude", "--version") == ""


def fake_proc(root: Path, procs: dict) -> Path:
    for name, cmdline in procs.items():
        (root / name).mkdir(parents=True)
        if cmdline is not None:  # None: the process is gone (no readable cmdline)
            (root / name / "cmdline").write_bytes(cmdline)
    return root


def test_status_reports_setup_state(st, monkeypatch, tmp_path):
    calls = []

    def sh(*cmd):
        calls.append(cmd)
        return {"claude": "2.0.0", "git": "dev"}[cmd[0]]

    monkeypatch.setattr(st, "sh", sh)
    monkeypatch.setattr(st, "HOME", tmp_path / "home")
    monkeypatch.setattr(
        st,
        "PROC",
        fake_proc(
            tmp_path / "proc",
            {
                "self": b"claude\0remote-control\0",  # not a pid
                "7": None,  # vanished while listing
                "8": b"bash\0-c\0echo remote-control\0",  # mentions remote-control, but is not claude
                "9": b"/usr/bin/node\0/usr/local/bin/claude\0remote-control\0",
            },
        ),
    )
    monkeypatch.setenv("NODE_EXTRA_CA_CERTS", "/etc/ca.pem")
    s = st.status()
    assert s["claude_version"] == "2.0.0" and s["git_name"] == "dev" and s["git_email"] == "dev"
    assert s["remote_control_running"] is True and s["gateway_ca_trusted"] is True
    assert s["claude_logged_in"] is False
    (tmp_path / "home" / ".claude").mkdir(parents=True)
    (tmp_path / "home" / ".claude" / ".credentials.json").write_text("{}")
    (tmp_path / "proc" / "9" / "cmdline").write_bytes(b"claude\0--version\0")
    monkeypatch.delenv("NODE_EXTRA_CA_CERTS")
    s = st.status()
    assert s["claude_logged_in"] is True
    assert s["remote_control_running"] is False and s["gateway_ca_trusted"] is False
    assert [c for c in calls if c[0] == "claude"] == [("claude", "--version")]  # version is cached
    json.dumps(s)  # served as JSON


# ---------------------------------------------------------------- probes
@pytest.mark.parametrize(
    ("env", "expected"),
    [
        ({}, ("egress-gw", 3128)),
        ({"HTTPS_PROXY": "http://gw.local:3129"}, ("gw.local", 3129)),
        ({"https_proxy": "http://lower:8000"}, ("lower", 8000)),
        ({"HTTPS_PROXY": "http://noport"}, ("noport", 3128)),
    ],
)
def test_proxy_from_environment(st, monkeypatch, env, expected):
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    assert st._proxy() == expected


def test_expect_fail_inverts_and_truncates(st):
    def refused():
        raise ConnectionRefusedError("x" * 500)

    ok = st.expect_fail("blocked probe", refused)
    assert ok["pass"] is True and ok["detail"].startswith("blocked (ConnectionRefusedError: xxx")
    assert len(ok["detail"]) == 200
    leak = st.expect_fail("leaky probe", lambda: "connected to 1.1.1.1:443")
    assert leak == {"name": "leaky probe", "pass": False, "detail": "UNEXPECTEDLY SUCCEEDED: connected to 1.1.1.1:443"}


def test_tcp_connects_or_raises(st):
    with socket.socket() as srv:
        srv.bind(("127.0.0.1", 0))
        srv.listen()
        port = srv.getsockname()[1]
        assert st.tcp("127.0.0.1", port) == f"connected to 127.0.0.1:{port}"
    with pytest.raises(OSError):
        st.tcp("127.0.0.1", port)  # closed now


def test_udp_dns_sends_a_query_and_reports_the_reply(st):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as srv:
        srv.bind(("127.0.0.1", 0))
        port = srv.getsockname()[1]
        got = {}

        def answer():
            q, addr = srv.recvfrom(512)
            got["q"] = q
            srv.sendto(q[:2] + b"\x81\x80" + b"\0" * 36, addr)

        t = threading.Thread(target=answer)
        t.start()
        assert st.udp_dns("127.0.0.1", port) == "got 40 byte reply from 127.0.0.1"
        t.join(5)
        assert got["q"][:2] == b"\x42\x42" and b"\x07example\x03com\x00" in got["q"]
        with pytest.raises(TimeoutError):  # nobody answers: blocked
            st.udp_dns("127.0.0.1", port)


# ---------------------------------------------------------------- fake CONNECT proxy
def make_cert(tmp: Path, host: str) -> tuple[Path, Path]:
    pytest.importorskip("cryptography")
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_p, key_p = tmp / "cert.pem", tmp / "key.pem"
    cert_p.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_p.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    return cert_p, key_p


class FakeProxy:
    """Answers CONNECT with `reply`; after a 200 it plays the upstream itself (TLS with `tls` cert)."""

    def __init__(self, reply: bytes, tls: tuple[Path, Path] | None = None) -> None:
        self.reply, self.requests = reply, []
        self.ctx = None
        if tls:
            self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.ctx.load_cert_chain(str(tls[0]), str(tls[1]))
        self.sock = socket.create_server(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._one, args=(conn,), daemon=True).start()

    def _one(self, conn):
        try:
            buf = b""
            while b"\r\n\r\n" not in buf:
                buf += conn.recv(1024)
            self.requests.append(buf.split(b"\r\n", 1)[0].decode())
            conn.sendall(self.reply)
            if self.ctx and b" 200 " in self.reply:
                with self.ctx.wrap_socket(conn, server_side=True) as t:
                    t.recv(1024)
                    t.sendall(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
        except (OSError, ssl.SSLError):
            pass  # the client hung up after the CONNECT reply, or refused our certificate
        finally:
            conn.close()

    def close(self):
        self.sock.close()


@pytest.fixture
def proxy(st, monkeypatch):
    made = []

    def factory(reply: bytes, tls=None) -> FakeProxy:
        p = FakeProxy(reply, tls)
        made.append(p)
        monkeypatch.setenv("HTTPS_PROXY", f"http://127.0.0.1:{p.port}")
        return p

    yield factory
    for p in made:
        p.close()


def test_connect_via_proxy_refused(st, proxy):
    p = proxy(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
    with pytest.raises(ConnectionRefusedError, match="403 Forbidden"):
        st.connect_via_proxy("192.168.1.1", 80)
    assert p.requests == ["CONNECT 192.168.1.1:80 HTTP/1.1"]


def test_connect_via_proxy_allowed(st, proxy):
    proxy(b"HTTP/1.1 200 Connection established\r\n\r\n")
    assert st.connect_via_proxy("example.test", 443) == "HTTP/1.1 200 Connection established"


def test_https_via_proxy_checks_the_certificate(st, proxy, tmp_path, monkeypatch):
    cert = make_cert(tmp_path, "api.anthropic.com")
    p = proxy(b"HTTP/1.1 200 Connection established\r\n\r\n", tls=cert)
    with pytest.raises(ssl.SSLCertVerificationError):  # the system store does not trust this CA
        st.https_via_proxy("api.anthropic.com")
    trusted = ssl.create_default_context
    monkeypatch.setattr(st.ssl, "create_default_context", lambda: trusted(cafile=str(cert[0])))
    assert st.https_via_proxy("api.anthropic.com") == (
        "HTTP/1.1 200 Connection established / TLS ok, HTTP/1.1 204 No Content"
    )
    assert set(p.requests) == {"CONNECT api.anthropic.com:443 HTTP/1.1"}


# ---------------------------------------------------------------- selftest
def isolated(st, monkeypatch, leak: str = ""):
    """Patch the probes: everything blocked (as in a correct setup), except `leak`."""
    calls = []

    def tcp(host, port, family=socket.AF_UNSPEC):
        calls.append(("tcp", host, port))
        if leak == "tcp" and host == "1.1.1.1":
            return "connected to 1.1.1.1:443"
        raise TimeoutError("timed out")

    def udp(server, port=53):
        raise TimeoutError("timed out")

    def connect(host, port):
        calls.append(("connect", host, port))
        if leak == "lan" and host == "192.168.1.1":
            return "HTTP/1.1 200 Connection established"
        raise ConnectionRefusedError("HTTP/1.1 403 Forbidden")

    def https(host):
        if leak == "no-api":
            raise ConnectionRefusedError("HTTP/1.1 502 Bad Gateway")
        return "HTTP/1.1 200 / TLS ok, HTTP/1.1 404 Not Found"

    real = socket.getaddrinfo

    def getaddrinfo(host, *a, **k):
        if host == "api.anthropic.com":
            raise socket.gaierror(-3, "Temporary failure in name resolution")
        return real(host, *a, **k)

    monkeypatch.setattr(st, "tcp", tcp)
    monkeypatch.setattr(st, "udp_dns", udp)
    monkeypatch.setattr(st, "connect_via_proxy", connect)
    monkeypatch.setattr(st, "https_via_proxy", https)
    monkeypatch.setattr(st.socket, "getaddrinfo", getaddrinfo)
    return calls


def test_selftest_all_blocked_passes(st, monkeypatch):
    monkeypatch.setenv("SELFTEST_BLOCKED_PROBES", "172.31.0.1:8081,,egress-gw:8081")
    calls = isolated(st, monkeypatch)
    res = st.selftest()
    assert all(r["pass"] for r in res), res
    names = [r["name"] for r in res]
    assert names[-1] == "Allowed path: api.anthropic.com via proxy"
    assert "Management endpoint 172.31.0.1:8081" in names and "Management endpoint egress-gw:8081" in names
    assert ("tcp", "172.31.0.1", 8081) in calls and ("tcp", "egress-gw", 8081) in calls  # each probe its own target
    assert ("connect", "169.254.169.254", 80) in calls
    assert next(r for r in res if "DNS resolution" in r["name"])["detail"].startswith("blocked (gaierror")


@pytest.mark.parametrize(
    ("leak", "failing"),
    [
        ("tcp", "Direct TCP to the internet (1.1.1.1:443)"),
        ("lan", "LAN via proxy (192.168.1.1:80, hard-deny)"),
        ("no-api", "Allowed path: api.anthropic.com via proxy"),
    ],
)
def test_selftest_reports_a_leak_or_a_broken_allowed_path(st, monkeypatch, leak, failing):
    isolated(st, monkeypatch, leak)
    res = st.selftest()
    assert [r["name"] for r in res if not r["pass"]] == [failing]


def test_main_selftest_prints_and_sets_the_exit_code(st, monkeypatch, capsys):
    isolated(st, monkeypatch)
    assert st.main(["--selftest"]) == 0
    out = capsys.readouterr().out.splitlines()
    assert out[0].startswith("PASS Direct TCP to the internet") and all(line.startswith("PASS ") for line in out)
    isolated(st, monkeypatch, "lan")
    assert st.main(["--selftest"]) == 1
    assert "FAIL LAN via proxy (192.168.1.1:80, hard-deny)  -- UNEXPECTEDLY SUCCEEDED" in capsys.readouterr().out


def test_main_serves_on_all_interfaces_of_the_agent_network(st, monkeypatch):
    seen = {}

    class Server:
        def __init__(self, addr, handler):
            seen["addr"], seen["handler"] = addr, handler

        def serve_forever(self):
            seen["served"] = True

    monkeypatch.setattr(st, "ThreadingHTTPServer", Server)
    assert st.main([]) == 0
    assert seen == {"addr": ("0.0.0.0", 7680), "handler": st.Handler, "served": True}
    monkeypatch.setenv("STATUS_PORT", "7699")
    st.main([])
    assert seen["addr"] == ("0.0.0.0", 7699)


# ---------------------------------------------------------------- HTTP endpoint
def test_handler_serves_status_and_selftest_read_only(st, monkeypatch):
    monkeypatch.setattr(st, "status", lambda: {"claude_version": "2.0.0"})
    monkeypatch.setattr(st, "selftest", lambda: [{"name": "n", "pass": True, "detail": "d"}])
    srv = ThreadingHTTPServer(("127.0.0.1", 0), st.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        with NO_PROXY.open(base + "/status", timeout=5) as r:
            assert r.headers["Content-Type"] == "application/json"
            assert json.loads(r.read()) == {"claude_version": "2.0.0"}
        with NO_PROXY.open(base + "/selftest", timeout=5) as r:
            assert json.loads(r.read()) == {"results": [{"name": "n", "pass": True, "detail": "d"}]}
        for path, method, code in (("/", "GET", 404), ("/status/../x", "GET", 404), ("/status", "POST", 501)):
            with pytest.raises(urllib.error.HTTPError) as e:
                NO_PROXY.open(
                    urllib.request.Request(base + path, method=method, data=b"" if method == "POST" else None)
                )
            assert e.value.code == code
    finally:
        srv.shutdown()
        srv.server_close()
