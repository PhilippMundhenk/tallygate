#!/usr/bin/env python3
"""Read-only status + isolation self-test for the setup wizard (agent network only, port 7680).

NOTE: results come from inside the agent, so a compromised agent could lie. They are a setup
aid. The authoritative check is tests/integration/bypass.sh, run by the admin via `docker compose exec`.
"""

import json
import os
import socket
import ssl
import struct
import subprocess
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HOME = Path.home()
PROC = Path("/proc")
TIMEOUT = 5


def sh(*cmd: str) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return ""


_version_cache: dict = {}


def status() -> dict:
    if "v" not in _version_cache:
        _version_cache["v"] = sh("claude", "--version")
    rc = False
    for p in PROC.iterdir():
        if p.name.isdigit():
            try:
                cmd = (p / "cmdline").read_bytes().split(b"\0")
            except OSError:
                continue
            if b"remote-control" in cmd and any(b"claude" in c for c in cmd):
                rc = True
                break
    return {
        "claude_version": _version_cache["v"],
        "claude_logged_in": (HOME / ".claude" / ".credentials.json").exists(),
        "git_name": sh("git", "config", "--global", "user.name"),
        "git_email": sh("git", "config", "--global", "user.email"),
        "remote_control_running": rc,
        "gateway_ca_trusted": bool(os.environ.get("NODE_EXTRA_CA_CERTS")),
        "time": time.time(),
    }


# ---------------------------------------------------------------- self-test
def _proxy() -> tuple[str, int]:
    u = urllib.parse.urlparse(os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy") or "http://egress-gw:3128")
    return u.hostname, u.port or 3128


def expect_fail(name: str, fn) -> dict:
    try:
        detail = fn()
        return {"name": name, "pass": False, "detail": f"UNEXPECTEDLY SUCCEEDED: {detail}"}
    except Exception as e:  # noqa: BLE001
        return {"name": name, "pass": True, "detail": f"blocked ({type(e).__name__}: {e})"[:200]}


def tcp(host: str, port: int, family=socket.AF_UNSPEC) -> str:
    infos = socket.getaddrinfo(host, port, family, socket.SOCK_STREAM)
    with socket.create_connection(infos[0][4][:2], timeout=TIMEOUT):
        return f"connected to {host}:{port}"


def udp_dns(server: str, port: int = 53) -> str:
    q = struct.pack(">HHHHHH", 0x4242, 0x0100, 1, 0, 0, 0) + b"\x07example\x03com\x00" + struct.pack(">HH", 1, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(TIMEOUT)
        s.sendto(q, (server, port))
        data = s.recv(512)
    return f"got {len(data)} byte reply from {server}"


def connect_via_proxy(host: str, port: int) -> str:
    ph, pp = _proxy()
    with socket.create_connection((ph, pp), timeout=TIMEOUT + 60) as s:
        s.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
        s.settimeout(TIMEOUT + 60)
        line = s.recv(256).split(b"\r\n", 1)[0].decode(errors="replace")
        if " 200 " not in line + " ":
            raise ConnectionRefusedError(line)
        return line


def https_via_proxy(host: str) -> str:
    line = connect_via_proxy(host, 443)
    ph, pp = _proxy()
    raw = socket.create_connection((ph, pp), timeout=TIMEOUT)
    raw.sendall(f"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n".encode())
    raw.recv(256)
    ctx = ssl.create_default_context()
    with ctx.wrap_socket(raw, server_hostname=host) as t:
        t.sendall(f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
        return f"{line} / TLS ok, {t.recv(64).split(b'\r\n')[0].decode(errors='replace')}"


def _socks() -> tuple[str, int]:
    u = urllib.parse.urlparse(os.environ.get("ALL_PROXY") or os.environ.get("all_proxy") or "")  # noqa: SIM112
    if u.hostname:
        return u.hostname, u.port or 1080
    return _proxy()[0], 1080


def raw_socket() -> str:
    """Opening a raw socket needs CAP_NET_RAW, which the agent container drops; this should fail."""
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    s.close()
    return "raw ICMP socket opened (CAP_NET_RAW present)"


def socks5_connect(host: str, port: int) -> str:
    """CONNECT through the gateway's SOCKS5 listener. Raises unless the tunnel is actually granted."""
    sh, sp = _socks()
    with socket.create_connection((sh, sp), timeout=TIMEOUT) as s:
        s.settimeout(TIMEOUT)
        s.sendall(b"\x05\x01\x00")  # version 5, one method: no auth
        if s.recv(2) != b"\x05\x00":
            raise ConnectionRefusedError("SOCKS5 no-auth refused")
        h = host.strip("[]")
        try:
            packed, atyp = socket.inet_pton(socket.AF_INET, h), b"\x01"
        except OSError:
            try:
                packed, atyp = socket.inet_pton(socket.AF_INET6, h), b"\x04"
            except OSError:
                packed, atyp = bytes([len(h)]) + h.encode(), b"\x03"
        s.sendall(b"\x05\x01\x00" + atyp + packed + port.to_bytes(2, "big"))
        rep = s.recv(4)
        if len(rep) < 2 or rep[1] != 0x00:  # 0x00 = succeeded; anything else is a refusal
            raise ConnectionRefusedError(f"SOCKS5 reply code {rep[1] if len(rep) > 1 else '?'}")
        return f"SOCKS5 connected to {host}:{port}"


def http_get_via_proxy(host: str, port: int = 80, path: str = "/") -> str:
    """Plain-HTTP absolute-URI request through the proxy. Raises when the gateway refuses it (5xx /
    'egress policy'); returns only if the forbidden origin actually answered."""
    ph, pp = _proxy()
    with socket.create_connection((ph, pp), timeout=TIMEOUT) as s:
        s.settimeout(TIMEOUT)
        s.sendall(f"GET http://{host}:{port}{path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
        line = s.recv(256).split(b"\r\n", 1)[0].decode(errors="replace")
    parts = line.split(" ")
    code = parts[1] if len(parts) > 2 else ""
    if not line or "egress policy" in line or code in ("", "400", "403", "407", "500", "502", "503"):
        raise ConnectionRefusedError(line or "no response")
    return f"reached {host}: {line}"


def _probe_specs() -> list[tuple[str, object]]:
    """(name, fn) for every probe that must be BLOCKED. Only targets the gateway refuses
    *unconditionally* are used -- hard-deny IP ranges (directly, as IPv4-mapped/NAT64/6to4/Teredo IPv6,
    over the HTTP proxy, as plain-HTTP, and over SOCKS), destinations with no route, and a raw socket --
    so the test never reaches the policy's `ask` path and never holds a connection for approval."""
    specs: list[tuple[str, object]] = [
        # No route out of the agent network at all (the proxy is the only path).
        ("Direct TCP to the internet (1.1.1.1:443)", lambda: tcp("1.1.1.1", 443)),
        (
            "Direct IPv6 to the internet (2606:4700:4700::1111:443)",
            lambda: tcp("2606:4700:4700::1111", 443, socket.AF_INET6),
        ),
        ("Direct TCP to cloud metadata (169.254.169.254:80)", lambda: tcp("169.254.169.254", 80)),
        ("Direct TCP to a private host (10.0.0.1:80)", lambda: tcp("10.0.0.1", 80)),
        ("Raw ICMP socket (needs CAP_NET_RAW)", raw_socket),
        # DNS is disabled in the container; the proxy resolves on the agent's behalf.
        ("Agent DNS resolution of public names", lambda: socket.getaddrinfo("api.anthropic.com", 443)),
        ("UDP DNS to a public resolver (1.1.1.1:53)", lambda: udp_dns("1.1.1.1")),
        # Hard-denied IP ranges over the HTTP proxy (CONNECT).
        ("Metadata via proxy (CONNECT 169.254.169.254:80)", lambda: connect_via_proxy("169.254.169.254", 80)),
        ("LAN via proxy (CONNECT 192.168.1.1:80)", lambda: connect_via_proxy("192.168.1.1", 80)),
        ("Loopback via proxy (CONNECT 127.0.0.1:80)", lambda: connect_via_proxy("127.0.0.1", 80)),
        ("IPv6 loopback via proxy (CONNECT [::1]:80)", lambda: connect_via_proxy("[::1]", 80)),
        ("CGNAT via proxy (CONNECT 100.64.0.1:80)", lambda: connect_via_proxy("100.64.0.1", 80)),
        ("Link-local via proxy (CONNECT 169.254.1.1:80)", lambda: connect_via_proxy("169.254.1.1", 80)),
        # Same ranges hidden inside IPv6 encodings (must be normalised, then hard-denied).
        (
            "Metadata as IPv4-mapped IPv6 via proxy ([::ffff:169.254.169.254]:80)",
            lambda: connect_via_proxy("[::ffff:169.254.169.254]", 80),
        ),
        ("LAN via NAT64 via proxy ([64:ff9b::192.168.1.1]:80)", lambda: connect_via_proxy("[64:ff9b::c0a8:101]", 80)),
        ("LAN via 6to4 via proxy ([2002:c0a8:101::]:80)", lambda: connect_via_proxy("[2002:c0a8:101::]", 80)),
        ("Teredo via proxy (CONNECT [2001::1]:80)", lambda: connect_via_proxy("[2001::1]", 80)),
        # Hard-denied ranges over other request shapes the proxy understands.
        (
            "Plain-HTTP to metadata via proxy (GET http://169.254.169.254/)",
            lambda: http_get_via_proxy("169.254.169.254", 80, "/latest/meta-data/"),
        ),
        ("Plain-HTTP to LAN via proxy (GET http://192.168.1.1/)", lambda: http_get_via_proxy("192.168.1.1", 80, "/")),
        ("SOCKS5 to cloud metadata (169.254.169.254:80)", lambda: socks5_connect("169.254.169.254", 80)),
        ("SOCKS5 to LAN (192.168.1.1:80)", lambda: socks5_connect("192.168.1.1", 80)),
    ]
    for p in [x for x in os.environ.get("SELFTEST_BLOCKED_PROBES", "").split(",") if x]:
        h, port = p.rsplit(":", 1)
        specs.append((f"Management endpoint {p}", lambda h=h, port=int(port): tcp(h, port)))
    return specs


def selftest() -> list[dict]:
    specs = _probe_specs()
    # Run the blocked-probe battery concurrently so a slow (timing-out) probe does not stall the UI.
    with ThreadPoolExecutor(max_workers=min(12, len(specs))) as ex:
        results = list(ex.map(lambda s: expect_fail(s[0], s[1]), specs))
    # One positive control last: the sanctioned path must still work.
    try:
        results.append(
            {
                "name": "Allowed path: api.anthropic.com via proxy",
                "pass": True,
                "detail": https_via_proxy("api.anthropic.com"),
            }
        )
    except Exception as e:  # noqa: BLE001
        results.append({"name": "Allowed path: api.anthropic.com via proxy", "pass": False, "detail": str(e)[:200]})
    return results


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/status":
            body = status()
        elif self.path == "/selftest":
            body = {"results": selftest()}
        else:
            self.send_error(404)
            return
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


def main(argv: list[str]) -> int:
    if "--selftest" in argv:
        res = selftest()
        for r in res:
            print(("PASS " if r["pass"] else "FAIL ") + r["name"] + "  -- " + r["detail"])
        return 0 if all(r["pass"] for r in res) else 1
    ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("STATUS_PORT", "7680"))), Handler).serve_forever()
    return 0


if __name__ == "__main__":  # pragma: no cover - process entry point, main() is tested
    import sys

    sys.exit(main(sys.argv[1:]))
