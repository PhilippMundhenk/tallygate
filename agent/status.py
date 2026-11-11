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


def selftest() -> list[dict]:
    probes = [p for p in os.environ.get("SELFTEST_BLOCKED_PROBES", "").split(",") if p]
    results = [
        expect_fail("Direct TCP to the internet (1.1.1.1:443)", lambda: tcp("1.1.1.1", 443)),
        expect_fail(
            "Direct IPv6 (2606:4700:4700::1111:443)", lambda: tcp("2606:4700:4700::1111", 443, socket.AF_INET6)
        ),
        expect_fail("Agent DNS resolution of public names", lambda: socket.getaddrinfo("api.anthropic.com", 443)),
        expect_fail("UDP DNS to 1.1.1.1", lambda: udp_dns("1.1.1.1")),
        expect_fail("LAN via proxy (192.168.1.1:80, hard-deny)", lambda: connect_via_proxy("192.168.1.1", 80)),
        expect_fail(
            "Loopback/metadata via proxy (169.254.169.254:80)", lambda: connect_via_proxy("169.254.169.254", 80)
        ),
    ]
    for p in probes:
        h, port = p.rsplit(":", 1)
        results.append(expect_fail(f"Management endpoint {p}", lambda h=h, port=int(port): tcp(h, port)))
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
