"""Small, dependency-free network clients used by the e2e tests (raw sockets on purpose:
we want to see exactly what the gateway does, without client-side proxy magic)."""

from __future__ import annotations

import http.cookiejar
import json
import socket
import ssl
import struct
import time
import urllib.error
import urllib.request

TIMEOUT = 20


def wait_http(url: str, timeout: float = 20) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.build_opener(urllib.request.ProxyHandler({})).open(url, timeout=2)
            return
        except Exception:
            time.sleep(0.2)
    raise TimeoutError(f"{url} did not come up")


def http_via_proxy(proxy_port: int, url: str, timeout: float = TIMEOUT) -> tuple[int, bytes]:
    """Plain-HTTP request through the HTTP proxy (absolute-form request line)."""
    host_port = url.split("://", 1)[1].split("/", 1)[0]
    path_host = url
    with socket.create_connection(("127.0.0.1", proxy_port), timeout=timeout) as s:
        s.sendall(f"GET {path_host} HTTP/1.1\r\nHost: {host_port}\r\nConnection: close\r\n\r\n".encode())
        return _read_response(s)


def connect_tunnel(proxy_port: int, target: str, timeout: float = TIMEOUT) -> tuple[socket.socket, str]:
    s = socket.create_connection(("127.0.0.1", proxy_port), timeout=timeout)
    s.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = s.recv(4096)
        if not chunk:
            break
        buf += chunk
    return s, buf.split(b"\r\n", 1)[0].decode(errors="replace")


def https_via_proxy(
    proxy_port: int,
    connect_target: str,
    sni: str,
    path: str,
    cafile: str,
    headers: dict | None = None,
    timeout: float = TIMEOUT,
) -> tuple[int, bytes]:
    """CONNECT to `connect_target`, then TLS with SNI `sni` (can differ: SNI-spoofing test)."""
    raw, status_line = connect_tunnel(proxy_port, connect_target, timeout)
    if " 200" not in status_line:
        raw.close()
        return int(status_line.split()[1]) if len(status_line.split()) > 1 else 0, b""
    ctx = ssl.create_default_context(cafile=cafile)
    with ctx.wrap_socket(raw, server_hostname=sni) as t:
        hdrs = "".join(f"{k}: {v}\r\n" for k, v in (headers or {}).items())
        t.sendall(f"GET {path} HTTP/1.1\r\nHost: {sni}\r\n{hdrs}Connection: close\r\n\r\n".encode())
        return _read_response(t)


def socks5_http(socks_port: int, host: str, port: int, path: str, timeout: float = TIMEOUT) -> tuple[int, bytes]:
    s = socket.create_connection(("127.0.0.1", socks_port), timeout=timeout)
    s.sendall(b"\x05\x01\x00")
    assert s.recv(2) == b"\x05\x00"
    s.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) + host.encode() + struct.pack(">H", port))
    rep = s.recv(10)
    if len(rep) < 2 or rep[1] != 0:
        s.close()
        raise ConnectionRefusedError(f"socks reply {rep!r}")
    with s:
        s.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n".encode())
        return _read_response(s)


def plain_http(port: int, path: str, timeout: float = TIMEOUT) -> tuple[int, bytes]:
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as s:
        s.sendall(f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n".encode())
        return _read_response(s)


def dns_rcode(port: int, name: str = "example.com") -> int:
    q = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    q += b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00" + struct.pack(">HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(5)
    s.sendto(q, ("127.0.0.1", port))
    return s.recv(512)[3] & 0x0F


def _read_response(s) -> tuple[int, bytes]:
    data = b""
    try:
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
    except (TimeoutError, ssl.SSLError, ConnectionResetError):
        pass
    head, _, body = data.partition(b"\r\n\r\n")
    try:
        status = int(head.split(b" ", 2)[1])
    except (IndexError, ValueError):
        status = 0
    return status, body


class Api:
    """JSON client with optional bearer token / session cookie; never uses environment proxies."""

    def __init__(self, base: str, token: str | None = None, csrf_header: str | None = None):
        self.base = base.rstrip("/")
        self.token = token
        self.csrf_header = csrf_header
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(self.jar), _NoRedirect()
        )

    def call(self, method: str, path: str, body=None, headers: dict | None = None, form: dict | None = None):
        h = {"Content-Type": "application/json"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        if self.csrf_header and method not in ("GET", "HEAD"):
            h[self.csrf_header] = "1"
        h.update(headers or {})
        data = None
        if form is not None:
            data = urllib.parse.urlencode(form).encode()
            h["Content-Type"] = "application/x-www-form-urlencoded"
        elif body is not None:
            data = json.dumps(body).encode()
        req = urllib.request.Request(self.base + path, data=data, method=method, headers=h)
        try:
            with self.opener.open(req, timeout=TIMEOUT) as r:
                raw = r.read()
                return r.status, _maybe_json(raw), dict(r.headers)
        except urllib.error.HTTPError as e:
            return e.code, _maybe_json(e.read()), dict(e.headers)


def _maybe_json(raw: bytes):
    try:
        return json.loads(raw)
    except ValueError:
        return raw


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


import urllib.parse  # noqa: E402  (used in Api.call)


def proxy_request(
    proxy_port: int,
    host_port: str,
    path: str,
    method: str = "GET",
    headers: dict | None = None,
    timeout: float = TIMEOUT,
) -> tuple[int, bytes]:
    """Plain-HTTP proxy request with full control over method, path (sent verbatim) and headers."""
    hdrs = {"Host": host_port, "Connection": "close", "Content-Length": "0", **(headers or {})}
    head = f"{method} http://{host_port}{path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in hdrs.items())
    with socket.create_connection(("127.0.0.1", proxy_port), timeout=timeout) as s:
        s.sendall(head.encode() + b"\r\n")
        return _read_response(s)


def tls_request(
    proxy_port: int,
    target: str,
    sni: str,
    cafile: str,
    method: str = "GET",
    path: str = "/",
    headers: dict | None = None,
    timeout: float = TIMEOUT,
) -> tuple[int, bytes]:
    """CONNECT + TLS + one request with arbitrary method/headers. Returns (0, b"") if the gateway cut it."""
    raw, status_line = connect_tunnel(proxy_port, target, timeout)
    if " 200" not in status_line:
        raw.close()
        return -1, status_line.encode()
    ctx = ssl.create_default_context(cafile=cafile)
    try:
        with ctx.wrap_socket(raw, server_hostname=sni) as tls:
            hdrs = {"Host": sni, "Connection": "close", "Content-Length": "0", **(headers or {})}
            tls.sendall(
                (f"{method} {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in hdrs.items()) + "\r\n").encode()
            )
            return _read_response(tls)
    except (OSError, ssl.SSLError):
        return 0, b""
