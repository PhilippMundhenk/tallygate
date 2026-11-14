"""#137: a raw-TCP / WebSocket tunnel opened under a grant is cut once the grant is revoked or expires."""

from __future__ import annotations

import time

from .test_grants import connect_tunnel, request_and_approve, revoke


def test_revoking_a_grant_cuts_an_open_raw_tunnel(gateway, upstream):
    request_and_approve(gateway, "raw", "write")
    raw, line = connect_tunnel(gateway["ports"]["http"], f"raw.test:{upstream['http2']}")
    assert " 200" in line
    try:
        # it works while the grant is active
        raw.sendall(b"GET /one HTTP/1.1\r\nHost: anything\r\n\r\n")
        raw.settimeout(5)
        assert b"200" in raw.recv(4096)
        revoke(gateway, "raw")
        time.sleep(0.3)
        # the next message after the revoke is cut: the tunnel closes (empty read / error)
        try:
            raw.sendall(b"GET /two HTTP/1.1\r\nHost: anything\r\n\r\n")
            raw.sendall(b"GET /three HTTP/1.1\r\nHost: anything\r\n\r\n")
            data = raw.recv(4096)
        except OSError:
            data = b""
        assert data == b"", data
    finally:
        raw.close()
