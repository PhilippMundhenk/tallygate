"""Second security review, F1: an IP address written like a name is not a name.

`192.168.1.1.` (a trailing dot) is not an IP literal for the proxy, so it used to be asked about as a name -
and the approval became an address rule above the blocked ranges. Through the real proxy: such a target is
refused as an invalid host name, nobody is asked, and no rule is added."""

from __future__ import annotations

import time

from .helpers import connect_tunnel, http_via_proxy


def test_an_ip_with_a_trailing_dot_is_refused_and_never_asked_about(make_gateway):
    gw = make_gateway({}, {"default": "ask", "ask_timeout": 5, "seeded": [], "rules": []})
    proxy, api = gw["ports"]["http"], gw["api"]
    before = api.call("GET", "/policy")[1]
    for target in ("192.168.1.1.:443", "169.254.169.254.:80", "127.1:443", "2130706433:443", "0x7f.1:443"):
        t0 = time.time()
        sock, line = connect_tunnel(proxy, target, 8)
        sock.close()
        assert " 200" not in line and time.time() - t0 < 3, target  # refused at once: not held for an answer
        assert api.call("GET", "/pending")[1] == [], target
    assert http_via_proxy(proxy, "http://169.254.169.254./latest/meta-data/")[0] == 502  # plain HTTP: the same
    assert api.call("GET", "/pending")[1] == []
    events = api.call("GET", "/events?limit=50")[1]
    for host, port in (("192.168.1.1.", 443), ("169.254.169.254.", 80), ("127.1", 443), ("2130706433", 443)):
        ev = next(e for e in events if e["host"] == host and e["port"] == port)
        assert (ev["action"], ev["reason"], ev["ips"]) == ("deny", "invalid hostname", []), ev  # never resolved
    assert not any(e["action"] in ("ask", "allow") for e in events if e["kind"] in ("conn", "ask"))
    # no rule was added, and the plain literals are refused by their blocks as before
    assert api.call("GET", "/policy")[1] == before
    for target, block in (("192.168.1.1:443", "block-192.168.0.0_16"), ("169.254.169.254:80", "block-169.254.0.0_16")):
        sock, line = connect_tunnel(proxy, target, 8)
        sock.close()
        assert " 200" not in line
        host, port = target.rsplit(":", 1)
        ev = next(e for e in api.call("GET", "/events?limit=5")[1] if e["host"] == host and e["port"] == int(port))
        assert ev["action"] == "deny" and ev["reason"] == f"rule {block} (built-in block)"
    assert api.call("GET", "/pending")[1] == []
