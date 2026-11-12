"""#58: read-only hosts can refuse POST as well (container registries, Hugging Face), with exceptions for
POSTs that only read, and take `*.domain` patterns."""

from __future__ import annotations

import json

from .helpers import tls_request


def test_post_is_refused_where_it_writes_and_allowed_where_it_reads(make_gateway, upstream):
    port = upstream["https"]
    gw = make_gateway(
        {
            "hard_deny_floor": ["203.0.113.7/32"],
            "readonly": [{"host": "*.ro.test", "post_is_write": True, "read_posts": ["/api/*/paths-info/*"]}],
        },
        {"default": "deny", "rules": [{"id": "ro", "action": "allow", "host": "ro.test", "port": port}]},
        GW_TEST_FLOOR_REPLACE="1",
        GW_TEST_STATIC_HOSTS="ro.test=127.0.0.1",
    )
    target, proxy = f"ro.test:{port}", gw["ports"]["http"]
    for method, path, ok in (
        ("GET", "/model/resolve/main/x.bin", True),
        ("POST", "/api/models/m/paths-info/main", True),
        ("POST", "/api/models/m/commit/main", False),
        ("PUT", "/x", False),
    ):
        status, body = tls_request(proxy, target, "ro.test", gw["ca"], method=method, path=path)
        if ok:
            assert status == 200 and json.loads(body)["method"] == method
        else:
            assert status == 403 and b"read-only host" in body
