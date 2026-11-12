"""Login flood protection (#20): body size limit, bounded queue on the password lock, failure limit
that holds for concurrent requests. Each test starts its own control so the shared one stays usable."""

from __future__ import annotations

import http.client
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

from .conftest import CONTROL_PASSWORD
from .helpers import Api


def login(base: str, guess: str = "wrong") -> tuple[int, float]:
    t0 = time.time()
    status, _, _ = Api(base).call("POST", "/login", form={"password": guess})
    return status, time.time() - t0


def parallel(base: str, n: int, guess: str = "wrong") -> list[tuple[int, float]]:
    with ThreadPoolExecutor(n) as pool:
        return list(pool.map(lambda _: login(base, guess), range(n)))


def test_oversized_body_is_refused_before_reading(control_with):
    base = control_with()
    status, _, _ = Api(base).call("POST", "/login", form={"password": "x" * 5000})
    assert status == 413
    # chunked bodies have no length to check: refused too
    u = urllib.parse.urlsplit(base)
    conn = http.client.HTTPConnection(u.hostname, u.port, timeout=10)
    conn.putrequest("POST", "/login")
    conn.putheader("Content-Type", "application/x-www-form-urlencoded")
    conn.putheader("Transfer-Encoding", "chunked")
    conn.endheaders()
    conn.send(b"8\r\npassword\r\n0\r\n\r\n")
    assert conn.getresponse().status == 413
    conn.close()
    # neither counted as a failed attempt
    assert login(base, CONTROL_PASSWORD)[0] == 302


def test_flood_is_answered_with_429_instead_of_queueing(control_with):
    base = control_with()
    results = parallel(base, 20)
    statuses = [s for s, _ in results]
    assert set(statuses) <= {302, 429}
    assert statuses.count(429) >= 14  # at most a handful may wait for the lock
    assert all(dt < 3 for s, dt in results if s == 429)  # refused at once, not after waiting


def test_concurrent_failures_cannot_exceed_the_limit(control_with):
    """Requests that pass the first check together are re-checked inside the lock (per-IP lockout on)."""
    base = control_with(TRUST_FORWARDED_FOR="1", TRUSTED_PROXIES="127.0.0.1/32")
    statuses = []
    for _ in range(3):  # waves small enough to all wait for the lock: 4 + 4 + 4 attempts
        statuses += [s for s, _ in parallel(base, 4)]
    assert statuses.count(302) == 10 and statuses.count(429) == 2
    assert login(base, CONTROL_PASSWORD)[0] == 429  # locked out for this address
