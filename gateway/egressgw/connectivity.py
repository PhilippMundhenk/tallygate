"""Does the gateway itself have a connection? (#218)

On 2026-11-16 the host's network was down for hours. Every upstream lookup failed with `dns failure`, the agent
saw "proxy refused the connection", and nothing said that the cause was outside tallygate. This module keeps the
gateway's own results (upstream lookups and connects that are not a policy decision) and says when they show an
outage. It reads nothing but those results.

Detection is two steps, so that an agent cannot fake an outage by asking for names that do not resolve:

1. `suspect()`: at least `min_failures` failures over at least `min_names` different names within `window`
   seconds, no success since the first of them, and the oldest of them is at least `min_age` seconds old.
2. The gateway then runs a control probe (a fixed, operator-configured name, resolved by the same resolver and
   connected to), at most once per `probe_interval`. Only when the probe fails too does the outage start.

A name that does not exist (NXDOMAIN / "no data", errno -2 / -5) is an answer, not a failure. The outage ends at
the first success: an answered lookup, an established upstream connection or a successful probe. The state shown
holds numbers, times and the KINDS of errors (dns / connect / timeout), never a host name or an error text.
"""

from __future__ import annotations

import json
import logging
import socket
import time
from collections import deque
from pathlib import Path

from egressgw.store import atomic_write

log = logging.getLogger("egressgw")

# Reason prefix of a failure that happened while the outage was on: a filter for denies can tell it apart.
PREFIX = "no connection: "
KINDS = ("dns", "connect", "timeout")
# Constants, not behaviour settings (ADR-0015): they are about how sure the gateway wants to be, not about what
# the operator wants it to do. The gateway.yaml keys `connectivity_*` override them (tests, odd networks).
MIN_FAILURES = 5
MIN_NAMES = 2
WINDOW = 600.0  # failures older than this are forgotten
MIN_AGE = 120.0  # the oldest unanswered failure must be this old
PROBE_INTERVAL = 30.0  # at most one probe per this many seconds, whatever the agent does
PROBE_HOSTS = ["api.anthropic.com"]
MAX_RUN = 500  # entries kept (bounds memory under a flood; the count of an outage keeps growing)

_ANSWERS = {socket.EAI_NONAME, getattr(socket, "EAI_NODATA", -5)}


def classify(exc: BaseException) -> str | None:
    """The kind of a failed lookup, or None when the resolver answered (the name just does not exist)."""
    if isinstance(exc, socket.gaierror) and exc.errno in _ANSWERS:
        return None
    return "timeout" if isinstance(exc, TimeoutError) else "dns"


def classify_connect(error: str) -> str:
    return "timeout" if "timed out" in error.lower() or "timeout" in error.lower() else "connect"


class Connectivity:
    def __init__(
        self,
        path: Path | None = None,
        *,
        min_failures: int = MIN_FAILURES,
        min_names: int = MIN_NAMES,
        window: float = WINDOW,
        min_age: float = MIN_AGE,
        probe_interval: float = PROBE_INTERVAL,
    ) -> None:
        self.path = path
        self.min_failures, self.min_names, self.window = min_failures, min_names, window
        self.min_age, self.probe_interval = min_age, probe_interval
        self.down = False
        self.since: float | None = None
        self.last_failure: float | None = None
        self.failures = 0
        self.kinds: set[str] = set()
        self.last_ok: float | None = None
        self.last_probe = 0.0
        self._run: deque[tuple[float, str, str]] = deque(maxlen=MAX_RUN)  # (time, name, kind)
        self._load()

    # ------------------------------------------------------------------ results
    def failure(self, name: str, kind: str | None, now: float) -> None:
        """A lookup or connect failed for a reason that is not a policy decision (`kind` None: it did not)."""
        if kind is None:
            return
        self._run.append((now, name.lower(), kind))
        if self.down:
            self.failures += 1
            self.last_failure = now
            if kind not in self.kinds:
                self.kinds.add(kind)
                self._save()

    def success(self, now: float) -> bool:
        """Something worked: forget the failures. True when this ends an outage (the caller records it)."""
        self.last_ok = now
        self._run.clear()
        return self.down

    def suspect(self, now: float) -> bool:
        """The pattern that is worth a probe (step 1)."""
        while self._run and now - self._run[0][0] > self.window:
            self._run.popleft()
        if len(self._run) < self.min_failures or now - self._run[0][0] < self.min_age:
            return False
        return len({n for _, n, _ in self._run}) >= self.min_names

    def probe_due(self, now: float) -> bool:
        return now - self.last_probe >= self.probe_interval

    # ------------------------------------------------------------------ transitions
    def begin(self, now: float) -> None:
        self.down, self.since = True, self._run[0][0] if self._run else now
        self.failures = len(self._run)
        self.last_failure = self._run[-1][0] if self._run else now
        self.kinds = {k for _, _, k in self._run} or {"dns"}
        self._save()

    def end(self, now: float) -> tuple[float, int]:
        """The outage is over: (its start, failures)."""
        since, count = self.since or now, self.failures
        self.down, self.since, self.failures, self.kinds, self.last_failure = False, None, 0, set(), None
        self._save()
        return since, count

    # ------------------------------------------------------------------ state
    def status(self) -> dict:
        if not self.down:
            return {"down": False, "since": None, "last_failure": None, "failures": 0, "kinds": []}
        return {
            "down": True,
            "since": self.since,
            "last_failure": self.last_failure,
            "failures": self.failures,
            "kinds": sorted(self.kinds),
        }

    def _save(self) -> None:
        """An outage survives a restart of the gateway, so that it still ends with its duration."""
        if self.path is None:
            return
        try:
            if self.down:
                atomic_write(self.path, json.dumps({**self.status(), "saved": time.time()}))
            else:
                self.path.unlink(missing_ok=True)
        except OSError:
            log.warning("connectivity: state not stored", exc_info=True)

    def _load(self) -> None:
        if self.path is None or not self.path.exists():
            return
        try:
            d = json.loads(self.path.read_text())
            since, last = float(d["since"]), float(d["last_failure"])
            self.failures = max(0, int(d.get("failures", 0)))
            self.kinds = {k for k in d.get("kinds", []) if k in KINDS} or {"dns"}
        except (OSError, ValueError, KeyError, TypeError):
            log.warning("connectivity: ignoring an unreadable state file", exc_info=True)
            return
        self.down, self.since, self.last_failure = True, since, last
