"""Learning mode (#69): for a limited time, destinations that no rule covers are allowed on a few ports and
recorded; afterwards the used destinations are grouped by registrable domain and proposed as rules.

Learning mode only replaces the *default* decision (no rule matched) for host names on `learning_ports`.
Deny and ask rules, the hard deny (also on the resolved addresses), the name-first decision (a name is only
resolved after it was allowed) and the SNI/Host binding all stay in force. It lives in memory only: it ends
when its time is up, when it is stopped, on the emergency stop, and when the gateway restarts.
"""

from __future__ import annotations

import json
import sqlite3
import time
import uuid

from egressgw.policy import Policy, is_ip, registrable_domain, valid_hostname
from egressgw.usage import permanently_allowed

REASON = "learning mode"


def parse_ports(value) -> list[int]:
    """`learning_ports` from the static config: whole port numbers. A broken entry stops the gateway."""
    ports = value if isinstance(value, list) else None
    if not ports or not all(isinstance(p, int) and not isinstance(p, bool) and 0 < p < 65536 for p in ports):
        raise ValueError("learning_ports: expected a list of port numbers, e.g. [80, 443]")
    return sorted(set(ports))


class Learning:
    def __init__(self, db: sqlite3.Connection, ports: list[int], max_minutes: int) -> None:
        self.db = db
        self.ports = ports
        self.max_minutes = max(1, int(max_minutes))
        self.active: dict | None = None
        db.execute(
            "CREATE TABLE IF NOT EXISTS learning(id TEXT PRIMARY KEY, started REAL NOT NULL, until REAL NOT NULL,"
            " ended REAL, by TEXT, ports TEXT NOT NULL, end_reason TEXT)"
        )
        # a session that was open when the gateway stopped ended then (at the latest when its time was up)
        db.execute(
            "UPDATE learning SET ended = MIN(until, ?), end_reason = 'gateway restart' WHERE ended IS NULL",
            (time.time(),),
        )

    def covers(self, port: int) -> bool:
        a = self.active
        return a is not None and port in a["ports"] and a["until"] > time.time()

    def current(self) -> dict | None:
        a = self.active
        return dict(a) if a is not None and a["until"] > time.time() else None

    def start(self, minutes, ports, by: str) -> dict:
        if isinstance(minutes, bool) or not isinstance(minutes, int) or not 1 <= minutes <= self.max_minutes:
            raise ValueError(f"minutes must be a whole number, 1..{self.max_minutes} (learning_max_minutes)")
        if not isinstance(ports, list) or not ports or not set(ports) <= set(self.ports):
            raise ValueError(f"ports must be a non-empty subset of {self.ports} (learning_ports)")
        if self.active:
            self.end(by, "replaced by a new session")
        now = time.time()
        self.active = {
            "id": uuid.uuid4().hex[:10],
            "started": now,
            "until": now + minutes * 60,
            "ports": sorted(set(ports)),
            "by": by[:64],
        }
        a = self.active
        self.db.execute(
            "INSERT INTO learning(id, started, until, by, ports) VALUES(?,?,?,?,?)",
            (a["id"], a["started"], a["until"], a["by"], json.dumps(a["ports"])),
        )
        return dict(a)

    def end(self, by: str, why: str) -> dict | None:
        a, self.active = self.active, None
        if a is None:
            return None
        ended = min(time.time(), a["until"])
        self.db.execute(
            "UPDATE learning SET ended = ?, end_reason = ? WHERE id = ?", (ended, f"{why} ({by})"[:200], a["id"])
        )
        return {**a, "ended": ended}

    def expired(self) -> bool:
        return self.active is not None and self.active["until"] <= time.time()

    def sessions(self, limit: int = 10) -> list[dict]:
        rows = self.db.execute(
            "SELECT id, started, until, ended, by, ports, end_reason FROM learning ORDER BY started DESC LIMIT ?",
            (limit,),
        )
        keys = ("id", "started", "until", "ended", "by", "ports", "end_reason")
        return [{**dict(zip(keys, r, strict=True)), "ports": json.loads(r[5])} for r in rows]

    def session(self, sid: str) -> dict | None:
        return next((s for s in self.sessions(1000) if s["id"] == sid), None)


def summary(db: sqlite3.Connection, s: dict, policy: Policy) -> list[dict]:
    """Destinations the agent connected to during session `s`, grouped by registrable domain and port, with a
    proposed rule for those that only learning mode allowed (not already allowed by a permanent rule)."""
    end = s["ended"] or time.time()
    rows = db.execute(
        "SELECT host, port, COUNT(*), SUM(reason LIKE ?), SUM(action = 'deny') FROM events"
        " WHERE kind = 'conn' AND ts >= ? AND ts <= ? AND host IS NOT NULL GROUP BY host, port",
        (REASON + "%", s["started"], end),  # "learning mode" or "learning mode (repeated 3x)"
    )
    groups: dict[tuple[str, int], dict] = {}
    for host, port, n, learned, denied in rows:
        if is_ip(host) or not valid_hostname(host):
            continue
        g = groups.setdefault(
            (registrable_domain(host) or host, port), {"hosts": [], "count": 0, "learned": 0, "denied": 0}
        )
        g["hosts"].append({"host": host, "count": n, "learned": learned, "denied": denied})
        g["count"] += n
        g["learned"] += learned
        g["denied"] += denied
    out = []
    for (domain, port), g in groups.items():
        hosts = sorted(h["host"] for h in g["hosts"] if h["learned"])
        proposal = None
        if hosts and not all(permanently_allowed(policy, h, port) for h in hosts):
            pattern = hosts[0] if len(hosts) == 1 else "*." + domain
            proposal = {"host": pattern, "port": port}
        out.append({"domain": domain, "port": port, **g, "proposal": proposal})
    return sorted(out, key=lambda x: (x["proposal"] is None, -x["count"], x["domain"]))


def check_rule(r) -> tuple[str, int]:
    """A rule to save from a learning session: an exact host name or `*.<registrable domain>`, and a port.
    Nothing broader (no `*`, no public suffix, no IPs)."""
    if not isinstance(r, dict) or set(r) - {"host", "port"}:
        raise ValueError("each rule is {host, port}")
    host, port = str(r.get("host", "")).lower().rstrip("."), r.get("port")
    if isinstance(port, bool) or not isinstance(port, int) or not 0 < port < 65536:
        raise ValueError(f"invalid port {port!r}")
    base = host[2:] if host.startswith("*.") else host
    if is_ip(base) or not valid_hostname(base) or (host.startswith("*.") and registrable_domain(base) != base):
        raise ValueError(f"{host!r}: use an exact host name or *.<registrable domain>")
    return host, port
