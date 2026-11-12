"""Event log (SQLite) and secrets store. Both live in the gateway's /data volume only."""

from __future__ import annotations

import base64
import json
import os
import re
import sqlite3
import time
from pathlib import Path


def atomic_write(path: Path, text: str, mode: int = 0o644) -> None:
    """Write via a temp file, fsync, then rename (and fsync the directory): after a power loss the file is
    either the old or the new version, never empty."""
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    tmp.replace(path)
    dfd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


class EventLog:
    def __init__(self, path: Path, keep_days: int = 30, max_events: int = 500_000) -> None:
        self.db = sqlite3.connect(str(path), isolation_level=None, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute(
            """CREATE TABLE IF NOT EXISTS events(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL NOT NULL, kind TEXT NOT NULL, proto TEXT, client TEXT,
                host TEXT, port INTEGER, ips TEXT, action TEXT, reason TEXT, extra TEXT)"""
        )
        self.db.execute("CREATE INDEX IF NOT EXISTS events_ts ON events(ts)")
        self.db.execute("CREATE INDEX IF NOT EXISTS events_host ON events(host, port)")  # log search (#80)
        # per-rule hit counters (flushed from memory by housekeeping) and approvals, for suggestions (#70)
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS rule_hits(rule_id TEXT PRIMARY KEY, hits INTEGER NOT NULL, last REAL, since REAL NOT NULL)"
        )
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS approvals(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL,"
            " host TEXT NOT NULL, port INTEGER NOT NULL, scope TEXT NOT NULL, by TEXT)"
        )
        self.db.execute("CREATE TABLE IF NOT EXISTS dismissed(key TEXT PRIMARY KEY, ts REAL NOT NULL)")
        self.keep_days = keep_days
        self.max_events = max_events
        self._last_prune = 0.0

    def add(self, ev: dict) -> dict:
        ev.setdefault("ts", time.time())
        cur = self.db.execute(
            "INSERT INTO events(ts,kind,proto,client,host,port,ips,action,reason,extra) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (
                ev["ts"],
                ev.get("kind", "conn"),
                ev.get("proto"),
                ev.get("client"),
                ev.get("host"),
                ev.get("port"),
                json.dumps(ev.get("ips") or []),
                ev.get("action"),
                ev.get("reason"),
                json.dumps(ev.get("extra")) if ev.get("extra") else None,
            ),
        )
        ev["id"] = cur.lastrowid
        if ev["ts"] - self._last_prune > 3600:
            self._last_prune = ev["ts"]
            self.db.execute("DELETE FROM events WHERE ts < ?", (ev["ts"] - self.keep_days * 86400,))
        return ev

    # ---------------------------------------------------------------- rule hits (#70)
    def flush_hits(self, hits: dict[str, list], rule_ids: list[str], now: float | None = None) -> None:
        """Add in-memory counts ({rule id: [count, last ts]}) and start the clock for rules seen the first time.
        Counters of rules that are gone and were not used for log_keep_days are forgotten."""
        now = now or time.time()
        self.db.executemany(
            "INSERT OR IGNORE INTO rule_hits(rule_id, hits, last, since) VALUES(?, 0, NULL, ?)",
            [(rid, now) for rid in rule_ids],
        )
        self.db.executemany(
            "INSERT INTO rule_hits(rule_id, hits, last, since) VALUES(?, ?, ?, ?) ON CONFLICT(rule_id) DO UPDATE"
            " SET hits = hits + excluded.hits, last = MAX(COALESCE(last, 0), excluded.last)",
            [(rid, n, last, now) for rid, (n, last) in hits.items()],
        )
        old = now - self.keep_days * 86400
        ids = list(rule_ids)
        marks = ",".join("?" * len(ids))
        self.db.execute(
            f"DELETE FROM rule_hits WHERE rule_id NOT IN ({marks}) AND COALESCE(last, since) < ?",  # noqa: S608
            [*ids, old],
        )
        self.db.execute("DELETE FROM approvals WHERE ts < ?", (old,))
        self.db.execute("DELETE FROM dismissed WHERE ts < ?", (old,))

    def hit_stats(self) -> dict[str, dict]:
        rows = self.db.execute("SELECT rule_id, hits, last, since FROM rule_hits")
        return {r[0]: {"hits": r[1], "last": r[2], "since": r[3]} for r in rows}

    def add_approval(self, host: str, port: int, scope: str, by: str) -> None:
        self.db.execute(
            "INSERT INTO approvals(ts, host, port, scope, by) VALUES(?,?,?,?,?)", (time.time(), host, port, scope, by)
        )

    def approvals_since(self, ts: float) -> list[tuple[str, int, str, float]]:
        """(host, port, scope, ts) of every approval since ts."""
        return list(self.db.execute("SELECT host, port, scope, ts FROM approvals WHERE ts >= ? ORDER BY ts", (ts,)))

    def dismiss(self, key: str) -> None:
        self.db.execute("INSERT OR REPLACE INTO dismissed(key, ts) VALUES(?, ?)", (key[:300], time.time()))

    def dismissed(self) -> set[str]:
        return {r[0] for r in self.db.execute("SELECT key FROM dismissed")}

    def enforce_cap(self) -> None:
        """Hard row cap on top of the age-based retention (disk-fill protection)."""
        row = self.db.execute("SELECT MAX(id) FROM events").fetchone()
        if row and row[0] and row[0] > self.max_events:
            self.db.execute("DELETE FROM events WHERE id <= ?", (row[0] - self.max_events,))

    def recent(self, limit: int = 200, before_id: int | None = None, q: str | None = None, **filters) -> list[dict]:
        """Newest first. Filters (#80): host (exact, or `*.domain` for the domain and its subdomains), port,
        kind and action (one value or a list), since/until (unix time, until exclusive)."""
        sql = "SELECT id,ts,kind,proto,client,host,port,ips,action,reason,extra FROM events"
        cond, args = _filters(**filters)
        if before_id:
            cond.append("id < ?")
            args.append(before_id)
        if q:
            cond.append("(host LIKE ? OR reason LIKE ? OR action LIKE ?)")
            args += [f"%{q}%"] * 3
        if cond:
            sql += " WHERE " + " AND ".join(cond)
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(min(int(limit), 2000))
        out = []
        for row in self.db.execute(sql, args):
            out.append(
                {
                    "id": row[0],
                    "ts": row[1],
                    "kind": row[2],
                    "proto": row[3],
                    "client": row[4],
                    "host": row[5],
                    "port": row[6],
                    "ips": json.loads(row[7] or "[]"),
                    "action": row[8],
                    "reason": row[9],
                    "extra": json.loads(row[10]) if row[10] else None,
                }
            )
        return out

    def destinations(self, limit: int = 200, only_new: bool = False, q: str | None = None, **filters) -> list[dict]:
        """Connection destinations (host:port) in the time range with counts, most recent first. `first_seen` is
        the first event for it in the whole log; `new` = first seen inside the range."""
        cond, args = _filters(**filters)
        cond += ["kind IN ('conn', 'ask')", "host IS NOT NULL"]
        if q:
            cond.append("host LIKE ?")
            args.append(f"%{q}%")
        sql = (  # fixed SQL: the conditions come from _filters, every value is bound
            "SELECT host, port, COUNT(*), MIN(ts), MAX(ts), SUM(action = 'allow'), SUM(action = 'deny'),"  # noqa: S608
            " SUM(kind = 'ask'), (SELECT MIN(e2.ts) FROM events e2 WHERE e2.host = events.host"
            " AND e2.port IS events.port AND e2.kind IN ('conn', 'ask')) AS first_seen"
            f" FROM events WHERE {' AND '.join(cond)} GROUP BY host, port"
        )
        since = filters.get("since")
        if only_new and since:
            sql += " HAVING first_seen >= ?"
            args.append(since)
        sql += " ORDER BY MAX(ts) DESC LIMIT ?"
        args.append(max(1, min(int(limit), 2000)))
        out = []
        for host, port, n, first, last, allowed, denied, asked, first_seen in self.db.execute(sql, args):
            out.append(
                {
                    "host": host,
                    "port": port,
                    "events": n,
                    "first": first,
                    "last": last,
                    "allowed": allowed,
                    "denied": denied,
                    "asked": asked,
                    "first_seen": first_seen,
                    "new": bool(since) and first_seen >= since,
                }
            )
        return out


EVENT_KINDS = ("conn", "ask", "dns", "admin", "grant")


def _filters(host=None, port=None, kind=None, action=None, since=None, until=None) -> tuple[list[str], list]:
    """WHERE conditions for the log search. Values are bound, never formatted into the SQL."""
    cond, args = [], []
    if host:
        host = host.lower().rstrip(".")
        if host.startswith("*."):
            base = host[2:]
            cond.append("(host = ? OR host LIKE ? ESCAPE '\\')")
            args += [base, "%." + base.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")]
        else:
            cond.append("host = ?")
            args.append(host)
    if port is not None:
        cond.append("port = ?")
        args.append(int(port))
    for col, val in (("kind", kind), ("action", action)):
        vals = [val] if isinstance(val, str) else list(val or [])
        if vals:
            cond.append(f"{col} IN ({','.join('?' * len(vals))})")
            args += vals
    if since is not None:
        cond.append("ts >= ?")
        args.append(float(since))
    if until is not None:
        cond.append("ts < ?")
        args.append(float(until))
    return cond, args


class Secrets:
    """Write-only from the API's perspective: values are never returned, only presence."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._data: dict[str, str] = {}
        if path.exists():
            os.chmod(path, 0o600)
        if path.exists():
            self._data = json.loads(path.read_text() or "{}")

    def names(self) -> list[str]:
        return sorted(self._data)

    def get(self, name: str) -> str | None:
        return self._data.get(name)

    def set(self, name: str, value: str | None) -> None:
        if not re.fullmatch(r"[a-z0-9_]{1,64}", name):
            raise ValueError("secret name must match [a-z0-9_]{1,64}")
        if value is not None and (len(value) > 8192 or any(ord(c) < 0x20 or ord(c) == 0x7F for c in value)):
            # values end up in HTTP headers: control characters would allow header injection
            raise ValueError("secret value must be <= 8192 printable characters (no CR/LF/control chars)")
        if value:
            self._data[name] = value
        else:
            self._data.pop(name, None)
        atomic_write(self.path, json.dumps(self._data), 0o600)


def render(template: str, secrets: Secrets) -> str | None:
    """Render '${name}' (secret value) and '${b64:...}' (base64 of the rendered inner text,
    which may itself contain ${name}). Returns None if any referenced secret is missing."""
    missing = False

    def parse(s: str, i: int, stop_at_brace: bool) -> tuple[str, int]:
        nonlocal missing
        out = []
        while i < len(s):
            if s.startswith("${b64:", i):
                inner, i = parse(s, i + 6, True)
                out.append(base64.b64encode(inner.encode()).decode())
            elif s.startswith("${", i):
                end = s.index("}", i)
                name = s[i + 2 : end]
                v = secrets.get(name)
                if v is None:
                    missing = True
                out.append(v or "")
                i = end + 1
            elif stop_at_brace and s[i] == "}":
                return "".join(out), i + 1
            else:
                out.append(s[i])
                i += 1
        if stop_at_brace:
            raise ValueError("unterminated ${b64:...}")
        return "".join(out), i

    text, _ = parse(template, 0, False)
    return None if missing else text
