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

    def enforce_cap(self) -> None:
        """Hard row cap on top of the age-based retention (disk-fill protection)."""
        row = self.db.execute("SELECT MAX(id) FROM events").fetchone()
        if row and row[0] and row[0] > self.max_events:
            self.db.execute("DELETE FROM events WHERE id <= ?", (row[0] - self.max_events,))

    def recent(self, limit: int = 200, before_id: int | None = None, q: str | None = None) -> list[dict]:
        sql = "SELECT id,ts,kind,proto,client,host,port,ips,action,reason,extra FROM events"
        cond, args = [], []
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
