"""Policy history: every saved policy is kept as a version (when, by whom, what changed), so the UI can
show a diff between any two versions and restore one. Also export/import of the policy and the UI grants
as one YAML document.

A version holds what `policy.yaml` holds: mode, approval timeout, the hard-deny *extras* and the rules.
Never the hard-deny floor (static config) and never secrets (they live in secrets.json, write-only).
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from pathlib import Path

import yaml

log = logging.getLogger("egressgw")

EXPORT_FORMAT = 1
EXPORT_KEYS = {"tallygate_export", "exported", "policy", "grants"}


class PolicyHistory:
    def __init__(self, path: Path, keep: int = 500) -> None:
        self.db = sqlite3.connect(str(path), isolation_level=None, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute(
            """CREATE TABLE IF NOT EXISTS versions(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL NOT NULL, by TEXT, what TEXT, policy TEXT NOT NULL)"""
        )
        self.keep = max(10, int(keep))
        row = self.db.execute("SELECT policy FROM versions ORDER BY id DESC LIMIT 1").fetchone()
        self._last = row[0] if row else None

    @property
    def latest(self) -> str | None:
        """The latest version as JSON text, None if there is none."""
        return self._last

    def record(self, policy: dict, by: str, what: str) -> int | None:
        """Store `policy` as a new version unless it equals the latest one. Returns the version id."""
        text = json.dumps(policy, sort_keys=True)
        if text == self._last:
            return None
        cur = self.db.execute(
            "INSERT INTO versions(ts, by, what, policy) VALUES(?,?,?,?)", (time.time(), by[:64], what[:300], text)
        )
        self._last = text
        self.db.execute("DELETE FROM versions WHERE id <= ?", (cur.lastrowid - self.keep,))
        return cur.lastrowid

    def versions(self, limit: int = 100, before: int | None = None) -> list[dict]:
        sql, args = "SELECT id, ts, by, what, policy FROM versions", []
        if before:
            sql += " WHERE id < ?"
            args.append(before)
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(max(1, min(int(limit), 500)))
        out = []
        for vid, ts, by, what, text in self.db.execute(sql, args):
            p = json.loads(text)
            out.append(
                {
                    "id": vid,
                    "ts": ts,
                    "by": by,
                    "what": what,
                    "default": p.get("default"),
                    "rules": len(p.get("rules") or []),
                }
            )
        return out

    def get(self, vid: int) -> dict | None:
        row = self.db.execute("SELECT id, ts, by, what, policy FROM versions WHERE id = ?", (vid,)).fetchone()
        if not row:
            return None
        return {"id": row[0], "ts": row[1], "by": row[2], "what": row[3], "policy": json.loads(row[4])}


def diff(old: dict, new: dict) -> dict:
    """What changed from `old` to `new` (both policy dicts as in policy.yaml). Rules are compared by id."""
    out: dict = {}
    for k in ("default", "ask_timeout"):
        if old.get(k) != new.get(k):
            out[k] = [old.get(k), new.get(k)]
    oh, nh = old.get("hard_deny") or [], new.get("hard_deny") or []
    hd = {"added": [c for c in nh if c not in oh], "removed": [c for c in oh if c not in nh]}
    if hd["added"] or hd["removed"]:
        out["hard_deny"] = hd
    orules = {r["id"]: r for r in old.get("rules") or []}
    nrules = {r["id"]: r for r in new.get("rules") or []}
    rules = {
        "added": [r for i, r in nrules.items() if i not in orules],
        "removed": [r for i, r in orules.items() if i not in nrules],
        "changed": [
            {"id": i, "before": orules[i], "after": r} for i, r in nrules.items() if i in orules and orules[i] != r
        ],
    }
    if any(rules.values()):
        out["rules"] = rules
    common_old = [i for i in orules if i in nrules]
    common_new = [i for i in nrules if i in orules]
    if common_old != common_new:
        out["reordered"] = True
    out["identical"] = not out
    return out


def export_doc(policy: dict, ui_grants: dict[str, dict]) -> str:
    """One YAML document with the policy and the grants defined in the UI. Secrets are never part of it:
    UI grants cannot inject credentials, and secret values are not readable at all."""
    doc = {
        "tallygate_export": EXPORT_FORMAT,
        "exported": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "policy": policy,
        "grants": {
            n: {k: v for k, v in g.items() if k not in ("name", "source", "inject")} for n, g in ui_grants.items()
        },
    }
    return yaml.safe_dump(doc, sort_keys=False, allow_unicode=True)


def parse_import(text: str) -> tuple[dict, dict, list[str]]:
    """(policy dict, grants {name: definition}, warnings) from an export document. Only the structure is
    checked here; the caller validates the policy like PUT /policy and every grant like PUT /grants."""
    if not isinstance(text, str) or not text.strip():
        raise ValueError("expected the exported YAML text")
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise ValueError(f"not valid YAML: {e}") from None
    if not isinstance(doc, dict) or doc.get("tallygate_export") != EXPORT_FORMAT:
        raise ValueError("not a tallygate export (tallygate_export: 1 missing)")
    unknown = set(doc) - EXPORT_KEYS
    if unknown:
        raise ValueError(f"unknown keys in the export: {sorted(unknown)}")
    policy, grants = doc.get("policy"), doc.get("grants") or {}
    if not isinstance(policy, dict):
        raise ValueError("policy: expected a mapping")
    if not isinstance(grants, dict) or not all(isinstance(g, dict) for g in grants.values()):
        raise ValueError("grants: expected a mapping of name to definition")
    warnings = []
    if "hard_deny_floor" in policy:
        policy = {k: v for k, v in policy.items() if k != "hard_deny_floor"}
        warnings.append("hard_deny_floor ignored: the floor comes only from the gateway config file")
    return policy, {str(n): g for n, g in grants.items()}, warnings
