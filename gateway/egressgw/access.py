"""One read-only view of what the agent may do where (#121).

Rules, read-only hosts, credential injection, repository limits and grants are defined in different places.
`overview` lists each destination once with everything that applies to it, so the UI can answer "what can the
agent reach, and how do I change it?" from one table. It reports the configuration; it decides nothing.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from egressgw.policy import host_matches, is_ip, port_matches

if TYPE_CHECKING:
    from egressgw.core import Gateway

LAST_USED_DAYS = 30


def _port_key(port) -> str:
    if port in (None, "*", "any"):
        return "*"
    if isinstance(port, (list, tuple)):
        return ",".join(str(p) for p in port)
    return str(port)


def _row(host: str, port, access: str | None, rule: dict | None = None) -> dict:
    return {
        "host": host,
        "port": _port_key(port),
        "access": access,  # allow | ask | deny | request (only through a grant) | None (depends on the name)
        "rule": rule,
        "read_only": None,
        "credentials": False,
        "repos": None,
        "grants": [],
        "last_used": None,
    }


def overview(gw: Gateway) -> dict:
    now = time.time()
    policy = gw.policy
    rows: list[dict] = []

    # 1) the rules, in their order (first match wins)
    for position, r in enumerate(policy.rules, 1):
        if r.expired(now):
            continue
        info = {"id": r.id, "position": position, "note": r.note, "expires": r.expires, "source": r.source}
        rows.append(_row(r.host or r.cidr, r.port, r.action, info))

    def rows_for(host: str, port: int | None = None) -> list[dict]:
        return [
            row
            for row in rows
            if row["host"] == host and (port is None or row["port"] == "*" or port_matches(_spec(row["port"]), port))
        ]

    def effective(host: str, port: int) -> dict:
        """A row of its own for a host that no rule names exactly: what the rules decide for it now."""
        if "*" in host or is_ip(host):
            row = _row(host, port, None)
        else:
            dec = policy.evaluate_name(host, port)
            rule = next((x["rule"] for x in rows if x["rule"] and x["rule"]["id"] == dec.rule_id), None)
            row = _row(host, port, dec.action, rule)
        rows.append(row)
        return row

    # 2) hosts with per-request limits: read-only, credentials, repository scope
    for ro in gw.readonly:
        for row in rows_for(ro.host) or [effective(ro.host, 443)]:
            row["read_only"] = {"post_is_write": ro.post_is_write, "read_posts": list(ro.read_posts)}
    for host in sorted(gw.inject_hosts):
        for row in rows_for(host) or [effective(host, 443)]:
            row["credentials"] = True
    if gw.github.patterns:
        repos = [f"{owner}/{repo}" for owner, repo in gw.github.patterns]
        for host in sorted(gw.github.hosts):
            for row in rows_for(host) or [effective(host, 443)]:
                row["repos"] = repos

    # 3) grants: access on request. A target the rules already allow by name keeps its row; otherwise it gets one.
    active = {a.name: a for a in gw.grants.active.values() if a.expires > now}
    for g in gw.grants.defs.values():
        for t in g.targets:
            entry = {
                "name": g.name,
                "levels": g.levels,
                "lan": t.lan,
                "scheme": t.scheme,
                "paths": None if t.scheme == "tcp" or t.paths == ["/*"] else t.paths,
                "credentials": any(i["host"] == t.host for i in g.inject),
                "active": {"level": active[g.name].level, "expires": active[g.name].expires}
                if g.name in active
                else None,
            }
            found = rows_for(t.host, t.port)
            if not found:
                found = [_row(t.host, t.port, "request")]
                rows.extend(found)
            for row in found:
                row["grants"].append(entry)

    # 4) when it was last used (exact host and port, from the log)
    for d in gw.events.destinations(2000, since=now - LAST_USED_DAYS * 86400):
        for row in rows:
            if d["allowed"] and _covers(row, d["host"], d["port"]):
                row["last_used"] = max(row["last_used"] or 0, d["last"])
    return {"default": policy.default, "rows": rows, "last_used_days": LAST_USED_DAYS}


def _spec(key: str):
    """The port spec a row was built from, in the form `port_matches` takes."""
    if key == "*":
        return "*"
    return [p if "-" in p else int(p) for p in key.split(",")]


def _covers(row: dict, host: str, port) -> bool:
    if port is not None and row["port"] != "*" and not port_matches(_spec(row["port"]), int(port)):
        return False
    if "/" in row["host"]:  # a CIDR rule: only for the same literal network string, never for names
        return False
    return host_matches(row["host"], host)
