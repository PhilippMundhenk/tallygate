"""Rule usage (#70): hit counters per rule, unused ("stale") rules, and suggestions for permanent rules from
repeated temporary approvals. Pure functions over the policy and what the event log stored."""

from __future__ import annotations

from egressgw.policy import Policy, is_ip, registrable_domain

TEMPORARY_SCOPES = ("once", "hour")


def rule_usage(
    policy: Policy, stored: dict[str, dict], unflushed: dict[str, list], now: float, stale_days: int
) -> list:
    """Every rule with hits, last match and whether it is stale: permanent, known for at least `stale_days`
    and not matched in that time. Rules with a time limit are never stale (they end by themselves)."""
    out = []
    limit = now - stale_days * 86400
    for pos, r in enumerate(policy.rules, 1):
        s = stored.get(r.id) or {"hits": 0, "last": None, "since": now}
        n, last = unflushed.get(r.id, (0, None))
        hits, last = s["hits"] + n, max(x for x in (s["last"], last, 0) if x is not None) or None
        stale = r.expires is None and s["since"] <= limit and (last is None or last < limit)
        out.append({**r.to_dict(), "pos": pos, "hits": hits, "last": last, "since": s["since"], "stale": stale})
    return out


def _permanently_allowed(policy: Policy, host: str, port: int) -> bool:
    d = policy.evaluate_name(host, port)
    rule = next((r for r in policy.rules if r.id == d.rule_id), None)
    return d.action == "allow" and rule is not None and rule.expires is None


def suggestions(
    approvals: list[tuple[str, int, str, float]], policy: Policy, dismissed: set[str], min_count: int
) -> list[dict]:
    """Destinations approved temporarily (2 min / 1 h) at least `min_count` times, and not yet allowed by a
    permanent rule. Several hosts of one registrable domain on one port become one `*.domain` suggestion."""
    per_host: dict[tuple[str, int], dict] = {}
    for host, port, scope, ts in approvals:
        if scope not in TEMPORARY_SCOPES:
            continue
        e = per_host.setdefault((host, port), {"count": 0, "last": 0.0})
        e["count"] += 1
        e["last"] = max(e["last"], ts)
    groups: dict[tuple[str, int], list[str]] = {}
    for host, port in per_host:
        if is_ip(host) or _permanently_allowed(policy, host, port):
            continue
        groups.setdefault((registrable_domain(host) or host, port), []).append(host)
    out = []
    for (domain, port), hosts in groups.items():
        count = sum(per_host[(h, port)]["count"] for h in hosts)
        last = max(per_host[(h, port)]["last"] for h in hosts)
        if count < min_count:
            continue
        pattern = hosts[0] if len(hosts) == 1 else "*." + domain
        key = f"{pattern}:{port}"
        if key in dismissed:
            continue
        out.append(
            {
                "key": key,
                "rule": {"action": "allow", "host": pattern, "port": port},
                "count": count,
                "hosts": sorted(hosts),
                "last": last,
            }
        )
    return sorted(out, key=lambda s: (-s["count"], s["key"]))
