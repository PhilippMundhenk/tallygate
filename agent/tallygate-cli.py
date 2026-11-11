#!/usr/bin/env python3
"""tallygate - ask the egress gateway for a grant (a pre-defined, time-limited bundle of access).

  tallygate grants                                   list grants you can request (and which are active)
  tallygate request NAME [--write] [--ttl 1h] --reason "why"   ask for a grant and wait for the decision
  tallygate status REQUEST_ID                        show the state of a request

A human approves or denies each request (some read-only grants may be approved automatically).
You cannot define or widen grants. Exit codes: 0 granted, 1 denied/expired, 2 usage/connection error.
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

BASE = os.environ.get("TALLYGATE_URL", "http://172.31.10.2:8079").rstrip("/")
if not BASE.startswith(("http://", "https://")):
    sys.exit("tallygate: TALLYGATE_URL must be an http(s) URL")
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # talk to the gateway directly


def call(method: str, path: str, body: dict | None = None, timeout: float = 70):
    req = urllib.request.Request(  # noqa: S310 - scheme checked above
        BASE + path,
        method=method,
        data=None if body is None else json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
    )
    try:
        with OPENER.open(req, timeout=timeout) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except ValueError:
            return e.code, {"error": e.reason}
    except OSError as e:
        sys.exit(f"tallygate: cannot reach the gateway at {BASE}: {e}")


def cmd_grants(_args) -> int:
    status, data = call("GET", "/v1/grants")
    if status != 200:
        sys.exit(f"tallygate: {data.get('error', status)}")
    if not data["grants"]:
        print("No grants are defined. Ask the operator to define one.")
    for g in data["grants"]:
        active = g.get("active")
        state = (
            f"ACTIVE ({active['level']}, {max(0, int(active['expires'] - time.time())) // 60} min left)"
            if active
            else "inactive"
        )
        print(
            f"{g['name']}  [{state}]  levels: {', '.join(g['levels'])}  default {g['default_ttl']}, max {g['max_ttl']}"
        )
        if g["description"]:
            print(f"    {g['description']}")
        for t in g["targets"]:
            print(f"    - {t}")
    return 0


def _wait(rid: str, deadline: float) -> dict:
    while True:
        status, r = call("GET", f"/v1/requests/{rid}?wait=50")
        if status != 200:
            sys.exit(f"tallygate: {r.get('error', status)}")
        if r["status"] != "pending" or time.time() > deadline:
            return r


def cmd_request(args) -> int:
    level = "write" if args.write else "read"
    body = {"level": level, "reason": args.reason}
    if args.ttl:
        body["ttl"] = args.ttl
    status, r = call("POST", f"/v1/grants/{args.name}/request", body)
    if status not in (200, 202):
        print(f"tallygate: {r.get('error', status)}", file=sys.stderr)
        return 2
    if r["status"] == "pending":
        if args.no_wait:
            print(f"requested ({r['id']}); check with: tallygate status {r['id']}")
            return 0
        print(f"waiting for a human to approve grant '{args.name}' ({level}) ...", file=sys.stderr)
        r = _wait(r["id"], time.time() + args.timeout)
    return _report(r)


def _report(r: dict) -> int:
    if r["status"] == "approved":
        print(f"granted: {r['grant']} ({r['granted_level']}) for {r['ttl'] // 60} min")
        if r["granted_level"] != r["level"]:
            print(f"note: you asked for {r['level']} but were granted {r['granted_level']} only")
        return 0
    print(f"{r['status']}: {r['grant']} ({r['level']})")
    return 1


def cmd_status(args) -> int:
    status, r = call("GET", f"/v1/requests/{args.id}")
    if status != 200:
        sys.exit(f"tallygate: {r.get('error', status)}")
    return 0 if _report(r) == 0 or r["status"] == "pending" else 1


def main() -> int:
    p = argparse.ArgumentParser(prog="tallygate", description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("grants", help="list grants").set_defaults(fn=cmd_grants)
    r = sub.add_parser("request", help="request a grant and wait for the decision")
    r.add_argument("name")
    r.add_argument("--write", action="store_true", help="ask for write access (default: read)")
    r.add_argument("--ttl", help="duration, e.g. 30m, 2h (capped by the grant)")
    r.add_argument("--reason", required=True, help="why you need it - shown to the human")
    r.add_argument("--no-wait", action="store_true")
    r.add_argument("--timeout", type=float, default=300, help="seconds to wait for a decision")
    r.set_defaults(fn=cmd_request)
    s = sub.add_parser("status", help="state of a request")
    s.add_argument("id")
    s.set_defaults(fn=cmd_status)
    args = p.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
