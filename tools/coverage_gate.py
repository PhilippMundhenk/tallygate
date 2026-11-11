#!/usr/bin/env python3
"""Fail when any measured module is below the line-coverage gate (default 95 %).

coverage.py only gates the total; this checks every file of coverage.json:

    python tools/coverage_gate.py coverage.json [--min 95]
"""

from __future__ import annotations

import argparse
import json
import sys


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("report", help="coverage.json from `coverage json`")
    ap.add_argument("--min", type=float, default=95.0, help="minimum line coverage per module in percent")
    a = ap.parse_args(argv)
    files = json.load(open(a.report, encoding="utf-8"))["files"]
    failed = 0
    for name, data in sorted(files.items()):
        s = data["summary"]
        if not s["num_statements"]:
            continue
        pct = s["percent_covered"]
        ok = pct >= a.min
        failed += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {pct:6.2f} %  {name}")
    print(f"{len(files) - failed}/{len(files)} modules at or above {a.min:g} %")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
