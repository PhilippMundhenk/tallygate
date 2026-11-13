"""Print a gateway config file in the current form (ADR-0014).

    python -m egressgw.convert /etc/egressgw/config.yaml > gateway.yaml

The gateway reads the old keys too, so a config file does not have to be converted for the gateway to keep
running; converting removes the warning at start. Nothing is written: the file is the operator's, and it is
usually mounted read-only. Comments are not kept.
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

from egressgw.policy import parse_never


def convert(config: dict) -> tuple[dict, list[str]]:
    """(the config in the current form, what was changed). Unknown keys are kept as they are."""
    every, lan, old = parse_never(config)  # also validates: a broken entry is an error here as at start
    out = {k: v for k, v in config.items() if k not in ("never", "hard_deny_floor", "grants_never")}
    never = [*every, *({"range": c, "scope": "all+lan"} for c in lan)]
    if never:
        out["never"] = never
    changes = {
        "hard_deny_floor": "hard_deny_floor -> never (scope all)",
        "grants_never": "grants_never -> never (scope all+lan: also closed for every connection)",
    }
    return out, [changes[k] for k in old]


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    try:
        config = yaml.safe_load(Path(argv[0]).read_text()) or {}
        out, changes = convert(config)
    except (OSError, yaml.YAMLError, ValueError) as e:
        print(f"{argv[0]}: {e}", file=sys.stderr)
        return 1
    sys.stdout.write(yaml.safe_dump(out, sort_keys=False))
    for c in changes or ["nothing to convert"]:
        print(f"# {c}", file=sys.stderr)
    return 0


if __name__ == "__main__":  # pragma: no cover - the module is run by `python -m`, main() is tested
    raise SystemExit(main())
