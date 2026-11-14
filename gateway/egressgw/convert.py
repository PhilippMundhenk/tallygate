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

from egressgw.destinations import CONFIG_KEYS, config_destinations
from egressgw.policy import parse_never

_DROP = ("never", "hard_deny_floor", "grants_never", *CONFIG_KEYS)


def convert(config: dict) -> tuple[dict, list[str]]:
    """(the config in the current form, what was changed). The property keys and `grants` become one
    `destinations:` list, the never keys become one `never:` list; other keys are kept as they are. Reuses
    the gateway parsers, so a broken config is an error here as at start."""
    every, lan, old = parse_never(config)  # validates the never keys
    dests = config_destinations(config)  # validates readonly/inject/github/grants
    out = {k: v for k, v in config.items() if k not in _DROP}
    if dests:
        out["destinations"] = [d.to_dict() for d in dests]
    never = [*every, *({"range": c, "scope": "all+lan"} for c in lan)]
    if never:
        out["never"] = never
    moved = [k for k in CONFIG_KEYS if config.get(k)]
    changes = []
    if moved:
        changes.append(f"{', '.join(moved)} -> destinations")
    changes += [
        {
            "hard_deny_floor": "hard_deny_floor -> never (scope all)",
            "grants_never": "grants_never -> never (scope all+lan: also closed for every connection)",
        }[k]
        for k in old
    ]
    return out, changes


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
