"""Behaviour settings the UI owns (ADR-0015, tier 2).

A small set of tunables that are about *what the gateway does* (log retention, learning, suggestions, grant
flow limits) rather than how it is wired (deployment, tier 1) or the trust boundary (credentials, LAN, the
never floor, tier 3 — those stay file-only in `gateway.yaml`). They live in a backend-owned `settings.yaml`
in the data volume, edited in the UI with no file edit and no mounted config.

Precedence: a value saved here wins; otherwise the operator's `gateway.yaml`, otherwise the built-in default.
On first start the effective values (from `gateway.yaml`/env or the defaults) are written once, so the file is
self-documenting and the UI has something to show. A broken `settings.yaml` stops the gateway (fail closed).
"""

from __future__ import annotations

import logging
from pathlib import Path

import yaml

from egressgw.store import atomic_write

log = logging.getLogger("egressgw.settings")

# key -> (default, kind) where kind validates/coerces a UI value. "ports" is a list of 1..65535.
DEFAULTS: dict = {
    "log_keep_days": 30,
    "log_max_events": 500_000,
    "learning_ports": [80, 443],
    "learning_max_minutes": 120,
    "rule_stale_days": 30,
    "suggest_min_approvals": 3,
    "suggest_window_days": 7,
    "grant_request_timeout": 300,
    "grant_max_pending": 3,
    "policy_history_keep": 500,
    "max_pending": 10,
}

# settings that only take effect on the next start (they are read once when a subsystem is built).
RESTART = {"log_keep_days", "log_max_events", "learning_ports", "learning_max_minutes", "policy_history_keep"}

# sane bounds so a UI typo cannot wedge the gateway (fail closed on load, 400 on the API).
_BOUNDS = {
    "log_keep_days": (1, 3650),
    "log_max_events": (1000, 50_000_000),
    "learning_max_minutes": (1, 1440),
    "rule_stale_days": (1, 3650),
    "suggest_min_approvals": (1, 1000),
    "suggest_window_days": (1, 365),
    "grant_request_timeout": (10, 86_400),
    "grant_max_pending": (1, 1000),
    "policy_history_keep": (10, 100_000),
    "max_pending": (1, 1000),
}


def _coerce(key: str, value) -> object:
    if key == "learning_ports":
        ports = value if isinstance(value, list) else [value]
        out = []
        for p in ports:
            try:
                p = int(p)
            except (TypeError, ValueError):
                raise ValueError(f"learning_ports: {p!r} is not a port (1..65535)") from None
            if not 1 <= p <= 65535:
                raise ValueError(f"learning_ports: {p} is not a port (1..65535)")
            out.append(p)
        return out
    try:
        v = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"{key}: {value!r} is not a whole number") from None
    lo, hi = _BOUNDS[key]
    if not lo <= v <= hi:
        raise ValueError(f"{key}: {v} is out of range ({lo}..{hi})")
    return v


class Settings:
    def __init__(self, path: Path, config: dict) -> None:
        self.path = path
        self.config = config or {}
        if path.exists():
            raw = yaml.safe_load(path.read_text()) or {}
            unknown = set(raw) - set(DEFAULTS)
            if unknown:
                raise ValueError(f"settings.yaml: unknown keys {sorted(unknown)}")
            self.values = {k: _coerce(k, raw[k]) for k in raw}  # validate: a bad file stops the gateway
        else:
            # migrate: seed from gateway.yaml/env (or defaults) and write once
            self.values = {k: _coerce(k, self.config.get(k, DEFAULTS[k])) for k in DEFAULTS}
            self.save()
            log.info("wrote %s with the effective behaviour settings (ADR-0015)", path)

    def get(self, key: str):
        if key in self.values:
            return self.values[key]
        return self.config.get(key, DEFAULTS[key])

    def all(self) -> dict:
        return {k: self.get(k) for k in DEFAULTS}

    def describe(self) -> dict:
        """What the UI shows: current values, the built-in defaults, and which need a restart to take effect."""
        return {"values": self.all(), "defaults": dict(DEFAULTS), "restart_keys": sorted(RESTART)}

    def update(self, changes: dict) -> list[str]:
        """Apply and persist UI changes. Returns the keys that will only take effect after a restart."""
        if not isinstance(changes, dict) or not changes:
            raise ValueError("expected a non-empty object of settings to change")
        unknown = set(changes) - set(DEFAULTS)
        if unknown:
            raise ValueError(f"not a behaviour setting: {sorted(unknown)} (trust-critical settings stay file-only)")
        coerced = {k: _coerce(k, v) for k, v in changes.items()}  # validate before touching anything
        self.values.update(coerced)
        self.save()
        return sorted(k for k in coerced if k in RESTART)

    def save(self) -> None:
        atomic_write(self.path, yaml.safe_dump(self.all(), sort_keys=True))
