"""Operator availability: away mode, quiet hours and a digest of what was refused meanwhile (#73).

While the operator is away or in quiet hours, nothing waits for a human. New connection asks and grant
requests that need an approval are refused at once, with a message that tells the agent why. Nothing is
ever allowed automatically because nobody can answer: this only turns "ask" into "deny" (fail closed).

What was refused is collected and sent as one digest: when quiet hours end, when away mode ends, and while
away every `digest_minutes`. An ask holds a connection for at most `ask_timeout`, so it cannot wait for a
digest; the digest lists the destinations so that the operator can allow them afterwards.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import yaml

from egressgw.store import atomic_write

log = logging.getLogger("egressgw")

DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
MAX_MISSED = 200  # distinct destinations kept for the digest; more are counted only
MAX_AWAY = 30 * 86400  # an away period with an end lasts at most this long


class Unavailable(Exception):
    """A request needs a human, but the operator is away or in quiet hours."""


def _hhmm(value, what: str) -> int:
    m = re.fullmatch(r"([01]?\d|2[0-3]):([0-5]\d)", str(value or "").strip())
    if not m:
        raise ValueError(f"quiet_hours: {what} must be HH:MM (00:00-23:59), not {value!r}")
    return int(m[1]) * 60 + int(m[2])


@dataclass(frozen=True)
class QuietHours:
    """A daily period without prompts. `days` are the weekdays on which a period starts (an overnight
    period that starts on Friday ends on Saturday morning). Times are in `tz`, else the gateway's local
    time (the container's TZ)."""

    start: int  # minutes after midnight
    end: int
    days: tuple[int, ...]
    tz: str | None = None

    @classmethod
    def parse(cls, d) -> QuietHours | None:
        if d is None or d == {}:
            return None
        if not isinstance(d, dict) or set(d) - {"start", "end", "days", "tz"}:
            raise ValueError("quiet_hours: expected {start: 'HH:MM', end: 'HH:MM', days: [mon, ...], tz: ...}")
        start, end = _hhmm(d.get("start"), "start"), _hhmm(d.get("end"), "end")
        if start == end:
            raise ValueError("quiet_hours: start and end must differ")
        days = d.get("days")
        if days is None:
            days = list(DAYS)
        if not isinstance(days, list) or not days or any(str(x).lower() not in DAYS for x in days):
            raise ValueError(f"quiet_hours: days must be a non-empty list of {', '.join(DAYS)}")
        tz = d.get("tz") or None
        if tz is not None:
            try:
                ZoneInfo(str(tz))
            except (ZoneInfoNotFoundError, ValueError) as e:
                raise ValueError(f"quiet_hours: unknown time zone {tz!r}") from e
        return cls(start, end, tuple(sorted({DAYS.index(str(x).lower()) for x in days})), str(tz) if tz else None)

    def to_dict(self) -> dict:
        d = {
            "start": f"{self.start // 60:02d}:{self.start % 60:02d}",
            "end": f"{self.end // 60:02d}:{self.end % 60:02d}",
            "days": [DAYS[i] for i in self.days],
        }
        if self.tz:
            d["tz"] = self.tz
        return d

    def _local(self, now: float) -> datetime:
        if self.tz:
            return datetime.fromtimestamp(now, ZoneInfo(self.tz))
        return datetime.fromtimestamp(now).astimezone()

    def ends(self, now: float) -> float | None:
        """The end of the quiet period `now` falls into, or None if it is not quiet now."""
        local = self._local(now)
        minute = local.hour * 60 + local.minute
        today = local.weekday()
        midnight = local.replace(hour=0, minute=0, second=0, microsecond=0)
        if self.start < self.end:  # same day, e.g. 12:00-13:00
            if today in self.days and self.start <= minute < self.end:
                return (midnight + timedelta(minutes=self.end)).timestamp()
            return None
        if minute >= self.start and today in self.days:  # overnight, before midnight
            return (midnight + timedelta(days=1, minutes=self.end)).timestamp()
        if minute < self.end and (today - 1) % 7 in self.days:  # overnight, after midnight
            return (midnight + timedelta(minutes=self.end)).timestamp()
        return None

    def zone(self, now: float) -> str:
        return self.tz or self._local(now).tzname() or "local time"


def _clock(ts: float) -> str:
    return time.strftime("%H:%M", time.localtime(ts))


class Availability:
    def __init__(self, config: dict, data_dir: Path) -> None:
        self.path = data_dir / "availability.yaml"
        self.config_quiet = QuietHours.parse(config.get("quiet_hours"))  # invalid: the gateway does not start
        self.digest_minutes = int(config.get("digest_minutes", 30))
        if self.digest_minutes < 0:
            raise ValueError("digest_minutes must be 0 or more")
        self.quiet: QuietHours | None = self.config_quiet
        self.quiet_source = "config"
        self.away: dict | None = None  # {"since", "by", "until"}
        self.missed: dict[tuple[str, str, int], dict] = {}
        self.missed_dropped = 0
        self.last_digest = time.time()
        if self.path.exists():
            try:
                state = yaml.safe_load(self.path.read_text(encoding="utf-8")) or {}
                self.away = state.get("away")
                if "quiet_hours" in state:
                    self.quiet, self.quiet_source = QuietHours.parse(state["quiet_hours"]), "ui"
            except (OSError, yaml.YAMLError, AttributeError, ValueError) as e:
                # fail closed: nobody is there to answer until the operator sets it again
                log.error("%s unreadable (%s): away mode is on until it is changed", self.path, e)
                self.away = {"since": 0, "by": "unreadable state file", "until": None}

    def _save(self) -> None:
        state: dict = {"away": self.away}
        if self.quiet_source == "ui":
            state["quiet_hours"] = self.quiet.to_dict() if self.quiet else None
        atomic_write(self.path, yaml.safe_dump(state, sort_keys=False))

    # ---------------------------------------------------------------- state
    def mode(self, now: float | None = None) -> tuple[str, float | None]:
        """("away" | "quiet" | "available", until or None). An away period whose end has passed is over."""
        now = time.time() if now is None else now
        if self.away and not (self.away.get("until") and self.away["until"] <= now):
            return "away", self.away.get("until")
        if self.quiet and (end := self.quiet.ends(now)):
            return "quiet", end
        return "available", None

    def blocking(self, now: float | None = None) -> str | None:
        """Why nobody can answer now (the message for the agent), or None."""
        mode, until = self.mode(now)
        if mode == "away":
            when = f" until {_clock(until)}" if until else ""
            return (
                f"operator away{when}: unknown destinations are refused without asking - try again later, "
                "or work with what the rules already allow"
            )
        if mode == "quiet":
            return (
                f"quiet hours until {_clock(until)}: unknown destinations are refused without asking - "
                f"try again after {_clock(until)}"
            )
        return None

    def set_away(self, on: bool, until: float | None, by: str) -> None:
        if not on:
            self.away = None
        else:
            if until is not None:
                if isinstance(until, bool) or not isinstance(until, (int, float)):
                    raise ValueError("away_until must be a unix timestamp")
                if not time.time() < until <= time.time() + MAX_AWAY:
                    raise ValueError("away_until must be in the future, at most 30 days ahead")
            self.away = {"since": time.time(), "by": by[:64], "until": int(until) if until else None}
        self._save()

    def set_quiet(self, d) -> None:
        self.quiet, self.quiet_source = QuietHours.parse(d), "ui"
        self._save()

    def expire_away(self, now: float) -> bool:
        """End an away period whose end has passed. True if one ended."""
        if self.away and self.away.get("until") and self.away["until"] <= now:
            self.away = None
            self._save()
            return True
        return False

    # ---------------------------------------------------------------- digest
    def note(self, kind: str, host: str, port: int, reason: str) -> None:
        """Remember a request that was refused because nobody could answer."""
        key = (kind, host, port)
        item = self.missed.get(key)
        now = time.time()
        if item:
            item["count"] += 1
            item["last"] = now
        elif len(self.missed) < MAX_MISSED:
            self.missed[key] = {"kind": kind, "host": host, "port": port, "first": now, "last": now, "count": 1}
        else:
            self.missed_dropped += 1
        log.debug("refused while unavailable: %s %s:%s (%s)", kind, host, port, reason)

    def take(self) -> tuple[list[dict], int]:
        """The collected items (newest first) and how many more were not kept; clears both."""
        items = sorted(self.missed.values(), key=lambda i: i["last"], reverse=True)
        dropped = self.missed_dropped
        self.missed, self.missed_dropped = {}, 0
        self.last_digest = time.time()
        return items, dropped

    def digest_due(self, now: float) -> bool:
        """While away, a digest every `digest_minutes` (0 = only when away ends). Quiet hours stay quiet."""
        mode, _ = self.mode(now)
        return (
            mode == "away"
            and self.digest_minutes > 0
            and bool(self.missed)
            and now - self.last_digest >= self.digest_minutes * 60
        )

    def describe(self, now: float | None = None) -> dict:
        now = time.time() if now is None else now
        mode, until = self.mode(now)
        return {
            "mode": mode,
            "until": until,
            "message": self.blocking(now),
            "away": self.away if mode == "away" else None,
            "quiet_hours": self.quiet.to_dict() if self.quiet else None,
            "quiet_source": self.quiet_source,
            "quiet_zone": self.quiet.zone(now) if self.quiet else datetime.fromtimestamp(now).astimezone().tzname(),
            "digest_minutes": self.digest_minutes,
            "missed": sorted(self.missed.values(), key=lambda i: i["last"], reverse=True),
            "missed_dropped": self.missed_dropped,
        }
