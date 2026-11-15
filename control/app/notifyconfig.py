"""Notification channel settings the web UI may change (#201, ADR-0018).

The bot channels (Telegram, Matrix, ntfy, Gotify, Pushover) can be configured in the environment, as
before, or in the web UI. What the UI saves lives in one backend-owned file in the control data volume
(notify.json, mode 0600, written atomically). Rules:

- Precedence is per field: a value saved in the UI overrides the environment variable of that field; a
  field the UI does not set falls back to the environment. Removing a channel's override returns the
  whole channel to the environment.
- Secrets are write-only: public() says whether a secret is set and where it comes from, never its value.
- A secret stays with its destination: when the URL of a channel changes, the token has to be entered
  again. Otherwise a UI session could point a stored (or environment) token at a server of its choice
  and read it there, which would undo "write-only".
- Telegram and Matrix decide approvals, so they are refused without their allowed users (ADR-0010).
- If the data volume is not writable the store is read-only and everything stays environment-only.
"""

from __future__ import annotations

import json
import logging
import os
import re
import urllib.parse
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger("notify")

MAX_URL = 2048


class ConfigError(ValueError):
    """The request is wrong (unknown channel or field, bad value): HTTP 400."""


class ReadOnlyError(RuntimeError):
    """The store cannot be written (data volume not writable): HTTP 503."""


@dataclass(frozen=True)
class Field:
    name: str
    env: str
    label: str
    kind: str  # secret | tg_token | url | tg_chat | tg_users | mx_room | mx_users
    required: bool = True
    hint: str = ""

    @property
    def secret(self) -> bool:
        return self.kind in ("secret", "tg_token")


CHANNELS: dict[str, tuple[Field, ...]] = {
    "telegram": (
        Field("bot_token", "TELEGRAM_BOT_TOKEN", "Bot token", "tg_token", hint="from @BotFather"),
        Field("chat_id", "TELEGRAM_CHAT_ID", "Chat id", "tg_chat", hint="the chat the prompts are sent to"),
        Field(
            "allowed_user_ids",
            "TELEGRAM_ALLOWED_USER_IDS",
            "Allowed user ids",
            "tg_users",
            hint="comma-separated; only these users may decide",
        ),
    ),
    "matrix": (
        Field("homeserver", "MATRIX_HOMESERVER", "Homeserver URL", "url", hint="e.g. https://matrix.example.org"),
        Field("access_token", "MATRIX_ACCESS_TOKEN", "Access token", "secret", hint="of the bot user"),
        Field("room_id", "MATRIX_ROOM_ID", "Room id", "mx_room", hint="!…:example.org, an unencrypted room"),
        Field(
            "allowed_users",
            "MATRIX_ALLOWED_USERS",
            "Allowed users",
            "mx_users",
            hint="comma-separated @user:server; only these users may decide",
        ),
    ),
    "ntfy": (
        Field("url", "NTFY_URL", "Topic URL", "url", hint="e.g. https://ntfy.example.org/tallygate"),
        Field("token", "NTFY_TOKEN", "Access token", "secret", required=False, hint="only for a protected topic"),
    ),
    "gotify": (
        Field("url", "GOTIFY_URL", "Server URL", "url", hint="e.g. https://gotify.example.org"),
        Field("token", "GOTIFY_TOKEN", "Application token", "secret"),
    ),
    "pushover": (
        Field("token", "PUSHOVER_TOKEN", "Application token", "secret"),
        Field("user", "PUSHOVER_USER", "User or group key", "secret"),
    ),
}
# Channels that decide approvals: (the field that switches the channel on, the allowed users it then needs).
INTERACTIVE = {"telegram": ("bot_token", "allowed_user_ids"), "matrix": ("homeserver", "allowed_users")}

_SECRET = re.compile(r"[\x21-\x7e]{1,1024}")
_TG_TOKEN = re.compile(r"[0-9]{1,20}:[A-Za-z0-9_-]{10,200}")  # it becomes part of the request path
_TG_CHAT = re.compile(r"-?[0-9]{1,20}|@[A-Za-z0-9_]{4,64}")
_TG_USER = re.compile(r"[0-9]{1,20}")
_MX_ROOM = re.compile(r"![^\s,]{1,254}")
_MX_USER = re.compile(r"@[^\s:,@]{1,200}:[^\s,@]{1,255}")


def _url(label: str, value: str) -> str:
    if len(value) > MAX_URL or any(c.isspace() or ord(c) < 0x20 or ord(c) == 0x7F for c in value):
        raise ConfigError(f"{label}: not a valid URL")
    try:
        parts = urllib.parse.urlsplit(value)
        _ = parts.port  # raises ValueError for a port that is not a number
    except ValueError:
        raise ConfigError(f"{label}: not a valid URL") from None
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ConfigError(f"{label}: must be an http:// or https:// URL")
    if parts.username is not None or parts.password is not None:
        raise ConfigError(f"{label}: must not contain a user name or password (use the token field)")
    if parts.fragment:
        raise ConfigError(f"{label}: must not contain a #fragment")
    return value


def _list(label: str, value: str, item: re.Pattern, what: str) -> str:
    items = [v.strip() for v in value.split(",") if v.strip()]
    if not items or len(items) > 50:
        raise ConfigError(f"{label}: expected 1 to 50 {what}, separated by commas")
    for v in items:
        if not item.fullmatch(v):
            raise ConfigError(f"{label}: {v[:40]!r} is not a valid entry ({what})")
    return ",".join(items)


def _one(label: str, value: str, pattern: re.Pattern, what: str) -> str:
    if not pattern.fullmatch(value):
        raise ConfigError(f"{label}: {what}")
    return value


def validate(field: Field, value: str) -> str:
    """The value as it is stored; ConfigError says what is wrong without repeating a secret."""
    if field.kind == "url":
        return _url(field.label, value)
    if field.kind == "tg_token":
        return _one(field.label, value, _TG_TOKEN, "does not look like a Telegram bot token (123456:ABC…)")
    if field.kind == "secret":
        return _one(field.label, value, _SECRET, "must be 1 to 1024 printable characters without spaces")
    if field.kind == "tg_chat":
        return _one(field.label, value, _TG_CHAT, "expected a numeric chat id (e.g. -1001234) or @channelname")
    if field.kind == "tg_users":
        return _list(field.label, value, _TG_USER, "numeric Telegram user ids")
    if field.kind == "mx_room":
        return _one(field.label, value, _MX_ROOM, "expected a room id that starts with ! (not an alias)")
    return _list(field.label, value, _MX_USER, "Matrix user ids like @you:example.org")


def _mask_userinfo(value: str) -> str:
    """A URL from the environment may carry user:password@; that part is a secret and is not shown."""
    head, sep, rest = value.partition("://")
    authority, slash, tail = rest.partition("/")
    if sep and "@" in authority:
        return f"{head}://***@{authority.rsplit('@', 1)[1]}{slash}{tail}"
    return value


class NotifyConfig:
    def __init__(self, path: Path | None) -> None:
        self.path = path
        self.overrides: dict[str, dict[str, str]] = {}
        self.writable = False
        if path is None:  # environment-only (tests, and callers without a data volume)
            return
        self.writable = self._probe()
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            channels = data["channels"] if isinstance(data, dict) else None
            if not isinstance(channels, dict):
                raise ValueError("not a notification config")
        except FileNotFoundError:
            return
        except (OSError, ValueError, KeyError) as e:
            log.error("notification config %s unreadable (%s): using the environment only", path, e)
            return
        for channel, fields in CHANNELS.items():
            stored = channels.get(channel)
            if not isinstance(stored, dict):
                continue
            kept = {f.name: stored[f.name] for f in fields if isinstance(stored.get(f.name), str) and stored[f.name]}
            if kept:
                self.overrides[channel] = kept

    def _probe(self) -> bool:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            probe = self.path.with_name(f".{self.path.name}.probe-{os.getpid()}")
            probe.write_text("")
            probe.unlink()
        except OSError as e:
            log.warning("notification channels are environment-only: %s is not writable (%s)", self.path.parent, e)
            return False
        return True

    # ---------------------------------------------------------------- reading
    @staticmethod
    def _fields(channel: str) -> tuple[Field, ...]:
        if channel not in CHANNELS:
            raise ConfigError("unknown channel")
        return CHANNELS[channel]

    def _resolve(self, field: Field, override: dict[str, str]) -> tuple[str, str]:
        """(value, source) of one field: the UI value wins, then the environment."""
        if override.get(field.name):
            return override[field.name], "ui"
        value = os.environ.get(field.env, "")
        return (value, "environment") if value.strip() else ("", "unset")

    def effective(self, channel: str, override: dict[str, str] | None = None) -> dict[str, str]:
        """Field name -> the value in use (empty when unset)."""
        override = self.overrides.get(channel, {}) if override is None else override
        return {f.name: self._resolve(f, override)[0] for f in self._fields(channel)}

    def source(self, channel: str) -> str:
        """Where the channel's settings come from: ui, environment, mixed or unset."""
        override = self.overrides.get(channel, {})
        sources = {self._resolve(f, override)[1] for f in self._fields(channel)} - {"unset"}
        return "unset" if not sources else sources.pop() if len(sources) == 1 else "mixed"

    def public(self) -> dict:
        """What the UI gets: every field with set/source, values of non-secret fields only."""
        channels = []
        for channel, fields in CHANNELS.items():
            override = self.overrides.get(channel, {})
            out = []
            for f in fields:
                value, source = self._resolve(f, override)
                item = {
                    "name": f.name,
                    "label": f.label,
                    "env": f.env,
                    "hint": f.hint,
                    "secret": f.secret,
                    "required": f.required,
                    "set": source != "unset",
                    "source": source,
                }
                if not f.secret:
                    item["value"] = _mask_userinfo(value.strip()) if f.kind == "url" else value.strip()
                out.append(item)
            channels.append(
                {
                    "channel": channel,
                    "interactive": channel in INTERACTIVE,
                    "override": bool(override),
                    "source": self.source(channel),
                    "fields": out,
                }
            )
        return {"writable": self.writable, "channels": channels}

    # ---------------------------------------------------------------- writing
    def _save(self, overrides: dict[str, dict[str, str]]) -> None:
        if not self.writable:
            raise ReadOnlyError("the control data volume is not writable: notification channels are environment-only")
        tmp = self.path.with_name(self.path.name + ".tmp")
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)  # never readable by others, even briefly
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump({"version": 1, "channels": overrides}, f, indent=1)
            tmp.chmod(0o600)
            tmp.replace(self.path)
        except OSError as e:
            raise ReadOnlyError(f"could not write the notification config ({e.strerror or e})") from None
        self.overrides = overrides

    def update(self, channel: str, body: object) -> list[str]:
        """Save UI values for one channel; returns the names of the fields that changed. A non-secret
        field sent empty drops its UI value (back to the environment); a secret sent empty (or not sent)
        keeps the stored one."""
        fields = self._fields(channel)
        if not isinstance(body, dict):
            raise ConfigError("expected a JSON object of field values")
        unknown = sorted(set(body) - {f.name for f in fields})
        if unknown:
            raise ConfigError(f"unknown field: {', '.join(str(u)[:40] for u in unknown)}")
        new = dict(self.overrides.get(channel, {}))
        changed, entered = [], set()
        for f in fields:
            if f.name not in body:
                continue
            raw = body[f.name]
            if not isinstance(raw, str):
                raise ConfigError(f"{f.label}: expected text")
            value = raw.strip()
            if not value:
                if not f.secret and new.pop(f.name, None) is not None:
                    changed.append(f.name)
                continue
            value = validate(f, value)
            entered.add(f.name)
            if new.get(f.name) != value:
                new[f.name] = value
                changed.append(f.name)
        before, after = self.effective(channel), self.effective(channel, new)
        for f in fields:
            if f.kind == "url" and after[f.name].strip().rstrip("/") != before[f.name].strip().rstrip("/"):
                kept = [s.label for s in fields if s.secret and after[s.name] and s.name not in entered]
                if kept:
                    raise ConfigError(
                        f"{f.label} changed: enter the {kept[0].lower()} again (a stored token stays with its server)"
                    )
        if channel in INTERACTIVE:
            switch, users = INTERACTIVE[channel]
            if after[switch].strip() and not [u for u in after[users].split(",") if u.strip()]:
                label = next(f.label for f in fields if f.name == users)
                raise ConfigError(f"{label} are required: only they may decide approvals")
        overrides = {k: v for k, v in {**self.overrides, channel: new}.items() if v}
        self._save(overrides)
        return changed

    def remove(self, channel: str) -> bool:
        """Drop the UI override of a channel (it falls back to the environment). False if there was none."""
        self._fields(channel)
        if channel not in self.overrides:
            return False
        self._save({k: v for k, v in self.overrides.items() if k != channel})
        return True
