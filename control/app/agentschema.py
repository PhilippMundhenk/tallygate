"""The agent's answers, reduced to what the UI expects (#243).

The status server runs as the agent user, so a hostile agent can answer control's calls with anything. The
UI escapes every value, but it also calls string methods on some and builds its pages from the others: a
number where a string belongs stopped the Setup tab half-rendered, with the notification settings missing.
So control passes on a fixed schema only: the known keys, each with its expected type, strings cut to a
length, lists to a number of entries. A key with a value of the wrong type is left out (the UI treats it
like a missing one), an unknown key is dropped, and nothing nested deeper than the schema says exists.
"""

from __future__ import annotations

import math

STR = "str"
BOOL = "bool"
NUM = "num"


def text(limit: int) -> tuple[str, int]:
    return (STR, limit)


def _number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def normalise(value: object, schema: object) -> object:
    """`value` as the schema allows it, or `...` (Ellipsis) if it does not fit at all.
    schema: BOOL | NUM | text(n) | {key: schema} | [item schema, max items] | (schema, None) for "or null"."""
    if isinstance(schema, dict):
        if not isinstance(value, dict):
            return ...
        out = {}
        for key, sub in schema.items():
            if key in value and (v := normalise(value[key], sub)) is not ...:
                out[key] = v
        return out
    if isinstance(schema, list):
        item, limit = schema
        if not isinstance(value, list):
            return ...
        return [v for v in (normalise(x, item) for x in value[:limit]) if v is not ...]
    if isinstance(schema, tuple) and schema[1] is None:  # nullable
        return None if value is None else normalise(value, schema[0])
    if schema == BOOL:
        return value if isinstance(value, bool) else ...
    if schema == NUM:
        return value if _number(value) else ...
    kind, limit = schema
    assert kind == STR
    return value[:limit] if isinstance(value, str) else ...


ERROR = text(300)
DISK = ({"total": NUM, "used": NUM, "free": NUM}, None)
GIT = {"name": text(200), "email": text(320), "state": text(20), "error": ERROR}
LOGIN = {"logged_in": BOOL, "url": text(2048), "message": text(300), "state": text(20), "error": ERROR}

# (method, what) -> schema, for every route control relays (main.AGENT_ROUTES)
SCHEMAS: dict[tuple[str, str], dict] = {
    ("GET", "status"): {
        "claude_version": text(100),
        "claude_logged_in": BOOL,
        "git_name": text(200),
        "git_email": text(320),
        "git_identity": text(20),
        "remote_control_enabled": BOOL,
        "remote_control_running": BOOL,
        "remote_control_consent": BOOL,
        "remote_control_prompt": text(300),
        "remote_control_name": text(100),
        "gateway_ca_trusted": BOOL,
        "workspace_disk": DISK,
        "home_disk": DISK,
        "time": NUM,
        "error": ERROR,
    },
    ("GET", "selftest"): {"results": [{"name": text(200), "pass": BOOL, "detail": text(300)}, 200], "error": ERROR},
    ("GET", "setup/claude-login"): LOGIN,
    ("POST", "setup/claude-login"): LOGIN,
    ("POST", "setup/claude-code"): LOGIN,
    ("GET", "setup/git-identity"): {
        "ok": BOOL,
        "reason": text(20),
        "message": text(300),
        "login": text(100),
        "name": text(200),
        "email": text(320),
        "token_expires": text(60),
        "current": GIT,
        "error": ERROR,
    },
    ("POST", "setup/git-identity"): GIT,
    ("POST", "setup/remote-control"): {"consent": BOOL, "restarted": BOOL, "error": ERROR},
}


def clean(method: str, what: str, data: object) -> dict:
    """The agent's answer to one relayed call as the UI may see it. ValueError if it is no JSON object."""
    out = normalise(data, SCHEMAS[(method, what)])
    if out is ...:
        raise ValueError("not an object")
    return out
