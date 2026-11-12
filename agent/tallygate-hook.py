#!/usr/bin/env python3
"""Claude Code PreToolUse hook: tell the gateway what is about to run (#74).

The operator then sees, next to an approval prompt, the command or URL that caused it ("Bash: npm install -
Install dependencies"). Sends only the tool name, the command / URL and Claude's own description of it:
never the environment or file contents. Obvious secrets are redacted here and again in the gateway.

Never in the agent's way: no output, always exit code 0, and the report gives up after TIMEOUT seconds.
"""

import json
import os
import re
import sys
import urllib.request

BASE = os.environ.get("TALLYGATE_URL", "http://172.31.10.2:8079").rstrip("/")
TIMEOUT = 0.5
MAX_IN = 64 * 1024
MAX_TEXT = 200
FIELDS = {"Bash": "command", "WebFetch": "url"}
_SECRETS = [
    (re.compile(r"(?i)\b(bearer|basic|token)\s+[A-Za-z0-9._~+/=-]+"), r"\1 <redacted>"),
    (re.compile(r"(?i)(\s-u\s*|--user[\s=]+)\S+"), r"\1<redacted>"),  # curl -u user:password
    (
        re.compile(
            r"(?i)\b([\w.-]*(?:authorization|bearer|token|passw(?:or)?d|secret|api[_-]?key|access[_-]?key|cookie)"
            r"[\w.-]*)(\s*[:=]\s*|\s+)([\"']?)[^\s\"']+"
        ),
        r"\1\2\3<redacted>",
    ),
    (re.compile(r"(://)[^/\s:@]+:[^/\s@]+@"), r"\1<redacted>@"),
    (re.compile(r"[A-Za-z0-9+/_=-]{40,}"), "<redacted>"),
]


def redact(text: str) -> str:
    text = " ".join(str(text or "")[: MAX_TEXT * 4].split())
    for rx, repl in _SECRETS:
        text = rx.sub(repl, text)
    return text[:MAX_TEXT]


def report(event: dict) -> dict | None:
    """The activity report for a PreToolUse event, or None if there is nothing to tell."""
    tool = str(event.get("tool_name", ""))
    args = event.get("tool_input") if isinstance(event.get("tool_input"), dict) else {}
    text = redact(args.get(FIELDS.get(tool, ""), ""))
    note = redact(args.get("description", ""))
    if not text and not note:
        return None
    return {"kind": "tool", "tool": tool[:40], "text": text, "note": note}


def send(body: dict) -> None:
    if not BASE.startswith(("http://", "https://")):
        return
    req = urllib.request.Request(  # noqa: S310 - scheme checked above
        BASE + "/v1/activity", data=json.dumps(body).encode(), headers={"Content-Type": "application/json"}
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # straight to the gateway
    with opener.open(req, timeout=TIMEOUT):
        pass


def main(stdin=None) -> int:
    try:
        event = json.loads((stdin or sys.stdin).read(MAX_IN))
        body = report(event) if isinstance(event, dict) else None
        if body:
            send(body)
    except Exception:  # noqa: BLE001, S110 - a report is best effort; the tool call must go ahead regardless
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
