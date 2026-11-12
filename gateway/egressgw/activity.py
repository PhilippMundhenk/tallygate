"""What the agent says it is doing, shown next to an approval (#74).

The agent reports the tool call Claude Code is about to run (a PreToolUse hook in the agent image) or a note
(`tallygate note "..."`) to the agent API. When a connection asks for approval, the recent entries from the
same client are attached to the prompt, so the operator sees *why* the agent wants the destination.

Everything here is written by the agent and therefore untrusted: single line, printable, size-limited, with
obvious secrets redacted, labelled as a claim wherever it is shown, and never used for a decision.
"""

from __future__ import annotations

import re
import time
from collections import deque

MAX_TEXT = 200  # characters per field
KEEP = 50  # entries kept in memory (all clients)
WINDOW = 120  # seconds: activity older than this is not attached to a new approval
ATTACH = 3  # entries attached to one approval
KINDS = ("tool", "note")

_SECRETS = [
    # first: "Authorization: Bearer <token>" must lose the token, not just the word Bearer
    (re.compile(r"(?i)\b(bearer|basic|token)\s+[A-Za-z0-9._~+/=-]+"), r"\1 <redacted>"),
    (re.compile(r"(?i)(\s-u\s*|--user[\s=]+)\S+"), r"\1<redacted>"),  # curl -u user:password
    # key=value / key: value / --key value for names that hold secrets
    (
        re.compile(
            r"(?i)\b([\w.-]*(?:authorization|bearer|token|passw(?:or)?d|secret|api[_-]?key|access[_-]?key|cookie)"
            r"[\w.-]*)(\s*[:=]\s*|\s+)([\"']?)[^\s\"']+"
        ),
        r"\1\2\3<redacted>",
    ),
    (re.compile(r"(://)[^/\s:@]+:[^/\s@]+@"), r"\1<redacted>@"),  # credentials in URLs
    (re.compile(r"\b(?:gh[pousr]_|github_pat_|glpat-|xox[abprs]-|sk-|AKIA)[A-Za-z0-9_-]{8,}"), "<redacted>"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"), "<redacted>"),  # JWT
    (re.compile(r"[A-Za-z0-9+/_=-]{40,}"), "<redacted>"),  # long opaque strings (keys, tokens)
]


def clean(text, limit: int = MAX_TEXT) -> str:
    """Agent-written text for humans: printable, one line, secrets redacted, bounded."""
    text = "".join(c if c.isprintable() else " " for c in str(text or "")[: limit * 8])
    text = " ".join(text.split())
    for rx, repl in _SECRETS:
        text = rx.sub(repl, text)
    return text if len(text) <= limit else text[: limit - 1] + "…"


class Activity:
    def __init__(self) -> None:
        self.entries: deque[dict] = deque(maxlen=KEEP)

    def add(self, body: dict, client: str) -> dict:
        """Store one report: {"kind": "tool" | "note", "tool": "Bash", "text": "...", "note": "..."}."""
        if not isinstance(body, dict):
            raise ValueError("JSON object expected")
        kind = str(body.get("kind", "tool"))
        if kind not in KINDS:
            raise ValueError(f"kind must be one of {list(KINDS)}")
        entry = {
            "ts": time.time(),
            "kind": kind,
            "tool": clean(body.get("tool", ""), 40) if kind == "tool" else "",
            "text": clean(body.get("text", "")),
            "note": clean(body.get("note", "")),
            "client": client,
        }
        if not entry["text"] and not entry["note"]:
            raise ValueError("text or note required")
        self.entries.append(entry)
        return entry

    def recent(self, client: str, now: float | None = None) -> list[dict]:
        """The newest entries of this client within WINDOW, newest first, without the client address."""
        now = time.time() if now is None else now
        out = []
        for e in reversed(self.entries):
            if now - e["ts"] > WINDOW or len(out) >= ATTACH:
                break
            if e["client"] == client:
                out.append({k: v for k, v in e.items() if k != "client" and v})
        return out
