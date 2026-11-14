"""Read-only hosts from the gateway config (`readonly`).

A leaf module (it imports only `policy`) so the destination model and the converter can parse `readonly`
without pulling in `core` (which needs mitmproxy). `core` re-exports `ReadOnly`/`parse_readonly` from here.
"""

from __future__ import annotations

from dataclasses import dataclass

from egressgw.model import is_write
from egressgw.policy import valid_hostname


@dataclass(frozen=True)
class ReadOnly:
    """A `readonly` entry: PUT/PATCH/DELETE are refused; with `post_is_write` also POST, except on the
    `read_posts` paths (POSTs that only read, e.g. a search or a batch lookup)."""

    host: str
    post_is_write: bool = False
    read_posts: tuple[str, ...] = ()

    def refuses(self, method: str, path: str) -> bool:
        return is_write(method, path, self.post_is_write, self.read_posts)


def parse_readonly(entries) -> list[ReadOnly]:
    """Validate `readonly` from the static config. A broken entry stops the gateway (fail closed)."""
    out = []
    for e in entries:
        spec = {"host": e} if isinstance(e, str) else e
        if not isinstance(spec, dict) or set(spec) - {"host", "post_is_write", "read_posts"}:
            raise ValueError(f"readonly: invalid entry {e!r} (a host, or {{host, post_is_write, read_posts}})")
        host = str(spec.get("host", "")).lower().rstrip(".")
        name = host[2:] if host.startswith("*.") else host
        reads = spec.get("read_posts") or []
        if (
            not valid_hostname(name)
            or not isinstance(reads, list)
            or not all(str(r).startswith(("/", "*")) for r in reads)
        ):
            raise ValueError(f"readonly: invalid entry {e!r}")
        out.append(ReadOnly(host, bool(spec.get("post_is_write", False)), tuple(str(r) for r in reads)))
    return out
