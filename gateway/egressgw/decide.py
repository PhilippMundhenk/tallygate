"""Deciding from the destination model (ADR-0014, step 2: shadow, before the switch).

`model.Access` reads the gateway's split structures (`gw.readonly`, `gw.inject`, `gw.github`, ...) directly.
The target state is that it reads one `destinations.Model` instead. This module is the first piece of that
move and the proof it is faithful: it recomputes a destination's request limits from a `Model` alone, and a
shadow test asserts it equals `Access.host_limits` for every host the existing tests touch.

It does not decide access (that maps one-to-one from rules and is round-tripped by the model's own tests) and
it is not yet wired into enforcement: the switch is a later, separate change, kept small because this proves
the merge of read-only, repository and credential properties first.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import TYPE_CHECKING

from egressgw.model import Limits
from egressgw.policy import host_matches

if TYPE_CHECKING:
    from egressgw.destinations import Destination

_READONLY_METHODS = ("no-writes", "no-writes+post")


def host_limits(dests: Iterable[Destination], host: str, strip_headers: list[str]) -> Limits:
    """The limits a destination has by itself, computed from the properties-only entries (access is None):
    read-only methods, repository scope and credential injection. Mirrors the old `Access.host_limits`.

    `dests` are the file properties (`destinations.file_destinations`). `host` is a checked name (an IP
    literal has no host limits). Entries are matched with the one matcher (`host_matches`), so a non-wildcard
    host is an exact match and `*.example.com` covers its subdomains."""
    dests = [d for d in dests if d.access is None]
    lim = Limits(host=host, add_needs_https_host=True)

    ro = next((d for d in dests if d.methods in _READONLY_METHODS and _matches(d, host)), None)
    if ro is not None:
        lim.no_writes, lim.post_is_write, lim.read_posts = True, ro.methods == "no-writes+post", tuple(ro.read_paths)

    lim.repos = any(d.repos and _matches(d, host) for d in dests)

    creds = [c for d in dests if d.credentials and _matches(d, host) for c in d.credentials]
    if creds:
        own = tuple(header for header, _ in creds)
        lim.strip = (*own, *strip_headers)
        lim.add = tuple(creds)
    return lim


def _matches(d, host: str) -> bool:
    return bool(d.match.host) and host_matches(d.match.host, host)
