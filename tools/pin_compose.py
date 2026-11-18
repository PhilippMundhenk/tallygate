#!/usr/bin/env python3
"""Tie a compose.yaml to the images of one release (used by the release job in .github/workflows/ci.yml).

On `main`, compose.yaml pulls `ghcr.io/…/tallygate-*:${TALLYGATE_VERSION:-latest}`. The file attached to a
release must start the images of that release, so that the isolation settings in it (networks,
GW_INTERNAL_NETS, hardening) and the images cannot drift apart:

    pin_compose.py 0.4.1 --compose compose.yaml --out dist/compose.yaml

rewrites the default of every image line to the version (`${TALLYGATE_VERSION:-0.4.1}`) and changes nothing
else. With the three image digests it also writes a compose override that pins the images by digest:

    pin_compose.py 0.4.1 --out dist/compose.yaml --digests-out dist/compose.digests.yaml \
        --digest gateway=sha256:… --digest control=sha256:… --digest agent=sha256:…

Only the standard library is used. A compose file whose image lines are not exactly the three expected ones
is refused: a release must not go out with a file this script did not understand.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

IMAGES = ("gateway", "control", "agent")
# an image line of compose.yaml: indentation, repository, and the tag as a compose variable with a default
IMAGE_LINE = re.compile(
    r"^(?P<head>[ ]+image:[ ]+(?P<repo>ghcr\.io/[a-z0-9][a-z0-9._/-]*/tallygate-(?P<name>[a-z]+))"
    r":\$\{TALLYGATE_VERSION:-)(?P<default>[^}\s]*)(?P<tail>\}[ \t]*)$"
)
ANY_IMAGE = re.compile(r"^[ ]+image:")
SERVICE = re.compile(r"^  (?P<service>[A-Za-z0-9][A-Za-z0-9._-]*):[ \t]*(#.*)?$")
VERSION = re.compile(r"\d+\.\d+\.\d+(-[0-9A-Za-z][0-9A-Za-z.]*)?")  # image tags carry no "v"
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


class PinError(ValueError):
    """The compose file or an argument is not what this script understands."""


def image_lines(text: str) -> list[dict]:
    """The image lines of the compose file as {line, service, name, repo, default}, in file order.
    Raises PinError unless they are exactly the gateway, control and agent image, each with a
    `${TALLYGATE_VERSION:-…}` tag."""
    found, service, in_services = [], "", False
    for i, line in enumerate(text.splitlines()):
        if line[:1] not in (" ", "#", ""):
            in_services = line.split("#")[0].strip() == "services:"
            continue
        m = SERVICE.match(line)
        if in_services and m:
            service = m["service"]
        if not ANY_IMAGE.match(line):
            continue
        m = IMAGE_LINE.match(line)
        if not m or not in_services:
            raise PinError(f"line {i + 1}: an image that is not tallygate-*:${{TALLYGATE_VERSION:-…}}: {line.strip()}")
        found.append({"line": i, "service": service, "name": m["name"], "repo": m["repo"], "default": m["default"]})
    names = sorted(f["name"] for f in found)
    if names != sorted(IMAGES):
        raise PinError(f"expected one image line each for {', '.join(IMAGES)}; found: {', '.join(names) or 'none'}")
    return found


def check_version(version: str) -> str:
    if not VERSION.fullmatch(version):
        raise PinError(f"version must look like 1.2.3 (no leading v): {version!r}")
    return version


def pin(text: str, version: str) -> str:
    """The compose file with `version` as the default tag of every image; every other byte is kept."""
    check_version(version)
    wanted = {f["line"] for f in image_lines(text)}
    out = []
    for i, line in enumerate(text.splitlines(keepends=True)):
        if i in wanted:
            body = line.rstrip("\r\n")
            m = IMAGE_LINE.match(body)
            line = m["head"] + version + m["tail"] + line[len(body) :]
        out.append(line)
    return "".join(out)


def digests_override(text: str, version: str, digests: dict[str, str]) -> str:
    """A compose override file that pins the three images of `version` by digest."""
    check_version(version)
    refs = image_lines(text)
    if sorted(digests) != sorted(IMAGES):
        raise PinError(f"need a digest for each of {', '.join(IMAGES)}; got: {', '.join(sorted(digests)) or 'none'}")
    for name, digest in digests.items():
        if not DIGEST.fullmatch(digest):
            raise PinError(f"digest of {name} must be sha256:<64 hex digits>: {digest!r}")
    lines = [
        f"# tallygate {version}: the images of this release by digest. Use it together with the compose.yaml of the",
        "# same release, so that a moved or replaced tag in the registry cannot change what runs:",
        "#",
        "#   docker compose -f compose.yaml -f compose.digests.yaml up -d",
        "#   (or COMPOSE_FILE=compose.yaml:compose.digests.yaml in .env)",
        "#",
        "# TALLYGATE_VERSION has no effect on these lines. See docs/operations.md#verifying-the-images.",
        "",
        "services:",
    ]
    for ref in refs:
        lines += [f"  {ref['service']}:", f"    image: {ref['repo']}:{version}@{digests[ref['name']]}"]
    return "\n".join(lines) + "\n"


def parse_digests(items: list[str]) -> dict[str, str]:
    out = {}
    for item in items:
        name, sep, digest = item.partition("=")
        if not sep or name in out:
            raise PinError(f"--digest takes NAME=sha256:…, once per image: {item!r}")
        out[name] = digest
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Pin compose.yaml to the images of one release.")
    ap.add_argument("version", help="release version without the leading v, e.g. 0.4.1")
    ap.add_argument("--compose", default="compose.yaml", type=Path, help="the file to read (default: compose.yaml)")
    ap.add_argument("--out", required=True, type=Path, help="where to write the pinned compose file")
    ap.add_argument("--digest", action="append", default=[], metavar="NAME=sha256:…", help="gateway, control, agent")
    ap.add_argument("--digests-out", type=Path, help="where to write the digest override (needs three --digest)")
    args = ap.parse_args(argv)
    try:
        if bool(args.digest) != bool(args.digests_out):
            raise PinError("--digest and --digests-out belong together")
        text = args.compose.read_bytes().decode()
        pinned = pin(text, args.version)
        override = digests_override(pinned, args.version, parse_digests(args.digest)) if args.digests_out else None
    except (PinError, OSError, UnicodeDecodeError) as e:
        print(f"pin_compose: {e}", file=sys.stderr)
        return 1
    # nothing is written unless everything was understood
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_bytes(pinned.encode())
    print(f"pin_compose: {args.out}: images default to {args.version}")
    if override is not None:
        args.digests_out.parent.mkdir(parents=True, exist_ok=True)
        args.digests_out.write_bytes(override.encode())
        print(f"pin_compose: {args.digests_out}: images by digest")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
