#!/usr/bin/env python3
"""tallygate - talk to the egress gateway, and install packages without root.

  tallygate grants                                   list grants you can request (and which are active)
  tallygate request NAME [--write] [--ttl 1h] --reason "why"   ask for a grant and wait for the decision
  tallygate status REQUEST_ID                        show the state of a request
  tallygate note "what and why"                      tell the human what you are about to do (shown next to
                                                     the approval prompts your next connections cause)
  tallygate install PKG...                           install Debian packages into your home (rootless)
  tallygate install --list | --remove PKG | --reset  manage the installed packages

A human approves or denies each grant request (some read-only grants may be approved automatically).
You cannot define or widen grants. Exit codes: 0 ok, 1 denied/expired/install failed, 2 usage/connection error.
"""

import argparse
import contextlib
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

BASE = os.environ.get("TALLYGATE_URL", "http://172.31.10.2:8079").rstrip("/")
if not BASE.startswith(("http://", "https://")):
    sys.exit("tallygate: TALLYGATE_URL must be an http(s) URL")
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # talk to the gateway directly


def call(method: str, path: str, body: dict | None = None, timeout: float = 70):
    req = urllib.request.Request(  # noqa: S310 - scheme checked above
        BASE + path,
        method=method,
        data=None if body is None else json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
    )
    try:
        with OPENER.open(req, timeout=timeout) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except ValueError:
            return e.code, {"error": e.reason}
    except OSError as e:
        sys.exit(f"tallygate: cannot reach the gateway at {BASE}: {e}")


def cmd_grants(_args) -> int:
    status, data = call("GET", "/v1/grants")
    if status != 200:
        sys.exit(f"tallygate: {data.get('error', status)}")
    operator = data.get("operator") or {}
    if operator.get("message"):  # away or quiet hours: requests that need a human are refused at once
        print(f"note: {operator['message']}")
    if not data["grants"]:
        print("No grants are defined. Ask the operator to define one.")
    for g in data["grants"]:
        active = g.get("active")
        state = (
            f"ACTIVE ({active['level']}, {max(0, int(active['expires'] - time.time())) // 60} min left)"
            if active
            else "inactive"
        )
        print(
            f"{g['name']}  [{state}]  levels: {', '.join(g['levels'])}  default {g['default_ttl']}, max {g['max_ttl']}"
        )
        if g["description"]:
            print(f"    {g['description']}")
        for t in g["targets"]:
            print(f"    - {t}")
    return 0


def _wait(rid: str, deadline: float) -> dict:
    while True:
        status, r = call("GET", f"/v1/requests/{rid}?wait=50")
        if status != 200:
            sys.exit(f"tallygate: {r.get('error', status)}")
        if r["status"] != "pending" or time.time() > deadline:
            return r


def cmd_request(args) -> int:
    level = "write" if args.write else "read"
    body = {"level": level, "reason": args.reason}
    if args.ttl:
        body["ttl"] = args.ttl
    status, r = call("POST", f"/v1/grants/{args.name}/request", body)
    if status == 503:  # the operator is away or in quiet hours: refused, not an error
        print(f"denied: {r.get('error', 'operator unavailable')}")
        return 1
    if status not in (200, 202):
        print(f"tallygate: {r.get('error', status)}", file=sys.stderr)
        return 2
    if r["status"] == "pending":
        if args.no_wait:
            print(f"requested ({r['id']}); check with: tallygate status {r['id']}")
            return 0
        print(f"waiting for a human to approve grant '{args.name}' ({level}) ...", file=sys.stderr)
        r = _wait(r["id"], time.time() + args.timeout)
    return _report(r)


def _report(r: dict) -> int:
    if r["status"] == "approved":
        print(f"granted: {r['grant']} ({r['granted_level']}) for {r['ttl'] // 60} min")
        if r["granted_level"] != r["level"]:
            print(f"note: you asked for {r['level']} but were granted {r['granted_level']} only")
        return 0
    print(f"{r['status']}: {r['grant']} ({r['level']})")
    return 1


def cmd_status(args) -> int:
    status, r = call("GET", f"/v1/requests/{args.id}")
    if status != 200:
        sys.exit(f"tallygate: {r.get('error', status)}")
    return 0 if _report(r) == 0 or r["status"] == "pending" else 1


def cmd_note(args) -> int:
    status, r = call("POST", "/v1/activity", {"kind": "note", "note": args.text}, timeout=5)
    if status != 202:
        print(f"tallygate: {r.get('error', status)}", file=sys.stderr)
        return 2
    print("noted: it is shown (as your claim) next to approval prompts in the next 2 minutes")
    return 0


# ---------------------------------------------------------------- rootless package install
# apt and dpkg run as the agent user (uid 1000). apt resolves and downloads the .debs through the egress
# proxy - held or allowed by the Debian/apt template, so the human still decides - and each .deb is then
# unpacked with `dpkg -x` into a prefix on the home volume. Maintainer scripts are not run and nothing
# outside the home volume is written, so the read-only root filesystem and the hardening are untouched.
# entrypoint.sh / /etc/profile.d put the prefix on PATH. See agent/CLAUDE.md and docs/operations.md.
HOME_DIR = Path(os.environ.get("HOME", "/home/agent"))
APT_STATE = HOME_DIR / ".local/share/tallygate/apt"  # lists, dpkg status copy, manifest
APT_CACHE = HOME_DIR / ".cache/tallygate/apt"  # downloaded .deb archives
INSTALL_ROOT = HOME_DIR / ".local/tallygate/root"  # the unpack prefix (…/usr/bin, …/usr/lib/<triplet>)
MANIFEST = APT_STATE / "installed.json"
DPKG_STATUS = APT_STATE / "dpkg-status"  # copy of the image's status: image packages are not re-downloaded
IMAGE_DPKG_STATUS = Path("/var/lib/dpkg/status")


class InstallError(Exception):
    """A step of the install flow failed; the message is shown to the agent."""


def _clean(s: object, limit: int = 400) -> str:
    """Printable text only (no terminal escapes), stripped and truncated - apt/dpkg output goes to the agent."""
    return "".join(c for c in str(s or "") if c >= " " or c == "\n").strip()[:limit]


def _sh(cmd: list[str], timeout: float = 600) -> subprocess.CompletedProcess:
    """Run a fixed argv (never a shell). Single choke point so the flow is easy to test."""
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _apt_user() -> str:
    """The name apt should drop to for downloads: the current user (never root, we are unprivileged)."""
    try:
        import pwd

        return pwd.getpwuid(os.getuid()).pw_name
    except (ImportError, KeyError, OSError):
        return "nobody"


def _apt_opts() -> list[str]:
    """apt options that keep all state under the home volume and read config/keyrings from the image."""
    return [
        "-o", f"Dir::State={APT_STATE}",
        "-o", f"Dir::State::Lists={APT_STATE}/lists",
        "-o", f"Dir::State::status={DPKG_STATUS}",
        "-o", f"Dir::Cache={APT_CACHE}",
        "-o", f"Dir::Cache::Archives={APT_CACHE}/archives",
        "-o", "Debug::NoLocking=true",  # no lock under /var: we never change the image's dpkg database
        "-o", f"APT::Sandbox::User={_apt_user()}",
    ]  # fmt: skip


def _prepare_dirs() -> None:
    for d in (APT_STATE / "lists/partial", APT_CACHE / "archives/partial", INSTALL_ROOT):
        d.mkdir(parents=True, exist_ok=True)
    if not DPKG_STATUS.exists():
        try:
            shutil.copyfile(IMAGE_DPKG_STATUS, DPKG_STATUS)  # so deps already in the image are not fetched
        except OSError:
            DPKG_STATUS.write_text("")  # empty: apt treats every dependency as missing (still correct)


def _load_manifest() -> dict:
    try:
        data = json.loads(MANIFEST.read_text())
    except (OSError, ValueError):
        data = {}
    data.setdefault("requested", [])  # top-level package names the agent asked for
    data.setdefault("debs", {})  # .deb filename -> {"package": name, "files": [./usr/bin/..., ...]}
    return data


def _save_manifest(data: dict) -> None:
    MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    tmp = MANIFEST.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True))
    os.replace(tmp, MANIFEST)


def _prefix_path(rel: str) -> Path | None:
    """A dpkg-listed relative path (./usr/bin/jq) as a path inside the prefix, or None if it escapes it."""
    p = INSTALL_ROOT / (rel[2:] if rel.startswith("./") else rel)
    root = str(INSTALL_ROOT)
    norm = os.path.normpath(str(p))
    return p if norm == root or norm.startswith(root + os.sep) else None


def _deb_package_name(deb: Path) -> str:
    r = _sh(["dpkg-deb", "-f", str(deb), "Package"])
    return r.stdout.strip() if r.returncode == 0 and r.stdout.strip() else deb.name.split("_")[0]


def _extract_deb(deb: Path) -> list[str]:
    """Unpack one .deb into the prefix; return the relative paths it placed (from `dpkg -X`)."""
    r = _sh(["dpkg", "-X", str(deb), str(INSTALL_ROOT)])
    if r.returncode != 0:
        raise InstallError(f"could not unpack {deb.name}: {_clean(r.stderr) or 'dpkg failed'}")
    return [ln.strip() for ln in r.stdout.splitlines() if ln.strip()]


def _install_packages(packages: list[str]) -> int:
    if shutil.which("apt-get") is None or shutil.which("dpkg") is None:
        print("tallygate install: apt-get/dpkg not found (is this the tallygate agent image?)", file=sys.stderr)
        return 2
    _prepare_dirs()
    opts = _apt_opts()
    upd = _sh(["apt-get", *opts, "-qq", "update"])
    if upd.returncode != 0:
        print(
            f"tallygate install: 'apt-get update' failed: {_clean(upd.stderr) or 'see the gateway log'}",
            file=sys.stderr,
        )
        print(
            "  the apt mirrors may need approval: apply the Debian/apt template (Rules -> Quick actions),"
            " or wait for the operator, then try again",
            file=sys.stderr,
        )
        return 1
    dl = _sh(["apt-get", *opts, "-y", "--no-install-recommends", "--download-only", "install", *packages])
    if dl.returncode != 0:
        print(
            f"tallygate install: could not resolve or download: {_clean(dl.stderr) or 'see the gateway log'}",
            file=sys.stderr,
        )
        return 1
    manifest = _load_manifest()
    added = 0
    try:
        for deb in sorted((APT_CACHE / "archives").glob("*.deb")):
            if deb.name in manifest["debs"]:
                continue
            manifest["debs"][deb.name] = {"package": _deb_package_name(deb), "files": _extract_deb(deb)}
            added += 1
    except InstallError as e:
        _save_manifest(manifest)
        print(f"tallygate install: {e}", file=sys.stderr)
        return 1
    for pkg in packages:
        if pkg not in manifest["requested"]:
            manifest["requested"].append(pkg)
    manifest["requested"].sort()
    _save_manifest(manifest)
    print(f"installed {', '.join(sorted(set(packages)))} into {INSTALL_ROOT} ({added} package(s) unpacked)")
    print("start a new shell (or re-run your command) so PATH picks up the new tools")
    return 0


def _install_list() -> int:
    manifest = _load_manifest()
    if not manifest["debs"]:
        print("no packages installed with 'tallygate install'")
        return 0
    print(f"requested with 'tallygate install' ({len(manifest['requested'])}):")
    for pkg in manifest["requested"]:
        print(f"  {pkg}")
    print(f"unpacked under {INSTALL_ROOT}: {len(manifest['debs'])} package(s) (including dependencies)")
    return 0


def _install_remove(names: list[str]) -> int:
    manifest = _load_manifest()
    removed = False
    for name in names:
        debs = [fn for fn, meta in manifest["debs"].items() if meta.get("package") == name]
        if not debs:
            print(f"tallygate install: {name} is not installed (see 'tallygate install --list')", file=sys.stderr)
            continue
        keep = {f for fn, meta in manifest["debs"].items() if fn not in debs for f in meta.get("files", [])}
        for fn in debs:
            for rel in manifest["debs"][fn].get("files", []):
                if rel in keep:
                    continue  # a file another retained package also provides: leave it
                p = _prefix_path(rel)
                if p is not None and not p.is_dir():
                    with contextlib.suppress(OSError):
                        p.unlink()
            del manifest["debs"][fn]
            with contextlib.suppress(OSError):
                (APT_CACHE / "archives" / fn).unlink()  # drop the cached .deb too
        if name in manifest["requested"]:
            manifest["requested"].remove(name)
        removed = True
        print(f"removed {name} from {INSTALL_ROOT}")
    if not removed:
        return 1
    _prune_empty_dirs(INSTALL_ROOT)
    _save_manifest(manifest)
    print("note: dependencies pulled in with these may remain; 'tallygate install --reset' clears everything")
    return 0


def _prune_empty_dirs(base: Path) -> None:
    if not base.exists():
        return
    dirs = sorted((p for p in base.rglob("*") if p.is_dir()), key=lambda p: len(p.parts), reverse=True)
    for d in dirs:
        with contextlib.suppress(OSError):
            d.rmdir()  # only succeeds when empty


def _install_reset() -> int:
    for d in (INSTALL_ROOT, APT_STATE, APT_CACHE):
        shutil.rmtree(d, ignore_errors=True)
    print("removed every 'tallygate install' package, the download cache and the apt state")
    return 0


def cmd_install(args) -> int:
    if args.reset:
        return _install_reset()
    if args.list:
        return _install_list()
    if args.remove:
        return _install_remove(args.remove)
    if not args.packages:
        print("tallygate install: name at least one package, or use --list / --remove PKG / --reset", file=sys.stderr)
        return 2
    return _install_packages(args.packages)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="tallygate", description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("grants", help="list grants").set_defaults(fn=cmd_grants)
    r = sub.add_parser("request", help="request a grant and wait for the decision")
    r.add_argument("name")
    r.add_argument("--write", action="store_true", help="ask for write access (default: read)")
    r.add_argument("--ttl", help="duration, e.g. 30m, 2h (capped by the grant)")
    r.add_argument("--reason", required=True, help="why you need it - shown to the human")
    r.add_argument("--no-wait", action="store_true")
    r.add_argument("--timeout", type=float, default=300, help="seconds to wait for a decision")
    r.set_defaults(fn=cmd_request)
    s = sub.add_parser("status", help="state of a request")
    s.add_argument("id")
    s.set_defaults(fn=cmd_status)
    n = sub.add_parser("note", help="say what you are about to do and why (shown to the human)")
    n.add_argument("text")
    n.set_defaults(fn=cmd_note)
    i = sub.add_parser("install", help="install Debian packages into your home, without root")
    i.add_argument("packages", nargs="*", help="package names, e.g. shellcheck sqlite3 dnsutils")
    i.add_argument("--list", action="store_true", help="list what you installed this way")
    i.add_argument("--remove", nargs="+", metavar="PKG", help="remove packages from the prefix")
    i.add_argument("--reset", action="store_true", help="delete the whole prefix, cache and apt state")
    i.set_defaults(fn=cmd_install)
    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
