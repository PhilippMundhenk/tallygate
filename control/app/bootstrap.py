"""First-start secrets, so `docker compose up` works without any configuration.

Every value can still be given as an environment variable, which always wins. Otherwise:

- GW_API_TOKEN       read from the gateway's volume (the gateway creates it; mounted read-only here)
- SESSION_SECRET     created in /data/session-secret
- TTYD_CREDENTIAL    created in the console volume, shared read-only with the agent
- UI password        scrypt hash in /data/password-hash; on first start a random password is
                     generated and printed to the log, where it stays readable until the log is
                     rotated. Change it with `python -m app.passwd` (this ends all open sessions).
"""

from __future__ import annotations

import hashlib
import logging
import os
import secrets
import time
from pathlib import Path

log = logging.getLogger("control")

DATA = Path(os.environ.get("CONTROL_DATA", "/data"))
GW_TOKEN_FILE = Path(os.environ.get("GW_API_TOKEN_FILE", "/run/tallygate/gw/api-token"))
TTYD_FILE = Path(os.environ.get("TTYD_CREDENTIAL_FILE", "/run/tallygate/ttyd/credential"))
PASSWORD_FILE = DATA / "password-hash"
# Present while the password is still the one generated on first start (the setup wizard asks to change it).
GENERATED_MARK = DATA / "password-generated"
LOG2N = 16


def _write(path: Path, value: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(value)
    tmp.chmod(mode)
    tmp.replace(path)


def _read_or_create(path: Path, factory, mode: int = 0o600) -> str:
    if not path.exists():
        _write(path, factory(), mode)
        log.info("created %s", path)
    return path.read_text().strip()


def unwritable(dirs: list[Path]) -> list[str]:
    """The directories this process must write to but cannot, typically a bind mount owned by root."""
    bad = []
    for d in dirs:
        try:
            d.mkdir(parents=True, exist_ok=True)
            probe = d / f".write-test-{os.getpid()}"
            probe.write_text("")
            probe.unlink()
        except OSError:
            bad.append(str(d))
    return bad


def owner_hint(component: str, bad: list[str], uid: int, gid: int) -> str:
    """One clear message instead of a PermissionError traceback (#95)."""
    return (
        f"{component} cannot write to {', '.join(bad)} (it runs as uid {uid}). If these are bind mounts, give the "
        f"host directories to that user, e.g. `chown {uid}:{gid} <host directory>`. "
        "See docs/operations.md#host-directories."
    )


def check_dirs(proxy_auth: bool = False) -> None:
    """Refuse to start with a clear message when the state directories are not writable."""
    dirs = []
    needs_data = not os.environ.get("SESSION_SECRET") or not (
        proxy_auth or os.environ.get("CONTROL_PASSWORD_HASH") or os.environ.get("CONTROL_PASSWORD")
    )
    if needs_data:
        dirs.append(DATA)
    if not os.environ.get("TTYD_CREDENTIAL"):
        dirs.append(TTYD_FILE.parent)
    if bad := unwritable(dirs):
        raise SystemExit(owner_hint("control", bad, os.getuid(), os.getgid()))


def hash_password(pw: str, log2n: int = LOG2N) -> str:
    salt = os.urandom(16)
    n = 2**log2n
    digest = hashlib.scrypt(pw.encode(), salt=salt, n=n, r=8, p=1, maxmem=256 * n * 8 + 1024 * 1024).hex()
    return f"scrypt:{log2n}:{salt.hex()}:{digest}"


def gw_token(timeout: float = 60) -> str:
    if os.environ.get("GW_API_TOKEN"):
        return os.environ["GW_API_TOKEN"]
    deadline = time.monotonic() + timeout
    while not GW_TOKEN_FILE.exists():  # the gateway creates it on its first start
        if time.monotonic() > deadline:
            raise SystemExit(f"GW_API_TOKEN is not set and {GW_TOKEN_FILE} does not exist (is the gateway running?)")
        time.sleep(1)
    return GW_TOKEN_FILE.read_text().strip()


def session_secret() -> bytes:
    if os.environ.get("SESSION_SECRET"):
        return os.environ["SESSION_SECRET"].encode()
    return _read_or_create(DATA / "session-secret", lambda: secrets.token_hex(32)).encode()


def ttyd_credential() -> str:
    if os.environ.get("TTYD_CREDENTIAL"):
        return os.environ["TTYD_CREDENTIAL"]
    # world-readable inside a volume that only control (rw) and the agent (ro) mount: the agent's ttyd needs it
    return _read_or_create(TTYD_FILE, lambda: "agent:" + secrets.token_urlsafe(24), 0o644)


def password_hash() -> str:
    """The stored hash (empty when the password comes from the environment or a proxy header)."""
    try:
        return PASSWORD_FILE.read_text().strip()
    except OSError:
        return ""


def password_generated() -> bool:
    """True while the stored password is still the one generated on first start."""
    return GENERATED_MARK.exists()


def ensure_password() -> None:
    """Generate a UI password on first start when nothing else is configured."""
    if os.environ.get("CONTROL_PASSWORD_HASH") or os.environ.get("CONTROL_PASSWORD") or password_hash():
        return
    pw = secrets.token_urlsafe(15)
    _write(PASSWORD_FILE, hash_password(pw))
    _write(GENERATED_MARK, "")
    bar = "=" * 72
    log.warning(
        "\n%s\n  tallygate web UI password: %s\n"
        "  It stays readable in this log until the log is rotated: change it after the first login with\n"
        "  docker compose exec control python -m app.passwd\n%s",
        bar,
        pw,
        bar,
    )
