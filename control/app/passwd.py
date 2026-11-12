"""Set the web UI password stored in the control volume:

    docker compose exec control python -m app.passwd

Takes effect at once, no restart needed: the next login needs the new password, and every session opened
with the old one ends at its next request. Has no effect while CONTROL_PASSWORD_HASH or CONTROL_PASSWORD
are set in the environment (they take precedence).

    docker compose exec control python -m app.passwd --print-hash

only prints a hash for CONTROL_PASSWORD_HASH (no checkout of the repository needed) and writes nothing.
"""

import argparse
import getpass
import os

from app.bootstrap import PASSWORD_FILE, _write, hash_password


def ask() -> str:
    pw = getpass.getpass("New password: ")
    if len(pw) < 12:
        raise SystemExit("use at least 12 characters")
    if pw != getpass.getpass("Repeat: "):
        raise SystemExit("mismatch")
    return pw


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="python -m app.passwd", description="Change the web UI password.")
    ap.add_argument(
        "--print-hash",
        action="store_true",
        help="print a scrypt hash for CONTROL_PASSWORD_HASH instead of storing the password",
    )
    args = ap.parse_args(argv)
    if args.print_hash:
        print(hash_password(ask()))
        return
    if os.environ.get("CONTROL_PASSWORD_HASH") or os.environ.get("CONTROL_PASSWORD"):
        raise SystemExit("CONTROL_PASSWORD_HASH / CONTROL_PASSWORD is set in the environment and takes precedence")
    _write(PASSWORD_FILE, hash_password(ask()))
    print(f"password updated ({PASSWORD_FILE}). Sessions opened with the old password end at their next request.")


if __name__ == "__main__":
    main()
