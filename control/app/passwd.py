"""Set the web UI password stored in the control volume:

    docker compose exec control python -m app.passwd

Takes effect at the next login, no restart needed. Has no effect while CONTROL_PASSWORD_HASH or
CONTROL_PASSWORD are set in the environment (they take precedence).
"""

import getpass
import os

from app.bootstrap import PASSWORD_FILE, _write, hash_password


def main() -> None:
    if os.environ.get("CONTROL_PASSWORD_HASH") or os.environ.get("CONTROL_PASSWORD"):
        raise SystemExit("CONTROL_PASSWORD_HASH / CONTROL_PASSWORD is set in the environment and takes precedence")
    pw = getpass.getpass("New password: ")
    if len(pw) < 12:
        raise SystemExit("use at least 12 characters")
    if pw != getpass.getpass("Repeat: "):
        raise SystemExit("mismatch")
    _write(PASSWORD_FILE, hash_password(pw))
    print(f"password updated ({PASSWORD_FILE})")


if __name__ == "__main__":
    main()
