"""Stand-ins for the tools agent/status.py drives inside the agent container: tmux, claude, gh and git.

The e2e tests put wrappers named after them on PATH (see conftest.fake_agent). State lives in FAKE_STATE:
- tmux/<session>/: the pane's output (log), its input (a FIFO) and the pid of the command
- gh-mode: ok | 401 | down (what `gh api -i user` answers)
- login-url: the URL `claude auth login` prints; good-code: the code it accepts
- gitconfig.json: `git config --global`
"""

from __future__ import annotations

import contextlib
import json
import os
import signal
import subprocess
import sys
from pathlib import Path

STATE = Path(os.environ["FAKE_STATE"])


def read(name: str, default: str = "") -> str:
    try:
        return (STATE / name).read_text().strip()
    except OSError:
        return default


# ---------------------------------------------------------------- tmux
def tmux(args: list[str]) -> int:
    cmd = args[0]
    opt = {args[i]: args[i + 1] for i in range(1, len(args) - 1) if args[i].startswith("-")}
    name = opt.get("-s") or opt.get("-t", "")
    d = STATE / "tmux" / name
    with open(STATE / "tmux.log", "a") as log:
        log.write(json.dumps(args) + "\n")
    if cmd == "new-session":
        if d.exists():
            print(f"duplicate session: {name}", file=sys.stderr)
            return 1
        d.mkdir(parents=True)
        os.mkfifo(d / "in")
        out = open(d / "out", "w")
        stdin = os.open(d / "in", os.O_RDWR)  # does not block, unlike O_RDONLY without a writer
        p = subprocess.Popen(
            ["sh", "-c", args[-1]], stdin=stdin, stdout=out, stderr=subprocess.STDOUT, start_new_session=True
        )
        (d / "pid").write_text(str(p.pid))
        return 0
    if not d.exists():
        print(f"can't find session: {name}", file=sys.stderr)
        return 1
    if cmd == "kill-session":
        with contextlib.suppress(OSError, ValueError):
            os.killpg(int((d / "pid").read_text()), signal.SIGKILL)
        for f in d.iterdir():
            f.unlink()
        d.rmdir()
    elif cmd == "capture-pane":
        sys.stdout.write((d / "out").read_text())
    elif cmd == "send-keys":
        text = args[-1] if "-l" in args else {"Enter": "\n"}.get(args[-1], "")
        fd = os.open(d / "in", os.O_WRONLY | os.O_NONBLOCK)
        os.write(fd, text.encode())
        os.close(fd)
    return 0


# ---------------------------------------------------------------- claude
def claude(args: list[str]) -> int:
    if args == ["--version"]:
        print("2.1.304 (Claude Code)")
        return 0
    if args[:2] == ["auth", "login"]:
        print("Opening browser to sign in…")
        print(
            "If the browser didn't open, visit: "
            + read("login-url", "https://claude.com/cai/oauth/authorize?code=true&state=e2e")
        )
        print("Paste code here if prompted > ", end="", flush=True)
        code = sys.stdin.readline().strip()
        if code and code == read("good-code", "good-code-1234#e2e"):
            creds = Path.home() / ".claude" / ".credentials.json"
            creds.parent.mkdir(parents=True, exist_ok=True)
            creds.write_text("{}")
            print("Login successful.")
            return 0
        print("Login failed: invalid code")
        return 1
    return 1


# ---------------------------------------------------------------- gh
def gh(args: list[str]) -> int:
    if args != ["api", "-i", "user"]:
        return 1
    mode = read("gh-mode", "ok")
    if mode == "down":
        print('Get "https://api.github.com/user": Forbidden', file=sys.stderr)
        return 1
    if mode == "401":
        sys.stdout.write(
            'HTTP/2.0 401 Unauthorized\r\nContent-Type: application/json\r\n\r\n{"message":"Bad credentials"}'
        )
        print("gh: Bad credentials (HTTP 401)", file=sys.stderr)
        return 1
    sys.stdout.write(
        "HTTP/2.0 200 OK\r\nContent-Type: application/json\r\n"
        "Github-Authentication-Token-Expiration: 2027-01-01 00:00:00 UTC\r\n\r\n"
        + json.dumps({"id": 583231, "login": "octocat", "name": "The Octocat"})
    )
    return 0


# ---------------------------------------------------------------- git
def git(args: list[str]) -> int:
    f = STATE / "gitconfig.json"
    cfg = json.loads(f.read_text()) if f.exists() else {}
    if args[:3] == ["config", "--global", "--get"]:
        if args[3] not in cfg:
            return 1
        print(cfg[args[3]])
        return 0
    if args[:2] == ["config", "--global"] and len(args) == 4:
        cfg[args[2]] = args[3]
        f.write_text(json.dumps(cfg))
        return 0
    return 1


if __name__ == "__main__":
    sys.exit({"tmux": tmux, "claude": claude, "gh": gh, "git": git}[sys.argv[1]](sys.argv[2:]))
