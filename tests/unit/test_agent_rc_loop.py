"""agent/rc-loop.sh: Remote Control comes back as the same environment and session (#214).

The script is run for real, with a fake `claude` on PATH that behaves like Remote Control does with its
pointer file: it writes the pointer when it is up, and discards one it does not accept."""

import json
import os
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "agent" / "rc-loop.sh"

# What the fake does is scripted per start in $PLAN (one word per line, the last one repeats):
#   up <env>   write the pointer for <env> (unless one is there, which it keeps: a resume) and stay up
#   refuse     discard the pointer and fail at once ("already served" / an environment the server forgot)
#   down       fail at once and leave the pointer alone (no network)
FAKE = r"""#!/bin/bash
echo "$*" >> "$CALLS"
n=$(wc -l < "$CALLS")
step=$(sed -n "${n}p" "$PLAN"); [ -n "$step" ] || step=$(tail -n 1 "$PLAN")
echo "seen: $(cat "$RC_POINTER" 2>/dev/null)" >> "$SEEN"
case $step in
  up*)   [ -s "$RC_POINTER" ] || { mkdir -p "$(dirname "$RC_POINTER")"; echo "{\"sessionId\": \"s-${step#up }\", \"environmentId\": \"${step#up }\"}" > "$RC_POINTER"; }
         sleep "${UP_FOR:-3}"; exit 0 ;;
  refuse) rm -f "$RC_POINTER"; echo "Error: This folder is already served"; exit 1 ;;
  down)  echo "Error: proxy refused the connection"; exit 1 ;;
esac
"""


@pytest.fixture
def loop(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "claude").write_text(FAKE)
    (bin_dir / "claude").chmod(0o755)
    try:  # on a noexec temp directory the fake is not found and the REAL claude would be started
        subprocess.run(
            [str(bin_dir / "claude")],
            env={"CALLS": os.devnull, "PLAN": os.devnull, "SEEN": os.devnull, "RC_POINTER": os.devnull},
            check=False,
            timeout=10,
        )
    except PermissionError:
        pytest.skip("the temp directory is mounted noexec (run with --basetemp on another file system)")
    work = tmp_path / "work"
    work.mkdir()
    pointer, kept = tmp_path / "home" / "projects" / "bridge-pointer.json", tmp_path / "home" / "kept.json"
    kept.parent.mkdir()

    def run(plan: list[str], starts: int, **env) -> subprocess.CompletedProcess:
        (tmp_path / "plan").write_text("\n".join(plan) + "\n")
        for f in ("calls", "seen"):
            (tmp_path / f).write_text("")
        full = {
            **os.environ,
            "PATH": f"{bin_dir}:{os.environ['PATH']}",
            "HOME": str(tmp_path / "home"),
            "RC_DIR": str(work),
            "RC_POINTER": str(pointer),
            "RC_POINTER_KEEP": str(kept),
            "RC_RESTART_DELAY": "0",
            "RC_KEEP_INTERVAL": "0.2",
            "RC_MIN_RUN": "2",  # whole seconds: a start that fails at once measures 0 or 1
            "RC_LOOP_MAX": str(starts),
            "PLAN": str(tmp_path / "plan"),
            "CALLS": str(tmp_path / "calls"),
            "SEEN": str(tmp_path / "seen"),
            **{k: str(v) for k, v in env.items()},
        }
        return subprocess.run(["bash", str(SCRIPT)], env=full, capture_output=True, text=True, timeout=60)

    run.pointer, run.kept, run.tmp = pointer, kept, tmp_path
    run.seen = lambda: [
        json.loads(line[6:])["environmentId"] if line[6:] else None
        for line in (tmp_path / "seen").read_text().splitlines()
    ]
    return run


def env_of(path: Path) -> str:
    return json.loads(path.read_text())["environmentId"]


def test_the_command_line_and_the_kept_copy_of_the_pointer(loop):
    r = loop(["up env_a"], 1, RC_NAME="my agent", AGENT_PERMISSION_MODE="default", RC_ARGS="--spawn worktree")
    assert r.returncode == 0, r.stderr
    assert (
        loop.tmp / "calls"
    ).read_text() == "remote-control --name my agent --permission-mode default --spawn worktree\n"
    assert env_of(loop.kept) == "env_a"  # remembered while it ran, on the home volume
    # the defaults
    r = loop(["up env_a"], 1, RC_NAME="", AGENT_PERMISSION_MODE="")
    assert (loop.tmp / "calls").read_text() == "remote-control --name tallygate --permission-mode bypassPermissions\n"


def test_a_pointer_that_got_lost_or_too_old_is_put_back_before_the_start(loop):
    """What happened in #214: after hours without the gateway Claude Code no longer believed its pointer, and
    the session was left behind. With the kept copy the next start is the same environment again."""
    loop(["up env_a"], 1)
    loop.pointer.unlink()  # discarded by Claude Code
    r = loop(["up env_b"], 1)
    assert "pointer restored: the same environment and session as before" in r.stdout
    assert loop.seen() == ["env_a"] and env_of(loop.pointer) == "env_a" and env_of(loop.kept) == "env_a"
    # a pointer that is there but old is made fresh, so that it is not discarded as stale
    old = loop.pointer.stat().st_mtime - 6 * 3600
    os.utime(loop.pointer, (old, old))
    loop(["down"], 1)
    assert loop.pointer.stat().st_mtime > old + 5 * 3600 and env_of(loop.pointer) == "env_a"
    # garbage in the pointer is not copied over the good copy
    loop.pointer.write_text("{not json")
    loop(["down"], 1)
    assert env_of(loop.kept) == "env_a" and env_of(loop.pointer) == "env_a"


def test_an_outage_never_costs_the_environment(loop):
    """Every start fails while the gateway is away, and Claude Code throws the pointer away on the way. When
    the network is back the kept environment is the one that is served."""
    loop(["up env_a"], 1)
    r = loop(["down", "refuse", "down", "refuse", "down", "refuse", "refuse", "up env_new"], 8)
    assert r.returncode == 0, r.stdout + r.stderr
    seen = loop.seen()
    assert seen[-1] == "env_a" and env_of(loop.kept) == "env_a"  # came up as the old one
    assert seen.count(None) == 1  # one start in between was tried without the pointer (see the next test)


def test_when_the_server_no_longer_knows_the_environment_a_new_one_is_taken(loop):
    """The kept pointer is refused again and again: after RC_POINTER_TRIES starts one is made without it. That
    registers a new environment, which is the one remembered from then on."""
    loop(["up env_a"], 1)
    r = loop(["refuse", "refuse", "refuse", "up env_b", "up env_b"], 5, RC_POINTER_TRIES=3)
    assert "3 starts with the kept pointer failed: one start without it" in r.stdout
    assert loop.seen() == ["env_a", "env_a", "env_a", None, "env_b"]
    assert env_of(loop.kept) == "env_b" and env_of(loop.pointer) == "env_b"
    # ... and if the start without it is refused too ("already served": the server does know the old one), the
    # kept pointer is not lost: it is put back for the next start
    loop.kept.write_text(json.dumps({"sessionId": "s", "environmentId": "env_a"}))
    loop.pointer.unlink()
    loop(["refuse", "refuse", "refuse", "refuse", "up env_c"], 5, RC_POINTER_TRIES=3)
    assert loop.seen() == ["env_a", "env_a", "env_a", None, "env_a"] and env_of(loop.kept) == "env_a"


def test_without_any_pointer_it_just_starts_and_restarts(loop):
    r = loop(["down", "up env_a"], 2)
    assert loop.seen() == [None, None] and env_of(loop.kept) == "env_a"
    assert "remote-control exited (1) - restarting in 0s; Ctrl-C to stop the loop" in r.stdout
