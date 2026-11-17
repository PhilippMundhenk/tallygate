#!/bin/bash
# tallygate: keep `claude remote-control` running, as the SAME environment with the SAME session (#214).
#
# Remote Control remembers which environment and session it serves for a directory in a small pointer file
# (~/.claude/projects/<dir>/bridge-pointer.json). With a fresh pointer a restart comes back as the same
# environment. Claude Code discards the pointer when it is older than about four hours - after a long outage
# of the gateway or the network, say - and then either refuses to start ("This folder is already served") or
# registers a new environment, and the session in the Claude app is left behind as "environment deleted".
# So a copy of the pointer is kept on the home volume and put back before every start.
set -u

DIR=${RC_DIR:-/workspace}
POINTER=${RC_POINTER:-$HOME/.claude/projects/$(printf %s "$DIR" | sed 's/[^A-Za-z0-9]/-/g')/bridge-pointer.json}
KEEP=${RC_POINTER_KEEP:-$HOME/.claude/tallygate-rc-pointer.json}
DELAY=${RC_RESTART_DELAY:-10}    # seconds between two starts
MIN_RUN=${RC_MIN_RUN:-60}        # a run shorter than this did not come up
GIVE_UP=${RC_POINTER_TRIES:-5}   # failed starts with the kept pointer before one start without it
MAX=${RC_LOOP_MAX:-0}            # stop after this many starts (0 = never; for tests)

say() { echo "[rc-loop] $*"; }

valid() {  # a pointer that names an environment
  python3 -c 'import json, sys; sys.exit(0 if json.load(open(sys.argv[1])).get("environmentId") else 1)' "$1" 2>/dev/null
}

keep() {  # remember the pointer Remote Control is using
  if valid "$POINTER" && ! cmp -s "$POINTER" "$KEEP"; then
    cp "$POINTER" "$KEEP.tmp" && mv "$KEEP.tmp" "$KEEP"
  fi
}

restore() {  # before a start: a pointer that is there and not too old to be believed
  if valid "$POINTER"; then
    keep
    touch "$POINTER"
  elif valid "$KEEP"; then
    mkdir -p "$(dirname "$POINTER")" && cp "$KEEP" "$POINTER" && say "pointer restored: the same environment and session as before"
  fi
}

cd "$DIR" || exit 1
failed=0 starts=0
while true; do
  if (( failed >= GIVE_UP )) && valid "$KEEP"; then
    # The kept environment was not accepted several times in a row. Try once without it: if the server no
    # longer knows it, this registers a new one; if it does, this start is refused and the pointer comes back.
    say "$failed starts with the kept pointer failed: one start without it"
    rm -f "$POINTER"
    failed=0
  else
    restore
  fi
  ( while sleep "${RC_KEEP_INTERVAL:-30}"; do keep; done ) &
  keeper=$!
  began=$SECONDS
  # shellcheck disable=SC2086  # RC_ARGS is a list of arguments
  claude remote-control --name "${RC_NAME:-tallygate}" --permission-mode "${AGENT_PERMISSION_MODE:-bypassPermissions}" ${RC_ARGS:-}
  code=$?
  kill "$keeper" 2>/dev/null
  wait "$keeper" 2>/dev/null
  keep
  if (( SECONDS - began < MIN_RUN )); then failed=$((failed + 1)); else failed=0; fi
  starts=$((starts + 1))
  (( MAX > 0 && starts >= MAX )) && exit "$code"
  echo
  say "remote-control exited ($code) - restarting in ${DELAY}s; Ctrl-C to stop the loop"
  sleep "$DELAY"
done
