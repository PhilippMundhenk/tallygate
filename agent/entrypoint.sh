#!/bin/bash
# tallygate agent entrypoint: trust gateway CA, set placeholder credentials, start consoles + Remote Control.
set -uo pipefail

log() { echo "[agent] $*"; }
# State directories must be writable (bind mounts owned by root are the usual mistake, #95).
for d in "$HOME" /workspace; do
  probe="$d/.write-test-$$"
  if ! { : >"$probe"; } 2>/dev/null; then
    log "ERROR: cannot write to $d (the agent runs as uid $(id -u)). If it is a bind mount, give the host"
    log "directory to that user, e.g. chown $(id -u):$(id -g) <host directory>. See docs/operations.md#host-directories."
    exit 1
  fi
  rm -f "$probe"
done
# Console credential (user:pass) shared with the control plane: from the environment, or created by
# control on its first start in a volume mounted read-only here.
if [[ -z "${TTYD_CREDENTIAL:-}" ]]; then
  CRED_FILE=${TTYD_CREDENTIAL_FILE:-/run/tallygate/ttyd/credential}
  for _ in $(seq 1 60); do [[ -s $CRED_FILE ]] && break; sleep 1; done
  [[ -s $CRED_FILE ]] || { log "ERROR: TTYD_CREDENTIAL not set and $CRED_FILE missing (is control running?)"; exit 1; }
  TTYD_CREDENTIAL=$(<"$CRED_FILE")
fi
PERMISSION_MODE=${AGENT_PERMISSION_MODE:-bypassPermissions}
RC_NAME=${RC_NAME:-tallygate}

# Packages installed rootless with `tallygate install` live on the home volume; put them on PATH for the
# consoles and Remote Control started below (the same snippet runs for interactive login shells).
if [[ -f /etc/profile.d/tallygate-install.sh ]]; then
  # shellcheck source=/dev/null
  . /etc/profile.d/tallygate-install.sh
fi

# ---------------------------------------------------------------- CA of the egress gateway
CA=/ca/egress-gw-ca.pem
for _ in $(seq 1 30); do [[ -s $CA ]] && break; sleep 1; done
if [[ -s $CA ]]; then
  cat /etc/ssl/certs/ca-certificates.crt "$CA" > /tmp/ca-bundle.pem
  export SSL_CERT_FILE=/tmp/ca-bundle.pem CURL_CA_BUNDLE=/tmp/ca-bundle.pem REQUESTS_CA_BUNDLE=/tmp/ca-bundle.pem \
         GIT_SSL_CAINFO=/tmp/ca-bundle.pem NODE_EXTRA_CA_CERTS=$CA PIP_CERT=/tmp/ca-bundle.pem
  log "trusting egress gateway CA"
else
  log "WARNING: gateway CA not found at $CA - GitHub credential injection will fail TLS verification"
fi

# ---------------------------------------------------------------- placeholder credentials
# The real GitHub token lives only in the gateway, which overwrites the Authorization header.
export GH_TOKEN=${GH_TOKEN:-injected-by-egress-gateway}
if ! git config --global --get credential.https://github.com.helper >/dev/null 2>&1; then
  git config --global credential.https://github.com.helper \
    '!f() { echo username=x-access-token; echo password=injected-by-egress-gateway; }; f'
fi
git config --global --get init.defaultBranch >/dev/null || git config --global init.defaultBranch main

# ---------------------------------------------------------------- Claude defaults (first start only)
mkdir -p ~/.claude
if [[ ! -f ~/.claude/settings.json ]]; then
  printf '{\n  "permissions": { "defaultMode": "%s" }\n}\n' "$PERMISSION_MODE" > ~/.claude/settings.json
fi

# ---------------------------------------------------------------- processes
start_rc() {
  [[ "${RC_ENABLE:-1}" == "1" ]] || return 0
  tmux has-session -t rc 2>/dev/null && return 0
  tmux new-session -d -s rc -x 200 -y 50 \
    "cd /workspace; while true; do claude remote-control --name '$RC_NAME' --permission-mode '$PERMISSION_MODE' ${RC_ARGS:-}; \
     echo; echo '[remote-control exited - restarting in 10s; Ctrl-C to stop the loop]'; sleep 10; done"
  log "remote-control started in tmux session 'rc'"
}

declare -A PIDS
start_ttyd() {  # name port command...
  local name=$1 port=$2; shift 2
  ttyd -p "$port" -W -c "$TTYD_CREDENTIAL" -b "/term/$name" -t titleFixed="tallygate · $name" \
       -t fontSize=14 -t disableLeaveAlert=true "$@" >"/tmp/ttyd-$name.log" 2>&1 &
  PIDS[$name]=$!
}

start_all() {
  start_rc
  if [[ -z "${PIDS[status]:-}" ]] || ! kill -0 "${PIDS[status]}" 2>/dev/null; then
    python3 /usr/local/bin/status.py &
    PIDS[status]=$!
  fi
  for spec in "rc:7681:tmux new-session -A -s rc" "bash:7682:tmux new-session -A -s bash -c /workspace" \
              "claude:7683:tmux new-session -A -s claude -c /workspace claude --permission-mode $PERMISSION_MODE"; do
    IFS=: read -r name port cmd <<<"$spec"
    if [[ -z "${PIDS[$name]:-}" ]] || ! kill -0 "${PIDS[$name]}" 2>/dev/null; then
      # shellcheck disable=SC2086
      start_ttyd "$name" "$port" $cmd
    fi
  done
}

trap 'log "stopping"; tmux kill-server 2>/dev/null; kill "${PIDS[@]}" 2>/dev/null; exit 0' TERM INT
log "consoles: rc:7681 bash:7682 claude:7683 · status:7680 · permission mode: $PERMISSION_MODE"
while true; do
  start_all
  sleep 5
done
