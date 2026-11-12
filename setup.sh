#!/bin/bash
# Optional host setup. tallygate needs no configuration: secrets and the UI password are created on
# first start. This script only
#   - creates .env from .env.example (if missing), readable only by you, and
#   - with a directory argument, keeps the state in host directories instead of Docker volumes:
#       ./setup.sh /srv/tallygate      -> /srv/tallygate/{gateway,agent-home,workspace} with the right owners
# Run it as your normal user; it uses sudo only to create and chown the state directories.
set -euo pipefail
cd "$(dirname "$0")"

if [[ ! -f .env ]]; then
  (umask 077 && cp .env.example .env)
  echo "created .env"
fi
set_var() { if grep -q "^$1=" .env; then sed -i "s|^$1=.*|$1=$2|" .env; else echo "$1=$2" >>.env; fi; }

if [[ -n "${1:-}" ]]; then
  DIR=$(realpath -m "$1")
  SUDO=""; [[ $(id -u) -eq 0 ]] || SUDO=sudo
  $SUDO mkdir -p "$DIR/gateway" "$DIR/agent-home" "$DIR/workspace" "$DIR/control-data"
  $SUDO chown 10001:10001 "$DIR/gateway"                      # gateway user
  $SUDO chown 1000:1000 "$DIR/agent-home" "$DIR/workspace"    # agent user
  $SUDO chown 10002:10002 "$DIR/control-data"                # control user
  $SUDO chmod 700 "$DIR/gateway" "$DIR/control-data"
  set_var GATEWAY_DATA "$DIR/gateway"
  set_var AGENT_HOME "$DIR/agent-home"
  set_var WORKSPACE "$DIR/workspace"
  set_var CONTROL_DATA "$DIR/control-data"
  echo "state in $DIR (GATEWAY_DATA, AGENT_HOME, WORKSPACE, CONTROL_DATA set in .env)"
fi
echo "Next: docker compose up -d   (or 'make up' to build from this checkout)"
echo "      docker compose logs control | grep -A1 password   (first start: generated UI password)"
