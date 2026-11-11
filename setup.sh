#!/bin/bash
# One-time host setup: create .env with random secrets, password hash, and state dirs with correct owners.
set -euo pipefail
cd "$(dirname "$0")"
[[ -f .env ]] || cp .env.example .env
set_var() { grep -q "^$1=" .env && sed -i "s|^$1=.*|$1=$2|" .env || echo "$1=$2" >> .env; }
get_var() { grep "^$1=" .env | head -1 | cut -d= -f2- | sed 's/[[:space:]]*#.*//'; }
rand() { python3 -c "import secrets;print(secrets.token_urlsafe($1))"; }

[[ -n "$(get_var GW_API_TOKEN)" ]]   || set_var GW_API_TOKEN "$(rand 32)"
[[ -n "$(get_var SESSION_SECRET)" ]] || set_var SESSION_SECRET "$(rand 32)"
[[ -n "$(get_var TTYD_CREDENTIAL)" ]] || set_var TTYD_CREDENTIAL "agent:$(rand 24)"
if [[ -z "$(get_var CONTROL_PASSWORD_HASH)" ]]; then
  echo "Choose the web UI password:"
  set_var CONTROL_PASSWORD_HASH "$(python3 control/hashpw.py)"
fi
chmod 600 .env

DIR=$(get_var TALLYGATE_DIR); DIR=${DIR:-./state}
mkdir -p "$DIR/gateway" "$DIR/agent-home" "$DIR/workspace"
chown -R 10001:10001 "$DIR/gateway"
chown -R 1000:1000 "$DIR/agent-home" "$DIR/workspace"
chmod 700 "$DIR/gateway"
echo "State in $DIR. Next: docker compose up -d --build, then open the UI and run the Setup wizard."
