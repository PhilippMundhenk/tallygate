#!/bin/bash
# Authoritative isolation test for a running sluicegate stack. Run on the Docker host:
#
#   ./tests/integration/bypass.sh
#
# Uses a fresh, independent probe container (curlimages/curl) attached to agent-net, so a compromised
# agent image cannot fake the results, plus structural checks of the compose networks and containers.
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 2

PROJECT=${COMPOSE_PROJECT_NAME:-sluicegate}
NET=${PROJECT}_agent-net
AGENT=${PROJECT}-agent-1
PROBE_IMAGE=docker.io/curlimages/curl:8.17.0
GW=172.31.10.2
failed=0

pass() { printf 'PASS  %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*"; failed=1; }
check() {  # check "description" command...
  local desc=$1; shift
  if "$@"; then pass "$desc"; else fail "$desc"; fi
}
probe() {  # prints the HTTP status code (000 = no connection)
  docker run --rm --network "$NET" --dns "$GW" "$PROBE_IMAGE" -sS -m 8 -o /dev/null -w '%{http_code}' "$@" 2>/dev/null
}
expect() {  # expect "description" <regex for status code> curl-args...
  local desc=$1 want=$2; shift 2
  local got
  got=$(probe "$@")
  if [[ $got =~ ^($want)$ ]]; then pass "$desc ($got)"; else fail "$desc (got $got, want $want)"; fi
}

echo "== structure"
check "agent-net is internal"   test "$(docker network inspect -f '{{.Internal}}' "$NET")" = true
check "control-net is internal" test "$(docker network inspect -f '{{.Internal}}' "${PROJECT}_control-net")" = true
check "agent is attached to agent-net only" \
  test "$(docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$AGENT")" = "$NET "
check "agent drops all capabilities" grep -q ALL <<<"$(docker inspect -f '{{.HostConfig.CapDrop}}' "$AGENT")"
check "agent has a read-only root filesystem" test "$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' "$AGENT")" = true
check "agent has no docker.sock" bash -c "! docker inspect -f '{{.HostConfig.Binds}}' '$AGENT' | grep -q docker.sock"

echo "== egress from agent-net (independent probe container)"
expect "direct internet by IP is blocked"     000          https://1.1.1.1/
expect "direct internet by name is blocked"   000          https://example.com/
expect "LAN via HTTP proxy is blocked"        '000|403|502' -x "http://$GW:3128" http://192.168.1.1/
expect "cloud metadata IP via proxy blocked"  '000|403|502' -x "http://$GW:3128" http://169.254.169.254/
expect "LAN via SOCKS5 is blocked"            000          --socks5-hostname "$GW:1080" http://10.0.0.1/
expect "gateway API not on agent-net"         000          "http://$GW:8081/health"
expect "control-net not routable"             000          http://172.31.11.2:8081/health
expect "control UI not on agent-net"          000          http://172.31.10.3:8080/healthz
expect "mgmt-net not routable"                000          http://172.31.12.3:8080/healthz
expect "allowed path works (api.anthropic.com)" '[1-4][0-9][0-9]' -x "http://$GW:3128" https://api.anthropic.com/

echo "== in-agent self-test"
docker compose exec -T agent python3 /usr/local/bin/status.py --selftest || failed=1

echo
if [[ $failed == 0 ]]; then echo "ALL CHECKS PASSED"; else echo "SOME CHECKS FAILED"; exit 1; fi
