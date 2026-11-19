#!/bin/bash
# Authoritative isolation test for a running tallygate stack. Run on the Docker host:
#
#   ./tests/integration/bypass.sh
#
# Uses a fresh, independent probe container (curlimages/curl) attached to agent-net, so a compromised
# agent image cannot fake the results, plus structural checks of the compose networks and containers.
set -uo pipefail
# Works from anywhere (also downloaded next to compose.yaml): it only talks to Docker, never to files.

PROJECT=${COMPOSE_PROJECT_NAME:-tallygate}
NET=${PROJECT}_agent-net
AGENT=${PROJECT}-agent-1
PROBE_IMAGE=docker.io/curlimages/curl:8.17.0
LISTENER_IMAGE=docker.io/library/busybox:1.37
HOST_PORT=18999
UDP_PORT=18998
GW=172.31.10.2
CTL=172.31.10.3
GW_CONTAINER=${PROJECT}-egress-gw-1
CTL_CONTAINER=${PROJECT}-control-1
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
for c in "$AGENT" "$GW_CONTAINER" "$CTL_CONTAINER"; do
  check "$c has IPv6 disabled (no link-local path)" \
    grep -q 'net.ipv6.conf.all.disable_ipv6:1' <<<"$(docker inspect -f '{{.HostConfig.Sysctls}}' "$c")"
done
for c in "$AGENT" "$GW_CONTAINER" "$CTL_CONTAINER"; do
  # the host's core_pattern usually hands a core dump to a handler on the host (systemd-coredump)
  check "$c writes no core dumps (ulimit core=0)" \
    grep -q 'core=0:0' <<<"$(docker inspect -f '{{.HostConfig.Ulimits}}' "$c")"
  check "$c is configured not to forward packets" \
    grep -q 'net.ipv4.ip_forward:0' <<<"$(docker inspect -f '{{.HostConfig.Sysctls}}' "$c")"
done
# Read inside the two dual-homed containers (gateway and control are trusted; the agent's own word is not).
for c in "$GW_CONTAINER" "$CTL_CONTAINER"; do
  for f in ip_forward conf/all/forwarding conf/all/proxy_arp; do
    check "$c: /proc/sys/net/ipv4/$f is 0 (not a router between agent-net and the outside)" \
      test "$(docker exec "$c" cat "/proc/sys/net/ipv4/$f" 2>/dev/null)" = 0
  done
done
check "agent has no docker.sock" bash -c "! docker inspect -f '{{.HostConfig.Binds}}' '$AGENT' | grep -q docker.sock"
# `tallygate install` unpacks into the home volume only: a write to the root filesystem must still fail.
check "agent cannot write to the root filesystem (/usr/bin)" \
  bash -c "! docker exec '$AGENT' sh -c 'touch /usr/bin/.tallygate-write-test' 2>/dev/null"
# python3 -I: the agent owns ~/.local (user site-packages) and its environment; isolated mode ignores both.
check "managed settings: bypass-mode prompt skipped (top-level key)" docker exec "$AGENT" python3 -I -c   "import json,sys; sys.exit(json.load(open('/etc/claude-code/managed-settings.json')).get('skipDangerousModePermissionPrompt') is not True)"

# A web server in the host's network namespace stands in for host services listening on 0.0.0.0
# (sshd, databases, exporters). The agent must not reach it through the bridge address of its network.
LISTENER=$(docker run -d --rm --network host "$LISTENER_IMAGE" httpd -f -p "0.0.0.0:$HOST_PORT" 2>/dev/null)
UDP_LISTENER=""   # started further down
trap 'for c in $LISTENER $UDP_LISTENER; do docker rm -f "$c" >/dev/null 2>&1; done' EXIT
BRIDGE_IP=$(docker network inspect -f '{{range .IPAM.Config}}{{.Gateway}}{{end}}' "$NET")
sleep 1
check "host listener is up (sanity check for the next probe)" test "$(docker run --rm --network host "$PROBE_IMAGE"   -s -m 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$HOST_PORT/" 2>/dev/null)" != 000

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
expect "host services via the bridge address unreachable" 000 "http://${BRIDGE_IP:-172.31.10.1}:$HOST_PORT/"
check "agent-net gives the host no address" test "$(docker network inspect -f '{{index .Options "com.docker.network.bridge.inhibit_ipv4"}}' "$NET")" = true
expect "unknown host is held, not connected"  '000|403|502' -x "http://$GW:3128" "https://exfil-$(date +%s).invalid/"
expect "grant API: listing works for the agent" 200       "http://$GW:8079/v1/grants"
expect "grant API: no admin endpoints"           404       "http://$GW:8079/grants"
expect "allowed path works (api.anthropic.com)" '[1-4][0-9][0-9]' -x "http://$GW:3128" https://api.anthropic.com/

echo "== UDP from agent-net to the host (independent probe containers)"
# TCP to the host is covered above (the bridge has no address, so there is nothing to connect to). UDP needs
# no answer: a datagram that reaches a host service listening on 0.0.0.0 (DNS resolver, mDNS, DHCP, syslog)
# is a one-way channel past the gateway. A listener in the host's network namespace must see none of:
#   - broadcast and multicast datagrams from agent-net,
#   - datagrams to the host's own addresses from a socket bound to the interface (SO_BINDTODEVICE needs no
#     capability and skips the routing table, which has no route to them),
#   - datagrams routed through the gateway or control as the next hop (they do not forward). The agent cannot
#     choose a next hop (no CAP_NET_ADMIN, no raw sockets); the probe can, to show the packet is dropped.
# The trusted gateway image supplies the Python for listener and sender; the agent's image is not involved.
GW_IMAGE=$(docker inspect -f '{{.Config.Image}}' "$GW_CONTAINER")
UDP_LISTEN='
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", int(sys.argv[1])))
print("listening", flush=True)
while True:
    data, peer = s.recvfrom(200)
    print(peer[0], data.decode("ascii", "replace").strip(), flush=True)
'
UDP_SEND='
import socket, sys, time
port = int(sys.argv[1])
def send(name, addr, dev=None, broadcast=False):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if broadcast:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        if dev:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, dev.encode())
        for _ in range(2):  # the first datagram may wait for ARP
            s.sendto(f"tallygate-probe-{name}".encode(), (addr, port))
            time.sleep(0.3)
        print(f"  sent      {name} -> {addr}")
    except OSError as e:
        print(f"  not sent  {name} -> {addr}: {e}")
if sys.argv[2] == "sanity":
    send("sanity", "127.0.0.1")
    sys.exit(0)
send("broadcast", "255.255.255.255", broadcast=True)
send("broadcast-dev", "255.255.255.255", dev="eth0", broadcast=True)
send("subnet-broadcast", "172.31.10.255", broadcast=True)
send("multicast", "224.0.0.1")
send("multicast-dev", "224.0.0.251", dev="eth0")
for i, addr in enumerate(sys.argv[2:]):
    send(f"hostaddr-{i}", addr)
    send(f"hostaddr-dev-{i}", addr, dev="eth0")
'
UDP_LISTENER=$(docker run -d --rm --network host --no-healthcheck --entrypoint python "$GW_IMAGE" \
  -I -u -c "$UDP_LISTEN" "$UDP_PORT" 2>/dev/null)
# the host's IPv4 addresses, as seen where the listener runs (the Docker host, or Docker Desktop's VM)
mapfile -t HOST_ADDRS < <(docker run --rm --network host "$LISTENER_IMAGE" ip -4 -o addr show 2>/dev/null \
  | awk '{print $4}' | cut -d/ -f1 | grep -v '^127\.' | head -8)
HOST_ADDR=$(docker run --rm --network host "$LISTENER_IMAGE" ip -4 route get 1.1.1.1 2>/dev/null \
  | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -1)
HOST_ADDR=${HOST_ADDR:-${HOST_ADDRS[0]:-}}
sleep 1
docker run --rm --network host --no-healthcheck --entrypoint python "$GW_IMAGE" -I -c "$UDP_SEND" "$UDP_PORT" sanity >/dev/null 2>&1
# the sender has what the agent has: agent-net only, no capabilities, no new privileges
docker run --rm --network "$NET" --cap-drop ALL --security-opt no-new-privileges:true --no-healthcheck \
  --entrypoint python "$GW_IMAGE" -I -c "$UDP_SEND" "$UDP_PORT" "${HOST_ADDRS[@]}" 2>&1
if [[ -n $HOST_ADDR ]]; then
  for hop in "$GW" "$CTL"; do
    # more than the agent can do: a route to the host's address through the gateway / control
    docker run --rm --network "$NET" --cap-drop ALL --cap-add NET_ADMIN "$LISTENER_IMAGE" sh -c \
      "ip route add $HOST_ADDR/32 via $hop && for i in 1 2; do echo tallygate-probe-nexthop-$hop | nc -u -w 1 $HOST_ADDR $UDP_PORT; done" \
      >/dev/null 2>&1
  done
else
  fail "no host address found for the next-hop probe"
fi
sleep 2
UDP_SEEN=$(docker logs "$UDP_LISTENER" 2>&1)
check "host UDP listener is up (sanity check for the next probes)" grep -q 'tallygate-probe-sanity' <<<"$UDP_SEEN"
udp_blocked() {  # udp_blocked "description" <probe name prefix>
  if grep -q "tallygate-probe-$2" <<<"$UDP_SEEN"; then
    fail "$1 (the host received: $(grep "tallygate-probe-$2" <<<"$UDP_SEEN" | sort -u | tr '\n' ';'))"
  else pass "$1"; fi
}
udp_blocked "UDP broadcast from agent-net does not reach host services" "broadcast"
udp_blocked "UDP subnet broadcast from agent-net does not reach host services" "subnet-broadcast"
udp_blocked "UDP multicast from agent-net does not reach host services" "multicast"
udp_blocked "UDP to the host's addresses (${#HOST_ADDRS[@]}) is not delivered, also not from a device-bound socket" "hostaddr"
udp_blocked "the gateway does not forward a packet routed through it ($GW -> $HOST_ADDR)" "nexthop-$GW"
udp_blocked "control does not forward a packet routed through it ($CTL -> $HOST_ADDR)" "nexthop-$CTL"

echo "== in-agent self-test"
# Runs inside the agent, so a compromised agent could fake it: the checks above do not depend on it.
# -I keeps the agent's home volume (user site-packages, PYTHON* variables) out of this interpreter.
docker exec "$AGENT" python3 -I /usr/local/bin/status.py --selftest || failed=1

echo
if [[ $failed == 0 ]]; then echo "ALL CHECKS PASSED"; else echo "SOME CHECKS FAILED"; exit 1; fi
