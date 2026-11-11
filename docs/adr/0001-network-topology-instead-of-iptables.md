# ADR-0001: Enforce isolation via Docker network topology, not iptables

- Status: Accepted
- Date: 2026-11-11

## Context

Common sandboxes for coding agents (e.g. Anthropic's reference dev container) restrict egress with an
`iptables` script inside the agent container. That needs `NET_ADMIN`/`NET_RAW` in the agent container (at
least at startup), resolves allowlisted domains to IPs once at startup (breaks with CDNs and rotating IPs),
has had IPv6 gaps, and places the enforcement inside the trust zone it is supposed to restrict.

## Decision

The agent is attached **only** to a Docker network with `internal: true`, which has no default route.
Its only useful peer on that network is the gateway. All policy is enforced in the gateway at the
application layer (domain/IP/port), outside the agent's container.

## Consequences

- ✅ Fail-closed by construction: a tool that ignores proxy settings simply cannot connect.
- ✅ The agent needs no capabilities at all (`cap_drop: ALL`).
- ✅ Domain-based decisions at connect time; no startup-time IP snapshots.
- ✅ No kernel firewall rules to maintain in containers; works with rootless Docker.
- ⚠️ Clients must use the proxy (env vars are set) or a service port; transparent interception is not possible.
- ⚠️ UDP/ICMP egress is unavailable to the agent (acceptable; QUIC falls back to TCP).
- ⚠️ An internal network still gives the host an address on the bridge, and traffic to the host itself
  is not filtered by Docker. `agent-net` and `control-net` therefore set
  `com.docker.network.bridge.inhibit_ipv4` (#7).
- ⚠️ Docker's embedded DNS still answers on the internal network; mitigated by [ADR-0006](0006-dns-nxdomain-for-the-agent.md).
