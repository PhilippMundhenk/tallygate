# ADR-0007: Hard-deny on resolved IPs and pinning to the checked IP

- Status: Accepted; the hard-deny part amended by [ADR-0019](0019-one-ordered-rule-list.md) (2026-11-15)
- Date: 2026-11-11

> **Amended by [ADR-0019](0019-one-ordered-rule-list.md).** Kept: the gateway decides on **every resolved
> address** and pins the connection to the checked one. Replaced: `hard_deny` as a separate check before any
> rule that "cannot be approved away". The same ranges are now ordinary `deny` rules (the built-in blocks) at
> the bottom of one ordered rule list. A rule for a name still never opens them, which is what this ADR was
> about; a rule that names the address, placed above the block, does, and the operator can delete a block.
> The first consequence below ("unreachable regardless of rules") therefore holds only for the locked ranges:
> the stack's own networks and the gateway's own listeners.

## Context

Allowing a hostname must never allow reaching the LAN, the Docker host or cloud metadata endpoints — e.g.
via a public name that resolves to `192.168.x.x`, or a DNS rebinding attack that changes the answer between
check and connect.

## Decision

- The gateway resolves the destination itself and checks **every** address against `hard_deny` CIDRs before
  any rule (IPv4-mapped IPv6 normalised). Hard-deny cannot be approved away; only explicit admin-configured
  service-port exceptions bypass it.
- After an `allow` decision the upstream address is **pinned** to the first checked IP, so the connection
  cannot re-resolve to something else. For intercepted hosts the upstream SNI is set explicitly so the
  certificate is still verified against the hostname.

## Consequences

- ✅ LAN, host, Docker networks, link-local/metadata and CGNAT ranges are unreachable regardless of rules.
- ✅ Rebinding between decision and connect is impossible.
- ⚠️ Multi-address hosts always use the first address (no happy-eyeballs fallback); acceptable for this use.
