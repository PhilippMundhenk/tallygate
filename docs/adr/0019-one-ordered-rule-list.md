# ADR-0019: One ordered rule list, first match wins

- Status: Accepted
- Date: 2026-11-15
- Issue: #208
- Supersedes: ADR-0017 (`floor_open`), the `lan` part of ADR-0014 §4 and the "a CIDR deny wins wherever it
  stands" rule of #119. Keeps: ADR-0007 (decide on resolved IPs, pin the connection to them).

## Outcome

Accepted by the maintainer in the Nov 2026 UI review. Reaching one device on the local network needed either
a file edit (`grants_lan_allow`) or unblocking a whole built-in range and re-blocking the rest. An allow rule
for a local address silently did nothing. The policy becomes what operators know from other firewalls
(pfSense, ufw, iptables, Azure NSG, Squid): **one ordered list, evaluated top to bottom, the first matching
rule decides, a default at the end.** Local addresses are handled like any other address.

## The list

From top to bottom:

1. **Rules**: the operator's rules, approvals (inserted at the top, as today), shortcuts and active grants,
   in the order shown. Every rule can be moved up and down.
2. **Built-in blocks**: the private, loopback, link-local/metadata, carrier-NAT, multicast and special
   ranges (today `DEFAULT_HARD_DENY` and `DEFAULT_NEVER`), and the `never` entries of `gateway.yaml`. They
   are ordinary `deny` rules with `source: builtin` (or `config`), seeded once at the bottom. They can be
   moved, edited and deleted like any rule; *Restore built-in blocks* adds the missing ones back at the bottom.
3. **Locked: the stack's own networks and the gateway's own listeners** (`GW_INTERNAL_NETS`, own sockets).
   Shown as the last rows before the default so the operator sees them, marked *locked*, with no actions.
   They are enforced **before** the list is walked, whatever the list says: an agent that could reach the
   control plane or the gateway API could remove every other rule.
4. **Default**: `ask` (or `deny` / `allow`, under *Settings*), shown as the last line.

## Evaluation

A destination is a name or an IP literal, a port, and the resolved addresses (ADR-0007). For **each**
resolved address the list is walked top to bottom; the connection gets the most restrictive result over all
addresses (`deny` > `ask` > `allow`).

- Locked ranges: `deny`, before anything else.
- An **address rule** (IP or CIDR) matches when the address is inside it (and the port matches). First
  match is final: `allow`, `ask` or `deny`.
- A **name rule** (host pattern) matches the name (and the port). `deny` is final. `allow` / `ask` is
  **provisional**: the walk continues below it, looking only at address rules with `deny`. If one matches,
  the result is `deny`.
- Nothing matches: the default.

So an address `allow` placed above a range block opens that address; a range block placed above it closes
part of it again; layers work as in other firewalls.

### Why a name rule cannot open a blocked range

Names are chosen by whoever controls DNS. If `allow *.example.com` could override the block of
`192.168.0.0/16`, pointing `x.example.com` at `192.168.44.1` would walk the agent into the local network (DNS
rebinding). Squid (`dstdomain` vs `dst`) and Smokescreen draw the same line: only a rule that names the
address opens it.

This must be **visible, not only documented**:

- The decision reason says it: `name allowed by rule <id>, but it resolves to <ip>, inside blocked range
  <cidr> (rule <id>): add an allow for the address above that rule`. It is in the log, in *Test a
  destination* and in the denial the agent gets.
- The gateway records it per rule (`shadowed`: count, last time, last address and blocking rule). The
  Destinations table marks such a name rule (*blocked by a range rule below — last: …*) with the way out.
- Static cases are marked without waiting for traffic: an address rule that can never match because an
  earlier address rule covers it completely is shown as *never reached (covered by rule …)*.

## Grants

A grant is a bundle of destinations with paths, levels, a time limit and approval. An **active** grant
behaves like rules at the top of the list for its targets. A target with an IP literal or a fixed `address`
is an address rule and may therefore be local. A target that is only a name is a name rule and cannot open a
blocked range; saving such a target whose name currently resolves into a blocked range is refused with that
explanation and the address to pin. The locked ranges apply to grants as to everything else.

`grants_lan_allow`, the `lan` flag of targets and the separate `never` scope `all+lan` are gone: they are
read from old files and ignored (logged once). Credentials and `tls.verify: false` stay file-only (ADR-0014 §4).

## Consequences

- An authenticated UI session can allow a local address. That was already decided in ADR-0017; what is new
  is that it can be done narrowly (one host and port) instead of by opening a /16.
- "A CIDR deny wins wherever it stands" (#119) no longer holds: position decides. What #119 protected is
  kept differently: approvals and shortcuts are name rules or are inserted for the approved address only,
  and a name rule never overrides an address block below it.
- The agent can never reach the stack itself; that check does not depend on the list.
- The pre-DNS decision on the name alone may only short-cut where the result cannot depend on the addresses.

## Migration

`policy.yaml` is migrated once at start (backup `*.pre-0019`, fail closed as in ADR-0014 §5):

- Existing CIDR `deny` rules move to the top, in their order: they won everywhere before, and keep winning.
- `hard_deny` extras become address `deny` rules above the built-in blocks.
- The built-in blocks are seeded at the bottom, except ranges listed in `floor_open` (the operator had
  opened them). `floor_open` and `hard_deny` are then dropped from the file.
- Which built-in and config blocks were seeded is remembered, so a deleted block stays deleted across
  restarts and a `never` entry added to `gateway.yaml` later is seeded once.
- Grants: `lan: true` is dropped; a LAN target that is only a name keeps working only with a fixed
  `address` (the migration log names such targets).

## Changelog

- 2026-11-15: accepted.
