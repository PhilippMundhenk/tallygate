# ADR-0019: One ordered rule list, first match wins

- Status: Accepted
- Date: 2026-11-15
- Issue: #208
- Supersedes: ADR-0017 (`floor_open`), the `lan` part of ADR-0014 §4 and the "a CIDR deny wins wherever it
  stands" rule of #119. Keeps: ADR-0007 (decide on resolved IPs, pin the connection to them), ADR-0011
  (decide on the name before resolving it) and ADR-0013 (an approved address is not an approval of the names
  that resolve to it).
- Amended 2026-11-17 after the security review of the implementation: see [Amendment](#amendment-2026-11-17-names-pass-two-checks).
  Where the sections below and the amendment differ, the amendment holds.

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

## Amendment (2026-11-17): names pass two checks

The security review of the implementation (PR #211) showed that walking one list for a *name* destination
gave up two things the earlier ADRs had secured, and that the migration opened what had been closed.

**What went wrong with "an address rule is final, also for a name":**

- One address `allow` for a port anywhere in the list meant that no `deny` or `ask` for a name on that port
  could be acted on before DNS any more: an address might still allow it. After the operator approved a
  single IP literal, the gateway resolved every name the agent asked for (DNS exfiltration, ADR-0011).
- An approved address allowed every name that resolves to it, with that name's SNI and Host, and outranked a
  name `deny` below it. On a shared CDN address that is another site (ADR-0013).

**Decision.** A destination given as an **IP literal** is decided as described above: the list top to bottom,
the first matching address rule is final. A catch-all name rule (`*`) with `allow` or `ask` above it does not
change that: the address rule below it decides (the more restrictive of the two, so an `ask` for `*` still
asks), and only when no address rule contains the address does the `*` rule. A destination given by **name** must pass two checks:

1. **The name**: the first matching name rule, else the default. `deny` and `ask` are acted on before the
   name is resolved, always. A name `deny` wins wherever it stands.
2. **Each resolved address**: locked ranges deny. Otherwise the first address rule with `allow` or `deny`
   that contains the address says whether the address is open: `deny` blocks it (with the reason from
   "Why a name rule cannot open a blocked range"), `allow` or no such rule leaves the result of step 1.
   Address `ask` rules are a question about an IP literal and are skipped for names.

So an address `allow` above a range block still opens that address for a name, but only for a name that is
allowed by name; it never lets a name through by itself. The position of a name rule relative to address
rules no longer matters: the order among the name rules decides step 1, the order among the address rules
decides step 2. "The pre-DNS decision may only short-cut where the result cannot depend on the addresses"
(Consequences) is now true for every `deny` and `ask`.

**Migration.** An address `allow`/`ask` rule never had an effect inside a blocked range. A built-in, config
or `hard_deny` block that such a rule overlaps is therefore placed at the **top** of the migrated list (after
the CIDR `deny` rules), not at the bottom, and the log names the rules. Nothing that was blocked opens by
upgrading; the operator moves a rule above its block to open the address. Restoring an old history version
and importing an old export record the same notes.

**Also decided here:**

- A seeded block takes no time limit (it would be pruned and, being remembered as seeded, never return), and
  a seeded block whose action is changed becomes an ordinary rule of the operator (`source: user`).
- Replacing the whole policy (PUT, import, restore) records which built-in and config blocks are not in
  force afterwards.
- The locked ranges also match an IPv6 address that carries a locked IPv4 address (NAT64, 6to4,
  IPv4-compatible).
- A grant target that is only a name is checked like a name rule: an address `allow` above the block opens
  the address for it too.
- Kept as decided under "Grants": a grant target with an IP literal or a fixed `address` is not subject to
  the blocks or to `deny` rules, only to the locked ranges. That includes loopback and metadata addresses and
  the `never` entries of `gateway.yaml`, which were closed to grants before. A target of that kind stored
  before the upgrade without `lan` was refused and now works while its grant is active; the migration log
  names each one.

**2026-11-17, second review** (of this amendment; findings in
[security-review.md](../security-review.md)). Decided:

- A host whose last label is a number (`192.168.1.1.`, `127.1`, `2130706433`, `0x7f.1`) is an IP address in
  another spelling, not a name: it is refused as an invalid host name, never asked about and never resolved.
- An approval is never the rule that opens a blocked range: an allowing answer for an IP address that an
  address `deny` rule blocks is refused. Opening such an address takes a rule added on *Destinations*.
- Replacing the whole policy also records which address rules stand above a block and are open inside it,
  and the gateway logs them at every start. A policy that ran a build from before this amendment is not
  migrated again.
- The reason for a name stopped by a blocked range ends `a name rule cannot open a blocked range`. The
  advice quoted under "Why a name rule cannot open a blocked range" is no longer part of it: the agent
  reads the reason too.
- `expires` is a finite number. A replacement is still put in force before it is saved.
- The locked ranges also recognise `64:ff9b:1::/48` and IPv4-translated addresses (`::ffff:0:a.b.c.d`);
  ISATAP, Teredo and a NAT64 prefix of the operator's own are not recognised.
- A seeded block that was edited stays a rule of the operator when it is edited back (`source: user`, takes
  a time limit, not skipped by the service-port exception). No address `deny` is offered as unused.
- A rule range written as IPv4-mapped IPv6 is accepted and never matches; rule ids are not restricted to a
  character set.

## Changelog

- 2026-11-15: accepted.
- 2026-11-17: amended (names pass two checks; migration keeps overlapped blocks on top).
