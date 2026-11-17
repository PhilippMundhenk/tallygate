# ADR-0011: Decide on names before resolving them

- Status: Accepted; the two phases amended by [ADR-0019](0019-one-ordered-rule-list.md) (2026-11-15)
- Date: 2026-11-11 (security review, finding TG-02)

> **Amended by [ADR-0019](0019-one-ordered-rule-list.md).** The decision stands: a name the policy denies or
> still has to ask about is not resolved. Two details changed. The result of the name phase is acted on
> before the lookup only where no address can change it: an address `allow` rule for the port (for a `deny`:
> also an address `ask` rule) above what decided makes the gateway resolve first. And an address rule is
> final for its address however the destination was named, so a CIDR `allow` again covers names that resolve
> into it (this reverses the last consequence below, #10); "the hard deny" in phase 2 is the rule list with
> the built-in blocks in it. See [rules.md](../rules.md#when-a-name-is-resolved).

## Context

The gateway resolved every requested hostname first and then evaluated the policy on name and IPs
([ADR-0007](0007-hard-deny-on-resolved-ips-and-pinning.md)). The lookup itself is a side channel: an agent
asking for `<data>.attacker.example` makes the gateway's resolver query the attacker's authoritative name
server — even if the connection is then denied or waits for an approval that never comes.

## Decision

Evaluation is split in two phases:

1. **Name phase (no DNS):** validate the name syntax, then walk the host rules. A matching host rule
   decides; CIDR rules are skipped. Otherwise the default applies.
   `deny` → refuse without resolving. `ask` → hold the connection and ask the human **before** resolving.
2. **IP phase:** only for allowed/approved names: resolve, then the hard deny on all resolved IPs, rules
   and default, and pinning as in ADR-0007. CIDR *allow/ask* rules apply only to IP-literal destinations;
   for names, CIDR *deny* rules (any resolved IP inside) can only make the result stricter.

## Consequences

- ✅ Denied or never-approved names never reach a resolver; DNS exfiltration through the proxy is closed.
- ✅ Approval prompts show only what the agent asked for (IPs are "not resolved yet").
- ⚠️ A name that later turns out to resolve to a hard-denied address may be asked about first (the human's
  approval does not override the hard deny).
- ⚠️ A CIDR `allow` rule no longer allows names that resolve into the range (#10: approving an IP literal
  created such a rule and re-opened lookups for every name on that port). Allow names with host rules.
