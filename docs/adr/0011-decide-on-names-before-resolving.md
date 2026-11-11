# ADR-0011: Decide on names before resolving them

- Status: Accepted
- Date: 2026-11-11 (security review, finding TG-02)

## Context

The gateway resolved every requested hostname first and then evaluated the policy on name and IPs
([ADR-0007](0007-hard-deny-on-resolved-ips-and-pinning.md)). The lookup itself is a side channel: an agent
asking for `<data>.attacker.example` makes the gateway's resolver query the attacker's authoritative name
server — even if the connection is then denied or waits for an approval that never comes.

## Decision

Evaluation is split in two phases:

1. **Name phase (no DNS):** validate the name syntax, then walk the rules. A matching host rule decides;
   a CIDR *deny* rule is skipped (it can only make the result stricter later); a CIDR *allow/ask* rule
   ends the phase undecided, because its answer depends on the IPs. Otherwise the default applies.
   `deny` → refuse without resolving. `ask` → hold the connection and ask the human **before** resolving.
2. **IP phase:** only for allowed/approved (or undecided) names: resolve, then the full evaluation
   (hard deny on all resolved IPs, rules, default) and pinning as in ADR-0007.

## Consequences

- ✅ Denied or never-approved names never reach a resolver; DNS exfiltration through the proxy is closed.
- ✅ Approval prompts show only what the agent asked for (IPs are "not resolved yet").
- ⚠️ A name that later turns out to resolve to a hard-denied address may be asked about first (the human's
  approval does not override the hard deny).
- ⚠️ CIDR `allow`/`ask` rules placed above host rules re-introduce lookups for unknown names; prefer host
  rules, or put CIDR allow rules below them.
