# ADR-0012: Grants for scoped, temporary access

- Status: Accepted
- Date: 2026-11-11

## Context

Users want the agent to work with services on their home network (Home Assistant, Proxmox, a NAS)
or other sensitive endpoints, sometimes read-only, sometimes with write access, and only while a task needs
it. Per-connection approvals ([ADR-0004](0004-human-in-the-loop-approvals.md)) are the wrong unit for this:
they cannot express "GET only" or "these paths", they prompt for every new host:port, and LAN addresses are
hard-denied anyway ([ADR-0007](0007-hard-deny-on-resolved-ips-and-pinning.md)).

Deployments were explicitly left out: an agent's code running outside the sandbox needs a different
mechanism, such as GitOps with human review.

## Decision

Introduce **grants**: named bundles of targets, HTTP path patterns, access levels (`read` = safe methods,
`write` = all), LAN exemption per exact target, credential injection and an approval mode per level.

- **Defined by the operator only**, in the read-only config file or in the UI. UI grants may reach the LAN
  only inside `grants_lan_allow` from the config file, so a compromised UI session cannot open the
  network at large.
- **Requested by the agent** through a minimal unauthenticated API on agent-net (list, request with a
  reason, poll), wrapped by a `tallygate` CLI and documented to Claude via the managed `CLAUDE.md`.
- **Approved by a human** in the UI, Telegram or Matrix, with the option to downgrade write to read.
  `auto` levels are granted immediately but logged and shown.
- **Enforced in the gateway** before the rules (only when the rules would not allow the name anyway).
  HTTP(S) targets are always intercepted and checked per request: Host, canonical path, method,
  no upgrades on read. Upstream TLS is verified normally or against a pinned leaf fingerprint for
  self-signed devices. `tcp` targets are passed through.
- **Time-limited** (1 min – 7 days, capped per grant) and revocable. State is in memory, so a restart ends
  all grants (fail closed).

## Consequences

- ✅ One tap for a coherent task-sized permission instead of many connection prompts.
- ✅ Read/write is part of the grant and the decision. The human can grant less than asked for.
- ✅ Secrets for LAN services stay in the gateway; the agent's own credentials are stripped.
- ✅ The agent learns what it may ask for (catalog, refusal hints) instead of probing.
- ⚠️ `read` relies on HTTP method semantics; APIs that mutate on GET defeat it (documented).
- ⚠️ Established `tcp` sessions survive expiry/revocation; keep their `max_ttl` short.
- ⚠️ The agent-written reason is shown to the human. It is sanitised and labelled as unverified, but it
  remains a social-engineering channel.
- ⚠️ More attack surface in the gateway: the agent API, interception of LAN targets and path parsing.
  These are covered by unit and e2e tests (traversal, Host spoofing, raw-TCP fallback, WebSocket on read,
  flooding).
