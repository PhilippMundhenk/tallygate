# ADR-0008: Approvals are rules with TTL; connections are held while asking

- Status: Accepted
- Date: 2026-11-11

## Context

Human-in-the-loop must not break tools with immediate failures, must not spam the operator for every
connection of one operation, and approvals must be inspectable and revocable.

## Decision

- `ask` holds the connection (async wait) up to `ask_timeout` (default 60 s). Concurrent attempts to the same
  `host:port` share one pending request.
- A decision creates a normal rule at the top of the rule list (with `expires` for temporary scopes), tagged
  `source: approval`. "Once" is a 2-minute rule so follow-up connections of the same operation pass.
- Timeouts deny and set a 60 s negative cache for that `host:port` to prevent notification storms.

## Consequences

- ✅ Approvals are visible, editable and deletable in the rules editor; expiry is automatic.
- ✅ Tools see either a successful connection or a clean 502, never a half-state.
- ⚠️ A held connection occupies a client socket for up to `ask_timeout`; some clients have shorter connect
  timeouts and will fail before the operator answers (they can simply retry after approval).
