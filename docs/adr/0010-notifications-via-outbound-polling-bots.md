# ADR-0010: Notifications via outbound-polling Telegram/Matrix bots

- Status: Accepted
- Date: 2026-11-11

## Context

Approvals must reach the operator's phone. Webhook-based bots need an internet-reachable endpoint on the
control plane.

## Decision

Bots use **outbound long-polling** only (Telegram `getUpdates`, Matrix `/sync`). Telegram uses inline
buttons; Matrix uses pre-seeded reactions or short text replies (`allow 3`). Only allowlisted user IDs / chat
IDs may decide; the Matrix bot refuses to run if its own user is in the allowlist.

## Consequences

- ✅ No inbound exposure of the control plane beyond the operator's reverse proxy.
- ✅ Works behind NAT and on the user's own Matrix homeserver.
- ⚠️ Matrix bot does not implement E2EE: use an unencrypted room on a homeserver you control.
- ⚠️ Telegram messages pass through Telegram's servers (destination host:port and IPs are disclosed there).
