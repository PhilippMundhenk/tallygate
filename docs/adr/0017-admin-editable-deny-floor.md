# ADR-0017: The admin may edit the deny floor from the UI

- Status: Superseded by [ADR-0019](0019-one-ordered-rule-list.md) (2026-11-15)
- Date: 2026-11-14
- Issue: #177
- Amends: ADR-0014 §4 (the trust split), for the never-floor only

> **Superseded by [ADR-0019](0019-one-ordered-rule-list.md).** The text below is kept as the record of the
> decision as it was taken. What it decided in principle still holds: an authenticated UI session may open
> the local network. How it is done no longer does: there is no deny floor, no `floor_open` and no
> *Unblock range* action. The blocked ranges are ordinary `deny` rules at the bottom of one ordered rule list,
> opened narrowly by an address rule above them or removed by deleting them, and `policy.yaml` is migrated
> (ranges in `floor_open` are not seeded as blocks). `grants.internal` lives on as the locked ranges. The
> statement that `lan: true` and `grants_lan_allow` stay file-only is void: both are gone.

## Outcome

Accepted by the maintainer during the Nov 2026 control-UI review. The never-reachable deny floor is no longer
file-only to *loosen*: an authenticated UI session (the admin) may remove or narrow the LAN ranges, the cloud
metadata address and its own `hard_deny` additions, each behind a prominent confirmation. Secure by default — a
fresh install still ships every built-in deny present; the admin opts out one range at a time.

**The gateway's own internal networks (`grants.internal` — the gateway / control / agent plumbing) stay
locked.** They are still shown in the one rules list, marked structural, but cannot be removed from the UI.
Removing them would let an agent that reaches the control plane disable the gateway itself; that is not a
security policy to tune but the gateway's structural integrity, which the isolation self-test exists to prove.
The rest of the trust split — `credentials`, `tls.verify: false`, and `lan: true` exemptions outside
`grants_lan_allow` — is unchanged and stays file-only.

## Context

ADR-0014 §4 made the never-floor file-only to loosen: the API/UI could add a `never` entry or narrow one, but
never remove one, so a prompt-injected agent — or a hijacked UI session — could never open the LAN even if it
reached the control plane. That is defense in depth: the UI password is layer one; the file-only floor is the
backstop if layer one fails.

In the review the maintainer judged that an authenticated admin editing their own network policy from the UI
is a legitimate, expected operation, and that a single "everything is a rule" model is worth more than the
extra layer for the parts of the floor that describe *their* network. The confusing, special-cased "Never
reachable" card (#177) was the real problem: people could not tell what the entries were, why those ranges, or
how to change them.

## Decision

- A new backend-owned policy field, `floor_open: [<range>, …]`, lists the `all+lan` floor ranges the admin has
  removed. It lives in `policy.yaml` like the rest of the editable policy, never in the read-only `gateway.yaml`.
- `_never()` drops a `grants.never` (`all+lan`) entry whose range is in `floor_open`. `grants.internal` is
  **never** dropped, whatever `floor_open` says. `hard_deny` (`scope: all`) stays editable as it already is.
- The destination model marks each floor row `removable` (LAN / metadata / `hard_deny`) or `locked`
  (`grants.internal`), so the Destinations table renders either a delete button with a scary confirm or a lock.
- A config-file `never` entry re-applies on reload unless its range is still in `floor_open`: the file stays
  authoritative for what it defines, and `floor_open` is the admin's explicit opt-out layered on top.

## Consequences

- A compromised agent that reaches the control API can now remove the LAN / metadata floor. This is the
  accepted trade. The mitigations that remain: the UI password (layer one), the per-delete confirmation, and —
  crucially — that the agent still cannot reach the control plane at all, because `grants.internal` stays
  locked and the isolation self-test is unchanged.
- Fresh installs behave exactly as before: every deny is present until the admin removes it.
- The separate "Never reachable" card is retired; the floor is shown as rows in the one rules list, each with
  its reason and its change path.

## Changelog

- 2026-11-14: accepted; amends ADR-0014 §4 for the never-floor only. `grants.internal` and the rest of the
  trust split are unchanged.
