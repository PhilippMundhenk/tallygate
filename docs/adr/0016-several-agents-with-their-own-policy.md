# ADR-0016: Several agents with their own policy

- Status: Proposed (needs the owner's go-ahead before implementation)
- Date: 2026-11-14
- Issue: #77

> **Note (2026-11-15):** written before [ADR-0019](0019-one-ordered-rule-list.md). Where this proposal says
> "the never-reachable floor" stays global, read: the locked ranges stay global, and each agent's rule list
> carries its own built-in blocks.

## Context

One gateway and control plane serving **several agent containers** ("work", "home lab", "experiments") is the
most requested shape for people who keep projects separate. Each agent should get its own policy, grants,
consoles and Remote Control session name, and the UI should switch between agents. The gateway already tells
agents apart in principle: each has a fixed address on `agent-net`.

Today everything is single-tenant: one `policy.yaml`, one set of grants, one console, one set of approvals and
history. The destination model (ADR-0014) is now the one representation of "what an agent may reach", which
makes a per-agent split cleaner than it would have been before — but it is still a larger change to the policy
store and the UI.

## Decision (proposed — not yet approved)

### Identity
The gateway maps the **source** of a connection (its `agent-net` IP, which is fixed per container) to an
**agent id**. Agent ids and their addresses are configured in `gateway.yaml` (deployment/trust tier): the set
of agents is an operator decision, not something the UI can invent. An unknown source fails closed (no policy →
deny).

### Per-agent policy store
Replace the single `policy.yaml`/`grants.yaml` with a per-agent set, keyed by agent id (e.g.
`agents/<id>/policy.yaml` in the data volume, each in the ADR-0014 destinations form). The one evaluation path
(`model.Access`/`decide`) takes the agent id and reads that agent's destinations; the never-reachable floor and
the trust split stay global and are **not** per-agent (an agent must not be able to widen the LAN/secret
boundary for itself). Approvals, learning, grants-in-flight and history become per-agent too.

### Control plane / UI
The UI gains an agent switcher; every policy/grants/approvals/log/console view is scoped to the selected agent.
The Remote Control session name and the console target follow the agent. The relay carries the agent id; the
gateway authorises it against the configured set.

### Migration
A single-agent deployment is "one agent": the existing `policy.yaml`/`grants.yaml` become
`agents/default/...` on first start (with a `*.pre-0014`/pre-multi backup), and a stack with one agent behaves
exactly as today.

## Consequences

- ✅ Clean separation of unrelated projects on one stack; the most requested feature.
- ✅ Builds naturally on ADR-0014's one destination model and per-start state migration.
- ⚠️ A broad change: the policy store, approvals, learning, history, consoles, notifications and the whole UI
  become agent-scoped. Significant surface and test cost.
- ⚠️ The trust boundary must stay global and per-agent policy must fail closed for unknown sources — a security
  property to get right and test.

## Status

Per issue #77 this is **not scheduled** and needs the owner to comment or label it before implementation. This
ADR captures a concrete design to review; it is intentionally not implemented here. If accepted, it should land
staged (store → enforcement keying → UI → migration), each step tested like the ADR-0014 work, with explicit
tests that the global trust floor and fail-closed-on-unknown-agent hold.
