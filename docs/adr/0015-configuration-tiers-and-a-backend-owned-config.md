# ADR-0015: Configuration tiers and a backend-owned config file

- Status: Accepted; tier 3 narrowed by [ADR-0019](0019-one-ordered-rule-list.md) (2026-11-15)
- Date: 2026-11-14
- Issue: #147

> **Amended by [ADR-0019](0019-one-ordered-rule-list.md).** The tiers stay. Tier 3 (file-only) no longer
> contains the "never-reachable floor", the LAN exemption or `grants_lan_allow`: the blocked ranges are rules
> in the policy, editable in the UI, and `grants_lan_allow` is ignored. Tier 3 is now credential injection and
> `tls_verify: false`, plus `GW_INTERNAL_NETS` in the environment (the locked ranges). Open question 3 is
> moot. The behaviour settings are found under *Settings → Behaviour settings* since the menu was reordered.

## Outcome

Accepted by the maintainer. First implementation: the tier-2 behaviour tunables (log retention, learning,
suggestions, grant-request limits, policy-history depth, pending caps) move to a backend-owned `settings.yaml`
in the data volume, seeded once from `gateway.yaml`/env and then edited in the UI (*Setup → Behaviour
settings*, `GET`/`PATCH /settings`), with no file edit and no restart for the live ones. The trust-critical
tier stays file-only in `gateway.yaml`; `settings.yaml` refuses any non-tier-2 key, and a broken file stops the
gateway (fail closed). Deeper tier-1 derivation and the `settings.yaml` schema beyond these keys remain open.

## Context

Standing a stack up today touches four places: `.env`, `compose.yaml` (service `environment:`, networks,
volumes), the read-only `gateway.yaml`, and `policy.yaml`/`grants.yaml` in volumes. Many values that could be
derived or defaulted are explicit environment variables, and some settings exist only in a file the operator
must mount and restart to change. `docs/configuration.md` is long for that reason.

Two properties must not regress:

- **The trust split (ADR-0014 §4).** Credential injection, `tls_verify: false`, the never-reachable floor
  (`GW_INTERNAL_NETS`, `never`), and `grants_lan_allow` are accepted only from the read-only config file. A
  stolen UI session must not be able to widen access to secrets or the LAN. This is a security boundary, not a
  convenience.
- **Zero-config, fail-closed first start.** The API token, session secret and UI password are already
  generated into volumes; a missing or broken config must fail closed, never open.

ADR-0014 already moved rules, grants, read-only hosts and credential injection toward one destination model and
the UI, and the gateway now reads a `destinations:` form and migrates its own state files. The configuration
rework builds on that settled format.

## Decision (proposed)

Separate configuration into three tiers by **who owns it and why**, and move only the middle tier into the UI.

### 1. Deployment — stays in `compose.yaml` / `.env`
How the containers are wired: networks and bind addresses, published ports, image versions/digests, the
reverse-proxy and TLS story, volumes. This is about the deployment, not the policy, and belongs with the
compose file. Reduce it to the few variables a deployment actually differs on; document the rest as derived or
defaulted.

### 2. Policy & behaviour — UI-editable, persisted to a backend-owned config file
Settings that are about *what the gateway does*, not *how it is wired*: the default mode and approval timeout,
availability/quiet-hours, notification channels, learning-mode parameters, log retention, suggestion
thresholds, and the non-trust-critical presets. These move into the UI and are persisted to a single
backend-owned file in the data volume (working name `settings.yaml`), which the control plane reads and writes
through the existing policy-relay pattern. Changes take effect without editing a file and restarting. The
policy history/export mechanism is extended to cover it (versioned, exportable, importable).

### 3. Trust-critical — stays file-only and read-only to the UI
Credential injection, `tls_verify: false`, LAN exemption / `grants_lan_allow`, the never-reachable floor and
`GW_INTERNAL_NETS`. These remain in the read-only `gateway.yaml` (and env for the stack-internal nets),
unreachable from the UI/API, exactly as ADR-0014 §4 requires. The UI *shows* them read-only and says where they
are changed.

### Secure defaults
Default or derive everything in tiers 1–2 whose value is almost always the same, and drop those env vars:
approval timeout, learning ports/minutes, log retention, request timeouts, suggestion windows. **Do not**
auto-derive tier-3 values: `GW_INTERNAL_NETS` (the stack's own networks, which must be blocked for LAN grants,
#112) stays explicit — guessing it wrong silently opens the management network. A wrong derivation here is a
vulnerability, so this stays operator-set with a loud check at start.

### Migration
`gateway.yaml` keeps loading (both the old keys and `destinations:`). The behaviour settings that move to
`settings.yaml` are read from their current env/`gateway.yaml` locations if present and written to
`settings.yaml` once, with a one-line log of what moved (mirroring the ADR-0014 state-file migration). Env
variables keep their names for one release.

## Consequences

- ✅ The common case needs little hand-editing; behaviour changes in the UI, no restart.
- ✅ The trust boundary is unchanged and still enforced by the read-only mount.
- ✅ `docs/configuration.md` shrinks to "defaults + the few things you'd change", with the full table as
  reference.
- ⚠️ A new persisted file and a new relayed surface to get right; it must fail closed and be covered by the
  trust-split tests.
- ⚠️ Deciding the exact tier-2 set is a judgement call that needs the owner's review before implementation.

## Open questions for review

1. The exact list of settings that move to tier 2 vs stay in `gateway.yaml`/`.env`.
2. The `settings.yaml` schema and whether it folds into the destinations file or stays separate.
3. Whether `grants_lan_allow` stays named as is or is renamed (ADR-0014 mentioned `lan_allow`).
4. How far to push derivation for deployment (tier 1) without surprising operators.

This ADR is a proposal; it needs the owner's sign-off on the tier split and the `settings.yaml` schema before
any code. The secure-defaults subset (defaulting/dropping tier-1/2 env vars, no tier-3 derivation) can land
first as a small, separately reviewed change.
