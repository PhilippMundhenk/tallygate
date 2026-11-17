# tallygate documentation

| Document | For | Content |
|---|---|---|
| [How access works](access.md) | operators | The whole model on one page: the one rule list, locked ranges, grants on request, the default; who decides what and where it is changed |
| [Architecture](architecture.md) | everyone | Components, network topology, request flows, policy model, state, ports |
| [Architecture decisions](adr/README.md) | reviewers, contributors | Why it's built this way (ADR-0001 … 0019) |
| [Threat model](threat-model.md) | security reviewers | Assets, trust boundaries, threats and mitigations, residual risks |
| [Security review 2026-11](security-review.md) | security reviewers | Findings TG-01 … TG-25, fixes, regression tests, accepted risks |
| [Operations runbook](operations.md) | operators | Install, reverse proxy, setup, upgrades, backup, monitoring, troubleshooting |
| [User guide](user-guide.md) | operators | UI tour, approvals, Telegram/Matrix setup, rule cookbook |
| [Rules by example](rules.md) | operators | How a destination is decided: one ordered rule list, name and address rules, built-in blocks, locked ranges; worked examples for hosts, ports, addresses, order and the local network |
| [Grants](grants.md) | operators | Access on request: bundles of destinations under the same rules, with levels, paths, credentials and a time limit; local devices |
| [Configuration reference](configuration.md) | operators | `.env`, `gateway.yaml`, `policy.yaml`, presets, component env |
| [API reference](api.md) | integrators | Gateway management API, agent grant API, control HTTP interface |
| [Development](development.md) | contributors | Layout, local dev, tests, style, releases |
| [UX concept](ux-concept.md) | contributors | The one vocabulary of the web UI: buttons, help, status, words |
| [Screenshots](screenshots.md) | contributors | One picture per surface of the UI, with captions |
| [Related work](related-work.md) | evaluators | Comparison with dev containers, Docker Sandboxes, Moat, gw0 |
| [Branding](BRANDING.md) | contributors | Name, logo, colours, typography, tone |
