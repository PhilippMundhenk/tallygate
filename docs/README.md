# tallygate documentation

| Document | For | Content |
|---|---|---|
| [How access works](access.md) | operators | The whole model on one page: never reachable, on request, rules, everything else; who decides what and where it is changed |
| [Architecture](architecture.md) | everyone | Components, network topology, request flows, policy model, state, ports |
| [Architecture decisions](adr/README.md) | reviewers, contributors | Why it's built this way (ADR-0001 … 0013) |
| [Threat model](threat-model.md) | security reviewers | Assets, trust boundaries, threats and mitigations, residual risks |
| [Security review 2026-11](security-review.md) | security reviewers | Findings TG-01 … TG-25, fixes, regression tests, accepted risks |
| [Operations runbook](operations.md) | operators | Install, reverse proxy, setup, upgrades, backup, monitoring, troubleshooting |
| [User guide](user-guide.md) | operators | UI tour, approvals, Telegram/Matrix setup, rule cookbook |
| [Rules by example](rules.md) | operators | How a connection is decided; ~20 worked examples for hosts, ports, CIDRs, order |
| [Grants](grants.md) | operators | Scoped, temporary access to the home network and other services (read/write, LAN, credentials) |
| [Configuration reference](configuration.md) | operators | `.env`, `gateway.yaml`, `policy.yaml`, presets, component env |
| [API reference](api.md) | integrators | Gateway management API, agent grant API, control HTTP interface |
| [Development](development.md) | contributors | Layout, local dev, tests, style, releases |
| [Related work](related-work.md) | evaluators | Comparison with dev containers, Docker Sandboxes, Moat, gw0 |
| [Branding](BRANDING.md) | contributors | Name, logo, colours, typography, tone |
