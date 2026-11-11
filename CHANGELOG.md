# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] - 2026-11-11

Security release. Full report: [docs/security-review.md](docs/security-review.md).

### Security
- **TG-01 (critical)**: the web console no longer reverse-proxies ttyd's HTTP interface. Control serves the
  console page and a vendored xterm.js itself and relays only a filtered ttyd WebSocket, so the agent can
  no longer serve script on the UI origin. Strict CSP on every page.
- **TG-02**: hostnames are decided before they are resolved; denied or pending names never reach DNS.
- **TG-03**: immutable hard-deny floor from the static config; the API/UI can only add CIDRs. NAT64,
  6to4, Teredo and documentation prefixes added.
- **TG-04**: "Always (*.domain)" uses the Public Suffix List incl. private suffixes and shows the pattern.
- **TG-05**: the agent's own `Authorization`/`Cookie` headers are always stripped on injection hosts.
- **TG-06**: `TELEGRAM_ALLOWED_USER_IDS` is mandatory.
- **TG-07**: forwarded/auth-proxy headers are only honoured from `TRUSTED_PROXIES`.
- TG-08 … TG-25: pending-approval cap, log-flood protection, strict hostname validation, read-only hosts
  (`npm publish` blocked), server-side sessions, scrypt N = 2^16 and serialised login checks, mandatory
  `CONTROL_BIND_HOST`, service exceptions bound to their port, IPv6 disabled in all containers, size limits
  on agent responses, pinned GitHub CLI signing key, `onboarding=false`, CR/LF-safe secrets, origin checks
  incl. scheme, `umask 077` in setup, bounded notifier state.

### Changed
- Approval prompts show the registrable domain, flag punycode names and show "not resolved yet" for IPs.
- `CONTROL_PASSWORD_HASH` format `scrypt:16:<salt>:<hash>` (the old format still works; regenerate).
- New settings: `TRUSTED_PROXIES`, `SESSION_IDLE`, gateway `hard_deny_floor`, `readonly`, `max_pending`,
  `log_max_events`, `inject_strip_headers`.

## [0.1.0] - 2026-11-11

### Added
- **egress-gw**: mitmproxy-based egress gateway with a single enforcement hook for HTTP(S) proxy,
  SOCKS5 and TCP service ports; allow/deny/ask policy with first-match rules, TTLs and presets;
  hard-deny CIDRs checked on resolved IPs; DNS pinning against rebinding; NXDOMAIN-only DNS for the
  agent; GitHub credential injection with CONNECT-target **and** SNI matching; SQLite event log;
  bearer-token management API on an internal network.
- **control**: web UI (approvals with live countdown, live log, rules editor, presets, dry-run test,
  setup wizard, web consoles via ttyd), scrypt password login, CSRF/origin protection, CSP;
  Telegram (inline buttons) and Matrix (reactions/replies) approval bots.
- **agent**: minimal Debian image with Claude Code, GitHub CLI (signed apt repo), checksum-verified
  ttyd; Remote Control supervised in tmux; placeholder credentials; status/self-test endpoint.
- Compose stack with internal networks and static addressing; all containers non-root,
  `cap_drop: ALL`, `no-new-privileges`, read-only root filesystems.
- Tests: policy unit tests, end-to-end suites (gateway, control, notifications), Docker-based
  isolation test (`tests/integration/bypass.sh`), CI workflow.
- Documentation: architecture, ADRs, threat model, configuration, API, operations, user guide.

[Unreleased]: https://github.com/PhilippMundhenk/tallygate/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/PhilippMundhenk/tallygate/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/PhilippMundhenk/tallygate/releases/tag/v0.1.0
