# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- **Docker Compose with prebuilt images is the recommended installation.** Multi-arch images
  (`linux/amd64`, `linux/arm64`) `ghcr.io/philippmundhenk/tallygate-{gateway,control,agent}` are published
  from `main` and for every release; releases attach `compose.yaml`, `.env.example`, `gateway.yaml` and
  `bypass.sh`.
- Zero-config first start: the gateway API token, session secret and console credential are created in
  volumes, and a UI password is generated and printed once to the control log. Environment variables still
  take precedence. `docker compose exec control python -m app.passwd` changes the stored password.
- `compose.build.yaml` to build the images from a checkout (`make up`).
- Health check for the agent; services start in order of health (`depends_on: condition: service_healthy`).

### Changed
- State lives in Docker volumes by default. `TALLYGATE_DIR` is replaced by `GATEWAY_DATA`, `AGENT_HOME` and
  `WORKSPACE` (each a volume name or a host path); `./setup.sh /path` sets them up for host directories.
- The default `config/gateway.yaml` is built into the gateway image; mount your own file to change it.
- `setup.sh` runs as your normal user (sudo only for `chown`) and no longer generates secrets.
- `TRUST_FORWARDED_FOR` defaults to `0`; docs explain that the `mgmt` bridge address is shared by every
  process on the host.

### Removed
- `gateway/config.example.yaml` (a stale duplicate of `config/gateway.yaml`).

### Fixed
- Web UI (#23):
  - Log tab: history loads even after live events arrived; "Load older" no longer duplicates rows.
  - After an event-stream reconnect, pending asks and grant requests from the gap are reloaded; a stream
    closed by an ended session leads to the login page.
  - Rules tab: a policy change elsewhere no longer overwrites unsaved edits (the field is marked instead).
  - Console: UTF-8 split across frames is no longer garbled; pastes over 64 KiB no longer kill the console;
    reconnecting after the session ended shows "session expired" instead of looping.
  - Approval and grant cards do not move under the cursor when another one goes away, and their buttons are
    disabled while a decision is sent.
  - The session cookie is `SameSite=Lax`, so links in Telegram/Matrix messages arrive logged in.
  - Invalid JSON, non-JSON gateway replies and an unreachable GitHub return `{"error": …}` with 400/502.
- Accessibility and mobile layout (#24): tables scroll inside their own container, rows wrap on phones, tabs
  are ARIA tabs (arrow keys work), the toast is a live region, the connection state is shown in words, and
  every input has a label. Browser notifications are enabled with a button in Setup (browsers ignore a
  permission request without a user gesture).

### Upgrading from 0.3.0
Keep your existing state: in `.env`, replace `TALLYGATE_DIR=/your/dir` with
`GATEWAY_DATA=/your/dir/gateway`, `AGENT_HOME=/your/dir/agent-home`, `WORKSPACE=/your/dir/workspace`. Your
secrets in `.env` keep working. If you changed `config/gateway.yaml`, mount it as described in
[docs/operations.md](docs/operations.md#with-docker-compose-recommended). Then `make up`, or switch to the
published images with `docker compose pull && docker compose up -d`.

## [0.3.0] - 2026-11-11

### Added
- **Grants** ([docs/grants.md](docs/grants.md), [ADR-0012](docs/adr/0012-grants-for-scoped-temporary-access.md)):
  named, time-limited bundles of access, defined in `config/gateway.yaml` or in the UI. A grant has:
  - targets: `https`/`http` with path patterns, or `tcp`; exact, wildcard or IP hosts;
  - `read`/`write` levels, each with its own approval mode (`ask`/`auto`);
  - a LAN exemption for exact targets (UI grants only within `grants_lan_allow`);
  - credential injection, and certificate pinning by SHA-256 fingerprint.
- Gateway enforcement per request on grant targets: Host match, canonical path match, safe methods and no
  upgrades on `read`, non-HTTP traffic cut, agent credentials stripped.
- Agent grant API on `172.31.10.2:8079` (list / request / long-poll; rate-limited) and the `tallygate` CLI
  in the agent image, plus a managed `/etc/claude-code/CLAUDE.md` that explains the gateway and grants to
  Claude. Refused connections name the grant that would allow them.
- UI: grant requests on the Approvals page (approve, approve read-only, deny), a new Grants tab (active
  grants with revoke, definitions, editor, activation), and write-only secret management.
- Telegram (buttons incl. *Revoke*) and Matrix (👍 / 📖 / 👎, `approve|read|deny|revoke N`) grant prompts.
- New config keys: `grants`, `grants_lan_allow`, `grants_never`, `grant_request_timeout`,
  `grant_max_pending`, `grant_api_rate`; new env `GW_GRANTS_PORT`, `TALLYGATE_URL`.

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

[Unreleased]: https://github.com/PhilippMundhenk/tallygate/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/PhilippMundhenk/tallygate/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/PhilippMundhenk/tallygate/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/PhilippMundhenk/tallygate/releases/tag/v0.1.0
