# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed
- CI: the image scan used an invalid image reference and failed on every push to `main`; release notes named
  `:vX.Y.Z` tags that don't exist; manual runs on other branches pushed images; the Claude Code workflow
  opens an issue when Actions may not create pull requests (#64).

### Security
- The gateway fails closed: an error inside a hook (e.g. the event log cannot be written) refuses the
  connection instead of letting it through. An invalid `hard_deny_floor` entry stops the gateway at
  startup, and until a failed startup has exited every connection is refused (it used to be proxied
  without the policy for a moment) ([#8](https://github.com/PhilippMundhenk/tallygate/issues/8)).
- TLS to injection and read-only hosts is always intercepted. A missing, trailing-dot or different SNI
  used to pass it through untouched, skipping credential stripping and the read-only check
  ([#9](https://github.com/PhilippMundhenk/tallygate/issues/9)).
- CIDR `allow`/`ask` rules, including those created by approving an IP literal, apply only to IP-literal
  destinations. They made the name phase inconclusive, so unknown names were resolved before the decision
  (TG-02 regression). **Behaviour change:** names resolving into an allowed CIDR are no longer allowed by
  it; use host rules ([#10](https://github.com/PhilippMundhenk/tallygate/issues/10)).
- `hard_deny_floor` now extends the built-in hard-deny list instead of replacing it; adding a VPS address
  silently dropped RFC 1918, loopback and metadata ranges. Extras from the API are compared with the floor
  in force ([#11](https://github.com/PhilippMundhenk/tallygate/issues/11)).
- Grants defined in the UI or API can no longer use `inject` or `tls_verify: false` (config-file grants
  only): a UI session could send stored secrets to any host. Such UI grants saved earlier are ignored at
  startup ([#12](https://github.com/PhilippMundhenk/tallygate/issues/12)).
- Rules reject null or non-integer ports (they matched every port; the UI produced them from typos such as
  `443,` or `https`), and IPv4-mapped IPv6 literals are matched like IPv4 by rules and approvals
  ([#13](https://github.com/PhilippMundhenk/tallygate/issues/13)).
- Grant enforcement: plain HTTP to an `https` grant target is refused instead of skipping the per-request
  checks; LAN grants also work while a rule (e.g. the `open` preset) allows the name; re-approving a grant
  keeps its id, so open connections survive; agent credentials are stripped on inject hosts reached
  through a grant ([#14](https://github.com/PhilippMundhenk/tallygate/issues/14)).
### Added
- Line-coverage gate of 95 % per module in CI (`make coverage`), measuring the gateway and control
  processes too; every module is now at 98-100 % (424 tests) (#27).
- **Help and examples**: `docs/rules.md` (how a connection is decided, ~20 worked examples), an example for
  every setting in the configuration reference and in `config/gateway.yaml`; in the UI, field help for rules
  and grants, expandable explanations with examples, *Test a destination* explains which rule or check
  decided, and host/CIDR typos are refused with a valid example (#35).
- **Quick actions** in the Rules tab: allow the web or all ports for 15 min / 1 h, switch what happens with
  unknown destinations, an emergency stop, a guided path to a local-network grant, and **templates** for
  Python, Node.js, Go, Rust, Debian/Ubuntu apt, container registries and Hugging Face. Preset rules are
  tagged `preset:<name>`; `DELETE /presets/<name>` undoes them; `GET /presets?details=1` (#34).
- **Docker Compose with prebuilt images is the recommended installation.** Multi-arch images
  (`linux/amd64`, `linux/arm64`) `ghcr.io/philippmundhenk/tallygate-{gateway,control,agent}` are published
  from `main` and for every release; releases attach `compose.yaml`, `.env.example`, `gateway.yaml` and
  `bypass.sh`.
- Zero-config first start: the gateway API token, session secret and console credential are created in
  volumes, and a UI password is generated and printed once to the control log. Environment variables still
  take precedence. `docker compose exec control python -m app.passwd` changes the stored password.
- `compose.build.yaml` to build the images from a checkout (`make up`).
- A weekly workflow opens a PR when a new Claude Code version is published; `agent/Dockerfile` is the
  single place that pins the version (#17).
- `AGENT_CPUS` to limit the agent's CPU (default: no limit), and a resource-limits section in the
  operations guide on keeping the workspace from filling the host disk (#25).
- Health check for the agent; services start in order of health (`depends_on: condition: service_healthy`).

### Changed
- CI: actions pinned to commit SHAs, base images pinned by digest, Dependabot groups minor/patch
  updates, gitleaks secret scan on every PR and weekly, Trivy scan of the published images, image
  build tested on pull requests, ttyd and tool versions pinned in one place (#18).
- Gateway and control images on Python 3.15 (was 3.13); actions/checkout and actions/setup-python v7;
  ruff 0.17.4 (also in pre-commit), pytest 9.2.0.
- State lives in Docker volumes by default. `TALLYGATE_DIR` is replaced by `GATEWAY_DATA`, `AGENT_HOME` and
  `WORKSPACE` (each a volume name or a host path); `./setup.sh /path` sets them up for host directories.
- The default `config/gateway.yaml` is built into the gateway image; mount your own file to change it.
- `setup.sh` runs as your normal user (sudo only for `chown`) and no longer generates secrets.
- `TRUST_FORWARDED_FOR` defaults to `0`; docs explain that the `mgmt` bridge address is shared by every
  process on the host.

### Fixed
- `bypass.sh` works when downloaded next to `compose.yaml` (it no longer changes directory and runs the
  self-test with `docker exec`); the meaningless IPv6 link-local probe is gone (the sysctl checks remain) (#65).
- Undoing a template could delete rules it never added (`lockdown` shares ids with the baseline, so undoing it
  removed the Anthropic rules). Template rule ids are now `<preset>:<id>`, rules from another source are never
  taken over (`409`), and `POST` refuses `policy` presets. "Apply again" with a time limit now limits the
  template's own earlier rules, and the UI shows the expiry the gateway set. Templates: GHCR and Docker Hub
  blob hosts, `repo.yarnpkg.com` for corepack, a correct Go note, Debian on 443 only; the docs say that
  template rules win over your own rules while active (#59).
- The gateway's warnings never reached its log: mitmdump ran with `-q`, which overrides the log level (#27).
- Agent status responses larger than one network read were cut off and reported as an error (#27).
- The managed setting `skipDangerousModePermissionPrompt` was nested under `permissions`, where Claude Code
  ignores it; it is now a top-level key, so the bypass-mode confirmation no longer appears (#26).

### Removed
- `gateway/config.example.yaml` (a stale duplicate of `config/gateway.yaml`).

### Security
- A `CONTROL_PASSWORD_HASH` that is not an scrypt hash refuses every login instead of falling back to
  `CONTROL_PASSWORD` (#27).

- Request bodies over 1 MB were streamed upstream before the per-request checks ran, so a large `PUT` to a
  read-only host, the agent's own credentials on an injection host, or a write on a read-only grant went
  through. The checks now run on the request headers, before anything is forwarded (#56).
- Domain fronting: the TLS SNI and the HTTP `Host` were not compared with the checked name, so on a shared
  CDN an allowed name gave access to other sites. TLS is now passed through only when the SNI matches the
  CONNECT name (a missing SNI is refused; for an IP literal an SNI name must be allowed by the rules), and
  HTTP requests with another `Host` get `403` (#57).
- The templates opened publish paths around `readonly`: Yarn, crates.io, the container registries and
  Hugging Face were writable. They are now read-only by default; `readonly` entries can refuse POST as
  well (`post_is_write`, with `read_posts` exceptions) and take `*.domain` patterns. The container template
  is called "pull only" (#58).
- The agent could reach services on the Docker host that listen on all interfaces through the host's
  address on `agent-net` (`172.31.10.1`), bypassing the gateway. `agent-net` and `control-net` no longer
  give the host an address (`com.docker.network.bridge.inhibit_ipv4`), and `bypass.sh` checks it with a
  listener on the host (#7).
- `TRUST_PROXY_SECRET`: forwarded and auth headers are believed only when the proxy also sends the
  shared secret in `X-Tallygate-Proxy-Secret`. The docs describe the safe proxy-auth setup (proxy container
  on `mgmt` with a fixed address, nothing else published) (#19).
- Login flood: bodies over 4 KiB are refused unread (413), more than 5 queued password checks get 429 at once,
  and the per-address failure limit is re-checked and recorded inside the password lock (#20).
- The event stream and the web console end within 10 s of logout or session expiry, and console input is
  checked before it reaches the agent (#21).
### Fixed
- e2e tests skip instead of erroring without aiohttp, and cover password hash formats, idle and absolute
  session expiry, dropped console frames, grant deny and revoke through Telegram and Matrix (#27).
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
- Notifications: Telegram and Matrix are sent concurrently and fail independently, so an outage of one no
  longer hides prompts on the other. A queue decouples delivery from the gateway event stream, and chat API
  calls time out after 15 s (#22).
### Security
- The event stream and the web console end within 10 s of logout or session expiry, and console input is
  checked before it reaches the agent (#21).
- Login flood: bodies over 4 KiB are refused unread (413), more than 5 queued password checks get 429 at once,
  and the per-address failure limit is re-checked and recorded inside the password lock (#20).
- `TRUST_PROXY_SECRET`: forwarded and auth headers are believed only when the proxy also sends the
  shared secret in `X-Tallygate-Proxy-Secret`. The docs describe the safe proxy-auth setup (proxy container
  on `mgmt` with a fixed address, nothing else published) (#19).
- The agent could reach services on the Docker host that listen on all interfaces through the host's
  address on `agent-net` (`172.31.10.1`), bypassing the gateway. `agent-net` and `control-net` no longer
  give the host an address (`com.docker.network.bridge.inhibit_ipv4`), and `bypass.sh` checks it with a
  listener on the host (#7).

### Upgrading from 0.3.0
Keep your existing state: in `.env`, replace `TALLYGATE_DIR=/your/dir` with
`GATEWAY_DATA=/your/dir/gateway`, `AGENT_HOME=/your/dir/agent-home`, `WORKSPACE=/your/dir/workspace`. Your
secrets in `.env` keep working. If you changed `config/gateway.yaml`, mount it as described in
[docs/operations.md](docs/operations.md#with-docker-compose-recommended). Then `make up`, or switch to the
published images with `docker compose pull && docker compose up -d`.
Recreate the networks so the new network option takes effect: `docker compose down && docker compose up -d`
(compose warns that the network configuration changed).

### Fixed
- Gateway robustness: "repeated N×" counts are no longer lost when a new event replaces an unflushed one;
  re-applying a preset with a TTL keeps its permanent rules permanent; policy, UI grants and secrets are
  fsynced before the atomic rename; per-connection state is released when an upstream connect fails
  ([#15](https://github.com/PhilippMundhenk/tallygate/issues/15)).

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
