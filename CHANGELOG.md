# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

The result of a full project review: Docker Compose with published images as the main installation, a large
set of security fixes from two review rounds, quick actions and templates, help everywhere, and a 95 %
coverage gate. Read [Upgrading from 0.3.0](#upgrading-from-030) before you update.

### Security
- **Host services:** the agent could reach services on the Docker host that listen on all interfaces through
  the host's address on `agent-net`, bypassing the gateway. `agent-net` and `control-net` no longer give the
  host an address (`com.docker.network.bridge.inhibit_ipv4`); `bypass.sh` checks it with a real listener (#7).
- **Fail closed:** an error inside a gateway hook (for example when the event log cannot be written) refuses
  the connection instead of letting it through. An invalid `hard_deny_floor` entry stops the gateway at
  startup, and until a failed startup has exited every connection is refused (#8).
- **Credential stripping and read-only hosts:** TLS to injection and read-only hosts is always intercepted.
  A missing, trailing-dot or different SNI used to pass it through untouched (#9).
- **Domain fronting:** TLS is passed through only when the SNI matches the checked name (a missing SNI is
  refused; for an IP literal an SNI name must be allowed by the rules), and HTTP requests whose `Host` is not
  the checked target get `403`. On shared CDNs an allowed name used to reach other sites (#57).
- **Large bodies:** request bodies over 1 MB were streamed upstream before the per-request checks ran. The
  checks now run on the headers, before anything is forwarded (#56).
- **DNS before the decision:** CIDR `allow`/`ask` rules, including those from approving an IP, apply only to
  IP-literal destinations; they used to make the gateway resolve unknown names before asking (TG-02
  regression) (#10).
- **Hard deny:** `hard_deny_floor` extends the built-in list instead of replacing it (#11).
- **Secrets:** grants defined in the UI or API can no longer use `inject` or `tls_verify: false`; a UI
  session could send stored secrets to any host (#12).
- **Rule validation:** null or non-integer ports are refused (they matched every port), and IPv4-mapped IPv6
  addresses match like IPv4 (#13).
- **Grants:** plain HTTP to an `https` grant target is refused; LAN grants work while a rule allows the name;
  re-approving keeps open connections; agent credentials are stripped on inject hosts reached through a
  grant (#14).
- **Publishing:** the npm, Yarn, crates.io, container registry and Hugging Face hosts are read-only by default.
  `readonly` entries can also refuse POST (`post_is_write`, with `read_posts` exceptions) and take `*.domain`
  patterns (#58).
- **Reverse proxy:** `TRUST_FORWARDED_FOR` defaults to `0`; the docs explain that the `mgmt` bridge address is
  shared by every process on the host; new optional `TRUST_PROXY_SECRET` (#19).
- **Login:** bodies over 4 KiB are refused unread, more than 5 queued password checks get `429`, and the
  failure limit is checked inside the password lock (#20).
- **Sessions:** the event stream and the console end within 10 s of logout or expiry (#21). Changing the UI
  password ends every session opened with the old one (#62). A `CONTROL_PASSWORD_HASH` that is not an scrypt
  hash refuses every login instead of falling back to `CONTROL_PASSWORD` (#27).
- **Policy writes:** the mode buttons and the emergency stop no longer send the browser's possibly stale
  policy back, which could restore deleted rules. `PATCH /policy` changes only the mode; `POST
  /emergency-stop` runs on the gateway: it revokes grants, denies pending requests, removes the internet
  shortcuts and sets mode `deny`, and it suspends grant auto-approval until the mode changes (#60).
- CI: actions pinned to commit SHAs, base images by digest, gitleaks secret scan, Trivy image scan (#18).

### Added
- **Docker Compose with published images** is the recommended installation. Multi-arch images
  `ghcr.io/philippmundhenk/tallygate-{gateway,control,agent}` (`linux/amd64`, `linux/arm64`) are published
  from `main` (`:main`) and for every release (`:X.Y.Z`, `:X.Y`, `:latest`). Releases attach `compose.yaml`,
  `.env.example`, `gateway.yaml` and `bypass.sh` (#16).
- **Zero-config first start:** the gateway API token, session secret and console credential are created in
  volumes, and a UI password is generated and printed to the control log. Environment variables still take
  precedence. `python -m app.passwd` changes the password; `--print-hash` prints a hash for
  `CONTROL_PASSWORD_HASH` (#16, #62).
- **Quick actions** in the Rules tab: allow the web or all ports for a while, choose what happens with unknown
  destinations, an emergency stop, a guided path to a local-network grant, and **templates** for Python,
  Node.js, Go, Rust, Debian/Ubuntu apt, container registries and Hugging Face (#34, #59, #61).
- **Help and examples:** [docs/rules.md](docs/rules.md) with about 20 worked examples, an example for every
  setting, field help and explanations in the UI, *Test a destination* says what decided (#35).
- `compose.build.yaml` to build the images from a checkout (`make up`) (#16).
- Health check for the agent; services start in order of health (#16).
- `AGENT_CPUS` and a guide to keeping the workspace from filling the host disk (#25).
- A weekly workflow that proposes new Claude Code versions (#17).
- `make coverage`: a gate of 95 % line coverage per module, including the gateway and control processes; every
  module is at 98–100 % (#27).

### Changed
- State lives in Docker volumes by default. `TALLYGATE_DIR` is replaced by `GATEWAY_DATA`, `AGENT_HOME` and
  `WORKSPACE`, which take a host path instead of the volume; `./setup.sh /path` prepares host directories (#16).
- The default `config/gateway.yaml` is built into the gateway image; mount your own file to change it (#16).
- `setup.sh` runs as your normal user and no longer generates secrets (#16).
- **Behaviour:** a CIDR `allow` rule no longer allows host names that resolve into it; use host rules (#10).
- Template rule ids are `<preset>:<id>`; applying a preset never takes over a rule from another source (`409`),
  and `policy` presets cannot be applied on top (#59).
- Gateway and control images on Python 3.15; `agent/Dockerfile` is the single place that pins Claude Code
  (#17, #18).

### Fixed
- Undoing a template could delete rules it never added; "Apply again" with a time limit kept the template
  permanent; template host lists completed (GHCR and Docker Hub blob hosts, `repo.yarnpkg.com`) (#59).
- The managed setting that skips the bypass-mode prompt had no effect (#26).
- The gateway's warnings never reached its log (#27). Agent status responses over one network read were cut
  off (#27).
- Web UI: log history, reconnects, unsaved edits, the console (UTF-8, large pastes, expired sessions), cards
  moving under the cursor, links from chat messages, error messages (#23); accessibility and phone layout
  (#24); quick-action selections and focus, in-page confirmations instead of `confirm()` (#61).
- Notifications: channels fail independently, a queue decouples delivery, a slow homeserver no longer delays
  other prompts, expired prompts are skipped (#22, #63).
- Gateway robustness: event counts, preset time limits, `fsync` before renames, connection state (#15).
- `bypass.sh` works when downloaded next to `compose.yaml` (#65).
- CI: the image scan, release notes and pushes from other branches (#64).

### Removed
- `gateway/config.example.yaml`, a stale duplicate of `config/gateway.yaml` (#16).

### Upgrading from 0.3.0

1. **Stop the stack first**: `docker compose down`. The internal networks changed (#7). A plain `up -d` keeps
   the running containers on the wrong addresses, and the gateway then fails to start.
2. **Keep your state.** 0.4.0 uses Docker volumes by default. If your state is in host directories, point the
   new variables at them in `.env`:
   - with `TALLYGATE_DIR=/your/dir`: `GATEWAY_DATA=/your/dir/gateway`, `AGENT_HOME=/your/dir/agent-home`,
     `WORKSPACE=/your/dir/workspace`;
   - without `TALLYGATE_DIR`, 0.3.0 used `./state` next to `compose.yaml`: `GATEWAY_DATA=./state/gateway`,
     `AGENT_HOME=./state/agent-home`, `WORKSPACE=./state/workspace`.

   Otherwise you start with empty volumes: no Claude login, no workspace, the default policy.
3. **Review `.env`.** Your secrets keep working. 0.3.0's `.env` set `TRUST_FORWARDED_FOR=1`; remove it unless
   you run a reverse proxy and set `TRUSTED_PROXIES` for it. While `CONTROL_PASSWORD_HASH` is set,
   `python -m app.passwd` refuses to change the password: change the hash in `.env` instead (use
   `--print-hash`), or remove it to use the stored password.
4. **Static config:** if you changed `config/gateway.yaml`, mount it as described in
   [docs/operations.md](docs/operations.md#with-docker-compose-recommended).
5. **Behaviour changes to check:** CIDR `allow` rules cover IP literals only (#10); UI grants with `inject` or
   `tls_verify: false` are ignored, so move them to the config file (#12); the Hugging Face and registry
   hosts are read-only (#58).
6. Start: `docker compose pull && docker compose up -d`, or `make up` from source. Then run the self-test or
   `bash bypass.sh`.

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
