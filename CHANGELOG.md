# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

The result of a full project review: Docker Compose with published images as the main installation, a large
set of security fixes from two review rounds, quick actions and templates, help everywhere, and a 95 %
coverage gate. Read [Upgrading from 0.3.0](#upgrading-from-030) before you update.

### Security
- **Read-only hosts refuse protocol upgrades:** a WebSocket (or any `Upgrade`) to a read-only host was a
  channel the gateway could not inspect, so writes could flow; it is now refused, like a write method.
- **Request paths with `#` or `;` are refused** (grants, read-only `read_posts`, `github_repos`): they were
  stripped before the canonical check while the raw path was forwarded, so a server that normalises `..`
  across a `#`, or `..;`, could step outside the allowed path (#137).
- **A request is checked against its connection's target, not the host it names:** an absolute-form
  `https://` request sent to the plain proxy (no CONNECT) is refused, so it cannot be checked against the host
  in its URL instead of a real, gated destination and thereby skip a grant's or an intercepted host's limits.
- **A CIDR `deny` wins for IP literals too** (completing #119): a `*` shortcut or a broader CIDR allow above a
  `deny` no longer lets the agent reach the denied range by connecting to an IP in it directly (#137).
- **A CIDR `deny` rule always wins for names:** a name that resolves into the range of a `deny` rule on a CIDR
  is refused wherever that rule stands. Before, a host `allow` rule above it won, and approvals and shortcuts
  are added on top, so an *Always allow* or *Allow web for 15 min* silently switched the deny off (#119).
- **`grants_never` adds to the built-in list** instead of replacing it: loopback, link-local, multicast and
  unspecified addresses stay closed for every grant, whatever the config lists.
- **Grants and the stack itself:** a `lan: true` grant target skips the hard deny, and `grants_never` did not
  cover the stack's own networks, so a LAN grant pointing there could reach the gateway's management API or
  the control UI. The stack's networks (`GW_INTERNAL_NETS`, set in `compose.yaml`) and the gateway's own
  listeners are now refused for every grant, whatever `grants_never` says. If you changed the subnets in
  `compose.yaml`, change `GW_INTERNAL_NETS` with them (#112).
- **IP literal to an intercepted host:** an intercepted host (credential injection / read-only) could be
  reached without interception by connecting to its IP as a literal — with the host's name as the TLS SNI, a
  mismatched SNI, or no SNI at all — skipping the credential strip/inject and the read-only check.
  Interception is keyed on the name, so the gateway now learns the intercept hosts' IPs (resolved at start, on
  a timer, and as they are used by name) and refuses any IP-literal connection to one; reach those hosts by
  name (#108).
- **Grant path scope:** `path_ok` decoded the request path only once, so a multiply-encoded traversal
  (`%252e%252e`) slipped past the check while the raw path decoded to `..` on a double-decoding upstream. The
  path is now decoded to a fixed point and a residual `%` is refused (#111).
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
- **How access works** (`docs/access.md`): the access model on one page — never reachable, on request, rules,
  everything else, the limits inside a destination, who decides what, and why some settings are file-only
  (#121).
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
- **Away mode, quiet hours and a digest:** while you are away or in quiet hours, new destinations and grant
  requests that need you are refused at once with a clear message to the agent (never allowed
  automatically). What was refused is listed in the UI and sent as one digest when you are back (#73).
- **Phone approvals without a chat bot:** the UI is an installable app with Web Push (VAPID key created on
  first start). Notifications have *Allow 2 min* / *Deny* buttons that work through single-use, signed
  action tokens, never an approve URL; plain HTTP degrades to a hint. ntfy, Gotify and Pushover can notify
  as well (#72).
- **Context for decisions:** an approval shows the agent's recent activity: the command or URL Claude Code was
  about to run (PreToolUse hook, secrets redacted, never blocks the agent) or a `tallygate note`. It is
  labelled as the agent's unverified claim and has its own rate limit (#74).
- **GitHub access per repository:** `github_repos: [owner/repo, owner/*]` in the gateway config refuses
  requests to other repositories (API, git, uploads) before they reach GitHub; GraphQL is refused unless
  `github_graphql: true`. Empty keeps the current behaviour (#78).
- **Guided first start:** the Setup tab is one flow in which every step says whether it is done and the next
  missing one is highlighted. It checks how the browser reaches the UI (HTTPS or localhost, cookie flag,
  forwarded headers, reverse proxy, `PUBLIC_URL`, how to reach it from another machine), whether the UI
  password is still the generated one, and offers the starting policy. *Log in to Claude* runs
  `claude auth login` in the agent and takes the code in the UI; *Use my GitHub identity* sets the git name
  and noreply address from `gh api user` after a preview (it explains a missing or refused token and never
  writes empty values); *Enable Remote Control* answers its one-time `(y/n)` question. No console needed (#75).
- **Overview tab** as the start page: Claude and Remote Control status with the session name, gateway health,
  Claude Code version and disk use; what needs attention (requests, rules and grants ending within the hour,
  a missing, refused or expiring GitHub token); the last hour (allowed/denied/asked, top and new
  destinations); emergency stop, *Allow web for 15 min* and the console as shortcuts. New gateway endpoint
  `GET /events/summary`; `/info` and the agent status report disk use (#68).
- **Keyboard shortcuts** on the Approvals tab (`j`/`k` select, `a` allow 2 min, `h` allow 1 h, `d` deny,
  `?` lists them; can be switched off), a **compact list** with one line per connection request, and an
  optional **sound** when a request arrives while the tab is in the background (#79).
- **Versions and update notice:** the Overview shows the running tallygate and Claude Code versions and the
  latest release; the header says **Update: X.Y.Z** when a newer one exists, with links to the changelog and
  the release and the upgrade command. Control asks GitHub's releases API from its own network (never through
  the agent), caches the answer for 6 h, and `UPDATE_CHECK=0` switches it off. The gateway image carries
  `VERSION` and reports it in `/info` (#81).
- **Workspace files** in a new *Files* tab: browse `/workspace`, upload into the open folder and download
  results, through the agent's status server (no new network path). Paths stay inside the workspace (no
  `..`, symlinks that leave it are refused), uploads are size-limited (`FILES_MAX_UPLOAD`, 50 MiB) and never
  replace a file unasked or write through a link, downloads are attachments that are never rendered in the
  UI (`FILES_MAX_DOWNLOAD`, 200 MiB) (#76).
- **Policy history:** every change to the policy is a version with time, author and what changed. The Rules
  tab shows a diff between any two versions and restores one; the policy and the UI grants can be exported
  as one YAML file and imported again, validated like any policy change (#71).
- **Rule usage:** hit counters and the last match per rule, sortable and filterable in the Rules tab; permanent
  rules that did not match for `rule_stale_days` are offered for removal, and destinations you keep approving
  for a limited time are offered as a permanent rule (#70).
- **Log search:** server-side search of the event log by host (`*.domain` too), kind, action and time range,
  saved filters, a destinations view with new destinations, a page per destination with the rule that decides
  it, and CSV or JSON export (#80).
- **Learning mode:** for a limited time, destinations no rule covers are allowed on the chosen ports and
  recorded; afterwards they are proposed as rules, grouped by domain, to save in one go. The hard deny, deny
  and ask rules, grants and name-first decisions stay in force; it is shown in the header and ends by itself,
  on the emergency stop and on restart (#69).

### Changed
- **Accessibility:** the filled buttons now meet WCAG AA contrast (the blue and red were 3.7:1 with white text; now 5.2:1 and 4.8:1), the Log tab shows an empty state instead of a bare table, the upgrade-command copy box is a labelled button for screen readers, the keyboard help matches the "Allow once" label, and "load the next page" reads *Load older* everywhere (#143).
- **One `never` list in the gateway config** replaces `hard_deny_floor` and `grants_never`: a plain range is
  closed for every connection; `{range, scope: all+lan}` is closed for LAN grants too. The old keys still
  work and are read as `never` (`grants_never` entries now also close every connection, not only grants); the
  gateway logs once at start that they can be renamed, and `python -m egressgw.convert gateway.yaml` prints the
  file in the new form (#122).
- **One evaluation path (ADR-0014, first part):** whether a connection is intercepted and what each request on
  it may do is now decided in one place (`gateway/egressgw/model.py`), for read-only hosts, credential
  injection, repository limits and grants alike. No behaviour change: the model ran next to the old code on
  every TLS handshake and request of the whole test suite without a difference before it took over (#122).
- **First run:** the *Starting policy* step of the setup points to learning mode as the quickest way to a
  working set of rules (*Learn from a first task*). It opens *Rules → Learning mode*, where the time limit is
  chosen and confirmed as before (#121).
- **What the agent can reach:** a new table at the top of the *Rules* tab lists each destination once with
  everything that applies to it: the deciding rule, read-only, added credentials, repository limits, the grants
  defined for it and when it was last used. Until now that took three tabs and the config file. New read-only
  route `GET /access` (#121).
- **One "Never reachable" list:** *Rules → Never reachable* shows every range that can never be reached in one
  table: the built-in list, `hard_deny_floor`, your additions, `grants_never`, the stack's own networks and the
  gateway's own listeners, each with where it comes from and where it is changed. It replaces the *Hard deny*
  card; adding ranges works as before. New read-only route `GET /never-reachable` (#121).
- **Simple grant form:** *New grant* asks for a name, an address (host and port, or a URL), the type, read-only
  or full access, and a duration. The other settings are under *Advanced* with their defaults. Grants saved from
  the simple form use the chosen duration as default and maximum, and ask for approval each time (#121).
- **One name for one-click rule sets:** the UI and the docs say **Shortcuts** (*Rules → Shortcuts*, with the
  groups *Internet* and *Tool ecosystems*) where they said quick actions, templates, internet shortcuts and
  presets. "Preset" remains the name of the files in `gateway/presets/` and of the `/presets` API routes; nothing
  about them changes (#121).
- **Approval prompts are shorter:** *Allow once*, *Always allow* and *Deny* come first; *Allow 1 h*,
  *Always (\*.domain)* and *Block forever* are behind **More** — in the web UI, in Telegram (*More…* adds them to
  the same message) and in Matrix (three reactions are pre-seeded, the others still work). *Allow 2 min* is now
  called *Allow once* and *Always (host)* *Always allow*; what they do is unchanged, and so are the keyboard
  shortcuts and the Matrix text replies (#121).
- **The UI is reachable on the LAN by default** (`CONTROL_PUBLISH=0.0.0.0:8080`) and the session cookie
  follows the connection (`COOKIE_SECURE=auto`): plain HTTP works out of the box, HTTPS keeps the cookie
  `Secure`, and the UI warns on unencrypted access from another machine. The agent still cannot reach the UI
  (#97).
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
- Mobile navigation: the eight top tabs no longer wrap onto three lines. The nav is a left sidebar on desktop
  and a hamburger drawer on mobile, keyboard-navigable with the arrow keys and `role="tab"` semantics kept; the
  `live`/`reconnecting` indicator and `Log out` stay in the header at every width (#138).
- Mobile Files upload: the file picker sits on its own line and *replace existing files* and *Upload* move to a
  row below, instead of overflowing one cramped line (#140).
- Setup: the lower *Notifications* card reused the *Phone notifications* step's element ids, so its channel
  status stayed empty and *Enable browser notifications* had no handler. Both cards now have unique ids and are
  updated together (#120).
- Notifications: channels fail independently, a queue decouples delivery, a slow homeserver no longer delays
  other prompts, expired prompts are skipped (#22, #63).
- Gateway robustness: event counts, preset time limits, `fsync` before renames, connection state (#15).
- `bypass.sh` works when downloaded next to `compose.yaml` (#65).
- State directories that are bind mounts with the wrong owner stop the containers with a clear message (directory, uid, the
  `chown` to run) instead of a traceback; the docs list every volume with its owner; `CONTROL_DATA` (#95).
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
6. **UI address:** the UI is now published on all interfaces (`0.0.0.0:8080`). With a reverse proxy on the
   same host, set `CONTROL_PUBLISH=127.0.0.1:8080` to keep it local; remove `COOKIE_SECURE=1` from `.env` unless
   you only use HTTPS (the new default `auto` decides per connection) (#97).
7. Start: `docker compose pull && docker compose up -d`, or `make up` from source. Then run the self-test or
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
