# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.4.1] - 2026-11-19

Fixes for the findings of the security review of 0.4.0. One of them changes how you reach the UI: read
[Upgrading from 0.4.0](#upgrading-from-040) before you update.

### Security
- **Control gets the stack's networks and `ALLOWED_HOSTS` from `compose.yaml`** (follow-up of #240 and #246):
  the check that keeps notification channel URLs out of the stack now covers all four of its networks, and
  `ALLOWED_HOSTS` is set in `.env` like every other setting, without an override file.
- **Documentation made true** (#235): what the built-in blocks and `never` are since the ordered rule list,
  what a compromised agent can do with the Claude login beyond this one session, which agent-written text
  reaches the notification channels (the grant reason), and how the authoritative isolation test runs.
- **Control plane hardening after the review of 0.4.0 (#242, #243, #245, #246; Low and Info).**
  - **The idle timeout works while a tab is open (#242).** Every request counted as activity, and the page
    polls the server every 30 s, so a visible tab was never logged out before the 12 h limit. Now only what
    you do counts (a key, a click, scrolling, typing in a console). What the page sends by itself is marked
    (`X-Tallygate-Poll: 1`) and does not count, nor do the event stream and console output. This protects a
    tab left open and unattended; someone sitting at your browser can still use it.
  - **The agent cannot break the Setup and Overview tabs with odd answers (#243).** Its status and setup
    answers are reduced to known keys with their expected types before the UI sees them; a number where a
    text belongs stopped the Setup tab before the notification settings. JSON nested too deeply is a `502`
    instead of an internal error.
  - **Without a login only the login page's own files are served (#245):** an exact list instead of the
    prefix `/static/login`, which also matched `/static/login/../app.js`.
  - **Smaller points (#246):** a session cookie with non-ASCII characters is "not logged in" instead of an
    internal error; a workspace download is refused when the browser says the request comes from another
    site; secret files in the data volume are created with mode 0600 instead of being tightened after
    writing; `COOKIE_SECURE=auto` also marks the cookie `Secure` when `PUBLIC_URL` is `https://`; a held key
    no longer decides the next approval card too; a notification can only open a page of the UI itself; a
    Telegram chat id that is a `@name` is refused with a clear message (its buttons never worked); and
    `ALLOWED_HOSTS` (new, optional) limits the host names the UI answers under, against DNS rebinding of the
    login form. The Setup tab warns when the UI is opened under a name with neither `PUBLIC_URL` nor
    `ALLOWED_HOSTS` set. Threat T55 in [docs/threat-model.md](docs/threat-model.md).

  **Check after upgrading:**
  - A `SESSION_SECRET` in `.env` shorter than 32 characters now stops the control plane with
    `SESSION_SECRET must be at least 32 characters`. Remove the line or use `openssl rand -hex 32`.
  - A UI tab you do not touch for `SESSION_IDLE` (2 h) is logged out, even if it stayed open. Raise
    `SESSION_IDLE` for a wall display.
  - `TELEGRAM_CHAT_ID=@name` switches Telegram off with a reason under **Setup → Notifications**: use the
    numeric chat id.
  - With `PUBLIC_URL=https://…` and `COOKIE_SECURE=auto`, the UI can no longer be used over plain HTTP by
    address at the same time (the cookie is `Secure`); changes from there were already refused.
  - Scripts: a download with a `Sec-Fetch-Site: cross-site` header is refused; scripts that poll the API
    keep their session alive as before unless they send `X-Tallygate-Poll: 1`.
  See [troubleshooting](docs/operations.md#troubleshooting).
- **A notification channel URL cannot point at the stack or at this machine, and Test no longer repeats the
  answer (#240, Low).** Found by the security review of v0.4.0. With a UI session (for example a stolen
  one), the URL of Matrix, ntfy or Gotify could be any `http(s)` URL: `127.0.0.1`, the cloud metadata
  address, the gateway's management API, the agent. A `?` in the Matrix or Gotify URL turned the fixed path
  the control plane appends into a query, so the path was free too, and **Test** returned the other side's
  error text. Now these URLs take no `?query` and no `#fragment`, and may not name this machine, a
  link-local address, or the stack itself (`GW_URL`, `AGENT_HOST`, the control plane's own address and
  name, and `GW_INTERNAL_NETS` if the control plane is given it). The check runs when a URL is saved, when
  it is loaded (also from the environment) and for every connection: a name that resolves to a refused
  address is not connected to, and the connection goes to the addresses that were checked. **Test** shows
  a fixed text with the class of the HTTP status; the detail is in the control log.
  Servers on your local network stay allowed: self-hosted ntfy, Gotify and Matrix are supported setups.
  Threat T54 in [docs/threat-model.md](docs/threat-model.md).
  **Check after upgrading:** a channel whose URL contains a query string (for example `NTFY_URL=…?auth=…`)
  or points at `localhost`, `127.0.0.1` or a link-local address is now *Off* with the reason under
  **Setup → Notifications**. Use the server's name or LAN address and the token field. If **Test** fails,
  read the reason in `docker compose logs control`
  ([troubleshooting](docs/operations.md#troubleshooting)).
- **Notification buttons end with their device and at a restart (#241, Low).** Found by the security review
  of v0.4.0. A push action token named its device, but pressing the button did not check that the device was
  still subscribed: for up to 10 minutes after *Remove*, a removed phone could still decide the requests it
  showed (attributed to `push:removed device`). And the list of used tokens lives in memory, so a restart
  of the control plane made a used token good again within its lifetime. Now a token whose device is gone is
  refused, and every token carries the boot id of the control process that minted it: no other run takes it.
  The boot id was chosen over storing used tokens on disk because it needs no new state file, cannot lose a
  write, and fails closed. `/api/push/act` now also requires the `Origin` header, as the threat model (T41)
  already said; the service worker's request always has it.
  **Check after upgrading:** after every restart of the control plane (this update included) the buttons of
  notifications that were sent before it answer *Not applied: tallygate was restarted since this
  notification*. Decide those requests under **Approvals**; new notifications work as before. Nothing else
  changes for browsers. A script of your own that calls `/api/push/act` must send `Origin`.
- **A chat approver can only decide the prompts shown, and the relay cannot leave its routes (#239, #244,
  Low).** Found by the security review of v0.4.0. The id in a Telegram button's callback data went into the
  gateway API path unchecked, and the HTTP client normalised `..` and took `?` as the start of a query. An
  allowed Telegram user with a modified client (callback data is free text) could therefore call any `POST`
  or `DELETE` of the gateway API with the control plane's token, for example the *Allow web* shortcut or a
  rollback of the policy, instead of deciding a prompt. The same normalisation let
  `DELETE /api/gw/destinations/..` from a UI session reach the gateway's `/` (no such route exists today).
  Now callback data is accepted only as an id of `[a-f0-9]{1,32}` with a known scope (connection requests)
  or `approve`/`read`/`deny` (grant requests); everything else is dropped without an answer and logged
  (`callback data from … dropped: not a button of this bot`). The decision functions of every channel check
  the same again, the relay's allow-list accepts no id that starts with a dot or contains `..`, and the one
  function that calls the gateway API refuses a path with `..`, `?`, `#` or any character outside
  `[A-Za-z0-9_:.-/]` and sends the path byte for byte. Matrix (reactions and replies name a prompt by event
  or number, never by id) and Web Push (signed tokens, id checked) were checked and needed no change.
  Threat T53 in [docs/threat-model.md](docs/threat-model.md). Nothing to do after upgrading.
- **Automatic grants while you are away are no longer silent (#237, Info).** A grant level with
  `approval: auto` is activated at once, also in away mode and in quiet hours. That stays so: you authorised
  the level beforehand, away mode is about requests that need a person, and the emergency stop suspends
  automatic approval. But until now nothing told you that it had happened. Every such activation is now
  listed under **While you were away** (the former *Refused while you were away*) as *activated
  automatically*, with the grant, the level, how often and when last, without an *Allow* button, and it is
  part of the digest, apart from what was refused. The entry holds only the grant's name and level, never
  the agent's reason, and a flood of refused destinations cannot push it out of the list. The threat model
  (T40), [grants](docs/grants.md) and the [user guide](docs/user-guide.md#away-mode-and-quiet-hours) now
  name the exemption. API: `missed` of `GET /availability` and the `digest` event have a third kind,
  `auto_grant`.
- **No core dumps, and no container routes (#233, Low).** A crashing process in the agent handed its memory
  to the Docker host: the core size limit was unlimited and `core_pattern` belongs to the host, where it
  usually pipes into `systemd-coredump` running as root. All three services now run with `ulimits: core: 0`.
  The network namespaces inherited `ip_forward=1` from the host, so the gateway and the control plane, each
  with a leg on `agent-net` and one on a network with a way out, were routers in principle (the agent has
  no way to address a packet to them as next hop, so this was not exploitable); forwarding, proxy ARP,
  redirects and source routing are now switched off by sysctl. `bypass.sh` checks both on the running
  stack and sends UDP broadcast, multicast, device-bound and routed datagrams from `agent-net` towards a
  listener on the host: none may arrive. **Both settings are in `compose.yaml`: take the new file**
  ([upgrading](docs/operations.md#upgrading-and-rolling-back)).
- **Supply chain and hardening from the review (#234, Low).**
  - Python dependencies are installed from lock files with hashes (`pip --require-hashes`); before, only the
    direct dependencies were pinned, by version. Claude Code is installed with `npm ci` from a lock file with
    integrity hashes. The GitHub CLI apt keyring is pinned by SHA-256 and by its exact set of keys; the old
    check passed a keyring that contained the pinned key *and any other*.
  - CI: no tag or branch name is pasted into a workflow script any more, and the image scan now fails on a
    CRITICAL vulnerability that has a fix. It runs before an image is pushed or signed (#256), so such an
    image is not published and there is no release ([development](docs/development.md#image-scan)).
  - The documented backup command wrote a world-readable archive with the GitHub token and the CA key, using
    an unpinned image. It now runs under `umask 077` with an image pinned by digest and no network
    ([backup and restore](docs/operations.md#backup-and-restore)). **Check the permissions of backups you
    already have** (`chmod 600`).
  - New: [Resetting the agent after a compromise](docs/operations.md#resetting-the-agent-after-a-compromise):
    what persists on the home volume and in the workspace, what to rotate, and the commands.
  - `bypass.sh` runs Python inside the agent with `-I`, so the agent's own packages cannot change the result.
  - The activity context shown next to approvals redacts tokens by their prefix (`ghp_…`, `github_pat_…`,
    `sk-…`, `xox?-…`, `AKIA…`, JWTs), Telegram bot tokens and `sshpass -p` in the agent's hook as well.
    Short secrets without any such mark still pass; that limit is now documented (threat model).
- **The Matrix bot can no longer approve requests itself (#238, Medium).** The check that the bot's account is
  not one of the allowed users depended on one `whoami` call when the control plane started. If that call
  failed (homeserver not up yet after a reboot, a 5xx) and the bot used an allowed user's token, the control
  plane took the reactions it pre-seeds on every prompt (👍 first), echoed by the homeserver, for that user's
  decision: every connection request was allowed and every grant request approved at the requested level.
  Now nothing from the room counts until `whoami` has succeeded: it is retried (5 s doubling to 5 min), the
  channel row under **Setup → Notifications** says *Matrix approvals paused* meanwhile, and what happened in
  the room during the pause is not applied afterwards (the request stays open for the UI). A bot account that
  is an allowed user switches Matrix approvals off on every path, and the row says so. Independently, the
  control plane remembers the events it sent itself and never takes them, or anything by their sender, as a
  decision. Telegram was checked and is not affected. **If you run the bot with your own account's token:**
  create a separate bot account ([user guide](docs/user-guide.md#matrix-approvals)).
- **The control plane never follows a redirect (#230, High).** The agent's status server and ttyd run as the
  agent user, so a hostile agent could replace them and answer the control plane's calls (status every 30 s
  while *Overview* is open, version, setup, files, console) with `302 Location: <any URL>`. Control, which
  has a route to the local network and the internet, fetched that URL itself: a path around the gateway with
  no policy, no approval and no log entry, including data in URLs and, with 307/308, re-sent POST and DELETE
  requests. Now every HTTP client of the control plane refuses any 3xx before a second request is built
  (HTTP and the console WebSocket alike), and the browser gets `502` with a fixed text. The client for the
  agent connects to `AGENT_HOST` on the status and console ports only, the one for the gateway to `GW_URL`
  only. Threat T49 in [docs/threat-model.md](docs/threat-model.md).
  **Check after upgrading:** calls to GitHub and to the notification services (ntfy, Gotify, Pushover,
  Telegram, Matrix, Web Push) are not followed either. If a channel worked only through a redirect (for
  example `http://` in `NTFY_URL` behind a reverse proxy that redirects to `https://`), it now fails with
  *answered with a redirect, which control never follows*: enter the final URL
  ([troubleshooting](docs/operations.md#troubleshooting)).
- **Every request is checked against its own destination, also on a reused connection (#236, high).** Found
  by the security review of v0.4.0. After one allowed plain-HTTP request to a grant target, a second request
  on the same keep-alive connection that named the target's **IP address** was forwarded without any check:
  any method and path on a read-only, path-limited grant, and into a blocked range if the target named a
  device there. The cause: mitmproxy reuses an open upstream connection whose address equals the host and
  port a request names, without asking the gateway again, and the request check trusted a request it had no
  connection decision for. The stack itself (the locked ranges) was not reachable this way. Now:
  - A plain-HTTP proxy request is decided on its own destination with the policy, and it is only sent on a
    connection that was checked for exactly that destination. A request that names an address on a
    connection that was opened for a name gets `403 request for … on a connection that was checked for …`.
    Open a new connection to the proxy for it; it is then decided like any new destination.
  - The fixed address of an active grant's target is not opened by the grant: reach the target by its name,
    where the grant's limits apply. By IP it is refused without a prompt unless a rule allows the address.
  - A request on an open connection is never asked about. If the destination needs your approval again (an
    approved IP literal whose time ran out, on a connection that is still open), the request is refused and
    the next connection asks.
  - A grant on an IP-literal target that is revoked or expires also ends on a connection that is still open.
  - Inside a CONNECT tunnel, over SOCKS5 and on intercepted TLS, an HTTP/1 request whose request line names
    another server (`GET http://other.example/…` with the checked `Host`) is refused like a wrong `Host`
    header: `403 request target does not match the checked target`.
  - A grant that starts or ends in the moment between the check of a request and the opening of its
    connection refuses that connection (`… changed while the request was checked: send it again`).

  Unchanged: a first request to a destination you are asked about is held until you answer, and keep-alive
  to one destination works as before. See threat T50 in [docs/threat-model.md](docs/threat-model.md) and
  [what is checked per connection and what per request](docs/architecture.md#what-is-checked-per-connection-and-what-per-request).
- **The UI is published on the Docker host only (`CONTROL_PUBLISH=127.0.0.1:8080`)** instead of every
  interface. The UI is plain HTTP, so on `0.0.0.0:8080` the generated password and the session crossed the
  network in clear text, and a port published by Docker is not filtered by host firewalls such as ufw. Other
  machines reach the UI through a TLS reverse proxy on the host or an SSH tunnel; publishing it to the
  network is an explicit `CONTROL_PUBLISH` setting. The reverse-proxy examples in the README and in
  docs/operations.md now show `CONTROL_PUBLISH`, so the plain port does not stay open next to the proxy.
  No other port of the stack is published (#231).
- **The `compose.yaml` of a release starts the images of that release.** It used to pull `:latest` whatever
  release it was downloaded from, so the images moved with every `docker compose pull` while the isolation
  settings in the file (networks, `GW_INTERNAL_NETS`, hardening) stayed behind. The release job now writes
  the version into the attached file (`${TALLYGATE_VERSION:-X.Y.Z}`, `tools/pin_compose.py`) and attaches
  `compose.digests.yaml`, an override that pins the three images by digest (#232).
- **Images are signed.** Every image pushed to GHCR (releases, `:main`, `:sha-…`) is signed by digest with
  cosign, keyless, bound to this repository's CI workflow. How to check:
  [docs/operations.md](docs/operations.md#verifying-the-images) (#232).
- **The gateway does not start without `GW_INTERNAL_NETS`.** An empty value was only a warning, and then no
  network of the stack was locked: the case of new images under an old compose file. It now stops the
  gateway like an invalid value does. `compose.yaml` always sets it, so installations from a release file
  are not affected (#232).

### Changed
- **Upgrading means replacing `compose.yaml`,** not only `docker compose pull`: download the file of the new
  release, then pull and start. To go back, put the previous file back. Both are described in
  [docs/operations.md](docs/operations.md#upgrading-and-rolling-back), and the update notice in the UI
  shows the new command.
- The first-start message in the control log, `setup.sh` and the UI's *Access to this UI* check name the new
  default address and how other machines reach the UI.
- `TALLYGATE_VERSION` is optional with a release's `compose.yaml`; it still overrides the version in the
  file. The `compose.yaml` on `main` keeps `:latest` as its default, for building from source and trying
  `main`.
- Development: a gateway run outside the compose stack (unit and e2e tests, by hand) needs
  `GW_TEST_NO_INTERNAL_NETS=1`; the test harness sets it (docs/development.md).

### Upgrading from 0.4.0

1. **Replace `compose.yaml`** with the one of the new release
   ([steps](docs/operations.md#upgrading-and-rolling-back)), and re-apply your own changes to it if you made
   any. If `.env` sets `TALLYGATE_VERSION`, remove the line or raise it.
2. **The UI no longer answers on `http://<host>:8080` from other machines.** With the new file it is
   published on `127.0.0.1:8080`. Choose one:
   - open it on the Docker host, or through `ssh -L 8080:127.0.0.1:8080 <host>` at `http://127.0.0.1:8080`;
   - put a TLS reverse proxy in front ([docs/operations.md](docs/operations.md#reverse-proxy));
   - **keep the old behaviour:** `CONTROL_PUBLISH=0.0.0.0:8080` in `.env` (or `<LAN address>:8080` for one
     interface). The password and the session then cross your network unencrypted, and ufw or firewalld do
     not filter the port: only on a network you trust.

   A `.env` that already sets `CONTROL_PUBLISH` keeps its value. With a reverse proxy on the host, check
   that it is `127.0.0.1:8080` (0.4.0 published on every interface unless you set it).
3. **If you changed the subnets** in `compose.yaml`, keep `GW_INTERNAL_NETS` in step with them, as before. A
   gateway without it now stops with `GW_INTERNAL_NETS is empty` in its log.
4. Start: `docker compose pull && docker compose up -d`, then the self-test or `bash bypass.sh`.

## [0.4.0] - 2026-11-18

The result of a full project review: Docker Compose with published images as the main installation, a large
set of security fixes from two review rounds, quick actions and templates, help everywhere, and a 95 %
coverage gate. Read [Upgrading from 0.3.0](#upgrading-from-030) before you update.

**How to read this section.** The policy model and the web UI were reworked in several steps, and the
entries below were written step by step. Where a later step of this release replaced an earlier one, the
earlier entry ends with *Replaced in this release*. The state you get:

- **The policy is one ordered rule list** ([ADR-0019](docs/adr/0019-one-ordered-rule-list.md), first entry
  under *Changed*). The "hard deny", the "deny floor", `hard_deny_floor`, `floor_open`, the "never reachable"
  list, `grants_lan_allow` and `lan: true` named in older entries do not exist any more: the blocked ranges
  are ordinary rules, and only the stack itself is locked ([docs/rules.md](docs/rules.md)).
- **The menu** is Overview, Approvals, Setup, Quick settings, Destinations, Grants, Log, Console, Files,
  Settings. Where an entry says *Rules tab*, read: *Destinations* (the rule list, *Test a destination*),
  *Quick settings* (learning mode, shortcuts, tool ecosystems, the local-network form), *Overview* (rule
  usage), *Log* (policy history, export and import), *Settings* (mode, behaviour settings, raw policy).
  *Quick start* was renamed *Quick settings*. Grant definitions are on the *Grants* tab.

### Security
- **An IP address written like a name is refused:** a host such as `192.168.1.1.` (trailing dot), `127.1`,
  `2130706433` or `0x7f.1` is an IPv4 address for resolvers, but was asked about as a name, and the
  approval became an allow rule for the address at the top of the list, above the built-in blocks. Such
  hosts are now refused as invalid host names (not asked about, not resolved, not covered by learning
  mode), an approval for an address inside a blocked range is refused, and *Allow for 1 h* in the away
  digest takes a second click for an address. Found by the review of the ADR-0019 amendment
  ([docs/security-review.md](docs/security-review.md)), like the next five entries.
- **Replacing the whole policy says what is open inside the blocks:** `PUT /policy`, restore and import
  record the address rules that stand above a block and reach into it (the import preview warns before
  applying), and the gateway logs them at every start.
- **`expires` must be a finite number:** `NaN` in `PUT /policy` answered `400` with the new policy in force
  and not saved. It is refused before anything changes, as is a `host` that is not a string.
- **The reason for a name stopped by a blocked range no longer says how to open the range:** the agent
  reads it too. It ends `a name rule cannot open a blocked range`.
- **Locked ranges:** the local-use NAT64 prefix `64:ff9b:1::/48` and IPv4-translated addresses
  (`::ffff:0:a.b.c.d`) that carry a locked IPv4 address are locked too.
- **A `deny` rule for an address or range is never offered as unused,** so *remove unused rules* cannot
  delete a block that was edited and edited back.
- **Read-only hosts refuse protocol upgrades:** a WebSocket (or any `Upgrade`) to a read-only host was a
  channel the gateway could not inspect, so writes could flow; it is now refused, like a write method.
- **Request paths with `#` or `;` are refused** (grants, read-only `read_posts`, `github_repos`): they were
  stripped before the canonical check while the raw path was forwarded, so a server that normalises `..`
  across a `#`, or `..;`, could step outside the allowed path (#137).
- **Revoking or expiring a grant now cuts its open tunnels:** a raw-TCP or WebSocket tunnel opened while a
  grant was active used to keep carrying traffic after the grant ended (new HTTP requests were already
  refused). It is now closed on the next message, so no further data flows (also on the emergency stop) (#137).
- **A request is checked against its connection's target, not the host it names:** an absolute-form
  `https://` request sent to the plain proxy (no CONNECT) is refused, so it cannot be checked against the host
  in its URL instead of a real, gated destination and thereby skip a grant's or an intercepted host's limits.
- **A CIDR `deny` wins for IP literals too** (completing #119): a `*` shortcut or a broader CIDR allow above a
  `deny` no longer lets the agent reach the denied range by connecting to an IP in it directly (#137).
- **A CIDR `deny` rule always wins for names:** a name that resolves into the range of a `deny` rule on a CIDR
  is refused wherever that rule stands. Before, a host `allow` rule above it won, and approvals and shortcuts
  are added on top, so an *Always allow* or *Allow web for 15 min* silently switched the deny off (#119).
- **`grants_never` adds to the built-in list** instead of replacing it: loopback, link-local, multicast and
  unspecified addresses stay closed for every grant, whatever the config lists. *Replaced in this release:
  `grants_never` is read as plain `never` entries, and a grant target that names such an address is decided
  like an address rule (ADR-0019).*
- **Grants and the stack itself:** a `lan: true` grant target skips the hard deny, and `grants_never` did not
  cover the stack's own networks, so a LAN grant pointing there could reach the gateway's management API or
  the control UI. The stack's networks (`GW_INTERNAL_NETS`, set in `compose.yaml`) and the gateway's own
  listeners are now refused for every grant, whatever `grants_never` says. If you changed the subnets in
  `compose.yaml`, change `GW_INTERNAL_NETS` with them (#112). *The fix stands and became the locked ranges of
  ADR-0019, which apply to every connection; `lan: true` and the hard deny it describes are gone.*
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
  the connection instead of letting it through. An invalid `hard_deny_floor` entry (now: `never`) stops the
  gateway at startup, and until a failed startup has exited every connection is refused (#8).
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
- **Hard deny:** `hard_deny_floor` extends the built-in list instead of replacing it (#11). *Replaced in this
  release: the key is read as `never`, whose entries are seeded once as `deny` rules (ADR-0019).*
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
- **A hint when the gateway has no connection** (#218). When the host's network is down (DNS or more), the
  gateway no longer looks like a policy that refuses everything: the *Overview* and the *Log* show *No
  connection from the gateway since HH:MM (N min): lookups and connections fail. This is a problem of the
  host's network, not a policy decision.* and clear it by themselves at the first success. It starts when at
  least five lookups or connections fail over at least two different names for at least two minutes with no
  success, **and** a control probe (a fixed name, `api.anthropic.com`, by default; at most once every 30 s)
  fails as well, so an agent that asks for names that do not exist cannot fake an outage. The Log gets an
  event when it starts and when it ends (with the duration); refusals during it carry the reason prefix
  `no connection:` and are not counted as denies on *Overview*. `GET /info` has a `connectivity` object, the
  stream a `connectivity` message, notification channels get one message when it starts and one when it ends,
  and `tallygate grants` tells the agent. Threat T48; keys `connectivity_*` in `gateway.yaml`
  ([configuration](docs/configuration.md#connectivity)).
- **Notification buttons are configurable** (#212): *Setup → Notifications → Notification buttons* chooses
  which decisions a connection request offers in a notification and in which order: one to four of *Allow
  once*, *Allow for 1 h*, *Allow host permanently*, *Allow \*.domain permanently*, *Deny* and *Deny
  permanently* ([user guide](docs/user-guide.md#notification-buttons)). The default is what it was (*Allow
  once*, *Deny*), so nothing changes until you save a choice.
  - Web Push shows exactly the chosen buttons; a device shows the first ones it has room for (two on most
    platforms, `Notification.maxActions`) and opens the approvals on a tap. Telegram and Matrix show the chosen
    buttons first and keep every decision behind *More*.
  - Every button still carries its own single-use action token, and the decision is part of the signed token:
    a *Deny* button cannot allow. A token whose button was switched off since is refused. *Allow \*.domain
    permanently* shows its pattern and is only offered for a name with a registrable domain. Switching on a
    permanent allow is confirmed (threat model T47).
  - API: `PUT` / `DELETE /api/notify/actions`; `GET /api/notify/config` reports the setting; `POST
    /api/push/act` also returns the text the notification then shows. The setting is stored in `notify.json`
    ([ADR-0018](docs/adr/0018-notification-credentials-stored-by-the-control-plane.md), amended); there is no
    environment variable.
- **Test and status for every notification channel** (#180): *Setup → Notifications* is now one section (the
  wizard step and the old standalone card are folded together). Each channel (Telegram, Matrix, ntfy, Gotify,
  Pushover, Web Push) shows whether it is active and, when off, why — e.g. the environment variables still to
  set — and where its settings come from. A **Test** button on each active channel sends a short
  "tallygate test" through just that channel and reports the result (`POST /api/notify/test` with `{"channel"}`
  for the bot channels, through the notifier's normal sender; Web Push keeps `POST /api/push/test`).
- **Notification channels can be configured in the web UI** (#201, ADR-0018): Telegram, Matrix, ntfy, Gotify
  and Pushover each have a **Configure** disclosure in *Setup → Notifications* with the fields of their
  environment variables, **Save** and **Remove override**. Saving applies at once, without a restart: only the
  poll loop of a changed channel is restarted, waiting requests stay open. Tokens are write-only (stored in
  `notify.json` in the control data volume, mode 0600; never returned by the API, shown or logged), a value
  saved in the UI overrides its environment variable field by field, and removing the override falls back to
  the environment. A changed server URL needs its token again, and Telegram/Matrix are refused without their
  allowed users. New routes: `GET /api/notify/config`, `PUT`/`DELETE /api/notify/config/{channel}`. On a
  read-only data volume the UI says so and the channels stay environment-only.
- **Behaviour settings in the UI** (ADR-0015): the gateway's tunables — log retention, learning-mode ports and
  limit, rule-suggestion thresholds, grant-request timeout and cap, policy-history depth, pending caps — are
  edited under *Setup → Behaviour settings* (`GET`/`PATCH /settings`) and persisted to a backend-owned
  `settings.yaml`, seeded once from `gateway.yaml`/env. No file edit, and the live ones apply without a restart.
  The trust-critical settings (credential injection, LAN, `tls_verify`, the never-reachable floor) stay
  file-only in `gateway.yaml` by design (#147). *Replaced in this release: the settings are under Settings →
  Behaviour settings, and only credential injection and `tls_verify` stay file-only (ADR-0019).*
- **State files in the destinations form** (ADR-0014): the gateway writes its own `policy.yaml` and UI
  `grants.yaml` as `destinations:`, and reads either form. A pre-0014 file is migrated once on first start —
  backed up as `*.pre-0014` and rewritten — and a file that cannot be translated stops the gateway (fail
  closed). Unattended updates keep working; the API is unchanged.
- **One management surface** (ADR-0014): the old per-mechanism API routes are removed — `POST`/`PATCH`/`DELETE
  /rules`, `POST /rules/group` and `PUT`/`DELETE /grants` are gone. Rules and on-request destinations are
  created, edited, deleted and grouped through one surface: `POST`/`PATCH`/`DELETE /destinations`,
  `POST /destinations/group` and `PUT`/`DELETE /destinations/grant/{name}`, with `GET /model` as the single
  read. The approval flow and presets are unchanged (they add rules in-process). **Breaking** for any external
  script that called the old routes.
- **One destination model** (ADR-0014, in progress): the gateway config accepts a single `destinations:`
  list — each entry a match plus its properties (access, methods, paths, credentials, repository scope,
  `request` grants, scheme/lan/tls) — as an alternative to the separate `readonly`, `inject`, `github_repos`
  and `grants` keys. The two forms are not mixed in one file. `python -m egressgw.convert <config>` rewrites a
  config in the new form. Access rules and the mode stay in the policy; the gateway reads either form with no
  change in behaviour (#122).
- **Destinations tab** (ADR-0014): one place for every destination — access rules, on-request grants,
  read-only hosts, credentials and repository scope — from a new `GET /model`, edited through one CRUD surface
  (`POST`/`PATCH`/`DELETE /destinations`). Access rules and simple on-request destinations are added, edited,
  deleted and grouped here; the mode, shortcuts, templates, test-a-destination, never-reachable list, raw-policy
  editor and policy history moved here too, and the separate **Rules tab is gone** (folded into Destinations).
  Grant *definitions* (the list and the full multi-target/credential editor) also moved to the Destinations
  tab; the **Grants tab is now a slim flow surface** — active grants and secrets (#122). *Replaced in this
  release: see "How to read this section" for where each part is now; there is no never-reachable list.*
- **Group rules into a named set** in the Rules tab: tick several rules, name a set and group them, so related
  allows (e.g. all the used-car shops) are shown and managed together. A rule's group is editable like its
  other fields and round-trips in the destination model (#142).
- **How access works** (`docs/access.md`): the access model on one page — never reachable, on request, rules,
  everything else, the limits inside a destination, who decides what, and why some settings are file-only
  (#121). *The page now describes the one rule list: locked ranges, on request, rules, everything else.*
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
- **Edit a rule in place** in the Rules tab (and `PATCH /rules/{id}`): change a rule's action, port, note or
  expiry without deleting and re-adding it — e.g. put a time limit on a permanent *Always allow* from the log,
  keeping its id and its place in the list. What a rule matches (host/cidr) stays fixed (#141).
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
- **Delete in the Files tab:** every row has a *Delete* button (second click confirms) for a file or a folder
  with everything in it (`DELETE /api/files?path=…`, CSRF-protected, logged with the user). Same path checks
  as upload and download; a link is removed itself, never its target, and the workspace folder itself cannot
  be deleted (#199).
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
  recorded; afterwards they are proposed as rules, grouped by domain, to save in one go. The hard deny (now:
  every rule, the built-in blocks among them), deny and ask rules, grants and name-first decisions stay in
  force; it is shown in the header and ends by itself, on the emergency stop and on restart (#69).
- **Rootless package installs for the agent** (`tallygate install PKG…`): the agent can add Debian tools
  (`shellcheck`, `sqlite3`, `dnsutils`, …) in the middle of a task without the operator rebuilding the image.
  `apt` and `dpkg` run as uid 1000; the `.deb`s are downloaded through the proxy (held or allowed by the
  Debian/apt template, so the human still decides) and unpacked into `~/.local/tallygate/root`, which
  `entrypoint.sh` and `/etc/profile.d` add to `PATH`/`LD_LIBRARY_PATH`. The hardening is untouched: the root
  filesystem stays read-only (checked by `bypass.sh`), no capabilities or setuid bits apply, and nothing
  outside the home volume is written. Maintainer scripts are not run, so daemons, `sudo` and packages that
  need fixed system paths or capabilities do not work. `--list`, `--remove PKG` and `--reset` manage the
  prefix (#116).

### Changed
- **Notification buttons use the words of the Approvals tab** (#212): in Telegram, Matrix and Web Push
  *Always allow* is now *Allow host permanently*, *Always (\*.domain)* is *Allow \*.domain permanently*,
  *Allow 1 h* is *Allow for 1 h* and *Block forever* is *Deny permanently*. What they do, the Matrix reactions
  and the text replies (`allow`, `hour`, `always`, `domain`, `deny`, `block`) are unchanged.
- **A request for an IP address can only be denied from a Web Push notification** (#212). It used to offer
  *Allow once* as well. Allowing an address adds an address rule on top of the list, which opens it even
  inside a blocked range, so that is decided in the UI (the notification says so and opens the approvals) or
  in Telegram / Matrix.
- **One ordered rule list, first match wins** ([ADR-0019](docs/adr/0019-one-ordered-rule-list.md), #208):
  the policy is evaluated like other firewalls do it. A destination given as an IP address is decided by the
  list from the top: the first rule for an address that contains it decides. A destination given by name
  passes two checks: the first rule for a name that matches decides (deny and ask before the name is looked
  up), and every address it resolves to must not be blocked. The most restrictive result over all addresses
  wins; the mode is the last line. What this changes:
  - **Local addresses are handled like any other address.** The built-in blocked ranges (private, loopback,
    link-local/metadata, CGNAT, multicast, special ranges) and the `never` entries of `gateway.yaml` are
    ordinary `deny` rules (`source: builtin` / `config`), seeded once at the bottom. They can be moved, edited
    and deleted; *Restore built-in blocks* adds the missing ones back. To reach one device, add an allow rule
    for its address and port: it is placed above the blocked range. To reach it by name, allow the name as
    well. `hard_deny`, `floor_open` (ADR-0017) and the read-only `hard_deny_floor` are gone.
  - **Restoring the built-in blocks does not close ranges that an address rule above them opens.** Restored
    blocks are added at the bottom; the message and the log list what is still open (`opened` in the API).
    A block takes no time limit (add an allow rule with a time limit above it instead), and a block whose
    action is changed becomes an ordinary rule of yours.
  - **Among address rules, position decides.** An address `allow` above a range block opens that address; a
    CIDR `deny` no longer wins "wherever it stands" over an address `allow` above it (#119).
  - **An address `allow` lets no name through by itself.** It opens the address for connections to the IP,
    and for a name that is allowed by name; the name still needs a name rule or your approval (as since #10).
    Address `ask` rules apply to IP destinations only.
  - **A name rule cannot open a blocked range, and a name `deny` wins wherever it stands.** If an allowed name
    resolves into a range that an address `deny` rule covers, the connection is denied. Where a name rule
    stands relative to address rules does not matter. The reason says so and what to do, in the log, in
    *Test a destination* and in the denial the agent gets; the Destinations table marks such a rule (*blocked
    by a range rule*, with a warning that the name may have been redirected) and address rules that can never
    decide (*never reached*).
  - **Only the stack itself is locked**: the stack's own networks (`GW_INTERNAL_NETS`) and the gateway's own
    listeners are denied before the list, whatever a rule, a grant or the API says. A listener bound to every
    address is now locked on loopback too, and so is an IPv6 address that carries a locked IPv4 address
    (NAT64, 6to4). An empty `GW_INTERNAL_NETS` is logged as a warning. They are shown as the last rows before
    the default, with no actions.
  - **Rules have an order you can change**: *Move up* / *Move down* in the table, `POST
    /destinations/{id}/move` in the API. Approvals and shortcuts are still added at the top.
  - **Grants are rules at the top of the list while active.** A target with an IP or a fixed `address` is an
    address rule and may be local; a target that is only a name cannot open a blocked range, and saving one
    that resolves into a blocked range is refused with the address to pin. A target that names an address is
    not subject to the blocked ranges or to `deny` rules at all, only to the locked ranges: that includes
    loopback, the cloud metadata address and your `never` entries, which were closed to grants before
    ([threat model](docs/threat-model.md#residual-risks)). `grants_lan_allow`, `lan: true` and
    the `never` scope `all+lan` are read from old files and ignored (logged once). The *Local-network device*
    checkbox is gone; the Quick settings form is always available.
  - **Names are still decided before they are resolved**, without exception: a name that is denied, or that
    you have not answered yet, never reaches a resolver, whatever address rules exist.
  - **Replacing a whole policy** (raw editor, `PUT /policy`, restore, import) records in the log which
    built-in blocks are not in force afterwards; an import shows them as warnings first. *Allow* on a log
    line for an IP address takes a second click, because the rule opens the address even inside a blocked
    range.
  - API: `GET /policy` returns `{default, ask_timeout, seeded, rules}`; `GET /model` returns `locked` instead
    of `never` and the rules in evaluation order; `GET /never-reachable` lists only what is locked; `POST
    /test` returns the deciding rule, its position and `shadow`; new `POST /destinations/{id}/move` and `POST
    /destinations/restore-blocks` (`{added, opened}`); a rule's `source` is validated; `GET /grants` has no
    `lan_allow_ui`. See [docs/api.md](docs/api.md).
  - Unused built-in blocks are never offered by *Remove unused rules*.
  - The isolation self-test also probes the management endpoints through the proxy (locked).
- **One UX concept for the whole web UI** ([docs/ux-concept.md](docs/ux-concept.md), #202): every page is built
  from the same parts. Each tab has one title and at most one line of purpose; a card or form has at most one
  filled button, other actions are secondary, row actions (Edit, Delete, Undo, Test) are quiet "ghost" buttons.
  Labels are verb + noun in sentence case with one verb per meaning, so some buttons were renamed: *Allow for
  5 min*, *Allow … permanently*, *Deny permanently* on a request, *Allow read / write for …* on a grant request,
  *Save token* (was *Validate & store*), *Save secret* (was *Store*), *Create grant…*, *Unblock range* /
  *Undo unblock*, *Start / End away mode*, *Save policy*. Help has three levels only: a one-sentence hint, a
  help disclosure for anything longer (the docs link is its last line), and the docs; long intro paragraphs
  moved into help without losing text. States are a word with a dot (*active*, *off*, *waiting*, *failed*,
  *done*) instead of emoji and check marks; access is always *allow / ask / deny*. Empty lists say why and
  what to do next. *Revoke*, deleting a rule and removing a push device now ask for confirmation, like every
  destructive action; the console is chosen from a list instead of buttons; the keyboard help is a help
  disclosure (`?` still opens it as a dialog); Availability moved below the requests. Type is 20/15/13/12 px,
  controls are at least 32 px high. What each control does, and every endpoint, is unchanged. A unit test
  (`tests/unit/test_ui_conventions.py`) keeps the mechanical rules.
- **One help affordance across the control UI (#178):** every in-place "more detail" trigger is now the same
  `<details class="help">` disclosure, marked with a muted ⓘ and a caret so it reads as help; the old
  `Keys (?)` button keeps its modal (a full keyboard reference) but its trigger now matches that look. The
  longest inline explanations on the Approvals, Quick start, Grants and Settings surfaces moved into that
  collapsible help so the default view is terse, and a duplicated "what stays in the gateway config" note was
  removed. No behaviour, IDs or copy were lost — only relocated.
- **The never-reachable deny floor is shown and edited in the one Destinations table (ADR-0017, #177):** every
  blocked range is listed with its reason; an authenticated admin may unblock a LAN, cloud-metadata or own
  `hard_deny` range for normal connections (a new `floor_open` policy field) behind a per-range confirmation,
  and re-block it. The gateway's own networks (`GW_INTERNAL_NETS`) stay locked and are checked first, so
  opening a broad range can never expose the stack, and the grant path is unchanged (grants still cannot reach
  loopback/metadata/the stack). Secure by default: a fresh install blocks everything it did before. The
  separate *Never reachable* card and the hard-deny textarea are retired. *Replaced in this release by the
  ordered rule list (ADR-0019 supersedes ADR-0017): no floor, no `floor_open`, no unblock action; the blocks
  are rules.*
- **Accessibility:** the filled buttons now meet WCAG AA contrast (the blue and red were 3.7:1 with white text; now 5.2:1 and 4.8:1), the Log tab shows an empty state instead of a bare table, the upgrade-command copy box is a labelled button for screen readers, the keyboard help matches the "Allow once" label, and "load the next page" reads *Load older* everywhere (#143).
- **One `never` list in the gateway config** replaces `hard_deny_floor` and `grants_never`: a plain range is
  closed for every connection; `{range, scope: all+lan}` is closed for LAN grants too. The old keys still
  work and are read as `never` (`grants_never` entries now also close every connection, not only grants); the
  gateway logs once at start that they can be renamed, and `python -m egressgw.convert gateway.yaml` prints the
  file in the new form (#122). *Replaced in part in this release: `never` entries are seeded once as `deny`
  rules, and the scope `all+lan` no longer means anything (ADR-0019).*
- **One evaluation path (ADR-0014, first part):** whether a connection is intercepted and what each request on
  it may do is now decided in one place (`gateway/egressgw/model.py`), for read-only hosts, credential
  injection, repository limits and grants alike. No behaviour change: the model ran next to the old code on
  every TLS handshake and request of the whole test suite without a difference before it took over (#122).
- **First run:** the *Starting policy* step of the setup points to learning mode as the quickest way to a
  working set of rules (*Learn from a first task*). It opens *Rules → Learning mode*, where the time limit is
  chosen and confirmed as before (#121). *Replaced in this release: the setup has no Starting policy step;
  learning mode is on Quick settings.*
- **What the agent can reach:** a new table at the top of the *Rules* tab lists each destination once with
  everything that applies to it: the deciding rule, read-only, added credentials, repository limits, the grants
  defined for it and when it was last used. Until now that took three tabs and the config file. New read-only
  route `GET /access` (#121). *Replaced in this release: the table is not in the UI any more (the
  Destinations table and Test a destination took its place); the route remains.*
- **One "Never reachable" list:** *Rules → Never reachable* shows every range that can never be reached in one
  table: the built-in list, `hard_deny_floor`, your additions, `grants_never`, the stack's own networks and the
  gateway's own listeners, each with where it comes from and where it is changed. It replaces the *Hard deny*
  card; adding ranges works as before. New read-only route `GET /never-reachable` (#121). *Replaced in this
  release: there is no such list; the route returns only the locked ranges (ADR-0019).*
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
- **Isolation self-test shown as "to do"** in Setup whenever the page was loaded, because its result is not stored.
  It is an optional spot check now: *optional* before a run, *done* after a passing one, *check* after a failing
  one, and it is no longer one of the steps counted in "N of M steps done".
- **Approval requests for the GitHub CLI's own traffic**: `gh` sends usage telemetry to `cafe.github.com` and
  checks for updates, which showed up as approval requests nobody wanted. The agent image switches both off
  (`GH_TELEMETRY=false`, `GH_NO_UPDATE_NOTIFIER=1`, `GH_NO_EXTENSION_UPDATE_NOTIFIER=1`).
- **Remote Control session lost after a long outage** (#214): after more than about four hours without the
  gateway or the network, Claude Code discarded its record of the environment it serves. The *rc* console
  then repeated `This folder is already served …`, and later a new environment was registered: the session
  in the Claude app showed *environment deleted*. The agent now keeps a copy of that record on the home
  volume and puts it back before every start (`agent/rc-loop.sh`), so Remote Control comes back as the same
  environment with the same session. The agent container also has a fixed hostname (`AGENT_HOSTNAME`,
  default `tallygate`): the Claude app showed Docker's container id as the device.
- **Browser-notification permission in Setup** (#201): the hint for a blocked site named a "lock / ⓘ icon"
  that Firefox does not have, and on plain HTTP it offered a button that could never work. The section now
  says what applies: on plain HTTP that browser notifications need HTTPS (or localhost); otherwise a
  **Request notification permission** button, which stays when the site is blocked (some browsers ask again)
  next to a browser-neutral explanation; and once allowed, **Send a test notification**.
- **Docs read-through** after the rework (#99): the user guide, rules and grants guides, API reference and
  configuration reference now describe the single **Destinations** tab (the Rules tab was folded in), the
  `/destinations` API (the old `/rules`/`/grants` CRUD is gone) and the `destinations:` config form. Added
  `docs/screenshots.md` with a caption per surface; `rules.png` → `destinations.png`. The screenshot images
  themselves still need a retake on a host with neutral demo data.
- **Accessibility review** of the control UI (#143): data tables mark their header cells with `scope="col"` for
  screen readers, and the mobile navigation drawer honours `prefers-reduced-motion`. The review confirmed the
  rest is already WCAG AA — text contrast ≥ 4.5:1, a visible focus outline, the sidebar/tabs follow the
  WAI-ARIA tabs pattern, the drawer is keyboard-operable, inputs are labelled, and there are no duplicate ids.
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
5. **Behaviour changes to check:** CIDR `allow` rules cover IP literals only: they let no name through by
   itself (#10; what they do for a name that is allowed by name: step 8); UI grants with `inject` or
   `tls_verify: false` are ignored, so move them to the config file (#12); the Hugging Face and registry
   hosts are read-only (#58).
6. **UI address:** the UI is now published on all interfaces (`0.0.0.0:8080`). With a reverse proxy on the
   same host, set `CONTROL_PUBLISH=127.0.0.1:8080` to keep it local; remove `COOKIE_SECURE=1` from `.env` unless
   you only use HTTPS (the new default `auto` decides per connection) (#97).
7. Start: `docker compose pull && docker compose up -d`, or `make up` from source. Then run the self-test or
   `bash bypass.sh`.
8. **The policy is migrated to one ordered rule list at the first start** (ADR-0019, #208). Nothing to do, but
   know what happens to `policy.yaml` and `grants.yaml` in the gateway's data volume:
   - The old files are kept next to the new ones as `policy.yaml.pre-0019` and `grants.yaml.pre-0019`. A file
     that cannot be translated stops the gateway with a message that names the entry, with the file untouched.
   - Your CIDR `deny` rules move to the top, in their order: they won everywhere before and keep winning.
   - `hard_deny` extras become `deny` rules below your rules. The built-in blocks and your `never` entries are
     added as `deny` rules at the bottom, except ranges you had opened (`floor_open`): they stay open.
   - **Nothing that was blocked opens by upgrading.** A CIDR `allow` or `ask` rule for an address inside a
     blocked range did nothing before. The blocks such a rule overlaps are placed at the **top** of the list,
     above it, so it still does nothing. The gateway log and the event log name the rules and the blocks
     (`policy migration: NOTE … block(s) stay at the top of the list, above rule(s) …`). To open such an
     address, move its rule above the block; otherwise delete the rule.
   - **A CIDR `allow` and names.** It opens the address for connections to the IP and for names that are
     allowed by name. It lets no name through by itself, and a `deny` or `ask` for a name is still acted on
     before the name is resolved.
   - **Grants for local devices need an address.** `lan: true` is dropped. A target with an IP or a fixed
     `address` keeps working. A target that is only a name (`ha.lan`) no longer reaches a blocked range: set
     its `address` (the log names each such target). `grants_lan_allow` can be removed from `gateway.yaml`.
   - **Check grant targets that name a blocked address.** A target with an IP or a fixed `address` inside a
     blocked range that did not have `lan: true` was always refused; now it is reachable while its grant is
     active, loopback, metadata and `never` addresses included. The gateway log and the event log name each one at the
     migration (`NOTE grant …`, with whether a level is approved automatically); delete those you do not want.
   - `grants.yaml.pre-0019` is only written when a UI grant had `lan: true`.
   - *Restore built-in blocks* does not close ranges that an address rule above the blocks opens.
   - To go back to an older release, restore the `*.pre-0019` files
     ([docs/operations.md](docs/operations.md#upgrade-to-the-ordered-rule-list)).

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

[Unreleased]: https://github.com/PhilippMundhenk/tallygate/compare/v0.4.1...HEAD
[0.4.1]: https://github.com/PhilippMundhenk/tallygate/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/PhilippMundhenk/tallygate/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/PhilippMundhenk/tallygate/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/PhilippMundhenk/tallygate/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/PhilippMundhenk/tallygate/releases/tag/v0.1.0
