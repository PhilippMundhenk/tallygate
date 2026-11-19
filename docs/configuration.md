# Configuration reference

Every setting and its default. For what the settings add up to, see [How access works](access.md).

Configuration lives in three places:

| File | Scope | Edited by |
|---|---|---|
| `.env` next to `compose.yaml` | Optional: access, state paths, agent and notification settings | you (`docker compose up -d` applies changes) |
| `config/gateway.yaml` | Static gateway config: grants, credential injection, service ports. Built into the image as `/etc/egressgw/config.yaml`; mount your own copy over it (see [operations](operations.md#with-docker-compose-recommended)) | you (restart `egress-gw` after changes) |
| `policy.yaml` in the `gateway-data` volume | Live policy: the default and the one ordered rule list (the built-in blocks are rules in it) | UI / API (or by hand while the gateway is stopped) |

## `.env`

All variables are optional. Secrets are created on first start when they are not set.

| Variable | Default | Description |
|---|---|---|
| `TALLYGATE_VERSION` | the release the `compose.yaml` belongs to | Image tag of all three images. The `compose.yaml` attached to a release defaults to that release, so normally leave it unset and [upgrade by replacing the file](operations.md#upgrading-and-rolling-back). Set it for a release up to 0.4.0 (`0.4.0`), or to follow a minor version (`0.4`); it overrides the version in the file. The `compose.yaml` on the `main` branch defaults to `latest`. See [versions and pinning](operations.md#versions-and-pinning). |
| `GATEWAY_DATA` | volume `gateway-data` | Gateway state. A host path makes it a bind mount (owner uid 10001, mode 700). |
| `AGENT_HOME` | volume `agent-home` | Agent home (Claude login, settings). A host path makes it a bind mount (owner uid 1000). |
| `WORKSPACE` | volume `workspace` | Agent workspace. A host path makes it a bind mount (owner uid 1000). |
| `CONTROL_DATA` | volume `control-data` | UI password hash and session secret. A host path makes it a bind mount (owner uid 10002, mode 700). See [host directories](operations.md#host-directories). |
| `CONTROL_PUBLISH` | `127.0.0.1:8080` | Host address:port the UI (plain HTTP) is published on. The default is the Docker host's loopback address: the host itself, a reverse proxy on it and an SSH tunnel reach it. `0.0.0.0:8080` (the default up to 0.4.0) or `<LAN address>:8080` publishes it to the network, unencrypted and past host firewalls such as ufw: only on a network you trust. See [reaching the UI](operations.md#reaching-the-ui). |
| `PUBLIC_URL` | – | External UI URL, included in notifications. When set, logins and changes are accepted from this origin only, and with `https://` the session cookie is `Secure`. |
| `ALLOWED_HOSTS` | – | Optional, comma-separated host names without port (`tallygate.lan,server.local`). When set, the UI answers only under these names, under the name in `PUBLIC_URL`, as `localhost` and by IP address; any other `Host` gets `421`. Protects the login form against DNS rebinding when you open the UI under a name ([threat model](threat-model.md)). Not wired in `compose.yaml` yet: add it to control's `environment:` in a `compose.override.yaml`. |
| `TZ` | UTC | Time zone of the gateway and control, e.g. `Europe/Berlin`: quiet hours and times in notifications use it. |
| `COOKIE_SECURE` | `auto` | `auto`: the session cookie is `Secure` when the browser uses HTTPS (directly, or `X-Forwarded-Proto` from a trusted proxy) or when `PUBLIC_URL` starts with `https://`. `1` / `0` force it on or off. |
| `TRUST_FORWARDED_FOR` | `0` | `1` when the UI sits behind your reverse proxy: trust `X-Forwarded-For`/`-Host`/`-Proto` for rate limiting and origin checks — **only** from peers in `TRUSTED_PROXIES`. |
| `TRUSTED_PROXIES` | – | Comma-separated CIDRs of your reverse/auth proxy as seen by control. Forwarded and auth headers from any other peer are ignored. With a published port this is the `mgmt` bridge gateway `172.31.12.1/32`, which every local process shares: see [reverse proxy](operations.md#reverse-proxy). |
| `FILES_MAX_UPLOAD` | `52428800` (50 MiB) | Largest file the *Files* tab uploads into the workspace (bytes). |
| `FILES_MAX_DOWNLOAD` | `209715200` (200 MiB) | Largest workspace file the *Files* tab downloads (bytes). |
| `UPDATE_CHECK` | `1` | Control asks GitHub's releases API (`api.github.com`, from control's own network, never through the agent) whether a newer tallygate release exists, at most every 6 h (30 min after a failure), and shows it in the UI. `0` switches it off. |
| `SESSION_IDLE` | `7200` | UI session idle timeout in seconds. Idle means: nothing you did. What the page asks the server by itself (status every 30 s, reloads after events, the event stream, an open console that only shows output) does not count; a click, a key or scrolling does, also typing in a console. A tab left open is logged out after this time; raise the value for a display that should stay logged in without anyone touching it. The absolute lifetime is 12 h (`SESSION_TTL`, not wired in `compose.yaml`: add it to control's `environment:` to change it). Sessions are server-side: logout and restarts end them, and open event streams and consoles are closed within 10 s. |
| `GW_API_TOKEN` | *(created in the `gw-token` volume)* | Bearer token between control and gateway (≥ 24 chars). |
| `SESSION_SECRET` | *(created in `control-data`)* | HMAC key that signs session ids in the cookie and the notification buttons. Leave it empty unless you need a fixed one; if set, at least 32 characters (`openssl rand -hex 32`), or the control plane does not start. |
| `TTYD_CREDENTIAL` | *(created in the `ttyd` volume)* | `user:password` shared by control and the agent's ttyd consoles. Added by control during the WebSocket handshake; the browser never sees it. |
| `CONTROL_PASSWORD_HASH` | *(generated password)* | `scrypt:16:<salt>:<hash>` (scrypt N = 2^16), create with `python3 control/hashpw.py` or `docker compose exec control python -m app.passwd --print-hash`. Without it (and without `CONTROL_PASSWORD` or `TRUST_PROXY_AUTH_HEADER`), control generates a password on first start, prints it to its log (where it stays until the log is rotated) and keeps the hash in `control-data`; change that one with `docker compose exec control python -m app.passwd`, which also ends all open sessions. The legacy `scrypt:<salt>:<hash>` (N = 2^14) is still accepted; regenerate it. |
| `CONTROL_PASSWORD` | – | Plain-text password instead of a hash. Discouraged (logged as a warning). |
| `TRUST_PROXY_AUTH_HEADER` | – | E.g. `Remote-User`: accept the user from this header set by an authenticating proxy (Authelia, oauth2-proxy). Requires `TRUSTED_PROXIES`; control refuses to start without it. Trust only the proxy container's own address: see [reverse proxy](operations.md#reverse-proxy). |
| `TRUST_PROXY_SECRET` | – | Shared secret (≥ 16 characters) that the proxy sends as `X-Tallygate-Proxy-Secret`. When set, forwarded and auth headers are believed only from `TRUSTED_PROXIES` **and** with this header (compared in constant time). Recommended with `TRUST_PROXY_AUTH_HEADER`. |
| `RC_NAME` | `tallygate` | Remote Control session name shown in the Claude app. |
| `AGENT_HOSTNAME` | `tallygate` | Hostname of the agent container. The Claude app shows it as the device a session runs on; without a fixed one it would be Docker's container id, which changes whenever the container is recreated. |
| `RC_ENABLE` | `1` | Start `claude remote-control` automatically in the `rc` tmux session. |
| `RC_ARGS` | – | Extra arguments for `claude remote-control`, e.g. `--spawn worktree`. |
| `AGENT_PERMISSION_MODE` | `bypassPermissions` | Claude Code permission mode for Remote Control and the `claude` console. Seeded into `~/.claude/settings.json` on first start. |
| `CLAUDE_VERSION` | pinned in `agent/Dockerfile` | Only when building from source: Claude Code npm version baked into the agent image (no auto-updater). |
| `AGENT_EXTRA_PACKAGES` | – | Only when building from source: extra Debian packages for the agent image, e.g. `build-essential golang-go`. With published images, use a [custom agent image](operations.md#custom-agent-image). |
| `AGENT_MEM_LIMIT` | `6g` | Memory limit of the agent container. |
| `AGENT_CPUS` | `0` | CPU limit of the agent container (e.g. `2`); `0` means no limit. See [resource limits](operations.md#resource-limits). |
| `TELEGRAM_BOT_TOKEN` | – | Bot token from @BotFather. Enables Telegram approvals together with the chat ID. This and the other notification variables below (Telegram, Matrix, ntfy, Gotify, Pushover) can also be set in the UI (*Setup → Notifications → Configure*); a value saved there overrides the variable, see [the user guide](user-guide.md#notification-channels-in-the-web-ui). |
| `TELEGRAM_CHAT_ID` | – | Chat (user or group) that receives approval requests: the **numeric** id (e.g. `-1001234567890`). A `@name` is refused: button presses carry the numeric id, so every approval would be answered *Not authorised*. |
| `TELEGRAM_ALLOWED_USER_IDS` | – | **Required** for Telegram: comma-separated user IDs allowed to decide. Without it Telegram approvals stay disabled. |
| `MATRIX_HOMESERVER` | – | e.g. `https://matrix.example.org`. Like `NTFY_URL` and `GOTIFY_URL`: no `?query` or `#fragment`, and not an address of this machine, a link-local address or the tallygate stack itself (see [where a channel URL may point](user-guide.md#where-a-channel-url-may-point)); a server on your local network is fine. |
| `MATRIX_ACCESS_TOKEN` | – | Access token of a dedicated bot user. |
| `MATRIX_ROOM_ID` | – | `!id:server` of an **unencrypted** room the bot has joined. |
| `MATRIX_ALLOWED_USERS` | – | **Required** for Matrix: comma-separated MXIDs allowed to decide (must not include the bot). |
| `NTFY_URL` | – | ntfy topic URL, e.g. `https://ntfy.example.org/tallygate`. Notifications only (link to the UI, no buttons). |
| `NTFY_TOKEN` | – | ntfy access token, sent as `Authorization: Bearer`. Recommended: on a public server anyone who guesses the topic reads it. |
| `GOTIFY_URL` / `GOTIFY_TOKEN` | – | Gotify server and application token. Notifications only. |
| `PUSHOVER_TOKEN` / `PUSHOVER_USER` | – | Pushover application token and user (or group) key. Notifications only. |
| `VAPID_SUBJECT` | `PUBLIC_URL` if it is `https://`, else the project URL | Contact for Web Push services (`mailto:` or `https:`). |
| `VAPID_PRIVATE_KEY` | *(created in `control-data`)* | EC P-256 private key (PEM; `\n` for line breaks) that signs Web Push messages. Changing it ends every subscription. |
| `PUSH_ALLOWED_HOSTS` | – | Comma-separated extra push service hosts (`*.example.org` allowed). Built in: Google (`fcm.googleapis.com`), Mozilla, Apple, Microsoft. Control only ever sends Web Push to these hosts. |

### Examples

Behind a reverse proxy on the same host, with Telegram approvals:

```sh
# .env
PUBLIC_URL=https://tallygate.example.org
TRUST_FORWARDED_FOR=1
TRUSTED_PROXIES=172.31.12.1/32     # the mgmt bridge: see operations.md#reverse-proxy for what this trusts
TELEGRAM_BOT_TOKEN=123456:ABC-DEF…
TELEGRAM_CHAT_ID=123456789
TELEGRAM_ALLOWED_USER_IDS=123456789
```

State in host directories, a smaller agent, and a pinned version:

```sh
# .env (create the directories with ./setup.sh /srv/tallygate)
TALLYGATE_VERSION=0.4                   # follow 0.4.x; without it the release's compose.yaml decides
GATEWAY_DATA=/srv/tallygate/gateway
AGENT_HOME=/srv/tallygate/agent-home
WORKSPACE=/srv/tallygate/workspace
CONTROL_DATA=/srv/tallygate/control-data
AGENT_MEM_LIMIT=4g
AGENT_CPUS=2
RC_NAME=homelab-agent
```

A self-hosted ntfy server for notifications, Web Push for deciding on the phone:

```sh
# .env
PUBLIC_URL=https://tallygate.example.org     # Web Push needs HTTPS
NTFY_URL=https://ntfy.example.org/tallygate
NTFY_TOKEN=tk_…
```

Matrix instead of Telegram:

```sh
# .env
MATRIX_HOMESERVER=https://matrix.example.org
MATRIX_ACCESS_TOKEN=syt_…            # of a dedicated bot account
MATRIX_ROOM_ID=!abcdef:example.org   # unencrypted room the bot has joined
MATRIX_ALLOWED_USERS=@you:example.org
```

## `config/gateway.yaml`

Every key with an example. The file in the repository lists them all, most of them commented at their default.

> **One destinations model (ADR-0014).** The `readonly`, `inject`, `github_repos` and `grants` keys below can
> instead be written as a single `destinations:` list — each entry a match plus its properties (access,
> methods, paths, credentials, repository scope, `request` grants). The two forms are not mixed in one file.
> `python -m egressgw.convert <gateway.yaml>` prints a config in that form. The properties that can hand out
> secrets (credential injection, `tls_verify: false`) are accepted only from this file either way. The blocked
> ranges are **not** in that group: they are rules in `policy.yaml`, and `never` below only seeds them
> ([ADR-0019](adr/0019-one-ordered-rule-list.md)). What no file and no rule opens is the stack itself, the
> locked ranges (`GW_INTERNAL_NETS`, see [Component environment](#component-environment)). See
> [ADR-0014](adr/0014-one-destination-model.md) for the destinations form.

| Key | Default | Example | Meaning |
|---|---|---|---|
| `initial_preset` | `baseline` | `lockdown` | Preset that creates `policy.yaml` on the very first start. |

> **Behaviour settings move to the UI (ADR-0015).** `log_keep_days`, `log_max_events`, `learning_ports`,
> `learning_max_minutes`, `rule_stale_days`, `suggest_min_approvals`, `suggest_window_days`,
> `grant_request_timeout`, `grant_max_pending`, `policy_history_keep` and `max_pending` are now edited in the UI
> under *Settings → Behaviour settings* and persisted to a backend-owned `settings.yaml` in the data volume. The
> values below are the built-in defaults; a value here (or the matching env var) only **seeds** `settings.yaml`
> on first start — after that the UI owns them and you need not set them. The trust-critical settings
> (`inject`, `tls_verify`) stay in this file, and `GW_INTERNAL_NETS` in the environment of the gateway.

| `log_keep_days` | `30` | `7` | Event log retention. |
| `log_max_events` | `500000` | `100000` | Hard cap on stored events. |
| `max_pending` | `10` | `5` | Open approvals at once; more unknown destinations are denied immediately. |
| `learning_ports` | `[80, 443]` | `[443]` | Ports learning mode may open. Only this file can change the list; an invalid entry stops the gateway. |
| `learning_max_minutes` | `120` | `30` | Longest learning-mode session. |
| `rule_stale_days` | `30` | `90` | A permanent rule that did not match for this many days is offered for removal. |
| `suggest_min_approvals` | `3` | `5` | Temporary approvals of one destination that lead to a "make it permanent?" suggestion. |
| `suggest_window_days` | `7` | `14` | The time window for those approvals (at most `log_keep_days`: older approvals are forgotten). |
| `policy_history_keep` | `500` | `100` | Policy versions kept for diff and rollback (at least 10); older ones are removed. |
| `never` | `[]` | `[203.0.113.7/32]` | Blocked ranges of your own, for example the public IP of a VPS that runs the stack (the example is a placeholder). Each entry is seeded **once** as an ordinary `deny` rule at the bottom of the rule list (source *never (config file)*), next to the [built-in blocks](rules.md#built-in-blocks). From then on it is a rule like any other: it can be moved, edited and deleted on the *Destinations* tab, a deleted one stays deleted, and *Restore built-in blocks* adds it back. An entry added later is seeded at the next start; removing an entry here leaves its rule in the list. An invalid entry stops the gateway. Old spellings: [Removed and ignored keys](#removed-and-ignored-keys). |
| `readonly` | `[]`; the shipped `gateway.yaml` lists npm, Yarn, crates.io, Docker Hub, GHCR, Quay, Hugging Face | `[registry.npmjs.org, {host: ghcr.io, post_is_write: true}]` | Hosts where writes are refused: PUT/PATCH/DELETE, and with `post_is_write` also POST (except `read_posts`). See [Read-only hosts](#read-only-hosts). |
| `inject` | `[]`; the shipped `gateway.yaml` has the GitHub entries | see below | Credential injection per host. |
| `github_repos` | `[]` (every repository) | `[acme/app, acme-tools/*]` | Limit GitHub to these repositories; others are refused before they reach GitHub. See [GitHub per repository](#github-per-repository). |
| `github_graphql` | `false` | `true` | With `github_repos`: allow `/graphql` anyway (it can reach any repository the token can). |
| `github_hosts` | `github.com`, `api.github.com`, `uploads.github.com` | `[github.example.org]` | Hosts `github_repos` applies to (GitHub Enterprise Server: your host). |
| `inject_strip_headers` | `[Authorization, Cookie]` | `[Authorization, Cookie, X-Api-Key]` | Agent headers always removed on inject hosts. |
| `services` | `[]` | `[{name: pg, listen: 15432, target: db.example.org:5432}]` | TCP service ports. |
| `quiet_hours` | – | `{start: "22:00", end: "07:00", days: [mon, tue, wed, thu, fri], tz: Europe/Berlin}` | Daily period in which requests that need you are refused at once. See [Availability](#availability). |
| `digest_minutes` | `30` | `0` | While away: a digest of what was refused every N minutes; `0` = only when you are back. |
| `grants`, `grant_*`, `activity_rate` | – | see [Grants](#grants) and [grants.md](grants.md) | Grants. |

### Read-only hosts

TLS to a read-only host is intercepted (the agent must trust the gateway CA, which the agent image does), and
writes are refused with `403`, so a package registry cannot be used to publish data. An entry is a host or
`*.domain` (the domain and all its subdomains), or a mapping:

| Key | Meaning |
|---|---|
| `host` | Host or `*.domain`. |
| `post_is_write` | `true` = POST is refused too. Default `false`, because some registries read with POST (`npm audit`). |
| `read_posts` | With `post_is_write`: path patterns (glob, `*` matches `/` too) where POST only reads and stays allowed. |

The default list and why:

| Host | POST | Why |
|---|---|---|
| `registry.npmjs.org`, `registry.yarnpkg.com` | allowed | Publish is a PUT; `npm audit` / `yarn audit` are POSTs. |
| `crates.io` | refused | Publish, yank and owner changes are PUT/DELETE; Cargo reads with GET. |
| `registry-1.docker.io`, `ghcr.io`, `*.quay.io` | refused | A push starts with `POST /v2/<name>/blobs/uploads/`; pulls are GET/HEAD. Token requests (`auth.docker.io`, `ghcr.io/token`) are GETs. |
| `huggingface.co` | refused, except `read_posts` | Uploads and commits are POSTs. Reads that POST: `paths-info`, the git-lfs download batch and `git-upload-pack` (clone/fetch). |

Not covered: Hugging Face's storage hosts (`*.hf.co`, Xet) accept chunk uploads by POST. Without a commit on
`huggingface.co` such data is not attached to any repository, but it reaches Hugging Face's storage. Leave
the Hugging Face template off if that matters to you. The templates are pull-only only as long as their
hosts are in this list: a `gateway.yaml` of your own replaces the whole list. The same goes for `inject`:
without it in your file no GitHub token is added.


```yaml
initial_preset: baseline   # preset used to create policy.yaml on first start
log_keep_days: 30          # event log retention
log_max_events: 500000     # hard cap on stored events; identical events within 2 s are counted, not stored
max_pending: 10            # open approvals at once; further unknown destinations are denied immediately
policy_history_keep: 500   # policy versions kept for diff and rollback (at least 10)
rule_stale_days: 30        # permanent rules unused this long are offered for removal
learning_ports: [80, 443]  # ports learning mode may open (the UI offers 443, or 80 and 443)
learning_max_minutes: 120  # longest learning-mode session
suggest_min_approvals: 3   # temporary approvals of one destination before a permanent rule is suggested ...
suggest_window_days: 7     # ... within this many days
# never: [203.0.113.7/32]  # blocked ranges of your own: seeded once as deny rules at the bottom of the rule list
readonly:                  # TLS intercepted, PUT/PATCH/DELETE refused (e.g. blocks `npm publish`)
  - registry.npmjs.org
  - host: ghcr.io            # POST refused too (an image push starts with a POST)
    post_is_write: true
# inject_strip_headers: [Authorization, Cookie]   # always removed from agent requests to inject hosts

inject:                    # credential injection (TLS interception only for these exact hosts)
  - host: api.github.com
    header: Authorization
    value: "Bearer ${github_token}"
  - host: uploads.github.com
    header: Authorization
    value: "Bearer ${github_token}"
  - host: github.com
    header: Authorization
    value: "Basic ${b64:x-access-token:${github_token}}"

services:                  # TCP service ports for non-proxy-aware clients
  - name: postgres
    listen: 15432          # agent connects to egress-gw:15432
    target: db.example.org:5432
    allow_private: false   # true = exempt exactly this target from the built-in and config blocks (LAN service)
```

Template syntax in `value`: `${name}` inserts the secret `name` (set via the UI/API); `${b64:…}` base64-encodes
the rendered inner text. The agent's own headers named in `inject_strip_headers` (default `Authorization`,
`Cookie`) and the injected header itself are **always removed** on inject hosts; if a referenced secret is
missing the request goes out without credentials (fail closed).

Every `inject` host must also be **allowed** by the policy (the baseline preset allows `github.com` and
`api.github.com`; `uploads.github.com`, used for release asset uploads, is asked).

### GitHub per repository

The injected token works for every repository it can reach. A fine-grained token limited to a few
repositories is the first line; `github_repos` is a second one in the gateway, independent of how the
token was made:

```yaml
github_repos:
  - acme/app            # exactly this repository (case-insensitive)
  - acme-tools/*        # every repository of this owner
```

With a list, TLS to the `github_hosts` is always intercepted and every request must name an allowed
repository, or it is refused with `403` before it reaches GitHub (no token is added):

| Host | Allowed paths |
|---|---|
| `github.com` (git, archives, raw files) | `/<owner>/<repo>[.git][/...]` |
| `api.github.com`, `uploads.github.com`, GitHub Enterprise `/api/v3`, `/api/uploads` | `/repos/<owner>/<repo>/...`; `GET`/`HEAD` of `/`, `/user`, `/rate_limit`, `/meta`, `/versions` |
| `/graphql` | refused, unless `github_graphql: true` |

Paths must be canonical (no `..`, `//`, encoded slashes). Everything else is refused: other repositories,
`/repositories/<id>` (repositories by number, which GitHub also uses to redirect renamed ones), search,
gists, organisations, creating repositories. **GraphQL** can address any repository by name or node id, so
it is refused while `github_repos` is set. `gh` uses it for pull requests (`gh pr create`, `gh pr view`)
and some other commands: `gh api repos/<owner>/<repo>/pulls` and git work; set `github_graphql: true` if
you need the GraphQL commands and accept that the limit then does not cover them. Raw downloads from
`*.githubusercontent.com` carry no token and are not covered by the list.

An empty list keeps the earlier behaviour. An invalid entry stops the gateway.

*Follow-up:* a GitHub App installation token (short-lived, repository-scoped, rotated by the gateway) instead
of a personal access token is not implemented yet.

### Availability

Away mode is switched in the UI (**Approvals → Availability**) or with `PATCH /availability`. Quiet hours
can be preset here:

```yaml
quiet_hours:
  start: "22:00"           # HH:MM
  end: "07:00"             # before start = over midnight
  days: [mon, tue, wed, thu, fri, sat, sun]   # the days a period STARTS on (default: every day)
  tz: Europe/Berlin        # default: the gateway's TZ (UTC unless set)
digest_minutes: 30         # while away: a digest every N minutes; 0 = only when you are back
```

While away or in quiet hours, connection asks and grant requests that need approval are **denied at once**
with a message to the agent; nothing is allowed automatically. A change in the UI is stored in
`availability.yaml` in the `gateway-data` volume and wins over this file from then on. An invalid entry here
stops the gateway; an unreadable `availability.yaml` turns away mode on until you change it (fail closed).

### Connectivity

The gateway notices when its own network is down ([user guide](user-guide.md#no-connection-from-the-gateway)).
The defaults fit most hosts; the keys are for odd networks and for tests:

| Key | Default | Meaning |
|---|---|---|
| `connectivity_probe_hosts` | `[api.anthropic.com]` | The control probe: fixed names (`name` or `name:port`, port 443 by default) that the gateway resolves and connects to when failures look like an outage, and while one is on. The outage only starts when the probe fails too. Use the host your agent needs most. |
| `connectivity_min_failures` | `5` | Failed lookups or connections needed. |
| `connectivity_min_names` | `2` | ... over this many different names. |
| `connectivity_window` | `600` | Seconds a failure counts. |
| `connectivity_min_age` | `120` | The oldest failure must be this old (seconds). |
| `connectivity_probe_interval` | `30` | At most one probe per this many seconds, whatever the agent does. |

An invalid probe host stops the gateway. The state is kept in `connectivity.json` in the `gateway-data` volume
while an outage is on, so that it ends with its whole duration after a restart.

### Grants

See [grants.md](grants.md) for the concept and examples. Keys in `config/gateway.yaml`:

| Key | Default | Meaning |
|---|---|---|
| `grants` | – | Map `name → definition` (`description`, `targets`, `levels`, `approval`, `default_ttl`, `max_ttl`, `inject`). Read-only in the UI. |
| `grant_request_timeout` | `300` | Seconds a request waits for a decision. |
| `grant_max_pending` | `3` | Open grant requests at once. |
| `grant_api_rate` | `30` | Requests/minute on the agent grant API. |
| `activity_rate` | `60` | Activity reports/minute (the agent's PreToolUse hook and `tallygate note`), counted separately from grant requests. Excess reports are refused with `429`. |

Target fields: `host` (name, `*.domain` or IP), `port`, `scheme` (`https` default, `http`, `tcp`), `paths`
(globs, default `/*`), `address` (fixed IP), `tls_fingerprint` (SHA-256), `tls_verify` (default `true`).
A target on the local network must name the address: an IP as `host`, or a fixed `address`
([grants.md](grants.md#local-targets-and-name-only-targets)). `grants_lan_allow`, `grants_never` and `lan` on
a target are gone: [Removed and ignored keys](#removed-and-ignored-keys).

### Removed and ignored keys

The policy became one ordered rule list ([ADR-0019](adr/0019-one-ordered-rule-list.md)). Keys of the model
before it are still read, so an unattended image update comes up without anyone touching a file. What
happens to each:

| Key | Where | What happens to it now |
|---|---|---|
| `grants_lan_allow` | `gateway.yaml` | Ignored; a warning at every start until you delete it. UI grants are no longer limited to listed ranges: a target that names an address may be local. |
| `lan: true` on a grant target | `gateway.yaml`, `grants.yaml` | Ignored; a warning names each target. A target with an IP or a fixed `address` keeps working. A target that is only a name no longer reaches a blocked range: set its `address`. In `grants.yaml` the flag is removed at the first start (backup `grants.yaml.pre-0019`). A target that names an address inside a blocked range and never had the flag was refused before and works now; the upgrade names each one in the Log. |
| `hard_deny_floor` | `gateway.yaml` | Still read, as `never` entries (a warning at start). Rename it to `never`. |
| `grants_never` | `gateway.yaml` | The same. |
| `{range: …, scope: all+lan}` in `never` | `gateway.yaml` | Still read; `scope` no longer means anything, the entry is a plain range. Write the CIDR alone. |
| `hard_deny` | `policy.yaml`, a policy sent to the API, an imported or restored policy | Migrated: each range becomes a `deny` rule below your rules, above the built-in blocks. A range that one of your address `allow`/`ask` rules overlaps is placed at the top instead, above that rule, so that nothing opens. |
| `floor_open` | the same | Migrated: the ranges you had opened are not seeded as blocks, so they stay open. Every other block that an address `allow`/`ask` rule overlaps is placed at the top, above that rule. |
| `rules` without `seeded` | the same | A policy from before the ordered list: migrated as described in [operations](operations.md#upgrade-to-the-ordered-rule-list). |

`python -m egressgw.convert <gateway.yaml>` prints your gateway config without the old keys (it writes
nothing; comments are not kept). The one-time migration of the files in the data volume, the backups and the
way back are in [operations](operations.md#upgrade-to-the-ordered-rule-list).

## `policy.yaml`

The live policy: the default and the one ordered rule list. It is edited in the UI; how the list decides,
with worked examples for hosts, ports, addresses and ordering, is in [rules.md](rules.md).

```yaml
default: ask               # allow | deny | ask: what happens when no rule matches
ask_timeout: 60            # seconds to hold a connection while waiting for a decision (5..3600)
seeded:                    # written by the gateway: the blocks that were added once (not added again)
  - 10.0.0.0/8
  - 192.168.0.0/16         # ... one line per built-in and config block
destinations:              # the rules, in the order they are checked: the first match decides
  - match: {host: github.com, port: 443}   # host: glob, "*.x" = x and all subdomains
    access: allow                          # allow | deny | ask
    id: github                             # optional, generated if missing; must be unique
    note: free text
  - match: {cidr: 192.168.44.1/32, port: 443}   # an address rule (either host or cidr); it stands
    access: allow                               # above the block of its range, so it opens the address
    expires: 1794390000                         # unix timestamp; omit for permanent
  - match: {cidr: 192.168.0.0/16}          # port: 443 | [80, 443] | "8000-8100" | "*" (default)
    access: deny
    id: block-192.168.0.0_16
    note: built-in block
    source: builtin                        # builtin | config: a seeded block; otherwise who added the rule
```

`source` is one of `user` (the default), `approval`, `learning`, `suggestion`, `preset:<name>`,
`builtin` and `config`; anything else is refused. A block (`builtin`, `config`) is a `deny` for a range
without `expires`: a time limit on one is refused, and a block whose `access` is changed is stored as
`user`.

- **Order is the order of the file.** An address rule above a block opens that address, one below it does
  not; among rules for names the first match decides. A destination given by name must pass both kinds
  ([rules.md](rules.md#how-a-destination-is-decided)).
- **The built-in blocks are rules in this file** (`source: builtin`), and the `never` entries of the gateway
  config too (`source: config`). The list of ranges and what each protects:
  [rules.md](rules.md#built-in-blocks).
- **`seeded`** is the gateway's memory of which blocks it has added. A range listed there is not added again,
  which is why a block you deleted stays deleted across restarts. Do not edit it by hand; to get deleted
  blocks back use *Destinations → Restore built-in blocks*
  ([operations](operations.md#restoring-the-built-in-blocks)).
- **The locked ranges are not in this file** and nothing in it opens them
  ([rules.md](rules.md#locked-ranges)).
- The gateway API and the raw-policy editor (*Settings → Raw policy (JSON)*) show the same policy with the
  rules as `rules: [{id, action, host | cidr, port, …}]` instead of `destinations` ([api.md](api.md)). A file
  in that form, or one from before the ordered list (`hard_deny`, `floor_open`, no `seeded`), is translated
  at start: [Removed and ignored keys](#removed-and-ignored-keys).
- If the Docker host has a public IP (a VPS), add it to `never` in the gateway config.
- For a LAN service that a client must reach without a proxy, use a service port with `allow_private: true`:
  it exempts exactly that target from the built-in and config blocks, and only on that service port, not
  through the proxy or SOCKS. Your own rules and the locked ranges still apply.

### Presets (`gateway/presets/*.yaml`)

The UI calls these **shortcuts** (*Quick settings*). "Preset" is the name of the file and of the API route
behind a shortcut; `category` decides where the UI lists it.

| Preset | Category | Content | Typical use |
|---|---|---|---|
| `baseline` | policy | default `ask`; allow Anthropic/Claude, GitHub, npm, PyPI | initial policy |
| `lockdown` | policy | default `deny`; Anthropic only | emergency: replace the policy via raw editor/API (`POST` refuses it) |
| `open` | internet | any public host on 80/443 | temporary, **always with a TTL** (*Quick settings → Internet*) |
| `internet` | internet | any public host on any port | temporary, **always with a TTL** |
| `python`, `node`, `go`, `rust`, `debian`, `containers`, `huggingface` | template | the hosts a tool ecosystem needs | *Quick settings → Tool ecosystems* |

Presets of the categories `internet` and `template` are applied **on top** (`POST /presets/<name>`):

- Their rules are inserted at the top of the list, so **while active they win over your own rules, name
  `deny` rules included**. They are name rules, so they never open a blocked range below them
  ([rules.md](rules.md#order-of-the-list)). Undo them (or give them a time limit) when the task is done.
- Rule ids are namespaced as `<preset>:<id>` (e.g. `python:pypi`) and tagged `source: preset:<name>`.
  `DELETE /presets/<name>` removes exactly the rules with that tag.
- A rule from another source is never taken over: if one already uses such an id, nothing is applied (`409`).
- Applying again replaces the template's own earlier rules, with the new TTL (or none). The answer reports
  the expiry that was set.
- `policy` presets (`baseline`, `lockdown`) are whole policies with their own `default`. `POST` refuses them
  (`400`); replace the policy with them instead (raw editor, `PUT /policy`).

A preset file is a policy file with three optional keys for the UI:

```yaml
title: "Python (PyPI)"            # shown in the UI
category: template                # policy | internet | template (where the UI lists it)
description: "pip, uv and poetry: the Python Package Index and its file host."
rules:
  - {id: pypi, action: allow, host: "pypi.org", port: 443}        # becomes python:pypi
  - {id: files, action: allow, host: "files.pythonhosted.org", port: 443}
```

Add your own shortcuts by mounting YAML files into the gateway's `/app/presets/`, e.g.
`./presets/company.yaml:/app/presets/company.yaml:ro` in `compose.yaml`. The file name (without `.yaml`) is
the preset name and may only contain letters, digits and `_` (no `-`). Without `category` a file is a
`template`.

## Component environment

Set by `compose.yaml` or the image, or left at the built-in default. They normally need no change; to change
one that `compose.yaml` does not list, add it to that service's `environment:` block.

| Container | Variable | Purpose |
|---|---|---|
| egress-gw | `GW_LISTEN_HOST` | Gateway address on agent-net (proxy, SOCKS5, DNS, service ports). |
| egress-gw | `GW_HTTP_PORT` / `GW_SOCKS_PORT` / `GW_DNS_PORT` | Listener ports (3128 / 1080 / 53). |
| egress-gw | `GW_API_HOST` / `GW_API_PORT` | API address on control-net / port (8081). |
| egress-gw | `GW_GRANTS_PORT` | Agent grant API port on agent-net (8079). |
| egress-gw | `GW_INTERNAL_NETS` | The **locked ranges**: the stack's own networks as comma-separated CIDRs (compose: the four `172.31.1x.0/24` networks). They are denied before the rule list is walked, for every connection and every grant; no rule, grant or API call opens them ([rules.md](rules.md#locked-ranges)). Empty or unset, the gateway **does not start** (`GW_INTERNAL_NETS is empty` in its log): without it only the built-in blocks, which can be deleted, would stand between the agent and the stack. `compose.yaml` always sets it; the message means the compose file is older than the images. The gateway's own listeners (`GW_API_HOST`/`GW_API_PORT`, `GW_LISTEN_HOST` with the grant, proxy and SOCKS ports) are locked the same way, without a setting. Change it together with the `networks:` subnets; an invalid entry stops the gateway. |
| egress-gw | `GW_CONFIG`, `DATA_DIR`, `CA_EXPORT_DIR`, `PRESET_DIR` | Paths. |
| egress-gw | `GW_EXTRA_ARGS` | Extra mitmdump arguments (advanced). |
| egress-gw, control | `GW_API_TOKEN_FILE` | Token file in the `gw-token` volume (`/run/tallygate/gw/api-token`), used when `GW_API_TOKEN` is not set. |
| egress-gw | `GW_TEST_STATIC_HOSTS` | **Test suite only.** Never set in production (logged as a warning). |
| egress-gw | `GW_TEST_NO_INTERNAL_NETS` | **Test suite and development only.** `1` = start although `GW_INTERNAL_NETS` is empty, for a gateway run outside the compose stack, where there are no networks of a stack to lock. Never set in production (logged as a warning): nothing of the stack is locked then. |
| egress-gw | `GW_TEST_FLOOR_REPLACE` | **Test suite only.** `1` = with `never` entries in the config, the built-in blocks are not seeded (the e2e upstreams run on loopback). Never set in production (logged as a warning). |
| control | `CONTROL_BIND_HOST` / `CONTROL_PORT` | UI bind address (mgmt network only) / port. |
| control | `GW_URL` | Gateway API base URL. |
| control | `AGENT_HOST`, `AGENT_STATUS_PORT`, `TERMINALS` | Agent address, status port, `name:port` list of ttyd consoles. |
| control | `SESSION_TTL`, `LOG_LEVEL` | Session lifetime (s, default 12 h), log level. |
| control | `SESSION_RECHECK` | Seconds between session re-checks of open event streams and consoles (10). |
| control | `CONTROL_DATA` | Control state directory inside the container (`/data`): session secret, password hash, VAPID key, push subscriptions, notification settings saved in the UI (`notify.json`: channel settings and the [notification buttons](user-guide.md#notification-buttons), which have no environment variable). Not the `.env` variable of the same name, which is the host path or volume mounted there. |
| control, agent | `TTYD_CREDENTIAL_FILE` | Credential file in the `ttyd` volume (`/run/tallygate/ttyd/credential`), used when `TTYD_CREDENTIAL` is not set. |
| control | `GITHUB_API_URL` | Releases API base URL for the update check (the test suite points it at a mock server). |
| control | `TELEGRAM_API_BASE`, `PUSHOVER_API_BASE` | API base URLs (the test suite points them at mock servers). |
| control | `PUSH_TEST_ALLOW_HTTP` | **Test suite only.** `1` = Web Push endpoints over plain HTTP are accepted (logged as a warning). |
| control | `NOTIFY_TEST_ALLOW_LOCAL` | **Test suite only.** `1` = the URLs of ntfy, Gotify and Matrix may point at loopback and at the hosts of the stack, where the test suite's mock services listen (logged as a warning). Link-local addresses and `GW_INTERNAL_NETS` stay refused. Never set it in an installation. |
| control | `GW_INTERNAL_NETS` | Optional for control: if it is set (the same value as for the gateway), no notification channel URL may point into these networks. The compose file does not pass it to control yet; without it control refuses the addresses it knows itself (`GW_URL`, `AGENT_HOST`, `CONTROL_BIND_HOST`). |
| agent | `HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY`, `NO_PROXY` (+ lowercase) | Route all tools through the gateway. |
| agent | `STATUS_PORT` | Status server port (7680); must match control's `AGENT_STATUS_PORT`. |
| agent | `SELFTEST_BLOCKED_PROBES` | Management endpoints the self-test expects to be unreachable. |
| agent | `TALLYGATE_URL` | Grant API for the `tallygate` CLI (`http://172.31.10.2:8079`). |
