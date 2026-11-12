# Configuration reference

Configuration lives in three places:

| File | Scope | Edited by |
|---|---|---|
| `.env` next to `compose.yaml` | Optional: access, state paths, agent and notification settings | you (`docker compose up -d` applies changes) |
| `config/gateway.yaml` | Static gateway config: grants, credential injection, service ports. Built into the image as `/etc/egressgw/config.yaml`; mount your own copy over it (see [operations](operations.md#with-docker-compose-recommended)) | you (restart `egress-gw` after changes) |
| `policy.yaml` in the `gateway-data` volume | Live policy: default action, rules, hard deny | UI / API (or by hand while the gateway is stopped) |

## `.env`

All variables are optional. Secrets are created on first start when they are not set.

| Variable | Default | Description |
|---|---|---|
| `TALLYGATE_VERSION` | `latest` | Image tag of all three images, e.g. `0.4` (minor version) or `0.4.0`. |
| `GATEWAY_DATA` | volume `gateway-data` | Gateway state. A host path makes it a bind mount (owner uid 10001, mode 700). |
| `AGENT_HOME` | volume `agent-home` | Agent home (Claude login, settings). A host path makes it a bind mount (owner uid 1000). |
| `WORKSPACE` | volume `workspace` | Agent workspace. A host path makes it a bind mount (owner uid 1000). |
| `CONTROL_DATA` | volume `control-data` | UI password hash and session secret. A host path makes it a bind mount (owner uid 10002, mode 700). See [host directories](operations.md#host-directories). |
| `CONTROL_PUBLISH` | `0.0.0.0:8080` | Host address:port the UI is published on. `127.0.0.1:8080` with a reverse proxy on the same host; see [reaching the UI](operations.md#reaching-the-ui). |
| `PUBLIC_URL` | – | External UI URL, included in notifications. |
| `TZ` | UTC | Time zone of the gateway and control, e.g. `Europe/Berlin`: quiet hours and times in notifications use it. |
| `COOKIE_SECURE` | `auto` | `auto`: the session cookie is `Secure` exactly when the browser uses HTTPS (directly, or `X-Forwarded-Proto` from a trusted proxy). `1` / `0` force it on or off. |
| `TRUST_FORWARDED_FOR` | `0` | `1` when the UI sits behind your reverse proxy: trust `X-Forwarded-For`/`-Host`/`-Proto` for rate limiting and origin checks — **only** from peers in `TRUSTED_PROXIES`. |
| `TRUSTED_PROXIES` | – | Comma-separated CIDRs of your reverse/auth proxy as seen by control. Forwarded and auth headers from any other peer are ignored. With a published port this is the `mgmt` bridge gateway `172.31.12.1/32`, which every local process shares: see [reverse proxy](operations.md#reverse-proxy). |
| `SESSION_IDLE` | `7200` | UI session idle timeout in seconds (absolute lifetime: `SESSION_TTL`, 12 h). Sessions are server-side: logout and restarts end them, and open event streams and consoles are closed within 10 s. |
| `GW_API_TOKEN` | *(created in the `gw-token` volume)* | Bearer token between control and gateway (≥ 24 chars). |
| `SESSION_SECRET` | *(created in `control-data`)* | HMAC key that signs session ids in the cookie. |
| `TTYD_CREDENTIAL` | *(created in the `ttyd` volume)* | `user:password` shared by control and the agent's ttyd consoles. Added by control during the WebSocket handshake; the browser never sees it. |
| `CONTROL_PASSWORD_HASH` | *(generated password)* | `scrypt:16:<salt>:<hash>` (scrypt N = 2^16), create with `python3 control/hashpw.py` or `docker compose exec control python -m app.passwd --print-hash`. Without it (and without `CONTROL_PASSWORD`), control generates a password on first start, prints it to its log (where it stays until the log is rotated) and keeps the hash in `control-data`; change that one with `docker compose exec control python -m app.passwd`, which also ends all open sessions. The legacy `scrypt:<salt>:<hash>` (N = 2^14) is still accepted; regenerate it. |
| `CONTROL_PASSWORD` | – | Plain-text password instead of a hash. Discouraged (logged as a warning). |
| `TRUST_PROXY_AUTH_HEADER` | – | E.g. `Remote-User`: accept the user from this header set by an authenticating proxy (Authelia, oauth2-proxy). Requires `TRUSTED_PROXIES`; control refuses to start without it. Trust only the proxy container's own address: see [reverse proxy](operations.md#reverse-proxy). |
| `TRUST_PROXY_SECRET` | – | Shared secret (≥ 16 characters) that the proxy sends as `X-Tallygate-Proxy-Secret`. When set, forwarded and auth headers are believed only from `TRUSTED_PROXIES` **and** with this header (compared in constant time). Recommended with `TRUST_PROXY_AUTH_HEADER`. |
| `RC_NAME` | `tallygate` | Remote Control session name shown in the Claude app. |
| `RC_ENABLE` | `1` | Start `claude remote-control` automatically in the `rc` tmux session. |
| `RC_ARGS` | – | Extra arguments for `claude remote-control`, e.g. `--spawn worktree`. |
| `AGENT_PERMISSION_MODE` | `bypassPermissions` | Claude Code permission mode for Remote Control and the `claude` console. Seeded into `~/.claude/settings.json` on first start. |
| `CLAUDE_VERSION` | pinned in `agent/Dockerfile` | Only when building from source: Claude Code npm version baked into the agent image (no auto-updater). |
| `AGENT_EXTRA_PACKAGES` | – | Only when building from source: extra Debian packages for the agent image, e.g. `build-essential golang-go`. With published images, use a [custom agent image](operations.md#custom-agent-image). |
| `AGENT_MEM_LIMIT` | `6g` | Memory limit of the agent container. |
| `AGENT_CPUS` | `0` | CPU limit of the agent container (e.g. `2`); `0` means no limit. See [resource limits](operations.md#resource-limits). |
| `TELEGRAM_BOT_TOKEN` | – | Bot token from @BotFather. Enables Telegram approvals together with the chat ID. |
| `TELEGRAM_CHAT_ID` | – | Chat (user or group) that receives approval requests. |
| `TELEGRAM_ALLOWED_USER_IDS` | – | **Required** for Telegram: comma-separated user IDs allowed to decide. Without it Telegram approvals stay disabled. |
| `MATRIX_HOMESERVER` | – | e.g. `https://matrix.example.org`. |
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
TALLYGATE_VERSION=0.4
GATEWAY_DATA=/srv/tallygate/gateway
AGENT_HOME=/srv/tallygate/agent-home
WORKSPACE=/srv/tallygate/workspace
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

Every key with an example. The file in the repository lists them all, commented where the default applies.

| Key | Default | Example | Meaning |
|---|---|---|---|
| `initial_preset` | `baseline` | `lockdown` | Preset that creates `policy.yaml` on the very first start. |
| `log_keep_days` | `30` | `7` | Event log retention. |
| `log_max_events` | `500000` | `100000` | Hard cap on stored events. |
| `max_pending` | `10` | `5` | Open approvals at once; more unknown destinations are denied immediately. |
| `hard_deny_floor` | built-in list | `[203.0.113.7/32]` | **Added** to the built-in hard deny (your VPS's public IP). |
| `readonly` | npm, Yarn, crates.io, Docker Hub, GHCR, Quay, Hugging Face | `[registry.npmjs.org, {host: ghcr.io, post_is_write: true}]` | Hosts where writes are refused: PUT/PATCH/DELETE, and with `post_is_write` also POST (except `read_posts`). See [Read-only hosts](#read-only-hosts). |
| `inject` | GitHub entries | see below | Credential injection per host. |
| `inject_strip_headers` | `[Authorization, Cookie]` | `[Authorization, Cookie, X-Api-Key]` | Agent headers always removed on inject hosts. |
| `services` | `[]` | `[{name: pg, listen: 15432, target: db.example.org:5432}]` | TCP service ports. |
| `quiet_hours` | – | `{start: "22:00", end: "07:00", days: [mon, tue, wed, thu, fri], tz: Europe/Berlin}` | Daily period in which requests that need you are refused at once. See [Availability](#availability). |
| `digest_minutes` | `30` | `0` | While away: a digest of what was refused every N minutes; `0` = only when you are back. |
| `grants`, `grants_*`, `grant_*` | – | see [Grants](#grants) and [grants.md](grants.md) | Grants. |

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
hosts are in this list: a `gateway.yaml` of your own replaces the whole list.


```yaml
initial_preset: baseline   # preset used to create policy.yaml on first start
log_keep_days: 30          # event log retention
log_max_events: 500000     # hard cap on stored events; identical events within 2 s are counted, not stored
max_pending: 10            # open approvals at once; further unknown destinations are denied immediately
# hard_deny_floor: [...]   # ADDED to the built-in hard deny below (cannot remove from it). Only this file can change it.
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
    allow_private: false   # true = exempt exactly this target from hard_deny (LAN service)
```

Template syntax in `value`: `${name}` inserts the secret `name` (set via the UI/API); `${b64:…}` base64-encodes
the rendered inner text. The agent's own `Authorization`/`Cookie` headers are **always removed** on inject
hosts; if a referenced secret is missing the request goes out without credentials (fail closed).

Every `inject` host must also be **allowed** by the policy (the baseline preset allows GitHub).

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

### Grants

See [grants.md](grants.md) for the concept and examples. Keys in `config/gateway.yaml`:

| Key | Default | Meaning |
|---|---|---|
| `grants` | – | Map `name → definition` (`description`, `targets`, `levels`, `approval`, `default_ttl`, `max_ttl`, `inject`). Read-only in the UI. |
| `grants_lan_allow` | `[]` | CIDRs that **UI-defined** grants may reach with `lan: true`. Empty = UI grants cannot target the LAN. |
| `grants_never` | loopback, link-local, multicast, unspecified | Never reachable through any grant. |
| `grant_request_timeout` | `300` | Seconds a request waits for a decision. |
| `grant_max_pending` | `3` | Open grant requests at once. |
| `grant_api_rate` | `30` | Requests/minute on the agent grant API. |

Target fields: `host` (name, `*.domain` or IP), `port`, `scheme` (`https` default, `http`, `tcp`), `paths`
(globs, default `/*`), `lan`, `address` (fixed IP), `tls_fingerprint` (SHA-256), `tls_verify`
(default `true`).

## `policy.yaml`

The live policy, edited in the UI. Worked examples for hosts, ports, CIDRs and ordering:
[rules.md](rules.md).

```yaml
default: ask               # allow | deny | ask
ask_timeout: 60            # seconds to hold a connection while waiting for a decision (5..3600)
hard_deny:                 # optional ADDITIONS to the floor (cannot remove floor entries)
  - 203.0.113.7/32         # e.g. the Docker host's own public IP
rules:                     # first match wins
  - id: github             # optional, generated if missing; must be unique
    action: allow          # allow | deny | ask
    host: github.com       # glob; "*.x" = x and all subdomains   (either host or cidr)
    # cidr: 140.82.112.0/20
    port: 443              # 443 | [80, 443] | "8000-8100" | "*" (default)
    note: free text
    expires: 1794390000    # unix timestamp; omit for permanent
```

Built-in hard-deny floor: `0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12,
192.0.0.0/24, 192.0.2.0/24, 192.88.99.0/24, 192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24,
224.0.0.0/4, 240.0.0.0/4, ::/96, ::ffff:0:0/96, 64:ff9b::/96, 64:ff9b:1::/48, 100::/64, 2001::/32,
2001:db8::/32, 2002::/16, fc00::/7, fe80::/10, fec0::/10, ff00::/8` (NAT64, 6to4 and Teredo prefixes are
included because they embed IPv4 addresses). The floor always contains this list; `hard_deny_floor` in the
read-only gateway config **adds** to it (it cannot remove built-in ranges), and an invalid entry stops the
gateway. `policy.yaml`/the API can only add further CIDRs. If the Docker host has a public IP (VPS), add it
to `hard_deny_floor`.
For LAN services use a service port with `allow_private: true` (exempts exactly that target, and only on
that service port — not via the proxy or SOCKS) rather than shrinking the floor.

### Presets (`gateway/presets/*.yaml`)

| Preset | Category | Content | Typical use |
|---|---|---|---|
| `baseline` | policy | default `ask`; allow Anthropic/Claude, GitHub, npm, PyPI | initial policy |
| `lockdown` | policy | default `deny`; Anthropic only | emergency: replace the policy via raw editor/API (`POST` refuses it) |
| `open` | internet | any public host on 80/443 | temporary, **always with a TTL** (*Quick actions*) |
| `internet` | internet | any public host on any port | temporary, **always with a TTL** |
| `python`, `node`, `go`, `rust`, `debian`, `containers`, `huggingface` | template | the hosts a tool ecosystem needs | *Quick actions → Templates* |

Presets of the categories `internet` and `template` are applied **on top** (`POST /presets/<name>`):

- Their rules are inserted at the top of the list, so **while active they win over your own rules, deny
  rules included**. Undo them (or give them a time limit) when the task is done.
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

Add your own templates by mounting YAML files into the gateway's `/app/presets/`, e.g.
`./presets/company.yaml:/app/presets/company.yaml:ro` in `compose.yaml`.

## Component environment (set by `compose.yaml`)

These are wired by the compose file and normally need no change.

| Container | Variable | Purpose |
|---|---|---|
| egress-gw | `GW_LISTEN_HOST` | Gateway address on agent-net (proxy, SOCKS5, DNS, service ports). |
| egress-gw | `GW_HTTP_PORT` / `GW_SOCKS_PORT` / `GW_DNS_PORT` | Listener ports (3128 / 1080 / 53). |
| egress-gw | `GW_API_HOST` / `GW_API_PORT` | API address on control-net / port (8081). |
| egress-gw | `GW_GRANTS_PORT` | Agent grant API port on agent-net (8079). |
| egress-gw | `GW_CONFIG`, `DATA_DIR`, `CA_EXPORT_DIR`, `PRESET_DIR` | Paths. |
| egress-gw | `GW_EXTRA_ARGS` | Extra mitmdump arguments (advanced). |
| egress-gw | `GW_TEST_STATIC_HOSTS` | **Test suite only.** Never set in production (logged as a warning). |
| egress-gw | `GW_TEST_FLOOR_REPLACE` | **Test suite only.** `1` = `hard_deny_floor` replaces the built-in list (the e2e upstreams run on loopback). Never set in production (logged as a warning). |
| control | `CONTROL_BIND_HOST` / `CONTROL_PORT` | UI bind address (mgmt network only) / port. |
| control | `GW_URL` | Gateway API base URL. |
| control | `AGENT_HOST`, `AGENT_STATUS_PORT`, `TERMINALS` | Agent address, status port, `name:port` list of ttyd consoles. |
| control | `SESSION_TTL`, `LOG_LEVEL` | Session lifetime (s, default 12 h), log level. |
| control | `CONTROL_DATA` | Control state directory (`/data`): session secret, password hash, VAPID key, push subscriptions. |
| control | `TELEGRAM_API_BASE`, `PUSHOVER_API_BASE` | API base URLs (the test suite points them at mock servers). |
| control | `PUSH_TEST_ALLOW_HTTP` | **Test suite only.** `1` = Web Push endpoints over plain HTTP are accepted (logged as a warning). |
| agent | `HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY`, `NO_PROXY` (+ lowercase) | Route all tools through the gateway. |
| agent | `SELFTEST_BLOCKED_PROBES` | Management endpoints the self-test expects to be unreachable. |
| agent | `TALLYGATE_URL` | Grant API for the `tallygate` CLI (`http://172.31.10.2:8079`). |
