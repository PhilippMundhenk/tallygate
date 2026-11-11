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
| `CONTROL_PUBLISH` | `127.0.0.1:8080` | Host address:port the UI is published on. Put a TLS reverse proxy in front. |
| `PUBLIC_URL` | – | External UI URL, included in notifications. |
| `COOKIE_SECURE` | `1` | Session cookie only over HTTPS. Set `0` only for local plain-HTTP testing. |
| `TRUST_FORWARDED_FOR` | `0` | `1` when the UI sits behind your reverse proxy: trust `X-Forwarded-For`/`-Host`/`-Proto` for rate limiting and origin checks — **only** from peers in `TRUSTED_PROXIES`. |
| `TRUSTED_PROXIES` | – | Comma-separated CIDRs of your reverse/auth proxy as seen by control. Forwarded and auth headers from any other peer are ignored. With a published port this is the `mgmt` bridge gateway `172.31.12.1/32`, which every local process shares: see [reverse proxy](operations.md#reverse-proxy). |
| `SESSION_IDLE` | `7200` | UI session idle timeout in seconds (absolute lifetime: `SESSION_TTL`, 12 h). Sessions are server-side: logout and restarts end them. |
| `GW_API_TOKEN` | *(created in the `gw-token` volume)* | Bearer token between control and gateway (≥ 24 chars). |
| `SESSION_SECRET` | *(created in `control-data`)* | HMAC key that signs session ids in the cookie. |
| `TTYD_CREDENTIAL` | *(created in the `ttyd` volume)* | `user:password` shared by control and the agent's ttyd consoles. Added by control during the WebSocket handshake; the browser never sees it. |
| `CONTROL_PASSWORD_HASH` | *(generated password)* | `scrypt:16:<salt>:<hash>` (scrypt N = 2^16), create with `python3 control/hashpw.py`. Without it (and without `CONTROL_PASSWORD`), control generates a password on first start, prints it once to its log and keeps the hash in `control-data`; change that one with `docker compose exec control python -m app.passwd`. The legacy `scrypt:<salt>:<hash>` (N = 2^14) is still accepted; regenerate it. |
| `CONTROL_PASSWORD` | – | Plain-text password instead of a hash. Discouraged (logged as a warning). |
| `TRUST_PROXY_AUTH_HEADER` | – | E.g. `Remote-User`: accept the user from this header set by an authenticating proxy (Authelia, oauth2-proxy). Requires `TRUSTED_PROXIES`; control refuses to start without it. |
| `RC_NAME` | `tallygate` | Remote Control session name shown in the Claude app. |
| `RC_ENABLE` | `1` | Start `claude remote-control` automatically in the `rc` tmux session. |
| `RC_ARGS` | – | Extra arguments for `claude remote-control`, e.g. `--spawn worktree`. |
| `AGENT_PERMISSION_MODE` | `bypassPermissions` | Claude Code permission mode for Remote Control and the `claude` console. Seeded into `~/.claude/settings.json` on first start. |
| `CLAUDE_VERSION` | `2.1.304` | Only when building from source: Claude Code npm version baked into the agent image (no auto-updater). |
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

## `config/gateway.yaml`

```yaml
initial_preset: baseline   # preset used to create policy.yaml on first start
log_keep_days: 30          # event log retention
log_max_events: 500000     # hard cap on stored events; identical events within 2 s are counted, not stored
max_pending: 10            # open approvals at once; further unknown destinations are denied immediately
# hard_deny_floor: [...]   # immutable hard deny (default: built-in list below). Only this file can change it.
readonly:                  # TLS intercepted, PUT/PATCH/DELETE refused (e.g. blocks `npm publish`)
  - registry.npmjs.org
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
included because they embed IPv4 addresses). The floor is set only by `hard_deny_floor` in the read-only
gateway config; `policy.yaml`/the API can only add CIDRs. If the Docker host has a public IP (VPS), add it.
For LAN services use a service port with `allow_private: true` (exempts exactly that target, and only on
that service port — not via the proxy or SOCKS) rather than shrinking the floor.

### Presets (`gateway/presets/*.yaml`)

| Preset | Content | Typical use |
|---|---|---|
| `baseline` | default `ask`; allow Anthropic/Claude, GitHub, npm, PyPI | initial policy |
| `open` | allow any public host on 80/443 | temporary, **always with a TTL** (e.g. 15 min during setup) |
| `lockdown` | default `deny`; Anthropic only | emergency: replace the policy via raw editor/API |

Presets are applied **on top** (their rules are inserted first, optionally with a TTL). Add your own presets
by mounting additional YAML files into `/app/presets/`.

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
| control | `CONTROL_BIND_HOST` / `CONTROL_PORT` | UI bind address (mgmt network only) / port. |
| control | `GW_URL` | Gateway API base URL. |
| control | `AGENT_HOST`, `AGENT_STATUS_PORT`, `TERMINALS` | Agent address, status port, `name:port` list of ttyd consoles. |
| control | `SESSION_TTL`, `LOG_LEVEL` | Session lifetime (s, default 12 h), log level. |
| agent | `HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY`, `NO_PROXY` (+ lowercase) | Route all tools through the gateway. |
| agent | `SELFTEST_BLOCKED_PROBES` | Management endpoints the self-test expects to be unreachable. |
| agent | `TALLYGATE_URL` | Grant API for the `tallygate` CLI (`http://172.31.10.2:8079`). |
