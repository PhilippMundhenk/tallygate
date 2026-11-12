# API reference

## Gateway management API

Base URL: `http://172.31.11.2:8081` (control-net only). All endpoints except `/health` require
`Authorization: Bearer $GW_API_TOKEN`. Request and response bodies are JSON. Validation errors return
`400 {"error": "..."}`.

| Method | Path | Body | Response |
|---|---|---|---|
| GET | `/health` | – | `{"ok": true}` (no auth) |
| GET | `/policy` | – | Full policy (`default`, `ask_timeout`, `hard_deny` = extras, `rules`) plus read-only `hard_deny_floor` |
| PUT | `/policy` | Full policy | Validated and replaced; returns the new policy. Replaces **every** rule: send only a policy you have just read |
| PATCH | `/policy` | `{"default": "ask"\|"deny"\|"allow", "ask_timeout": 5..3600}` (either or both) | Changes only the mode and/or the approval timeout; the rules stay as they are. Any other key, a non-integer timeout or an empty body is a `400` |
| POST | `/emergency-stop` | optional `{"by": "who"}` | Best-effort stop, see below: `{"ok": bool, "steps": [{"step", "ok", "errors"?, ...}]}` |
| POST | `/rules` | Rule (+ optional `"top": false` to append) | `201` created rule |
| DELETE | `/rules/{id}` | – | `{"ok": true}` or `404` |
| GET | `/presets` | – | `["baseline", "containers", …]`; with `?details=1`: `[{name, title, description, category, default, rules}]` |
| POST | `/presets/{name}` | optional `{"ttl": seconds}` | `{"added": [rule ids], "expires": ts \| null}`: rules inserted on top as `<name>:<id>`, tagged `source: preset:<name>`; applying again replaces them (new TTL). `409` if another rule uses such an id; `400` for `policy` presets (use `PUT /policy`) |
| DELETE | `/presets/{name}` | – | `{"removed": [rule ids]}`: removes the rules tagged `preset:<name>` (undo) |
| GET | `/pending` | – | Pending approvals: `id, host, port, ips, proto, client, created, expires, attempts` |
| POST | `/pending/{id}/decide` | `{"scope": "once"\|"hour"\|"always"\|"domain"\|"deny"\|"deny_always", "by": "who"}` | `{"rule": {...}}`; `404` if already decided/timed out |
| POST | `/test` | `{"host": "...", "port": 443}` | Dry run: `{"action", "reason", "rule_id", "ips"}` |
| GET | `/events?limit=200&before=<id>&q=<text>` | – | Newest-first event log entries |
| GET | `/stream` | – | Server-sent events (see below) |
| GET | `/secrets` | – | `{"names": [...]}` — values are never returned |
| PUT | `/secrets/{name}` | `{"value": "..."}` (empty removes) | `{"names": [...]}` |
| GET | `/info` | – | `inject_hosts`, `inject_secrets_needed`, `services`, `ca_pem`, `pending` |
| GET | `/grants` | – | `defs` (with `source` config/ui), `active`, pending `requests`, `lan_allow_ui`, `missing_secrets`, `auto_suspended` (`null` or `{"since", "by"}` after an emergency stop) |
| PUT | `/grants/{name}` | Grant definition ([grants](grants.md)) | Validated, stored as a UI grant; `400` for config grants or LAN targets outside `grants_lan_allow` |
| DELETE | `/grants/{name}` | – | UI grants only; also ends an active instance |
| POST | `/grants/{name}/activate` | `{"level": "read"\|"write", "ttl": "1h", "by": "who"}` | Active grant (admin activation without a request) |
| DELETE | `/active-grants/{id}?by=who` | – | Revoked active grant |
| POST | `/grant-requests/{id}/decide` | `{"decision": "approve"\|"read"\|"deny", "by": "who", "ttl": optional}` | The decided request; `read` downgrades a write request |

### Emergency stop

`POST /emergency-stop` runs these steps in this order. Every step runs even if an earlier one failed; each
reports `ok` and, if it failed, `errors`:

| Step | What it does | Result fields |
|---|---|---|
| `suspend_auto_approval` | Grant levels with `approval: auto` need a human until the mode is changed again | – |
| `revoke_grants` | Revokes every active grant | `revoked` (grant names) |
| `deny_pending` | Denies every connection waiting for approval | `denied` (`host:port`) |
| `deny_grant_requests` | Denies every pending grant request | `denied` (grant names) |
| `remove_internet_presets` | Removes the rules of every `category: internet` preset (`open`, `internet`) | `removed` (rule ids) |
| `mode_deny` | Sets the mode to `deny` | `previous` (the mode before) |

The suspension is stored in `grants-state.yaml` in the gateway's data volume, so it survives a restart (an
unreadable file keeps it on). It ends when the mode changes (`PATCH /policy` or `PUT /policy` with a
different `default`); a write that keeps `deny` does not end it. The stop is logged as one `admin` event
(`action: emergency-stop`). The control plane relays it as `POST /api/gw/emergency-stop` and sets `by` to
the session user.

### Event log entry

```json
{"id": 812, "ts": 1794386562.06, "kind": "conn", "proto": "regular", "client": "172.31.10.10",
 "host": "api.github.com", "port": 443, "ips": ["140.82.121.6"], "action": "allow",
 "reason": "rule github-api", "extra": null}
```

`kind`: `conn` (decision), `ask` (approval requested), `dns` (blocked DNS query), `admin` (policy/secret
change), `grant` (grant requested/approved/denied/expired/revoked). `proto`: `regular` (HTTP proxy), `socks5`, `reverse` (service port), `dns`.

### Stream events

```
data: {"type": "event", "event": {...log entry...}}
data: {"type": "ask", "pending": {...pending request...}}
data: {"type": "resolved", "id": "5ae33c9d25", "action": "allow", "scope": "hour", "by": "telegram:philipp"}
data: {"type": "resolved", "id": "...", "action": "deny", "reason": "timeout"}
data: {"type": "policy"}
data: {"type": "grant_request", "request": {...}, "grant": {...summary...}}
data: {"type": "grant_resolved", "request": {..., "status": "approved", "granted_level": "read"}}
data: {"type": "grants"}                       (definitions or active grants changed)
```

## Agent grant API

Base URL: `http://172.31.10.2:8079` (agent network, **no authentication**, rate-limited to
`grant_api_rate` requests/min, 4 KiB bodies). This is the only gateway API the agent can reach. It can
list, ask and poll, nothing else. The `tallygate` CLI in the agent image wraps it.

| Method | Path | Body | Response |
|---|---|---|---|
| GET | `/v1/grants` | – | `{"grants": [{name, description, levels, default_ttl, max_ttl, targets, active?}]}`: no credentials |
| POST | `/v1/grants/{name}/request` | `{"level": "read"\|"write", "ttl": "30m", "reason": "..."}` | `202 {"id", "status": "pending", ...}` or `200` if auto-approved; `429` when too many are pending |
| GET | `/v1/requests/{id}?wait=0..55` | – | `{"id", "grant", "level", "status": pending\|approved\|denied\|expired, "granted_level"?}`; `wait` long-polls |

Keep-alive comments (`: ping`) are sent every 20 s.

## Control plane HTTP interface

Used by the bundled web UI; documented for scripting and review.

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/healthz` | – | Liveness |
| GET/POST | `/login` | – | Login form / submit (`password`); 10 failures per 15 min per client lock out (429); bodies over 4 KiB get 413; 429 while 5 checks are already queued |
| POST | `/logout` | session | Clears the session |
| GET | `/` | session | Single-page UI |
| GET | `/api/meta` | session | Current user, terminal names, notification status |
| GET | `/api/stream` | session | Relayed gateway SSE stream |
| * | `/api/gw/{path}` | session + CSRF | Relay to an **allowlisted** subset of the gateway API (policy, rules, pending/decide, events, test, presets, secrets, info). For `decide`, `by` is overwritten with `web:<user>`. |
| POST | `/api/github/check` | session + CSRF | `{"token": "...", "store": true}` — validate a token against GitHub from the control plane and store it in the gateway |
| GET | `/api/agent/status` | session | Agent status (Claude login, git identity, Remote Control running, versions) |
| GET | `/api/agent/selftest` | session | Run the in-agent isolation self-test |
| GET | `/term/{name}/` | session | Console page (served by control: vendored xterm.js, no agent content) |
| GET (WS) | `/term/{name}/ws` | session + Origin | Filtered relay to the agent's ttyd `name`: browser → `0` input / `1` resize, agent → `0` output only; control adds the ttyd credential |

**CSRF rule:** non-GET requests under `/api/` must carry `X-Tallygate: 1` and, if an `Origin` header is
present, it must match the host. Session cookies are `HttpOnly`, `SameSite=Lax` and `Secure` (unless
`COOKIE_SECURE=0`). `Lax` lets the `PUBLIC_URL` link in a notification open the UI logged in; cross-site
POSTs still carry no cookie, and the header and Origin checks do not depend on it. API errors are JSON
`{"error": …}`: 400 for an invalid request body, 502 when the gateway, the agent or GitHub fails.
