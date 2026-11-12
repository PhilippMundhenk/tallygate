# API reference

## Gateway management API

Base URL: `http://172.31.11.2:8081` (control-net only). All endpoints except `/health` require
`Authorization: Bearer $GW_API_TOKEN`. Request and response bodies are JSON. Validation errors return
`400 {"error": "..."}`. An optional `X-Tallygate-By` header (at most 64 characters) names who made a change in
the policy history; without it the change is attributed to `api`. The control plane sets it to `web:<user>`.

Every write to the policy (`PUT`/`PATCH /policy`, rules, presets, approvals, the emergency stop, restores,
imports, removal of expired rules) stores a version in the policy history, unless the policy did not change.

| Method | Path | Body | Response |
|---|---|---|---|
| GET | `/health` | – | `{"ok": true}` (no auth) |
| GET | `/policy` | – | Full policy (`default`, `ask_timeout`, `hard_deny` = extras, `rules`) plus read-only `hard_deny_floor` |
| PUT | `/policy` | Full policy | Validated and replaced; returns the new policy. Replaces **every** rule: send only a policy you have just read |
| PATCH | `/policy` | `{"default": "ask"\|"deny"\|"allow", "ask_timeout": 5..3600}` (either or both) | Changes only the mode and/or the approval timeout; the rules stay as they are. Any other key, a non-integer timeout or an empty body is a `400` |
| GET | `/learning` | – | `{"active": {id, started, until, ports, by} \| null, "ports_allowed", "max_minutes", "sessions": [last 10 with ended, end_reason]}` |
| POST | `/learning` | `{"minutes": 30, "ports": [443]}` | Starts learning mode (`201`, the state as above); replaces a running session. `minutes` 1..`learning_max_minutes`, `ports` a subset of `learning_ports` |
| DELETE | `/learning` | – | Ends learning mode; the state |
| GET | `/learning/{id}` | – | `{"session", "groups": [{domain, port, hosts: [{host, count, learned, denied}], count, learned, denied, proposal: {host, port} \| null}]}`: the destinations used during that session; `proposal` only for what learning mode allowed and no permanent rule allows now |
| POST | `/learning/apply` | `{"rules": [{host, port}]}` | Adds allow rules at the **bottom** (tagged `source: learning`). Only exact host names or `*.<registrable domain>`, no `*`, no public suffixes, no IPs |
| GET | `/rules/stats` | – | `{"rules": [{...rule, pos, hits, last, since, stale}], "stale_days"}`: every rule in order with its hit count, last match (`null` = never) and since when it is counted; `stale` = permanent and unused for `rule_stale_days` |
| POST | `/rules/cleanup` | `{"ids": [...]}` | Removes those of the rules that are unused right now, keeps the others: `{"removed", "kept"}` |
| GET | `/suggestions` | – | `{"suggestions": [{key, rule: {action, host, port}, count, hosts, last}], "min_approvals", "window_days"}`: destinations approved for a limited time at least `suggest_min_approvals` times in `suggest_window_days`, not covered by a permanent rule and not dismissed |
| POST | `/suggestions/accept` | `{"key": "..."}` | Adds the suggested permanent rule (built by the gateway, tagged `source: suggestion`): `201` rule; `404` if there is no such suggestion now |
| POST | `/suggestions/dismiss` | `{"key": "..."}` | Hides the suggestion for `log_keep_days` |
| GET | `/policy/history?limit=100&before=<id>` | – | `{"versions": [{id, ts, by, what, default, rules}], "keep"}`, newest first; `rules` is the number of rules |
| GET | `/policy/history/{id}` | – | `{id, ts, by, what, policy}`: the policy as stored in `policy.yaml` (no floor); `404` if unknown or no longer kept |
| GET | `/policy/diff?from=<id>&to=<id>\|current` | – | Changes from one version to another (default `to=current`): `default`/`ask_timeout` as `[old, new]`, `hard_deny` `{added, removed}`, `rules` `{added, removed, changed: [{id, before, after}]}`, `reordered`, `identical`. Only what changed is present |
| POST | `/policy/history/{id}/restore` | – | Replaces the policy with that version (validated like `PUT /policy`; the floor stays as configured); returns the new policy |
| GET | `/policy/export` | – | `{"filename", "yaml"}`: the policy and the UI grants as one YAML document (`tallygate_export: 1`). No secrets, no config-file grants, no floor |
| POST | `/policy/import` | `{"yaml": "...", "apply": false}` | Validates the document (policy like `PUT /policy`, each grant like `PUT /grants/{name}`) and returns `{diff, grants: {added, changed}, warnings, applied}`. With `"apply": true` it replaces the policy and adds or replaces those UI grants, all or nothing. A `hard_deny_floor` in the file is ignored with a warning |
| POST | `/emergency-stop` | optional `{"by": "who"}` | Best-effort stop, see below: `{"ok": bool, "steps": [{"step", "ok", "errors"?, ...}]}` |
| POST | `/rules` | Rule (+ optional `"top": false` to append) | `201` created rule |
| DELETE | `/rules/{id}` | – | `{"ok": true}` or `404` |
| GET | `/presets` | – | `["baseline", "containers", …]`; with `?details=1`: `[{name, title, description, category, default, rules}]` |
| POST | `/presets/{name}` | optional `{"ttl": seconds}` | `{"added": [rule ids], "expires": ts \| null}`: rules inserted on top as `<name>:<id>`, tagged `source: preset:<name>`; applying again replaces them (new TTL). `409` if another rule uses such an id; `400` for `policy` presets (use `PUT /policy`) |
| DELETE | `/presets/{name}` | – | `{"removed": [rule ids]}`: removes the rules tagged `preset:<name>` (undo) |
| GET | `/pending` | – | Pending approvals: `id, host, port, ips, proto, client, created, expires, attempts, context` (`context`: up to 3 entries `{ts, kind, tool?, text?, note?}` the agent reported in the 2 minutes before; agent-written, untrusted) |
| POST | `/pending/{id}/decide` | `{"scope": "once"\|"hour"\|"always"\|"domain"\|"deny"\|"deny_always", "by": "who"}` | `{"rule": {...}}`; `404` if already decided/timed out |
| POST | `/test` | `{"host": "...", "port": 443}` | Dry run: `{"action", "reason", "rule_id", "ips"}` |
| GET | `/events?limit=200&before=<id>&q=<text>` | – | Newest-first event log entries |
| GET | `/events/summary?since=<ts>` | – | Connection events since `since` (default: one hour ago, at most 7 days back): `{"since", "counts": {"allow", "deny", "ask"}, "top": [{"host", "port", "count", "allow", "deny", "ask", "last"}] (10), "new": [{"host", "port", "first", "count"}] (20)}`. `new` = first seen within the kept log. Counts are log rows: identical events within a few seconds are coalesced |
| GET | `/events?limit=200&before=<id>&q=<text>` | – | Newest-first event log entries (`limit` at most 2000). Filters, all optional and combined: `host` (exact name or IP, or `*.domain` for the domain and its subdomains), `port`, `kind` and `action` (comma-separated lists), `since`/`until` (unix time, `until` exclusive). Invalid values are a `400` |
| GET | `/destinations?since=&until=&q=&new=1&limit=200` | – | Connection destinations (`conn` and `ask` events) in the range, most recent first: `[{host, port, events, first, last, allowed, denied, asked, first_seen, new}]`. `first_seen` is the first event in the whole log; `new=1` returns only those first seen inside the range |
| GET | `/destinations/detail?host=&port=443` | – | One destination: `stats` (as above, or `null`), `decision` `{action, reason, rule_id, rule}` = what the policy decides for it now on the name (not resolved; for an IP including the hard deny), and its latest `events` |
| GET | `/stream` | – | Server-sent events (see below) |
| GET | `/secrets` | – | `{"names": [...]}` — values are never returned |
| PUT | `/secrets/{name}` | `{"value": "..."}` (empty removes) | `{"names": [...]}` |
| GET | `/info` | – | `inject_hosts`, `inject_secrets_needed`, `services`, `github_repos`, `ca_pem`, `pending` |
| GET | `/availability` | – | `mode` (`available` \| `away` \| `quiet`), `until`, `message` (what the agent is told), `away` (`{since, by, until}`), `quiet_hours`, `quiet_source` (`config` \| `ui`), `quiet_zone`, `digest_minutes`, `missed` (`[{kind: conn\|grant, host, port, first, last, count}]`), `missed_dropped` |
| PATCH | `/availability` | `{"away": bool, "away_until": ts, "quiet_hours": {start, end, days?, tz?} \| null, "by": "who"}` (any of them) | Away on/off (optionally until a time, at most 30 days), quiet hours set or off. Going away denies everything waiting for a human. Returns the state; any other key is a `400` |
| DELETE | `/availability/missed` | – | Clears the list of refused requests |
| GET | `/info` | – | `inject_hosts`, `inject_secrets_needed`, `services`, `ca_pem`, `pending`, `version` (the release, from `VERSION`), `data_disk` (`{"total", "used", "free"}` of the file system holding the gateway state, or `null`), `events_db_bytes` (event log incl. WAL) |
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
| `end_learning` | Ends learning mode | `ended` (session ids) |
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
data: {"type": "availability"}                 (away mode or quiet hours changed)
data: {"type": "digest", "why": "away ended", "items": [{kind, host, port, count, ...}], "more": 0}
```

## Agent grant API

Base URL: `http://172.31.10.2:8079` (agent network, **no authentication**, rate-limited to
`grant_api_rate` requests/min, 4 KiB bodies). This is the only gateway API the agent can reach. It can
list, ask and poll, and say what it is doing (shown as its claim), nothing else. The `tallygate` CLI in the agent image wraps it.

| Method | Path | Body | Response |
|---|---|---|---|
| GET | `/v1/grants` | – | `{"grants": [{name, description, levels, default_ttl, max_ttl, targets, active?}], "operator": {"state": "available"\|"away"\|"quiet", "until", "message"}}`: no credentials |
| POST | `/v1/grants/{name}/request` | `{"level": "read"\|"write", "ttl": "30m", "reason": "..."}` | `202 {"id", "status": "pending", ...}` or `200` if auto-approved; `429` when too many are pending; `503 {"error", "status": "denied"}` while the operator is away or in quiet hours (auto-approved levels still work) |
| POST | `/v1/activity` | `{"kind": "tool"\|"note", "tool": "Bash", "text": "npm install", "note": "Install deps"}` | `202`. What the agent is about to do, attached to its next approvals for 2 minutes. Cleaned, secrets redacted, 200 characters per field; own rate limit `activity_rate` (60/min) |
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
| GET | `/api/meta` | session | Current user, terminal names, notification status (`telegram`, `matrix`, `webpush`, `ntfy`, `gotify`, `pushover`) |
| GET | `/api/stream` | session | Relayed gateway SSE stream |
| * | `/api/gw/{path}` | session + CSRF | Relay to an **allowlisted** subset of the gateway API: `GET`/`PUT`/`PATCH /policy`, `POST /emergency-stop`, `POST /rules`, `DELETE /rules/{id}`, `GET /pending`, `POST /pending/{id}/decide`, `GET /events`, `POST /test`, `GET`/`POST`/`DELETE /presets…`, `GET /secrets`, `PUT /secrets/{name}`, `GET`/`PUT`/`DELETE /grants/{name}`, `POST /grants/{name}/activate`, `DELETE /active-grants/{id}`, `POST /grant-requests/{id}/decide`, `GET /info`, `GET`/`PATCH /availability`, `DELETE /availability/missed`. Everything else is refused (404). For decisions, the emergency stop and availability changes, `by` is set to `web:<user>`. |
| POST | `/api/github/check` | session + CSRF | `{"token": "...", "store": true}` — validate a token against GitHub from the control plane and store it in the gateway |
| GET | `/api/agent/status` | session | Agent status (Claude login, git identity, Remote Control running, versions) |
| GET | `/api/agent/selftest` | session | Run the in-agent isolation self-test |
| GET | `/api/push` | session | Web Push: `{"enabled", "public_key" (VAPID, for `applicationServerKey`), "subscriptions": [{id, label, created, service}]}` |
| POST | `/api/push/subscribe` | session + CSRF | `{"subscription": <PushSubscription JSON>, "label": "phone"}` → `201`; `400` for an unknown push service or invalid keys; `503` when Web Push is off |
| DELETE | `/api/push/{id}` | session + CSRF | Stop notifications to that device |
| POST | `/api/push/test` | session + CSRF | Send a test notification: `{"delivered": n}`; `502` if no device could be reached |
| POST | `/api/push/act` | action token + CSRF | `{"token": ...}` from a notification button. No session needed: the token is signed, bound to one request, one decision and one device, single use, valid ≤ 10 min. `403` invalid/used/expired, `409` already decided, `200 {"ok", "decision"}` |
| GET | `/sw.js`, `/manifest.webmanifest`, `/static/icon*` | – | Service worker, PWA manifest and icons (static, no session: browsers fetch them without cookies) |
| GET | `/api/meta` | session | Current user, terminal names, notification status |
| GET | `/api/version` | session | `{"tallygate", "claude_code", "check": "ok"\|"error"\|"off", "latest": {"version", "url", "published"} \| null, "update_available": bool \| null, "error"?, "changelog", "upgrade"}`. `tallygate` is the gateway's VERSION; the latest release comes from GitHub's releases API (control's network, cached 6 h, `UPDATE_CHECK=0` switches it off); the release URL is built by control |
| GET | `/api/stream` | session | Relayed gateway SSE stream |
| * | `/api/gw/{path}` | session + CSRF | Relay to an **allowlisted** subset of the gateway API: `GET`/`PUT`/`PATCH /policy`, `POST /emergency-stop`, `POST /rules`, `DELETE /rules/{id}`, `GET /pending`, `POST /pending/{id}/decide`, `GET /events`, `GET /events/summary`, `POST /test`, `GET`/`POST`/`DELETE /presets…`, `GET /secrets`, `PUT /secrets/{name}`, `GET`/`PUT`/`DELETE /grants/{name}`, `POST /grants/{name}/activate`, `DELETE /active-grants/{id}`, `POST /grant-requests/{id}/decide`, `GET /info`. Everything else is refused (404). For decisions and the emergency stop, `by` is set to `web:<user>`. |
| * | `/api/gw/{path}` | session + CSRF | Relay to an **allowlisted** subset of the gateway API: `GET`/`PUT`/`PATCH /policy`, `GET /policy/history…`, `POST /policy/history/{id}/restore`, `GET /policy/diff`, `GET /policy/export`, `POST /policy/import`, `POST /emergency-stop`, `POST /rules`, `DELETE /rules/{id}`, `GET /rules/stats`, `POST /rules/cleanup`, `GET`/`POST`/`DELETE /learning`, `GET /learning/{id}`, `POST /learning/apply`, `GET /suggestions`, `POST /suggestions/accept`, `POST /suggestions/dismiss`, `GET /pending`, `POST /pending/{id}/decide`, `GET /events`, `GET /destinations`, `GET /destinations/detail`, `POST /test`, `GET`/`POST`/`DELETE /presets…`, `GET /secrets`, `PUT /secrets/{name}`, `GET`/`PUT`/`DELETE /grants/{name}`, `POST /grants/{name}/activate`, `DELETE /active-grants/{id}`, `POST /grant-requests/{id}/decide`, `GET /info`. Everything else is refused (404). For decisions and the emergency stop, `by` is set to `web:<user>`; every relayed call carries `X-Tallygate-By: web:<user>` for the policy history. |
| POST | `/api/github/check` | session + CSRF | `{"token": "...", "store": true}` — validate a token against GitHub from the control plane and store it in the gateway |
| GET | `/api/agent/status` | session | Agent status (Claude login, git identity, Remote Control running, versions) |
| GET | `/api/agent/selftest` | session | Run the in-agent isolation self-test |
| GET/POST | `/api/agent/setup/claude-login` | session (+ CSRF for POST) | State of the Claude login / start it (see the agent status server below). A `url` that is not `https://` on Anthropic's login hosts with path `…/oauth/authorize` is replaced by `""`. |
| POST | `/api/agent/setup/claude-code` | session + CSRF | `{"code": "…"}`: the code from the login page |
| GET/POST | `/api/agent/setup/git-identity` | session (+ CSRF for POST) | Preview from GitHub / set `{"name", "email"}` |
| POST | `/api/agent/setup/remote-control` | session + CSRF | Give Remote Control's one-time consent and restart it |
| GET | `/api/setup/checks?origin=<page origin>` | session | Deployment checks of the setup wizard: `{"checks": [{"id", "state": "ok"\|"warn"\|"bad"\|"info", "title", "detail"}], "password": "generated"\|"changed"\|"env-hash"\|"env-plain"\|"proxy"}`. `origin` is only compared, never trusted. |
| GET | `/api/files?path=<dir>` | session | Workspace folder listing: `{"path", "entries": [{"name", "type": "file"\|"dir"\|"link"\|"other", "size", "mtime"}], "truncated", "max_upload", "max_download"}`. Odd entries from the agent are dropped |
| GET | `/api/files/download?path=<file>` | session | The file as `application/octet-stream` with `Content-Disposition: attachment` and `Content-Security-Policy: sandbox`; 413 over `FILES_MAX_DOWNLOAD` |
| PUT | `/api/files?path=<file>&overwrite=1` | session + CSRF | Upload the request body (`Content-Length` required, at most `FILES_MAX_UPLOAD`, else 411 / 413); 409 if the file exists without `overwrite=1` or is a folder or link |
| GET | `/term/{name}/` | session | Console page (served by control: vendored xterm.js, no agent content) |
| GET (WS) | `/term/{name}/ws` | session + Origin | Filtered relay to the agent's ttyd `name`: browser → `0` input / `1` resize, agent → `0` output only; control adds the ttyd credential |

Paths under `/api/files` are relative to `/workspace`; absolute paths, `.` / `..` components, backslashes
and control characters get 400 before the agent is asked. The agent answers 403 for anything that resolves
outside the workspace (symlinks) and 404 for what does not exist; both are passed on.

Agent requests are relayed only for the listed methods and paths; bodies over 4 KiB get 413, and every answer
from the agent is size-limited (1 MiB) and must be a JSON object. The agent's own refusals (400, 409) are passed
on with its `{"error": …}`; anything else from the agent becomes 502.

**CSRF rule:** non-GET requests under `/api/` must carry `X-Tallygate: 1` and, if an `Origin` header is
present, it must match the host. Session cookies are `HttpOnly`, `SameSite=Lax` and `Secure` over HTTPS
(`COOKIE_SECURE=auto`, the default; `1`/`0` force it). `Lax` lets the `PUBLIC_URL` link in a notification open the UI logged in; cross-site
POSTs still carry no cookie, and the header and Origin checks do not depend on it. API errors are JSON
`{"error": …}`: 400 for an invalid request body, 502 when the gateway, the agent or GitHub fails.

## Agent status server

`agent/status.py` inside the agent, port 7680 on `agent-net` (reachable by control and by the agent itself).
It runs as the agent user and only does what that user can do anyway; control relays it under
`/api/agent/…`. Bodies are JSON objects of at most 4 KiB.

| Method | Path | Description |
|---|---|---|
| GET | `/status` | `claude_version`, `claude_logged_in`, `git_name`, `git_email`, `git_identity` (`ok` \| `empty`: set but empty \| `missing`), `remote_control_enabled` (`RC_ENABLE`), `remote_control_running`, `remote_control_consent` (`remoteDialogSeen` in `~/.claude.json`), `remote_control_prompt` (the question the *rc* console waits for, if any), `remote_control_name` (`RC_NAME`), `gateway_ca_trusted`, `workspace_disk` and `home_disk` (`{"total", "used", "free"}` of their file systems, or `null`), `time` |
| GET | `/selftest` | `{"results": [{"name", "pass", "detail"}]}` |
| GET | `/setup/claude-login` | `{"state": "idle"\|"starting"\|"waiting_code"\|"done"\|"failed", "url", "message", "logged_in"}`, read from the tmux session `tg-login` |
| POST | `/setup/claude-login` | (Re)starts `claude auth login` in `tg-login` and waits up to 20 s for the login URL; returns the state |
| POST | `/setup/claude-code` | `{"code"}` (8–2048 characters of `A-Za-z0-9._~#+/=-`), typed into `tg-login`; waits up to 30 s for the result. 400 for a malformed code, 409 if no login waits for one |
| GET | `/setup/git-identity` | `gh api -i user`: `{"ok": true, "login", "name", "email": "<id>+<login>@users.noreply.github.com", "token_expires", "current"}` or `{"ok": false, "reason": "token"\|"network"\|"github", "message", "current"}` |
| POST | `/setup/git-identity` | `{"name", "email"}` → `git config --global user.name/user.email`. 400 for an empty name (or over 100 characters) or an invalid address: nothing is written |
| GET | `/files?path=` | Folder listing (at most 2000 entries, folders first); `link` entries are not followed |
| GET | `/files/download?path=` | The regular file (opened with `O_NOFOLLOW`), `application/octet-stream` with its `Content-Length` |
| PUT | `/files?path=&overwrite=0\|1` | Store the body (`Content-Length` required) through a temporary file in the same folder, then rename; the folder must exist |
| POST | `/setup/remote-control` | Sets `remoteDialogSeen` and `projects["/workspace"].hasTrustDialogAccepted` in `~/.claude.json` (atomically, mode 0600) and restarts the Remote Control loop (`tmux respawn-pane -k -t rc`). 409 with `RC_ENABLE=0` or before the Claude login |
