# API reference

## Gateway management API

Base URL: `http://172.31.11.2:8081` (control-net only). All endpoints except `/health` require
`Authorization: Bearer $GW_API_TOKEN`. Request and response bodies are JSON. Validation errors return
`400 {"error": "..."}`; so does an unknown grant, active grant or grant request id. A missing or wrong token
is `401 {"error": "unauthorized"}`. Bodies are limited to 1 MiB. The API is not started at all when
`GW_API_TOKEN` is shorter than 24 characters. An optional `X-Tallygate-By` header (cut to 64 characters) names
who made a change in the policy history; without it the change is attributed to `api`. The control plane sets
it to `web:<user>`.

Every write to the policy (`PUT`/`PATCH /policy`, rules, presets, approvals, the emergency stop, restores,
imports, removal of expired rules) stores a version in the policy history, unless the policy did not change.

| Method | Path | Body | Response |
|---|---|---|---|
| GET | `/health` | – | `{"ok": true}` (no auth) |
| GET | `/policy` | – | The policy as it is stored: `default`, `ask_timeout`, `rules` in evaluation order (the built-in and config blocks are ordinary `deny` rules among them, `source: builtin` / `config`) and `seeded` = the CIDRs of the blocks that were seeded once and are not added again (ADR-0019). The locked ranges are not part of a policy: see `GET /model` |
| PUT | `/policy` | Full policy | Validated and replaced; returns the new policy. Replaces **every** rule **and their order**: send only a policy you have just read. Blocks that are neither in `seeded` nor in `rules` are seeded again at the bottom. A document without `seeded`, or with `hard_deny` / `floor_open`, is a pre-0019 one and is migrated: CIDR `deny` rules move to the top, `hard_deny` entries become `deny` rules, every block not listed in `floor_open` is added at the bottom, except a block that an address `allow`/`ask` rule of the document overlaps: it is placed at the top, above that rule, so that nothing that was blocked opens. The admin event of the replacement records the migration notes, `built-in block(s) not in force: …` when the new policy lacks blocks, and `open inside blocked ranges: <cidr> (<action> rule <id>), …` for the address `allow`/`ask` rules that stand above a block and reach into it. A rule's `expires` must be a finite number (`NaN` and `Infinity` are a `400`) and its `host` a string. Nothing in a policy opens the locked ranges |
| PATCH | `/policy` | `{"default": "ask"\|"deny"\|"allow", "ask_timeout": 5..3600}` (either or both) | Changes only the mode and/or the approval timeout; the rules stay as they are. Any other key, a non-integer timeout or an empty body is a `400` |
| GET | `/settings` | – | The behaviour settings the UI owns ([ADR-0015](adr/0015-configuration-tiers-and-a-backend-owned-config.md)): current value, default, range and whether a change needs a restart, per key. |
| PATCH | `/settings` | `{key: value, …}` | Changes one or more of them and applies the live-reloadable ones at once; `restart_needed` lists the keys that only take effect after a restart. `400` for an unknown key or a value out of range (nothing is changed). |
| GET | `/learning` | – | `{"active": {id, started, until, ports, by} \| null, "ports_allowed", "max_minutes", "sessions": [last 10 with ended, end_reason]}` |
| POST | `/learning` | `{"minutes": 30, "ports": [443]}` | Starts learning mode (`201`, the state as above); replaces a running session. `minutes` 1..`learning_max_minutes`, `ports` a subset of `learning_ports` |
| DELETE | `/learning` | – | Ends learning mode; the state |
| GET | `/learning/{id}` | – | `{"session", "groups": [{domain, port, hosts: [{host, count, learned, denied}], count, learned, denied, proposal: {host, port} \| null}]}`: the destinations used during that session; `proposal` only for what learning mode allowed and no permanent rule allows now; `404` for an unknown session |
| POST | `/learning/apply` | `{"rules": [{host, port}]}` | Adds allow rules at the **bottom** (tagged `source: learning`): `201 {"added": [rules]}`. Only exact host names or `*.<registrable domain>`, no `*`, no public suffixes, no IPs |
| GET | `/rules/stats` | – | `{"rules": [{...rule, pos, hits, last, since, stale}], "stale_days"}`: every rule in order with its hit count, last match (`null` = never) and since when it is counted; `stale` = permanent and unused for `rule_stale_days` (never a seeded block, `source` `builtin` / `config`, nor any other address `deny`); `shadowed` as in `GET /model` where it applies |
| POST | `/rules/cleanup` | `{"ids": [...]}` | Removes those of the rules that are unused right now, keeps the others: `{"removed", "kept"}` |
| GET | `/suggestions` | – | `{"suggestions": [{key, rule: {action, host, port}, count, hosts, last}], "min_approvals", "window_days"}`: destinations approved for a limited time at least `suggest_min_approvals` times in `suggest_window_days`, not covered by a permanent rule and not dismissed |
| POST | `/suggestions/accept` | `{"key": "..."}` | Adds the suggested permanent rule (built by the gateway, tagged `source: suggestion`): `201` rule; `404` if there is no such suggestion now |
| POST | `/suggestions/dismiss` | `{"key": "..."}` | Hides the suggestion for `log_keep_days`: `{"dismissed": key}` |
| GET | `/policy/history?limit=100&before=<id>` | – | `{"versions": [{id, ts, by, what, default, rules}], "keep"}`, newest first (`limit` at most 500); `rules` is the number of rules |
| GET | `/policy/history/{id}` | – | `{id, ts, by, what, policy}`: the policy as stored in `policy.yaml` at that time (a version from before ADR-0019 has `hard_deny` / `floor_open`); `404` if unknown or no longer kept |
| GET | `/policy/diff?from=<id>&to=<id>\|current` | – | Changes from one version to another (default `to=current`): `default`/`ask_timeout` as `[old, new]`, `rules` `{added, removed, changed: [{id, before, after}]}`, `reordered` (rules both have stand in another order), `identical`. Only what changed is present. Each side is compared as it would be in force if restored (a pre-0019 version is migrated first). `400` without `from`, `404` for an unknown version |
| POST | `/policy/history/{id}/restore` | – | Replaces the policy with that version (validated like `PUT /policy`, a pre-0019 version is migrated, and the admin event records the same notes); returns the new policy; `404` for an unknown version |
| GET | `/policy/export` | – | `{"filename", "yaml"}`: the policy (as `GET /policy`) and the UI grants as one YAML document (`tallygate_export: 1`). No secrets, no config-file grants |
| POST | `/policy/import` | `{"yaml": "...", "apply": false}` | Validates the document (policy like `PUT /policy`, each grant like `PUT /destinations/grant/{name}`, against the imported policy) and returns `{diff, grants: {added, changed}, warnings, applied}`; the diff shows the policy as it will be in force. With `"apply": true` it replaces the policy and adds or replaces those UI grants, all or nothing. `warnings` is a list of strings to show before applying: what a migration changed when the export is from before ADR-0019 (the same `NOTE` lines as at an upgrade, e.g. blocks that stay above an old address rule), `built-in block(s) not in force in this policy: …` when the imported policy lacks blocks, `open inside blocked ranges: <cidr> (<action> rule <id>), …` for address rules above a block that reach into it, and `lan` on a grant target being ignored. When it is applied, the admin event records the same notes |
| POST | `/emergency-stop` | optional `{"by": "who"}` | Best-effort stop, see below: `{"ok": bool, "steps": [{"step", "ok", "errors"?, ...}]}` |
| GET | `/model` | – | The whole configuration as one destination model (ADR-0014, ADR-0019): `{default, destinations, locked}`. `destinations` starts with the rules **in evaluation order** (each with a stable `id`), then on-request destinations (`grant:<name>`) and the file properties. A rule may carry `shadowed` `{count, last, address, by, range}` (a name rule that the address `deny` rule `by` blocked) and `covered_by` (an address rule that can never decide: the id of the earlier permanent address rule that covers it completely; an `allow` or `deny` covered only by an `ask` is not reported). `locked` is `[{range, source: stack\|listener, reason}]`: the stack's own networks and the gateway's own listeners, denied before the list, with no actions. `default` is the last line. The single source for the Destinations view. |
| POST | `/destinations` | a destination `{match, access, …}` (+ optional `"id"`, `"top": false`) | The one CRUD surface. `access` `allow`/`ask`/`deny` adds a policy rule at the top (`"top": false`: below the other rules, above the seeded blocks); an IP given as `match.host` becomes an address rule. A rule's `source` is one of `user`, `approval`, `learning`, `suggestion`, `preset:<name>`, `builtin`, `config`; any other value is a `400`. `access: request` adds a single-target on-request destination (grant), checked like `PUT /destinations/grant/{name}`. `expires` is a unix time: a finite number or `null` (`400` otherwise, also in `PATCH`). `201` with the created destination; `400` if the id is taken. |
| PATCH | `/destinations/{id}` | subset of `{access, match: {port}, note, group, expires}` for a rule | Edits a rule in place (`expires: null` clears it). `{id}` is a rule id. `404` if unknown. What a rule matches is not editable here. A seeded block (`source` `builtin` / `config`) takes no `expires` (`400`: add an allow rule with a time limit above it instead); one whose `access` is changed from `deny` becomes an ordinary rule (`source: user`). The same holds for rules in `PUT /policy`. |
| DELETE | `/destinations/{id}` | – | Deletes a rule (`{id}` = rule id) or a UI grant (`{id}` = `grant:<name>`): `{"ok": true}` or `404`. |
| POST | `/destinations/group` | `{ids: [...], group}` | Puts rules in a named set (empty `group` clears); grant ids are skipped. |
| POST | `/destinations/{id}/move` | `{"before": "<rule id>" \| null}` | Moves a rule in the evaluation order: in front of the rule `before`, or to the end of the list with `null`. Returns `{"order": [rule ids]}`. `404` for an unknown rule; `400` if `before` is not a rule, is the rule itself, or the id is a grant. Any rule can be moved, the seeded blocks too. |
| POST | `/destinations/restore-blocks` | – | Adds back, at the bottom, every built-in or config block that is no longer in the list as a permanent `deny` for exactly that range on every port: `{"added": [rules], "opened": [{rule, action, cidr, block}]}`. `opened` lists the address `allow`/`ask` rules that stand above a built-in or config block and reach into it: restoring does not close those addresses. |
| PUT | `/destinations/grant/{name}` | Grant definition ([grants](grants.md)) | Create/replace an on-request destination (multi-target, levels, approval). Validated; `400` for config grants, for credentials or `tls_verify: false`, for a target that names a locked address, and for a target that is **only a name** and resolves into an address `deny` rule now - the error names the address to set as the fixed `address` (ADR-0019). `lan` is accepted and ignored. |
| DELETE | `/destinations/grant/{name}` | – | Delete a UI on-request destination (also ends an active instance): `{"ok": true}` or `404`. |
| GET | `/presets` | – | `["baseline", "containers", …]`; with `?details=1`: `[{name, title, description, category, default, rules}]` |
| POST | `/presets/{name}` | optional `{"ttl": seconds}` | `{"added": [rule ids], "expires": ts \| null}`: rules inserted on top as `<name>:<id>`, tagged `source: preset:<name>`; applying again replaces them (new TTL). `409` if another rule uses such an id; `400` for `policy` presets (use `PUT /policy`); `404` for an unknown preset |
| DELETE | `/presets/{name}` | – | `{"removed": [rule ids]}`: removes the rules tagged `preset:<name>` (undo) |
| GET | `/pending` | – | Pending approvals: `id, host, domain, idn, port, ips, proto, client, created, expires, attempts, context` (`domain`: the registrable domain, `null` for an IP; `idn`: the name has punycode labels; `context`: up to 3 entries `{ts, kind, tool?, text?, note?}` the agent reported in the 2 minutes before; agent-written, untrusted) |
| POST | `/pending/{id}/decide` | `{"scope": "once"\|"hour"\|"always"\|"domain"\|"deny"\|"deny_always", "by": "who"}` | `{"rule": {...}}` (the rule it added, see [approval scopes](#approval-scopes)); `400` for another scope, for a `domain` approval of a host without a registrable domain, and for an allowing scope when the request is for an IP address that the list refuses without a question, such as one inside a blocked range (`<address> is refused by the list (<reason>): an approval cannot open it …`; the request stays pending and can be denied). An address that the list only asks about, such as one with your own `ask` rule above a block, can be approved; `404` if already decided/timed out |
| POST | `/test` | `{"host": "...", "port": 443}` | Dry run, decided as a connection is: `{"action", "reason", "rule_id", "rule", "pos", "shadow", "ips"}`. `rule` is the deciding rule and `pos` its position in the list (`null` for the default; `rule_id` is `locked` for a locked range). `shadow` is `{rule, address, by, range}` when a name rule allowed the name but the address `deny` rule `by` blocked the address. `ips` is empty when the name was decided without resolving it. No `rule_id` for an invalid host name or a DNS failure |
| GET | `/events/summary?since=<ts>` | – | Connection events since `since` (default: one hour ago, at most 7 days back): `{"since", "counts": {"allow", "deny", "ask"}, "no_connection" (refusals tagged `no connection:` during an outage of the host's network, #218: not in `deny`), "top": [{"host", "port", "count", "allow", "deny", "ask", "last"}] (10), "new": [{"host", "port", "first", "count"}] (20)}`. `new` = first seen within the kept log. Counts are log rows: identical events within a few seconds are coalesced |
| GET | `/events?limit=200&before=<id>&q=<text>` | – | Newest-first event log entries (`limit` at most 2000). Filters, all optional and combined: `host` (exact name or IP, or `*.domain` for the domain and its subdomains), `port`, `kind` and `action` (comma-separated lists), `since`/`until` (unix time, `until` exclusive). Invalid values are a `400` |
| GET | `/destinations?since=&until=&q=&new=1&limit=200` | – | Connection destinations (`conn` and `ask` events) in the range, most recent first: `[{host, port, events, first, last, allowed, denied, asked, first_seen, new}]`. `first_seen` is the first event in the whole log; `new=1` returns only those first seen inside the range; `limit` at most 2000 |
| GET | `/destinations/detail?host=&port=443&limit=100` | – | One destination: `host`, `port`, `stats` (as above, or `null`), `decision` `{action, reason, rule_id, rule}` = what the rule list says about it now on the name (not resolved; for an IP the full decision), and its latest `events` |
| GET | `/stream` | – | Server-sent events (see below) |
| GET | `/secrets` | – | `{"names": [...]}` — values are never returned |
| PUT | `/secrets/{name}` | `{"value": "..."}` (empty removes) | `{"names": [...]}`. The name matches `[a-z0-9_]{1,64}`; the value has at most 8192 characters and no control characters |
| GET | `/availability` | – | `mode` (`available` \| `away` \| `quiet`), `until`, `message` (what the agent is told), `away` (`{since, by, until}`), `quiet_hours`, `quiet_source` (`config` \| `ui`), `quiet_zone`, `digest_minutes`, `missed` (`[{kind: conn\|grant\|auto_grant, host, port, first, last, count}]`; `auto_grant` is not a refusal but a grant level with `approval: auto` that was activated meanwhile: `host` is the grant, `port` 0, plus `level`), `missed_dropped` |
| PATCH | `/availability` | `{"away": bool, "away_until": ts, "quiet_hours": {start, end, days?, tz?} \| null, "by": "who"}` (any of them) | Away on/off (optionally until a time, at most 30 days), quiet hours set or off. Going away denies everything waiting for a human. Returns the state; any other key is a `400` |
| DELETE | `/availability/missed` | – | Clears the list of refused requests and automatic grants |
| GET | `/access` | – | Each destination once, for one table in the UI: `{default, last_used_days, rows}`. A row has `host`, `port`, `access` (`allow`, `ask`, `deny`, `request` = only through a grant, or `null` for a pattern that no rule names), `rule` (`{id, position, note, expires, source}` or `null`), `read_only` (`{post_is_write, read_posts}` or `null`), `credentials`, `repos`, `grants` (`[{name, levels, local, scheme, paths, credentials, active}]`) and `last_used`. Read-only: it reports the configuration and decides nothing. |
| GET | `/never-reachable` | – | What no rule, grant or API call can open: the locked ranges, `[{range, source, reason}]` with `source` `stack` (`GW_INTERNAL_NETS`) or `listener` (the gateway's own `address:port`). The same list as `locked` in `GET /model`. Every other blocked range is a rule (`GET /policy`). |
| GET | `/info` | – | `inject_hosts`, `inject_secrets_needed`, `services`, `github_repos`, `ca_pem`, `pending`, `version` (the release, from `VERSION`), `data_disk` (`{"total", "used", "free"}` of the file system holding the gateway state, or `null`), `events_db_bytes` (event log incl. WAL), `connectivity` (#218: `{"down": bool, "since", "last_failure", "failures", "kinds": ["dns"\|"connect"\|"timeout"]}`; read-only, derived from the gateway's own lookups and connects, never holds a name or an error text; the stream sends `{"type": "connectivity", …same fields}` when it starts and when it ends) |
| GET | `/grants` | – | `defs` (with `source` config/ui; each target with `local`: it names an address that is not public), `active`, pending `requests`, `missing_secrets`, `auto_suspended` (`null` or `{"since", "by"}` after an emergency stop). On-request grant *definitions* are created/edited via `PUT`/`DELETE /destinations/grant/{name}` (above); this read and activation stay here for the flow. |
| POST | `/grants/{name}/activate` | `{"level": "read"\|"write", "ttl": "1h", "by": "who"}` | Active grant (admin activation without a request) |
| DELETE | `/active-grants/{id}?by=who` | – | Revoked active grant |
| POST | `/grant-requests/{id}/decide` | `{"decision": "approve"\|"read"\|"deny", "by": "who", "ttl": optional}` | The decided request; `read` downgrades a write request |

### Approval scopes

`POST /pending/{id}/decide` adds a rule at the top, for the exact host and the port of the request:

- `once`: allow for 2 minutes;
- `hour`: allow for 1 hour;
- `always`: allow, permanent;
- `domain`: allow `*.<registrable domain>` (the domain and its subdomains), permanent;
- `deny`: deny for 2 minutes;
- `deny_always`: deny, permanent.

For a destination given as an IP address, every scope adds a rule for that one address (`domain` too). The
allowing scopes are refused for an address that an address `deny` rule blocks: an approval never opens a
blocked range ([rules.md](rules.md#order-of-the-list)).

### Emergency stop

`POST /emergency-stop` runs these steps in this order. Every step runs even if an earlier one failed; each
reports `ok` and, if it failed, `errors`:

| Step | What it does | Result fields |
|---|---|---|
| `suspend_auto_approval` | Grant levels with `approval: auto` need a human until the mode is changed again | – |
| `revoke_grants` | Revokes every active grant | `revoked` (grant names) |
| `deny_pending` | Denies every connection waiting for approval | `denied` (`host:port`) |
| `deny_grant_requests` | Denies every pending grant request | `denied` (grant names) |
| `remove_internet_presets` | Removes the rules of every `category: internet` preset (`open`, `internet`), and `allow` rules that carry such a preset's own rule id (`web`, `all`) | `removed` (rule ids) |
| `end_learning` | Ends learning mode | `ended` (session ids) |
| `mode_deny` | Sets the mode to `deny` | `previous` (the mode before) |

The suspension is stored in `grants-state.yaml` in the gateway's data volume, so it survives a restart (an
unreadable file keeps it on). It ends when the mode changes (`PATCH /policy`, `PUT /policy`, a restore or an
applied import with a different `default`); a write that keeps `deny` does not end it. The stop is logged as
one `admin` event (`action: emergency-stop`), next to the `grant` events of the grants it revoked and the
requests it denied. The control plane relays it as `POST /api/gw/emergency-stop` and sets `by` to
the session user.

### Event log entry

```json
{"id": 812, "ts": 1794386562.06, "kind": "conn", "proto": "regular", "client": "172.31.10.10",
 "host": "api.github.com", "port": 443, "ips": ["140.82.121.6"], "action": "allow",
 "reason": "rule github-api", "extra": null}
```

`kind`: `conn` (decision), `ask` (approval requested), `dns` (blocked DNS query), `admin` (policy/secret
change), `grant` (grant requested/approved/denied/expired/revoked). `proto`: `regular` (HTTP proxy), `socks5`, `reverse` (service port), `dns`.
Refusals inside an allowed connection use `tls` (a refused TLS passthrough, e.g. the SNI does not match the checked name), `http` (a refused
request) and `grant` (non-HTTP traffic or a WebSocket cut on a grant target).

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
data: {"type": "learning"}                     (learning mode started or ended)
data: {"type": "digest", "why": "away ended", "items": [{kind, host, port, count, ...}], "more": 0}
```

The stream starts with a `: connected` comment. A keep-alive comment (`: ping`) is sent whenever 20 s pass
without an event.

## Agent grant API

Base URL: `http://172.31.10.2:8079` (agent network, **no authentication**, rate-limited to
`grant_api_rate` requests/min (default 30), 4 KiB bodies). This is the only gateway API the agent can reach. It can
list, ask and poll, and say what it is doing (shown as its claim), nothing else. The `tallygate` CLI in the agent image wraps it.

| Method | Path | Body | Response |
|---|---|---|---|
| GET | `/v1/grants` | – | `{"grants": [{name, description, levels, default_ttl, max_ttl, targets, active?: {level, expires}}], "operator": {"state": "available"\|"away"\|"quiet", "until", "message"}, "network": {"down": bool, "since"}}`: no credentials. `network` says whether the gateway itself has no connection (#218), so that the agent can tell an outage from a policy: times and a flag only |
| POST | `/v1/grants/{name}/request` | `{"level": "read"\|"write", "ttl": "30m", "reason": "..."}` | `202 {"id", "grant", "level", "status": "pending", "ttl"}` (`ttl` in seconds, after capping) or `200` if auto-approved; a repeated request for the same grant and level returns the one that is already pending; `429` when too many are pending; `503 {"error", "status": "denied"}` while the operator is away or in quiet hours (auto-approved levels still work) |
| POST | `/v1/activity` | `{"kind": "tool"\|"note", "tool": "Bash", "text": "npm install", "note": "Install deps"}` | `202 {"ok": true}`. What the agent is about to do, attached to its next approvals for 2 minutes; `text` or `note` is required. Cleaned, secrets redacted, 200 characters per field (`tool`: 40); own rate limit `activity_rate` (60/min) |
| GET | `/v1/requests/{id}?wait=0..55` | – | `{"id", "grant", "level", "status": pending\|approved\|denied\|expired, "ttl", "granted_level"?}`; `wait` long-polls |

Errors are `{"error": …}`: `400` for an invalid body, level or duration, `404` for an unknown grant or
request, `429` when the rate limit is reached.

## Control plane HTTP interface

Used by the bundled web UI; documented for scripting and review.

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/healthz` | – | Liveness |
| GET/POST | `/login` | – | Login form / submit (`password`). Checks run one at a time, with a 1 s delay after a failure; 429 while 5 checks are already queued. With `TRUST_FORWARDED_FOR=1` and `TRUSTED_PROXIES` set, 10 failures per 15 min per client address also lock out (429); without them every client shares one address and this lockout is off. Bodies over 4 KiB or without `Content-Length` get 413; a foreign `Origin` gets 403 |
| POST | `/logout` | session | Clears the session |
| GET | `/` | session | Single-page UI |
| GET | `/api/meta` | session | Current user, terminal names, notification status (`telegram`, `matrix`, `webpush`, `ntfy`, `gotify`, `pushover`) |
| GET | `/api/stream` | session | Relayed gateway SSE stream |
| * | `/api/gw/{path}` | session + CSRF | Relay to an **allowlisted** subset of the gateway API: `GET`/`PUT`/`PATCH /policy`, `GET /policy/history`, `GET /policy/history/{id}`, `POST /policy/history/{id}/restore`, `GET /policy/diff`, `GET /policy/export`, `POST /policy/import`, `POST /emergency-stop`, `GET /model`, `POST /destinations`, `POST /destinations/group`, `POST /destinations/{id}/move`, `POST /destinations/restore-blocks`, `PATCH`/`DELETE /destinations/{id}`, `PUT`/`DELETE /destinations/grant/{name}`, `GET /rules/stats`, `POST /rules/cleanup`, `GET`/`POST`/`DELETE /learning`, `GET /learning/{id}`, `POST /learning/apply`, `GET /suggestions`, `POST /suggestions/accept`, `POST /suggestions/dismiss`, `GET /pending`, `POST /pending/{id}/decide`, `GET /events`, `GET /events/summary`, `GET /destinations`, `GET /destinations/detail`, `POST /test`, `GET /presets`, `POST`/`DELETE /presets/{name}`, `GET /secrets`, `PUT /secrets/{name}`, `GET /grants`, `POST /grants/{name}/activate`, `DELETE /active-grants/{id}`, `POST /grant-requests/{id}/decide`, `GET /info`, `GET /never-reachable`, `GET /access`, `GET`/`PATCH /availability`, `DELETE /availability/missed`. The old per-mechanism CRUD routes (`POST`/`PATCH`/`DELETE /rules`, `PUT`/`DELETE /grants`) were removed (ADR-0014): the UI uses `/destinations`. Everything else is refused (404 `{"error": "not allowed"}`), and so is an id that does not start with a letter or digit or that contains `..` (`/api/gw/destinations/..` is not the gateway's `/`). The path is sent to the gateway exactly as it was matched, nothing is normalised on the way; the query string is passed on re-encoded. For decisions, grant activation and revocation, the emergency stop and availability changes, `by` is set to `web:<user>`; a body sent to `/emergency-stop` is discarded. Every relayed call carries `X-Tallygate-By: web:<user>` for the policy history. |
| POST | `/api/github/check` | session + CSRF | `{"token": "...", "store": true}` — validate a token against GitHub from the control plane and store it in the gateway (secret `github_token`): `{"ok": true, "login", "scopes", "expires", "stored"?}`, or `{"ok": false, "status", "message"}` when GitHub rejects it; `400` without a token |
| GET | `/api/agent/status` | session | Agent status (Claude login, git identity, Remote Control running, versions) |
| GET | `/api/agent/selftest` | session | Run the in-agent isolation self-test |
| GET | `/api/push` | session | Web Push: `{"enabled", "public_key" (VAPID, for `applicationServerKey`), "subscriptions": [{id, label, created, service}]}` |
| POST | `/api/push/subscribe` | session + CSRF | `{"subscription": <PushSubscription JSON>, "label": "phone"}` → `201`; `400` for an unknown push service or invalid keys; `503` when Web Push is off |
| DELETE | `/api/push/{id}` | session + CSRF | Stop notifications to that device; `404` for an unknown device |
| POST | `/api/push/test` | session + CSRF | Send a test notification: `{"delivered": n}`; `400` if no device is subscribed, `502` if no device could be reached, `503` when Web Push is off |
| GET | `/api/notify/config` | session | Notification channel settings without secrets: `{"writable", "channels": [{channel, label, active, reason, source (`ui`/`environment`/`mixed`/`unset`), override, interactive, fields: [{name, label, env, hint, secret, required, set, source (`ui`/`environment`/`unset`), value?}]}]}`. `value` only for non-secret fields; a token is never returned. `writable` is `false` when the control data volume is read-only. Also `"actions": {"value": [action, ...], "custom": bool, "default": ["once", "deny"], "max": 4, "choices": [{action, label, effect, kind (`allow`/`deny`), confirm}]}`: the [notification buttons](user-guide.md#notification-buttons) in use, whether they were saved in the UI, and what can be chosen |
| POST | `/api/notify/test` | session + CSRF | `{"channel": "telegram"\|"matrix"\|"ntfy"\|"gotify"\|"pushover"}`: send one test message → `{"ok", "channel"}`. `400` unknown or unconfigured channel. `502 {"error"}` with a fixed text: `<Channel> answered with an error (HTTP 4xx\|5xx): see the control log`, `… could not be reached: see the control log`, `… did not answer in time`, `answered with a redirect, which control never follows`, `destination refused: the URL must not point at …` (a name that resolves to this machine, a link-local address or the stack). What the service answered is never returned (only Telegram's own description is, its host is not a setting); it is in control's log |
| PUT | `/api/notify/config/{channel}` | session + CSRF | Save UI settings for `telegram`, `matrix`, `ntfy`, `gotify` or `pushover` and apply them without a restart. Body: `{field: "value", ...}`; a secret sent empty (or left out) keeps the stored one, a non-secret field sent empty falls back to the environment. → `{"ok", "changed": [field names], ...the config as above}`. `400` unknown channel or field, invalid value (for a URL also: a `?query` or `#fragment`, or a host that is this machine, a link-local address or the stack itself), a changed URL without its token, Telegram/Matrix without allowed users; `503` data volume not writable |
| DELETE | `/api/notify/config/{channel}` | session + CSRF | Drop the UI settings of a channel (back to the environment) → `{"ok", "removed": bool, ...the config}`; `400` unknown channel, `503` not writable |
| PUT | `/api/notify/actions` | session + CSRF | Choose the buttons of a connection-approval notification. Body: `{"actions": ["once", "deny"]}`: 1 to 4 of `once`, `hour`, `always`, `domain`, `deny`, `deny_always`, each once, in the order they are shown. Applies to the next request; buttons already sent that are no longer chosen stop working. → `{"ok", ...the config as above}`. `400` unknown action, empty or too long list, duplicate; `503` data volume not writable |
| DELETE | `/api/notify/actions` | session + CSRF | Back to the default buttons → `{"ok", "removed": bool, ...the config}`; `503` not writable |
| POST | `/api/push/act` | action token + CSRF | `{"token": ...}` from a notification button; nothing else in the body is read. No session needed: the token is signed, bound to one request, one decision and one device, single use, valid ≤ 10 min. `403` invalid/used/expired, or a connection decision whose button is not switched on (any more); `409` already decided, `502` gateway unreachable, `503` Web Push off, `200 {"ok", "decision", "message"}` (`message`: what the notification then shows, e.g. `Allowed api.example.com for 2 min`) |
| GET | `/sw.js`, `/manifest.webmanifest`, `/static/icon*` | – | Service worker, PWA manifest and icons (static, no session: browsers fetch them without cookies) |
| GET | `/static/logo.svg`, `/static/favicon.svg`, `/static/login*` | – | What the login page needs. Everything else under `/static/` needs a session |
| GET | `/api/version` | session | `{"tallygate", "claude_code", "check": "ok"\|"error"\|"off", "latest": {"version", "url", "published"} \| null, "update_available": bool \| null, "error"?, "changelog", "upgrade"}`. `tallygate` is the gateway's VERSION; the latest release comes from GitHub's releases API (control's network, cached 6 h, a failed check 30 min, `UPDATE_CHECK=0` switches it off); the release URL is built by control |
| GET/POST | `/api/agent/setup/claude-login` | session (+ CSRF for POST) | State of the Claude login / start it (see the agent status server below). A `url` that is not `https://` on Anthropic's login hosts with path `…/oauth/authorize` is replaced by `""`. |
| POST | `/api/agent/setup/claude-code` | session + CSRF | `{"code": "…"}`: the code from the login page; a `url` in the answer is filtered in the same way |
| GET/POST | `/api/agent/setup/git-identity` | session (+ CSRF for POST) | Preview from GitHub / set `{"name", "email"}` |
| POST | `/api/agent/setup/remote-control` | session + CSRF | Give Remote Control's one-time consent and restart it |
| GET | `/api/setup/checks?origin=<page origin>` | session | Deployment checks of the setup wizard: `{"checks": [{"id", "state": "ok"\|"warn"\|"bad"\|"info", "title", "detail"}], "password": "generated"\|"changed"\|"env-hash"\|"env-plain"\|"proxy"}`. `origin` is only compared, never trusted. |
| GET | `/api/files?path=<dir>` | session | Workspace folder listing: `{"path", "entries": [{"name", "type": "file"\|"dir"\|"link"\|"other", "size", "mtime"}], "truncated", "max_upload", "max_download"}`. Odd entries from the agent are dropped |
| GET | `/api/files/download?path=<file>` | session | The file as `application/octet-stream` with `Content-Disposition: attachment` and `Content-Security-Policy: sandbox`; 413 over `FILES_MAX_DOWNLOAD` |
| PUT | `/api/files?path=<file>&overwrite=1` | session + CSRF | Upload the request body (`Content-Length` required, at most `FILES_MAX_UPLOAD`, else 411 / 413); 409 if the file exists without `overwrite=1` or is a folder or link; answers `{"path", "size"}` |
| DELETE | `/api/files?path=<file or folder>` | session + CSRF | Delete one file, link or folder (with everything in it); a link is removed, never its target. 400 for the workspace itself (empty path); answers `{"path", "type": "file"\|"dir"}`. Logged with the user |
| GET | `/term/{name}/` | session | Console page (served by control: vendored xterm.js, no agent content) |
| GET (WS) | `/term/{name}/ws` | session + Origin | Filtered relay to the agent's ttyd `name`: browser → `0` input / `1` resize, agent → `0` output only; control adds the ttyd credential |

Paths under `/api/files` are relative to `/workspace`; absolute paths, `.` / `..` components, backslashes
and control characters get 400 before the agent is asked. The agent answers 403 for anything that resolves
outside the workspace (symlinks) and 404 for what does not exist; both are passed on.

Agent requests are relayed only for the listed methods and paths (anything else under `/api/agent/` is 404); bodies over 4 KiB get 413, and every answer
from the agent is size-limited (1 MiB) and must be a JSON object. The agent's own refusals (400, 409) are passed
on with its `{"error": …}`; anything else from the agent becomes 502.

**CSRF rule:** requests under `/api/` other than `GET`/`HEAD`/`OPTIONS` must carry `X-Tallygate: 1` and, if an
`Origin` header is present, it must equal the UI's origin (scheme and host: `PUBLIC_URL` if set, otherwise
those of the request, with forwarded headers counted only from a trusted proxy); otherwise
`403 {"error": "csrf check failed"}`. `POST /login` and `POST /logout` get the Origin check without the
header; the console WebSocket needs an `Origin` header that matches. Session cookies are `HttpOnly`, `SameSite=Lax` and `Secure` over HTTPS
(`COOKIE_SECURE=auto`, the default; `1`/`0` force it). `Lax` lets the `PUBLIC_URL` link in a notification open the UI logged in; cross-site
POSTs still carry no cookie, and the header and Origin checks do not depend on it. API errors are JSON
`{"error": …}`: 400 for an invalid request body, 401 without a session (`/api/` and `/term/`; other pages
redirect to `/login`), 500 for an internal error, 502 when the gateway, the agent or GitHub fails. A redirect (any 3xx) from one of
them is such a failure: control never follows it, and for the agent and the gateway the error text is fixed
(`the agent answered with a redirect, which is never followed`).

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
