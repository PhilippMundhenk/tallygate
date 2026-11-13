# Grants: controlled access to your home network and other sensitive services

Approving single connections works for the open internet. It is the wrong unit for "let the agent check
Home Assistant" or "let it SSH into the NAS for ten minutes". A **grant** is a named, scoped,
time-limited bundle of access that you define once. The agent requests it with a reason, and you approve
it with one tap. When the time runs out, everything falls back to the normal policy and hard deny.
[How access works](access.md) shows where grants sit next to rules and the never-reachable list.

```text
agent:  tallygate request homeassistant --write --ttl 30m --reason "turn off the living room lights"
you:    🔑 homeassistant (write) for 30m   [Approve write]  [Approve read-only]  [Deny]
agent:  granted: homeassistant (read) for 30 min
        note: you asked for write but were granted read only
```

![Grant request on the approvals page](images/approvals.png)

## What a grant contains

| Part | Meaning |
|---|---|
| **targets** | `host:port` plus `scheme`. `https`/`http` targets are inspected per request (method, path, Host). `tcp` passes raw traffic through (SSH, databases, MQTT …). Hosts can be exact, `*.lan` wildcards or IPs. A wildcard covers subdomains only: unlike in rules, `*.example.lan` does not include `example.lan`. |
| **paths** | HTTP path patterns (`/api/*`): globs in which `*` also matches `/`, compared case-sensitively with the path without its query. Paths are matched after rejecting traversal tricks: `.` and `..` segments, `//`, backslashes, spaces and control characters, an encoded `.`, `/`, `\` or NUL (`%2e`, `%2f`, `%5c`, `%00`), any of these hidden by repeated encoding, more than three layers of encoding, and a `%` that is left after decoding. |
| **levels** | `read` = `GET`/`HEAD`/`OPTIONS` only, no WebSocket upgrades. `write` = every method. A grant can offer one or both. `tcp` targets are only usable at `write`. |
| **approval** | Per level: `ask` (a human decides) or `auto` (granted at once, still logged and shown). A common choice is `read: auto, write: ask`. |
| **lan** | Exempts **exactly this target** from the hard deny, so it may resolve to a private address. Loopback, link-local/metadata and multicast stay unreachable (`grants_never`), and so does the tallygate stack itself (`GW_INTERNAL_NETS`). |
| **address** | Fixed IP for the target (no DNS lookup), handy when the gateway cannot resolve your local names. |
| **tls_fingerprint** | SHA-256 of the service's certificate: lets the gateway trust a self-signed cert (Proxmox, a NAS, a router) **without** turning verification off. `tls_verify: false` exists (config-file grants only), but avoid it. |
| **inject** | Header templates such as `Authorization: Bearer ${ha_token}`. The secret lives in the gateway, and the agent never sees it. On a host with an inject rule, the agent's own `Authorization`/`Cookie` (`inject_strip_headers`) are stripped. Only for exact-host `https` targets; while a referenced secret is missing, the request goes out without the header. **Config-file grants only.** |
| **default_ttl / max_ttl** | How long an approval lasts (1 min … 7 days). The agent may ask for less or more; the duration is capped at `max_ttl`. |

Defaults and limits:

- The name matches `[a-z0-9][a-z0-9_-]{0,47}`; the description is cut at 300 characters. Unknown fields are
  rejected. A grant needs at least one target.
- `scheme` defaults to `https`, `paths` to `["/*"]`. A path pattern starts with `/` and has at most 200
  characters.
- `levels` defaults to `[read]`. `approval` defaults to `ask`; one word (`approval: auto`) applies to every
  level.
- `default_ttl` defaults to `1h`, `max_ttl` to `4h`. Durations are written `90s`, `30m`, `4h`, `2d` or as
  seconds. A requested duration below one minute is raised to one minute.
- `tcp` targets take no `paths` and no TLS options, `http` targets no TLS options. A grant with only `tcp`
  targets cannot be `[read]`.
- `address` must be an IP and needs an exact host (no wildcard).
- An `inject` entry is `{host, header, value}`; `header` defaults to `Authorization`, and `host` must be an
  exact `https` target of the grant.
- A grant in the config file wins over a UI grant with the same name.

## Defining grants

### In the config file (`config/gateway.yaml`)

```yaml
grants_lan_allow: [192.168.1.0/24]     # LAN ranges that UI-defined grants may reach (config grants: any)

grants:
  homeassistant:
    description: Home Assistant REST API
    targets:
      - {host: ha.lan, port: 8123, scheme: http, paths: ["/api/*"], lan: true}
    levels: [read, write]
    approval: {read: auto, write: ask}
    default_ttl: 1h
    max_ttl: 4h
    # for https:  inject: [{host: ha.lan, header: Authorization, value: "Bearer ${ha_token}"}]

  proxmox:
    description: Proxmox VE API, read-only
    targets:
      - host: pve.lan
        port: 8006
        paths: ["/api2/json/*"]
        lan: true
        tls_fingerprint: "AB:CD:…"       # openssl s_client -connect pve.lan:8006 </dev/null | openssl x509 -noout -fingerprint -sha256
    levels: [read]
    inject:
      - {host: pve.lan, header: Authorization, value: "PVEAPIToken=${pve_token}"}

  nas-ssh:
    description: SSH to the NAS
    targets: [{host: nas.lan, port: 22, scheme: tcp, lan: true}]
    levels: [write]
    default_ttl: 30m
    max_ttl: 1h
```

Store the referenced secrets (`ha_token`, `pve_token`) in the UI under **Grants → Secrets**. They are
write-only.

### In the UI

**Grants → New grant** asks for five things: a name, the address (`ha.lan:8123`, or a URL such as
`https://api.example.com/v1/`, whose path then limits the grant), the type (HTTPS, HTTP, or TCP for SSH and
databases), read-only or full access, and for how long each approval lasts. *This is a device on my local
network* is ticked for you when the address looks local. Everything else (automatic approval, separate default
and maximum durations, paths, several targets, a fixed IP, a pinned certificate) is under **Advanced** and keeps
its defaults until you change it; a grant that uses those settings opens with *Advanced* unfolded. Grants from the config file are shown read-only;
UI grants are stored in `grants.yaml` in the `gateway-data` volume.

![Grants tab](images/grants.png)

![Grant editor](images/grant-editor.png)

A UI-defined grant can only use `lan: true` for addresses inside `grants_lan_allow`, which only the
config file can set. That way a compromised UI session cannot open arbitrary parts of your network.

`inject` and `tls_verify: false` are only accepted in grants from the config file. Otherwise whoever holds
a UI session or the API token could define a grant that sends a stored secret (e.g. the GitHub token) to a
host of their choosing. The UI and API reject such grants with a validation error; a UI grant saved by an
older version with either setting is ignored at startup (and logged). Define such grants in
`config/gateway.yaml`.

## Using grants

| Who | How |
|---|---|
| Agent | `tallygate grants` lists what exists. `tallygate request <name> [--write] [--ttl 30m] --reason "…"` asks and waits for the decision, up to `--timeout` seconds (default 300); `--no-wait` returns at once, and `tallygate status <id>` shows the state later. Exit codes: 0 granted, 1 denied or expired, 2 usage or connection error. `tallygate note "…"` tells you what the agent is about to do. The agent image tells Claude about this in its managed `CLAUDE.md`, and a refused connection mentions the grant (`available via grant homeassistant`). |
| You | Approve, approve read-only, or deny on the Approvals page, in Telegram (buttons) or in Matrix (👍 approve, 📖 read-only, 👎 deny, or reply `approve 3` / `read 3` / `deny 3`; `allow` and `block` work too). A Web Push notification offers read access and *Deny* only: write access needs the UI or a chat. Revoke at any time: **Grants → Revoke**, Telegram's *Revoke* button, or `revoke 3` in Matrix. You can also activate a grant yourself (**Activate read/write**). |

Only one instance of a grant is active at a time; a new approval replaces the old one (level and end time
change in place, so open connections continue under the new level). Pending requests
time out after `grant_request_timeout` (300 s). At most `grant_max_pending` (3) can be open at once.

## How it is enforced

1. A connection to a target of an **active** grant is checked before the normal rules. Names are resolved
   (or `address` is used) and the resolved IPs are checked: `grants_never` always applies, the hard deny
   applies unless `lan: true`, and for UI grants `grants_lan_allow` applies. The stack's own networks
   (`GW_INTERNAL_NETS`) and the gateway's own listeners are refused for every grant. The connection is then pinned
   to the checked IP.
2. `https`/`http` targets are **always intercepted**, so every request is checked:
   - plain HTTP to an `https` target is refused;
   - the `Host` header must equal the granted host;
   - the path must be canonical and match;
   - on `read`, only safe methods are allowed and upgrades are refused;
   - credentials are injected (`https` targets);
   - on GitHub hosts, `github_repos` still applies: a grant does not widen it;
   - anything that is not HTTP on such a target is cut.
3. Upstream TLS is verified normally, or against the pinned fingerprint, or not at all with
   `tls_verify: false`.
4. When the grant expires or is revoked, new connections and new requests on open HTTP connections are
   refused. Established `tcp` sessions (e.g. an open SSH session) are not cut; keep `max_ttl` short for those.

Grants **add** access. A destination that your rules already allow is unaffected by a grant that also covers
it. This holds for names outside the LAN: a `lan: true` target and a destination given as an IP address always
go through the active grant and its checks. A target that a grant covers but that no rule allows is refused with a hint instead of a connection prompt.

## Choosing levels well

- `read` relies on HTTP semantics. Most APIs (Home Assistant, Proxmox, Synology) do not change anything on
  `GET`. Check yours before setting `read: auto`.
- Narrow paths are the strongest control: `/api/states*` is better than `/api/*` if that is all you need.
- Prefer `https` with injection over handing the agent credentials. The agent then never has a token it
  could misuse outside the grant.
- For `tcp` grants (SSH), use a dedicated key with a restricted account on the target. The gateway can only
  decide *whether* the connection exists, not what happens inside it.
