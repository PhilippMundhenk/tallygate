# Operations runbook

- [Requirements](#requirements)
- [Installation](#installation)
  - [With Docker Compose (recommended)](#with-docker-compose-recommended)
  - [Host directories](#host-directories)
  - [From source](#from-source)
  - [Custom agent image](#custom-agent-image)
- [Reverse proxy](#reverse-proxy)
- [First-time setup](#first-time-setup)
- [Day-to-day](#day-to-day)
- [Upgrades](#upgrades)
- [Resource limits](#resource-limits)
- [Backup and restore](#backup-and-restore)
- [Monitoring](#monitoring)
- [Troubleshooting](#troubleshooting)
- [Migrating from another Claude Code container](#migrating-from-another-claude-code-container)
- [Uninstall](#uninstall)

## Requirements

- Linux host or VM with Docker Engine ≥ 25 and the Compose plugin (amd64 or arm64).
- ~6 GB free disk for images plus your workspace. Keep an eye on the disk: see
  [resource limits](#resource-limits).
- A claude.ai subscription (Pro/Max/Team/Enterprise) for Remote Control. API keys don't work with Remote
  Control.
- Recommended: a reverse proxy with TLS and SSO (Caddy, Traefik, nginx + Authelia/Authentik/oauth2-proxy).

## Installation

### With Docker Compose (recommended)

Prebuilt images for amd64 and arm64 are published on GHCR: `tallygate-gateway`, `tallygate-control` and
`tallygate-agent` under `ghcr.io/philippmundhenk/`. You only need the compose file.

```bash
mkdir tallygate && cd tallygate
curl -fsSLO https://github.com/PhilippMundhenk/tallygate/releases/latest/download/compose.yaml
docker compose up -d
docker compose logs control | grep -A1 password    # the generated UI password
```

The generated password stays readable in the control log (`docker compose logs`) until the log is rotated,
so change it after the first login, see [Changing the UI password](#changing-the-ui-password).

The UI is published **only on localhost of the Docker host** (`CONTROL_PUBLISH=127.0.0.1:8080`). Open
<http://127.0.0.1:8080> on the host, or from elsewhere through an SSH tunnel (`ssh -L 8080:127.0.0.1:8080 <host>`,
then the same address), or through a [reverse proxy](#reverse-proxy). For a short test on a trusted network you
can publish it on the LAN with `CONTROL_PUBLISH=0.0.0.0:8080` **and** `COOKIE_SECURE=0` (browsers drop the
secure session cookie over plain HTTP from another machine, so the login would loop); password and session
then travel unencrypted. Continue with [First-time setup](#first-time-setup).

On first start the containers create everything they need in Docker volumes:

| Volume | Mounted in | Contains |
|---|---|---|
| `gateway-data` | egress-gw | policy, event log, stored secrets (GitHub token), CA key |
| `gw-token` | egress-gw (rw), control (ro) | management API token |
| `control-data` | control | session secret, UI password hash |
| `ttyd` | control (rw), agent (ro) | console credential |
| `ca` | egress-gw (rw), agent (ro) | the gateway's public CA certificate |
| `agent-home`, `workspace` | agent | Claude login and settings; your repositories |

Settings go into a `.env` file next to `compose.yaml`; all of them are optional. Start from
[`.env.example`](../.env.example) and see the [configuration reference](configuration.md). The ones you will
most likely want: `PUBLIC_URL` and `TRUSTED_PROXIES` for a [reverse proxy](#reverse-proxy), `RC_NAME`, and
Telegram or Matrix for phone approvals. Apply changes with `docker compose up -d`.

To keep state in host directories instead of volumes, see [Host directories](#host-directories).

To change the static gateway configuration (grants, service ports, credential injection), save
[`config/gateway.yaml`](../config/gateway.yaml) as `gateway.yaml` next to `compose.yaml`, edit it and
uncomment the `./gateway.yaml:/etc/egressgw/config.yaml:ro` line in `compose.yaml`.

Check the isolation with the UI's **Setup → Self-test**. The authoritative test runs on the host, with a
separate probe container:

```bash
curl -fsSLO https://github.com/PhilippMundhenk/tallygate/releases/latest/download/bypass.sh
bash bypass.sh                 # must end with ALL CHECKS PASSED
```

Pin a version with `TALLYGATE_VERSION=0.4` (minor version, gets patches) or `0.4.0` in `.env`. Each release
also attaches `compose.yaml`, `.env.example`, `gateway.yaml` and `bypass.sh` for that version.

### Host directories

Docker volumes get the right owners automatically. **Host directories do not**: Docker creates a missing
directory as `root`, and the containers run as fixed unprivileged users without any capabilities, so they
cannot write there. The container then stops with a message like `egress-gw cannot write to /data (it runs as
uid 10001)`. Create the directories with these owners before the first start:

| Volume | Container path | Owner (uid:gid) | Mode | `.env` variable | Contains |
|---|---|---|---|---|---|
| `gateway-data` | egress-gw `/data` | `10001:10001` | 700 | `GATEWAY_DATA` | policy, log, secrets, CA key |
| `gw-token` | egress-gw `/run/tallygate/gw`, control (ro) | `10001:10001` | 755 | – | API token (recreated) |
| `ca` | egress-gw `/ca`, agent (ro) | `10001:10001` | 755 | – | public CA certificate (recreated) |
| `control-data` | control `/data` | `10002:10002` | 700 | `CONTROL_DATA` | UI password hash, session secret |
| `ttyd` | control `/run/tallygate/ttyd`, agent (ro) | `10002:10002` | 755 | – | console credential (recreated) |
| `agent-home` | agent `/home/agent` | `1000:1000` | 755 | `AGENT_HOME` | Claude login, settings |
| `workspace` | agent `/workspace` | `1000:1000` | 755 | `WORKSPACE` | your repositories |

The users don't need to exist on the host; `chown` takes the numbers. For all seven under one directory:

```bash
cd /srv/tallygate
sudo mkdir -p gateway-data gw-token ca control-data ttyd agent-home workspace
sudo chown 10001:10001 gateway-data gw-token ca
sudo chown 10002:10002 control-data ttyd
sudo chown 1000:1000 agent-home workspace
sudo chmod 700 gateway-data control-data
```

The four with an `.env` variable hold everything worth keeping; set them to the host paths. `./setup.sh
/srv/tallygate` from the repository prepares those four and writes the variables. `gw-token`, `ca` and `ttyd`
are recreated on every start; keep them as volumes unless you replace them in `compose.yaml` yourself as above.
Don't set `user:` in compose: the images are built for these uids.

### From source

Builds the images from a checkout instead of pulling them, for development or to change the code:

```bash
git clone https://github.com/PhilippMundhenk/tallygate.git && cd tallygate
./setup.sh                # optional: creates .env; `./setup.sh /srv/tallygate` also uses host directories
make up                   # docker compose -f compose.yaml -f compose.build.yaml up -d --build
make bypass-test          # authoritative isolation test (must end with ALL CHECKS PASSED)
```

The `make` targets add [`compose.build.yaml`](../compose.build.yaml), which gives every service a `build:`
section; the local images are tagged `:local`. Requirements: Docker, `make`, and Python 3.12+ for the tests.

### Custom agent image

The agent image contains Claude Code, git, gh, Node.js, Python and common CLI tools. Add your toolchains in an
image of your own:

```dockerfile
FROM ghcr.io/philippmundhenk/tallygate-agent:0.4
USER root
RUN apt-get update && apt-get install -y --no-install-recommends build-essential golang-go \
 && rm -rf /var/lib/apt/lists/*
USER 1000:1000
```

Build it (`docker build -t my-agent .`) and set `image: my-agent` for the `agent` service in a
`compose.override.yaml`. When building from source, `AGENT_EXTRA_PACKAGES` in `.env` does the same.

### Docker log rotation

All three services set `max-size: 10m` themselves. To rotate other containers too, configure the host:

```json
// /etc/docker/daemon.json
{ "log-driver": "json-file", "log-opts": { "max-size": "10m", "max-file": "3" } }
```

## Reverse proxy

Publish the UI only on localhost (`CONTROL_PUBLISH=127.0.0.1:8080`, the default) and terminate TLS in
front. Set `PUBLIC_URL` (used for the origin check), `TRUST_FORWARDED_FOR=1` and `TRUSTED_PROXIES`, the
address control sees for your proxy. Forwarded headers from any other peer are ignored. WebSockets must be
passed through (web consoles).

With a proxy on the host talking to the published port, control sees the `mgmt` bridge gateway,
`172.31.12.1` (check with `docker compose logs control` after a failed login). Every other process on the
host that connects to the published port arrives from that address too, so trusting it means trusting the
whole host. That is acceptable for `X-Forwarded-For` on a single-user host, but **not** together with
`TRUST_PROXY_AUTH_HEADER`: then use the [safe setup for an authenticating proxy](#authenticating-proxy) below.

If the Docker host has a public IP (VPS), add it to `hard_deny_floor` in `config/gateway.yaml` so the agent
cannot reach host services through the egress path. Entries there are added to the built-in list
(RFC 1918, loopback, metadata, ...), which always stays in force:

```yaml
hard_deny_floor: [203.0.113.7/32]   # your host's public IP; the built-in ranges still apply
```

Caddy on the host, with SSO in front of the built-in password:

```caddy
tallygate.example.org {
    forward_auth authelia:9091 {
        uri /api/authz/forward-auth
        copy_headers Remote-User
    }
    reverse_proxy 127.0.0.1:8080
}
```

### Authenticating proxy

With an authenticating proxy you may set `TRUST_PROXY_AUTH_HEADER=Remote-User` to skip the built-in
password. It is honoured only from `TRUSTED_PROXIES` (control refuses to start without it). Anyone who can
send requests from a trusted address can log in as anyone, so:

1. Run the proxy as a container on the `mgmt` network with a **fixed address**.
2. Publish **nothing** of control: only the proxy publishes a port.
3. Trust only the proxy's address, and let the proxy send a shared secret.

A `compose.override.yaml` next to `compose.yaml` (Compose ≥ 2.24 for `!reset`):

```yaml
services:
  control:
    ports: !reset []                # no published UI port: reachable only through the proxy
  proxy:
    image: caddy:2
    ports: ["443:443"]
    environment:
      TRUST_PROXY_SECRET: ${TRUST_PROXY_SECRET}
    volumes: ["./Caddyfile:/etc/caddy/Caddyfile:ro"]
    networks:
      mgmt: {ipv4_address: 172.31.12.10}
```

`.env`:

```sh
PUBLIC_URL=https://tallygate.example.org
TRUST_PROXY_AUTH_HEADER=Remote-User
TRUSTED_PROXIES=172.31.12.10/32
TRUST_PROXY_SECRET=<openssl rand -hex 24>
TRUST_FORWARDED_FOR=1
```

The proxy forwards to `172.31.12.3:8080`, must never pass on a `Remote-User` sent by the client, and adds the
secret:

```caddy
tallygate.example.org {
    forward_auth authelia:9091 {
        uri /api/authz/forward-auth
        copy_headers Remote-User
    }
    reverse_proxy 172.31.12.3:8080 {
        header_up X-Tallygate-Proxy-Secret {$TRUST_PROXY_SECRET}
    }
}
```

With `TRUST_PROXY_SECRET` set, control ignores the auth and forwarded headers of any request that lacks the
secret, even from the trusted address; the secret is compared in constant time. Give the proxy container
the same value (the override above does). Your authentication service (here `authelia`) must be reachable
from the proxy, for example on a second network of the proxy.


## First-time setup

Open the UI → **Setup**:

1. **Gateway**: must show "CA exported".
2. **GitHub token**: create a fine-grained PAT (Settings → Developer settings → Fine-grained tokens) limited
   to the repositories the agent may work on, with *Contents*, *Pull requests*, *Issues* read/write.
   *Validate & store* checks it against GitHub and stores it in the gateway only.
3. **Claude login**: in the *bash* console run `claude auth login`, open the URL, paste the code.
4. **Git identity**: run the two `git config` lines in the *bash* console. Use your GitHub noreply address.
5. **Remote Control**: open the *rc* console. On first start answer `Enable Remote Control? (y/n)` with `y`
   (and `Trust /workspace? [y/N]` if asked). The session appears in the Claude app under **Code**.
6. **Self-test**: all rows must be PASS.

Then clone repositories in the *bash* console: `gh repo clone owner/repo /workspace/repo`.

## Changing the UI password

```bash
docker compose exec control python -m app.passwd
```

It asks for the new password twice (at least 12 characters) and stores its scrypt hash in `control-data`.
It applies at once, no restart needed: **every session opened with the old password ends** at its next
request (each session remembers a fingerprint of the password it was opened with), so a leaked password
cannot be used through a session that is already open.

This has no effect while `CONTROL_PASSWORD_HASH` or `CONTROL_PASSWORD` are set; change those in `.env` or
`compose.yaml` and recreate control (`docker compose up -d control`), which also ends all sessions. To create
a value for `CONTROL_PASSWORD_HASH` without a checkout of the repository:

```bash
docker compose exec control python -m app.passwd --print-hash   # prints scrypt:16:..., writes nothing
```

`python3 control/hashpw.py` in a checkout does the same.

## Day-to-day

| Task | How |
|---|---|
| Approve/deny connections | UI → Approvals, Telegram buttons, Matrix reactions/replies |
| Review traffic | UI → Log (filter, "only blocked", one-click allow/deny rule) |
| Tighten/loosen policy | UI → Rules (mode, add/delete rules, presets with TTL, dry-run test) |
| Temporarily open the internet | Rules → Presets → `open` with TTL `900` |
| Emergency stop | Rules → Quick actions → *Emergency stop* (revokes grants, denies what is pending, removes the internet shortcuts, mode `deny`, suspends auto-approved grants), or `docker compose stop agent` |
| Several sessions in parallel | New session in the Claude app on the same environment; `RC_ARGS=--spawn worktree` for isolated worktrees |
| Shell in the agent | UI → Console → bash (or `docker compose exec agent bash`) |

## Upgrades

| Component | Procedure |
|---|---|
| tallygate (Compose) | Read the [CHANGELOG](../CHANGELOG.md), including its *Upgrading* notes → `docker compose pull && docker compose up -d` → self-test or `bash bypass.sh`. Download the new `compose.yaml` when the changelog says so. When the networks changed (as in 0.4.0), run `docker compose down` first: a plain `up -d` keeps the running containers on the wrong addresses. |
| tallygate (from source) | `git pull` → read `CHANGELOG.md` → `make up` → `make bypass-test`. |
| Claude Code | Part of the agent image, which has no auto-updater by design. New Claude Code versions arrive as tallygate patch releases: update tallygate. From source, set `CLAUDE_VERSION` in `.env` and run `make up`. |
| Base images / dependencies | Published images are rebuilt for every release. From source: `docker compose -f compose.yaml -f compose.build.yaml build --pull && make up`. |

Running sessions are reconnected by Remote Control after a restart if you're back within about 4 hours.

## Resource limits

The agent is limited to `AGENT_MEM_LIMIT` (6 GB) of memory, 1024 processes and a 1 GB `/tmp`. CPU is unlimited
by default; set `AGENT_CPUS` (e.g. `2`) so a busy or looping agent leaves CPU for the gateway, the UI and the
host.

Disk is the limit Docker does not enforce. The workspace and the agent home grow without bound, and by default
they share a filesystem with Docker itself (`/var/lib/docker`) and the gateway's event log. A runaway or
hostile agent can fill it, and then Claude Code fails with `ENOSPC` in confusing places and other containers
on the host suffer too. On a host that runs more than tallygate:

- Put the workspace on its own filesystem or a dataset with a quota (LVM volume, ZFS/btrfs dataset, a loop
  file) and point `WORKSPACE` (and `AGENT_HOME`) there. Keep `GATEWAY_DATA` on a different filesystem, so the
  gateway can still log and decide while the agent's disk is full.
- Alternatively give Docker's data root its own filesystem.
- Monitor free space; `docker system df` shows what Docker uses.

The gateway's event log is capped by `log_max_events` and `log_keep_days`, and identical events are coalesced.

## Backup and restore

Back up the volumes (or the directories in `GATEWAY_DATA`, `AGENT_HOME`, `WORKSPACE`), plus `.env` and your
`gateway.yaml` if you have them:

| Volume | Contains | Sensitivity |
|---|---|---|
| `gateway-data` | policy, event log, **secrets (GitHub token)**, gateway CA private key | **high**: encrypt backups |
| `agent-home` | **Claude login**, settings, skills, git config | **high** |
| `workspace` | your repositories | as your code |
| `control-data` | session secret, UI password hash | medium |
| `gw-token`, `ttyd`, `ca` | recreated on start when missing | – |

Copy a volume with a throwaway container, stopping the stack first for a consistent copy:

```bash
docker run --rm -v tallygate_gateway-data:/v:ro -v "$PWD":/b debian tar czf /b/gateway-data.tgz -C /v .
```

Restore the same way into the volume (`tar xzf` as root keeps the owners). If you restore only `agent-home`
to a new gateway, the CA changes. That's harmless: the agent re-reads the CA on start.

## Monitoring

- `docker compose ps` shows health checks for `egress-gw`, `control` and `agent`.
- The UI header dot shows the live event stream status.
- Long-running: alert on `docker inspect -f '{{.State.Health.Status}}' tallygate-egress-gw-1`.
- The event log is SQLite (`events.db` in `gateway-data`). Query ad hoc, for example the last denials:

  ```bash
  docker compose exec egress-gw python -c "import sqlite3; db = sqlite3.connect('/data/events.db')
  for r in db.execute(\"select datetime(ts,'unixepoch'),host,port,reason from events where action='deny' order by id desc limit 20\"): print(*r)"
  ```

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Remote Control session not visible in the app | Open the *rc* console: is it waiting for `Enable Remote Control? (y/n)`? Not logged in (`claude auth login`)? Same claude.ai account in the app? Look under **Code**, tab *Active*. |
| `Remote Control requires feature-flag evaluation …` | A settings file or env sets `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC`, `DISABLE_GROWTHBOOK` or (older versions) `DISABLE_TELEMETRY`. tallygate's agent image sets none of them; check `~/.claude/settings.json` in `agent-home`. |
| Tool fails with "could not resolve host" | It resolves locally instead of via the proxy. Use `socks5h://`, proxy-side resolution, or a service port. |
| Tool hangs ~60 s then fails | The destination is in `ask` and nobody answered. Approve it in the UI/phone, then retry. |
| `502 egress policy: blocked (hard-deny …)` | Destination resolves to a private range. For LAN services define a [grant](grants.md), or a service port with `allow_private: true`. |
| `gh`/`git` 401 against GitHub | No token stored (Setup step 2), PAT expired, or PAT lacks access to that repository. |
| TLS errors only for github.com | The agent doesn't trust the gateway CA: check `/ca/egress-gw-ca.pem` exists in the agent (`ls /ca`) and restart the agent after the gateway. |
| `ENOSPC: no space left on device` | Host disk full. Free space (`docker system df`, logs) or grow the VM disk. |
| UI login loops | `COOKIE_SECURE=1` while accessing via plain HTTP from another machine. Use HTTPS, or an SSH tunnel to `127.0.0.1` (localhost counts as secure); set `0` for tests only. |
| Lost the UI password | `docker compose exec control python -m app.passwd` sets a new one and ends all open sessions. |
| Self-test "Management endpoint … UNEXPECTEDLY SUCCEEDED" | Network wiring changed. Re-check `compose.yaml` and run `make bypass-test`. |

## Migrating from another Claude Code container

1. Stop the old container.
2. Copy skills into the agent home with a throwaway container (the agent itself has no capability to change
   owners): `docker run --rm -v tallygate_agent-home:/h -v "<old>/claude-home/skills":/s:ro debian sh -c
   'mkdir -p /h/.claude && cp -r /s /h/.claude/skills && chown -R 1000:1000 /h/.claude'`.
3. Copy repositories into the `tallygate_workspace` volume the same way (or re-clone).
4. **Log in again** instead of copying credentials, and create a new fine-grained PAT for the gateway.
5. Revoke tokens that were stored in the old container.

## Uninstall

```bash
docker compose down -v --rmi all   # -v deletes the volumes: logins, secrets, workspace!
```

If you used host directories, delete them too. Then revoke the GitHub PAT and sign the session out in claude.ai (Settings → sessions).
