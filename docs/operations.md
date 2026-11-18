# Operations runbook

- [Requirements](#requirements)
- [Installation](#installation)
  - [With Docker Compose (recommended)](#with-docker-compose-recommended)
  - [Reaching the UI](#reaching-the-ui)
  - [Host directories](#host-directories)
  - [From source](#from-source)
  - [Custom agent image](#custom-agent-image)
  - [Docker log rotation](#docker-log-rotation)
- [Reverse proxy](#reverse-proxy)
  - [Authenticating proxy](#authenticating-proxy)
- [First-time setup](#first-time-setup)
- [Changing the UI password](#changing-the-ui-password)
- [Day-to-day](#day-to-day)
- [Upgrades](#upgrades)
  - [Upgrade to the ordered rule list](#upgrade-to-the-ordered-rule-list)
  - [Restoring the built-in blocks](#restoring-the-built-in-blocks)
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

Open `http://<host>:8080` and continue with [First-time setup](#first-time-setup). See
[Reaching the UI](#reaching-the-ui) for HTTPS, a localhost-only setup and an SSH tunnel.

### Reaching the UI

| Setup | `CONTROL_PUBLISH` | How you open it |
|---|---|---|
| LAN, plain HTTP (default) | `0.0.0.0:8080` | `http://<host>:8080`. Password and session travel unencrypted: fine for a trusted home network or a first look; the UI shows a warning. |
| TLS reverse proxy on the same host (recommended) | `127.0.0.1:8080` | `https://tallygate.example.org`, see [Reverse proxy](#reverse-proxy) |
| Localhost only, SSH tunnel | `127.0.0.1:8080` | `ssh -L 8080:127.0.0.1:8080 <host>`, then `http://127.0.0.1:8080` |

`CONTROL_PUBLISH` is a compose variable: set it in `.env` or as a stack variable (Portainer), or change the
default in the `ports:` line. Under the service's `environment:` it has no effect.

The session cookie follows the connection (`COOKIE_SECURE=auto`): `Secure` over HTTPS, so it is never sent
unencrypted once you use a proxy, and a normal cookie over plain HTTP, so the LAN setup works without changes.

None of these setups lets the agent reach the UI: control listens only on its `mgmt` address, the Docker host
has no address on `agent-net`, and the gateway refuses private addresses (`bypass.sh` checks all three).

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

Check the isolation with the UI's **Setup → Isolation self-test**. The authoritative test runs on the host, with a
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
sudo mkdir -p gateway gw-token ca control-data ttyd agent-home workspace
sudo chown 10001:10001 gateway gw-token ca
sudo chown 10002:10002 control-data ttyd
sudo chown 1000:1000 agent-home workspace
sudo chmod 700 gateway control-data
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

### Rootless package installs (`tallygate install`)

For a tool the agent needs **once**, in the middle of a task, it does not have to interrupt you to rebuild
the image. Inside the agent, `tallygate install PKG…` installs Debian packages without root:

```bash
tallygate install shellcheck sqlite3   # resolve, download and unpack into the home volume
tallygate install --list               # what was installed this way
tallygate install --remove shellcheck  # remove a package from the prefix
tallygate install --reset              # delete the whole prefix and cache
```

`apt` and `dpkg` run as the agent user (uid 1000); the `.deb`s are downloaded through the egress proxy and
unpacked under `~/.local/tallygate/root`, which `entrypoint.sh` and `/etc/profile.d` add to
`PATH`/`LD_LIBRARY_PATH`. The hardening is untouched: the root filesystem stays read-only, no capabilities
or setuid bits apply, and nothing outside the home volume is written (`bypass.sh` checks the root
filesystem stays read-only). The downloads use the **Debian/apt** template, so if it is not active they
are held for approval like any other destination.

Because maintainer scripts are not run, packages that rely on them, on system services, on fixed paths under
`/etc`, or on setuid/file capabilities (daemons, `sudo`, `iputils-ping`) do not work; most CLI tools and
libraries do. Installed packages live on the home volume and survive restarts and image upgrades, like
`pip install --user`. For tools the agent needs regularly, add them to the image with `AGENT_EXTRA_PACKAGES`
or a custom image as above.

### Docker log rotation

All three services set `max-size: 10m` themselves. To rotate other containers too, configure the host:

```json
// /etc/docker/daemon.json
{ "log-driver": "json-file", "log-opts": { "max-size": "10m", "max-file": "3" } }
```

## Reverse proxy

Publish the UI only on localhost (`CONTROL_PUBLISH=127.0.0.1:8080`) and terminate TLS in front. Set `PUBLIC_URL` (used for the origin check), `TRUST_FORWARDED_FOR=1` and `TRUSTED_PROXIES`, the
address control sees for your proxy. Forwarded headers from any other peer are ignored. WebSockets must be
passed through (web consoles).

With a proxy on the host talking to the published port, control sees the `mgmt` bridge gateway,
`172.31.12.1` (check with `docker compose logs control` after a failed login). Every other process on the
host that connects to the published port arrives from that address too, so trusting it means trusting the
whole host. That is acceptable for `X-Forwarded-For` on a single-user host, but **not** together with
`TRUST_PROXY_AUTH_HEADER`: then use the [safe setup for an authenticating proxy](#authenticating-proxy) below.

If the Docker host has a public IP (VPS), add it to `never` in `config/gateway.yaml` so the agent
cannot reach host services through the egress path. Entries there are added to the built-in list
(RFC 1918, loopback, metadata, ...), which always stays in force:

```yaml
never: [203.0.113.7/32]   # your host's public IP; the built-in ranges still apply
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

Open the UI → **Setup**. Each step says whether it is done; *Next* at the top leads to the first one still
to do ([user guide](user-guide.md#setup-wizard)):

1. **Access to this UI**: fix what is marked (for example `TRUSTED_PROXIES` behind a reverse proxy, or
   `PUBLIC_URL`). It also says how to reach the UI from another machine ([Reaching the UI](#reaching-the-ui)).
2. **UI password**: change the generated one: `docker compose exec control python -m app.passwd`.
3. **Gateway**: must show "CA exported".
4. **GitHub token**: create a fine-grained PAT (Settings → Developer settings → Fine-grained tokens) limited
   to the repositories the agent may work on, with *Contents*, *Pull requests*, *Issues* read/write.
   *Save token* checks it against GitHub and stores it in the gateway only.
5. **Log in to Claude**: *Start login*, open the link, sign in, paste the code.
6. **Git identity**: *Use my GitHub identity* → check the preview → *Save identity* (needs the token from step 4).
7. **Remote Control**: *Enable Remote Control*. The session appears in the Claude app under **Code**.
8. **Notifications** (optional): approvals on your phone.
9. **Isolation self-test**: all rows must be PASS.

The policy starts from the `baseline` preset: Claude, GitHub, npm and PyPI are allowed, everything else asks
you. **Quick settings** has learning mode and the shortcuts for the first task
([How access works](access.md#getting-to-a-working-setup)).

Without the UI, the same steps work in the consoles: `claude auth login` in *bash*, the `git config` lines,
and answering `y` in *rc*.

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
| Tighten/loosen policy | UI → Destinations (add, edit, move and delete rules, *Test a destination*); the default under Settings → Mode; shortcuts and learning mode under Quick settings; versions under Log → *Policy history, export and import* |
| Let the agent reach one local device | An allow rule for its address and port on Destinations, or a grant (Quick settings → Local network) when it should ask each time: [rules.md](rules.md#a-allow-one-local-device) |
| Temporarily open the internet | Quick settings → Internet → *Allow web for 15 min* (or Overview → *Allow web for 15 min*) |
| Emergency stop | Quick settings → *Emergency stop*, or Overview (revokes grants, denies what is pending, removes the internet shortcuts, ends learning mode, mode `deny`, suspends auto-approved grants), or `docker compose stop agent` |
| Several sessions in parallel | New session in the Claude app on the same environment; `RC_ARGS=--spawn worktree` for isolated worktrees |
| Files into or out of the workspace | UI → Files (upload into the open folder, download results) |
| Shell in the agent | UI → Console → bash (or `docker compose exec agent bash`) |

## Upgrades

| Component | Procedure |
|---|---|
| tallygate (Compose) | The UI shows **Update: X.Y.Z** in the header when a newer release exists (Overview → *Versions*; switch the check off with `UPDATE_CHECK=0`). Read the [CHANGELOG](../CHANGELOG.md), including its *Upgrading* notes → `docker compose pull && docker compose up -d` → self-test or `bash bypass.sh`. Download the new `compose.yaml` when the changelog says so. When the networks changed (as in 0.4.0), run `docker compose down` first: a plain `up -d` keeps the running containers on the wrong addresses. |
| tallygate (from source) | `git pull` → read `CHANGELOG.md` → `make up` → `make bypass-test`. |
| Claude Code | Part of the agent image, which has no auto-updater by design. New Claude Code versions arrive as tallygate patch releases: update tallygate. From source, set `CLAUDE_VERSION` in `.env` and run `make up`. |
| Base images / dependencies | Published images are rebuilt for every release. From source: `docker compose -f compose.yaml -f compose.build.yaml build --pull && make up`. |

Remote Control comes back as the same environment with the same session after a restart of the agent, an
update, or an outage of the gateway or the network, however long it lasted on the agent's side. Claude Code
itself only believes its record of the environment for about four hours; the agent keeps a copy on the home
volume (`~/.claude/tallygate-rc-pointer.json`) and puts it back before every start. If the Claude service no
longer knows the environment, a new one is registered after five refused starts, and the old session shows
*environment deleted* in the app. Its conversation is still on the home volume: `claude --resume` in the
*claude* console lists it.

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

### Upgrade to the ordered rule list

The policy is evaluated as one ordered rule list ([ADR-0019](adr/0019-one-ordered-rule-list.md); how it
decides: [rules.md](rules.md); the release that brought it: [CHANGELOG](../CHANGELOG.md)). The files in the
gateway's data volume are migrated **once, at the first start** of a gateway with that model. Nothing has to
be done before the upgrade, and an unattended image update works.

What the gateway does:

| File | Change | Backup |
|---|---|---|
| `policy.yaml` | Your CIDR `deny` rules move to the top, in their order: they won wherever they stood, and keep winning. `hard_deny` ranges become `deny` rules below your other rules. The [built-in blocks](rules.md#built-in-blocks) and your `never` entries are added as `deny` rules at the bottom, except ranges you had opened (`floor_open`): those stay open. **Exception, so that nothing opens by upgrading:** a block (built-in, `never` or `hard_deny`) that one of your address `allow` or `ask` rules overlaps is placed at the **top**, right after your CIDR `deny` rules, above that rule. Such a rule had no effect inside the blocked range before and has none after. `hard_deny` and `floor_open` are removed from the file. | `policy.yaml.pre-0019` |
| `grants.yaml` (grants defined in the UI) | `lan: true` is removed from targets. Only rewritten when a target had it. | `grants.yaml.pre-0019` |
| `gateway.yaml` (your config, mounted read-only) | Never rewritten. Old keys are read or ignored with a warning: [configuration](configuration.md#removed-and-ignored-keys). | – |

- **Backups are written before anything is changed** and are never overwritten by a later start.
- **Fail closed.** A file that cannot be translated, or a backup that cannot be written, stops the gateway
  with a message that names the entry; the old file is untouched. The agent has no network while the gateway
  is down. Fix the entry (or restore a backup) and start again.
- **Where it is reported:** in the container log (`docker compose logs egress-gw | grep -i migrat`), as an
  admin entry in the UI's **Log** (`policy.yaml migrated to one ordered rule list (ADR-0019): …`) and as a
  version in **Log → Policy history**.

What to check afterwards:

1. **Address `allow` and `ask` rules inside a blocked range.** They did nothing before, and they still do
   nothing: the migration keeps the blocks they overlap above them and says so (`policy migration: NOTE n
   block(s) stay at the top of the list, above rule(s) …: these address rules had no effect inside the
   blocked ranges and still have none. To open an address, move its rule above the block. Blocks: …`). If
   you want such a rule to open its address, use *Move up* on it until it stands above the block; if not,
   delete it.
2. **Grants for local devices.** A target with an IP or a fixed address keeps working. A target that is only
   a name (`ha.lan`) no longer reaches a blocked range; the log names each one (`` `lan` is ignored now, and
   a target that is only a name cannot open a blocked range ``). Set its fixed address, or add an allow
   rule for the address above the block ([grants.md](grants.md#local-targets-and-name-only-targets)).
   **The other direction:** a target that names an address inside a blocked range and did *not* have
   `lan: true`, or one inside the old never list (loopback, metadata, the config's `never`) with or without
   it, was always refused before and is reachable now while its grant is active. The container log
   and the migration entry in the Log name each one (`NOTE grant …: target … names the address … inside blocked range …. It was
   refused before; now it is reachable while the grant is active`, with `approval for … is automatic` where
   that applies). Delete the target, or the grant, if that is not wanted.
3. **Address rules that are open inside a blocked range.** At every start the gateway logs the address
   `allow` and `ask` rules that stand above a built-in or config block and reach into it
   (`docker compose logs egress-gw | grep "open inside blocked ranges"`): `policy: open inside blocked
   ranges: 192.168.44.1/32 (allow rule 3f9a1c2e)`. Rules you added for a device belong there. A rule you
   do not recognise does not: this is also how an installation shows that ran a pre-release build of the
   rule list, whose migration put old address rules above the blocks, and a `never` entry added to
   `gateway.yaml` after such a rule existed. Delete the rule, or move the block above it.
4. **The table.** *Destinations* shows the list in the order it is checked; the line under it counts the
   built-in and config blocks. *Test a destination* shows what decides for one host and port.
5. **`gateway.yaml`**: delete `grants_lan_allow`, rename `hard_deny_floor` / `grants_never` to `never`.

**Going back to the older release:** the older gateway refuses the migrated `policy.yaml` (it stops at the
key `seeded`), so put the backups back before you start it. Changes made after the migration are lost.

```bash
docker compose stop egress-gw
docker run --rm -v tallygate_gateway-data:/v debian sh -c \
  'cp -p /v/policy.yaml.pre-0019 /v/policy.yaml; [ ! -f /v/grants.yaml.pre-0019 ] || cp -p /v/grants.yaml.pre-0019 /v/grants.yaml'
# set TALLYGATE_VERSION to the older release in .env, then:
docker compose up -d
```

With a host directory instead of the volume (`GATEWAY_DATA`), copy the files there and keep owner 10001.
The same copy, followed by a start of the **new** gateway, runs the migration again from the old file.

Exports and policy versions from before the upgrade stay usable: an import or a *Restore version* of one is
migrated the same way, and the preview shows the policy as it will be in force. The same `NOTE` lines are
recorded: an import shows them as warnings before you apply it, and the Log entry of the import or restore
carries them. Whenever a whole policy is put in force (import, restore, `PUT /policy`, the raw editor), the
Log entry also says which built-in or config blocks are **not** in force in it (`built-in block(s) not in
force: …`).

### Restoring the built-in blocks

The built-in blocks are ordinary rules and can be deleted; a deleted block stays deleted across restarts
and upgrades ([rules.md](rules.md#built-in-blocks), and what that means:
[threat model](threat-model.md#residual-risks)). To get them back:

- **Destinations → Restore built-in blocks** adds back, at the bottom of the list, every built-in block and
  every `never` entry of the gateway config that is not in the list as a permanent `deny` for exactly that
  range on every port. It changes no other rule and says how many it added (*No built-in block is missing*
  when there is nothing to do). The API route is `POST /destinations/restore-blocks` ([api.md](api.md)).
- **Restoring does not close what an address rule above the blocks opens.** A restored block is added at the
  bottom; an `allow` (or `ask`) rule for an address in its range that stands above it keeps deciding for that
  address. The message after the click and the Log entry list these (`Still open by rules above the blocks:
  192.168.44.1/32`; in the API answer: `opened`). Delete such rules if you want the whole range closed again.
- To see who removed a block and when, or to go back to the policy as it was: **Log → Policy history**,
  *Show changes* and *Restore version*.
- The line under the *Destinations* table counts the built-in and config blocks in the list.

The locked ranges need no restoring: they are not rules and cannot be removed
([rules.md](rules.md#locked-ranges)).

## Backup and restore

Back up the volumes (or the directories in `GATEWAY_DATA`, `CONTROL_DATA`, `AGENT_HOME`,
`WORKSPACE`), plus `.env` and your `gateway.yaml` if you have them:

| Volume | Contains | Sensitivity |
|---|---|---|
| `gateway-data` | policy (and its history, the `*.pre-0019` migration backups), UI grants, event log, **secrets (GitHub token)**, gateway CA private key | **high**: encrypt backups |
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
| A session in the app shows *environment deleted*, or the *rc* console repeats `This folder is already served by a terminal claude remote-control on this device` | Remote Control lost its record of the environment (in earlier releases: after more than about four hours without the gateway). The agent now restores it by itself. To continue the old conversation, run `claude --resume` in the *claude* console. To start over with a new environment, delete `~/.claude/tallygate-rc-pointer.json` in `agent-home` and restart the agent. |
| Approval requests keep coming, although Claude is in `bypassPermissions` | They are two different things. `bypassPermissions` is Claude Code's own prompt for tools and file access; tallygate's approvals are about *destinations* the agent connects to and are decided by the mode under **Settings** (ask / deny / allow). Look at the host in the request: telemetry and update checks (`cafe.github.com`, `cli.github.com` from the GitHub CLI, `http-intake.logs.*.datadoghq.com` from Claude Code) are the usual repeat visitors. The agent image switches the `gh` ones off. For the rest choose **Deny permanently** once: it becomes a rule and stops the prompts. |
| Remote Control session not visible in the app | Open the *rc* console: is it waiting for `Enable Remote Control? (y/n)`? Not logged in (`claude auth login`)? Same claude.ai account in the app? Look under **Code**, tab *Active*. |
| `Remote Control requires feature-flag evaluation …` | A settings file or env sets `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC`, `DISABLE_GROWTHBOOK` or (older versions) `DISABLE_TELEMETRY`. tallygate's agent image sets none of them; check `~/.claude/settings.json` in `agent-home`. |
| Tool fails with "could not resolve host" | It resolves locally instead of via the proxy. Use `socks5h://`, proxy-side resolution, or a service port. |
| Tool hangs ~60 s then fails | The destination is in `ask` and nobody answered. Approve it in the UI/phone, then retry. |
| `502 egress policy: blocked (rule block-… (built-in block))` | The address is inside a blocked range (the local network, loopback, metadata …). To reach one device, add an allow rule for its address and port, or define a [grant](grants.md): [rules.md](rules.md#the-local-network-worked-examples). |
| `… blocked (name allowed by rule …, but it resolves to …, inside blocked range …)` | A rule allows the name, but a rule for a name never opens a blocked range. If the address should be reachable, add an allow rule for the address; if not, the block did its job: [rules.md](rules.md#why-a-name-rule-cannot-open-a-blocked-range). |
| `… blocked (locked: … belongs to the tallygate stack itself)` | The destination is the stack's own network or the gateway itself. Nothing opens these: [rules.md](rules.md#locked-ranges). |
| After an upgrade the gateway does not start, the log names a policy or grant entry | The migration to the ordered rule list failed closed: [Upgrade to the ordered rule list](#upgrade-to-the-ordered-rule-list). |
| `gh`/`git` 401 against GitHub | No token stored (Setup step 4, GitHub token), PAT expired, or PAT lacks access to that repository. |
| TLS errors only for github.com | The agent doesn't trust the gateway CA: check `/ca/egress-gw-ca.pem` exists in the agent (`ls /ca`) and restart the agent after the gateway. |
| `ENOSPC: no space left on device` | Host disk full. Free space (`docker system df`, logs) or grow the VM disk. |
| UI login loops | `COOKIE_SECURE=1` forces a Secure cookie, which browsers drop over plain HTTP from another machine. Use the default `auto`, or HTTPS. |
| UI does not answer on `http://<host>:8080` | `docker port tallygate-control-1` must show `0.0.0.0:8080`. `127.0.0.1:8080` means `CONTROL_PUBLISH` is set to localhost (or was put under `environment:`, where it has no effect). Otherwise check the host firewall. |
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
