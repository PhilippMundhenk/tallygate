# Operations runbook

- [Requirements](#requirements)
- [Installation](#installation)
- [Reverse proxy](#reverse-proxy)
- [First-time setup](#first-time-setup)
- [Day-to-day](#day-to-day)
- [Upgrades](#upgrades)
- [Backup and restore](#backup-and-restore)
- [Monitoring](#monitoring)
- [Troubleshooting](#troubleshooting)
- [Migrating from another Claude Code container](#migrating-from-another-claude-code-container)
- [Uninstall](#uninstall)

## Requirements

- Linux host or VM with Docker Engine ≥ 25 and the Compose plugin (amd64 or arm64).
- ~6 GB free disk for images plus your workspace. Keep an eye on the root filesystem: a full disk makes
  Claude Code fail with `ENOSPC` in confusing places.
- A claude.ai subscription (Pro/Max/Team/Enterprise) for Remote Control. API keys don't work with Remote
  Control.
- Recommended: a reverse proxy with TLS and SSO (Caddy, Traefik, nginx + Authelia/Authentik/oauth2-proxy).

## Installation

```bash
git clone https://github.com/PhilippMundhenk/tallygate.git && cd tallygate
sudo ./setup.sh           # .env with random secrets, UI password, state dirs with correct owners
$EDITOR .env              # RC_NAME, CONTROL_PUBLISH, PUBLIC_URL, TRUST_FORWARDED_FOR, notifications
make up                   # docker compose up -d --build
make bypass-test          # authoritative isolation test (must end with ALL CHECKS PASSED)
```

`setup.sh` is idempotent: it only fills empty values and fixes ownership (gateway state uid 10001, agent
state uid 1000).

Configure Docker log rotation on the host (all three services also set `max-size: 10m` themselves):

```json
// /etc/docker/daemon.json
{ "log-driver": "json-file", "log-opts": { "max-size": "10m", "max-file": "3" } }
```

## Reverse proxy

Publish the UI only on localhost (`CONTROL_PUBLISH=127.0.0.1:8080`) and terminate TLS in front. Set
`PUBLIC_URL` (used for the origin check), `TRUST_FORWARDED_FOR=1` and `TRUSTED_PROXIES` — the address
control sees for your proxy. With a proxy on the host talking to the published port that is the `mgmt`
bridge gateway, `172.31.12.1/32` (check with `docker compose logs control` after a failed login: the
logged address is what control sees). Forwarded headers from any other peer are ignored. WebSockets must
be passed through (web consoles).

Caddy example with forward-auth:

```caddy
tallygate.example.org {
    forward_auth authelia:9091 {
        uri /api/authz/forward-auth
        copy_headers Remote-User
    }
    reverse_proxy 127.0.0.1:8080
}
```

With an authenticating proxy you may set `TRUST_PROXY_AUTH_HEADER=Remote-User` to skip the built-in
password. It is honoured only from `TRUSTED_PROXIES` (control refuses to start without it); still keep port
8080 unreachable except through the proxy.

If the Docker host has a public IP (VPS), add it to `hard_deny_floor` in `config/gateway.yaml` so the agent
cannot reach host services through the egress path. Entries there are added to the built-in list
(RFC 1918, loopback, metadata, ...), which always stays in force:

```yaml
hard_deny_floor: [203.0.113.7/32]   # your host's public IP; the built-in ranges still apply
```

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

## Day-to-day

| Task | How |
|---|---|
| Approve/deny connections | UI → Approvals, Telegram buttons, Matrix reactions/replies |
| Review traffic | UI → Log (filter, "only blocked", one-click allow/deny rule) |
| Tighten/loosen policy | UI → Rules (mode, add/delete rules, presets with TTL, dry-run test) |
| Temporarily open the internet | Rules → Presets → `open` with TTL `900` |
| Emergency stop | Rules → default `deny`, or `docker compose stop agent` |
| Several sessions in parallel | New session in the Claude app on the same environment; `RC_ARGS=--spawn worktree` for isolated worktrees |
| Shell in the agent | UI → Console → bash (or `docker compose exec agent bash`) |

## Upgrades

| Component | Procedure |
|---|---|
| Claude Code | Set `CLAUDE_VERSION` in `.env` → `docker compose up -d --build agent`. There is no auto-updater in the agent by design. |
| tallygate | `git pull` → read `CHANGELOG.md` → `make up` → `make bypass-test`. |
| Base images / dependencies | Rebuild regularly: `docker compose build --pull && make up`. Dependabot proposes pin updates. |

Running sessions are reconnected by Remote Control after a restart if you're back within about 4 hours.

## Backup and restore

Back up `${TALLYGATE_DIR}` (default `./state`) plus `.env` and `config/`:

| Path | Contains | Sensitivity |
|---|---|---|
| `state/gateway/` | policy, event log, **secrets (GitHub token)**, gateway CA private key | **high**: encrypt backups |
| `state/agent-home/` | **Claude login**, settings, skills, git config | **high** |
| `state/workspace/` | your repositories | as your code |
| `.env` | API token, session secret, password hash | **high** |

Restore: stop the stack, put the files back with the original owners (`setup.sh` fixes them), start the
stack. If you restore only `agent-home` to a new gateway, the CA changes. That's harmless: the agent re-reads
the CA on start.

## Monitoring

- `docker compose ps` shows health checks for `egress-gw` and `control`.
- The UI header dot shows the live event stream status.
- Long-running: alert on `docker inspect -f '{{.State.Health.Status}}' tallygate-egress-gw-1`.
- The event log is SQLite (`state/gateway/events.db`). Query ad hoc:
  `sqlite3 state/gateway/events.db "select datetime(ts,'unixepoch'),host,port,action,reason from events where action='deny' order by id desc limit 20"`.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Remote Control session not visible in the app | Open the *rc* console: is it waiting for `Enable Remote Control? (y/n)`? Not logged in (`claude auth login`)? Same claude.ai account in the app? Look under **Code**, tab *Active*. |
| `Remote Control requires feature-flag evaluation …` | A settings file or env sets `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC`, `DISABLE_GROWTHBOOK` or (older versions) `DISABLE_TELEMETRY`. tallygate's agent image sets none of them; check `~/.claude/settings.json` in `agent-home`. |
| Tool fails with "could not resolve host" | It resolves locally instead of via the proxy. Use `socks5h://`, proxy-side resolution, or a service port. |
| Tool hangs ~60 s then fails | The destination is in `ask` and nobody answered. Approve it in the UI/phone, then retry. |
| `502 egress policy: blocked (hard-deny …)` | Destination resolves to a private range. For LAN services use a service port with `allow_private: true`. |
| `gh`/`git` 401 against GitHub | No token stored (Setup step 2), PAT expired, or PAT lacks access to that repository. |
| TLS errors only for github.com | The agent doesn't trust the gateway CA: check `/ca/egress-gw-ca.pem` exists in the agent (`ls /ca`) and restart the agent after the gateway. |
| `ENOSPC: no space left on device` | Host disk full. Free space (`docker system df`, logs) or grow the VM disk. |
| UI login loops | `COOKIE_SECURE=1` while accessing via plain HTTP; use HTTPS or set `0` for local tests only. |
| Self-test "Management endpoint … UNEXPECTEDLY SUCCEEDED" | Network wiring changed. Re-check `compose.yaml` and run `make bypass-test`. |

## Migrating from another Claude Code container

1. Stop the old container.
2. Copy skills: `cp -r <old>/claude-home/skills state/agent-home/.claude/` and run `sudo ./setup.sh` to fix
   ownership.
3. Copy repositories into `state/workspace/` (or re-clone).
4. **Log in again** instead of copying credentials, and create a new fine-grained PAT for the gateway.
5. Revoke tokens that were stored in the old container.

## Uninstall

```bash
docker compose down -v --rmi local
sudo rm -rf "${TALLYGATE_DIR:-./state}"   # deletes logins, secrets, workspace!
```

Then revoke the GitHub PAT and sign the session out in claude.ai (Settings → sessions).
