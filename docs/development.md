# Development

## Repository layout

```
.
├── compose.yaml              # the stack with published images: networks, hardening, wiring, volumes
├── compose.build.yaml        # override: build the images from this checkout (used by `make`)
├── setup.sh                  # optional host setup: .env, host state directories
├── config/gateway.yaml       # default static gateway config, built into the gateway image
├── gateway/                  # egress-gw container (build context: repository root)
│   ├── run.py                #   API token on first start, builds the mitmdump command line
│   ├── presets/              #   policies (baseline, lockdown), internet shortcuts (open, internet) and
│   │                         #   templates (python, node, go, rust, debian, containers, huggingface)
│   └── egressgw/
│       ├── addon.py          #   mitmproxy script entry point (thin loader)
│       ├── core.py           #   hooks: server_connect, tls_clienthello, request, dns_request; approvals
│       ├── policy.py         #   pure policy engine (rules, hard deny, approvals → rules)
│       ├── grants.py         #   grant definitions, requests, active grants
│       ├── availability.py   #   away mode, quiet hours, digest of refused requests
│       ├── activity.py       #   what the agent says it is doing (context for approvals)
│       ├── github.py         #   github_repos: GitHub access per repository
│       ├── history.py        #   policy versions: diff, restore, export and import
│       ├── learning.py       #   learning mode
│       ├── usage.py          #   rule hit counters, unused rules, suggestions
│       ├── store.py          #   SQLite event log, secrets store, header templating
│       ├── api.py            #   management API (aiohttp, bearer token)
│       └── agentapi.py       #   grant request API for the agent (agent network)
├── control/                  # control container
│   ├── hashpw.py             #   host-side password hash helper (CONTROL_PASSWORD_HASH)
│   └── app/
│       ├── main.py           #   auth, CSRF, gateway relay, terminal proxy, agent status
│       ├── bootstrap.py      #   secrets and UI password on first start
│       ├── passwd.py         #   `python -m app.passwd`: change the stored UI password
│       ├── notify.py         #   Telegram + Matrix bots, Web Push, ntfy, Gotify, Pushover
│       ├── webpush.py        #   Web Push: VAPID, RFC 8291 encryption, subscriptions, action tokens
│       └── static/           #   single-page UI (vanilla JS, no build step)
├── agent/                    # agent container
│   ├── Dockerfile            #   Debian + Claude Code + gh (signed repo) + ttyd (checksummed)
│   ├── entrypoint.sh         #   CA trust, placeholders, tmux/ttyd/Remote Control supervisor
│   ├── status.py             #   status, isolation self-test and setup actions (agent network)
│   ├── tallygate-cli.py      #   `tallygate` CLI: list and request grants, request status, notes
│   ├── tallygate-hook.py     #   PreToolUse hook: reports the running command to the gateway
│   ├── CLAUDE.md             #   managed memory: explains the gateway and grants to Claude
│   └── managed-settings.json #   managed Claude Code settings (incl. the PreToolUse hook)
├── tests/
│   ├── unit/                 # unit tests for every component (gateway, control, agent, tools)
│   ├── e2e/                  # real gateway + control on localhost, mock upstreams and bot APIs
│   └── integration/bypass.sh # Docker-based isolation test against the running stack
├── tools/coverage_gate.py    # coverage gate: fails when a module is below the minimum (`make coverage`)
└── docs/                     # this documentation
```

## Local development

```bash
python3 -m venv .venv && . .venv/bin/activate
make dev-setup
make lint coverage
```

The e2e suite (`tests/e2e`) needs no Docker and no root:

- The gateway runs as a real `mitmdump` process on random localhost ports, with DNS on an unprivileged
  port (`GW_DNS_PORT`) and test-only static name resolution (`GW_TEST_STATIC_HOSTS`) instead of
  `/etc/hosts`. `GW_TEST_FLOOR_REPLACE=1` lets the test config's `hard_deny_floor` replace the built-in
  list, because the upstreams run on loopback.
- Upstreams are local HTTP/HTTPS echo servers with a throwaway certificate.
- The control plane runs as a real process; Telegram, Matrix, a Web Push service, ntfy, Gotify and Pushover are
  mocked (`tests/e2e/mockbots.py`).
- The web-console test runs if `ttyd` is installed (CI installs the checksum-verified binary).

Run a subset: `pytest tests/e2e -k injection -x -vv`. Process logs end up in pytest's tmp directories
(`gateway.log`, `control-*.log`).

### Running the UI against a local gateway

```bash
# terminal 1: gateway
cd gateway && DATA_DIR=/tmp/sg CA_EXPORT_DIR=/tmp/sg/ca GW_LISTEN_HOST=127.0.0.1 GW_DNS_PORT=5353 \
  GW_API_HOST=127.0.0.1 GW_API_TOKEN=dev-token-dev-token-dev-token python3 run.py
# terminal 2: control
cd control && GW_URL=http://127.0.0.1:8081 GW_API_TOKEN=dev-token-dev-token-dev-token \
  CONTROL_BIND_HOST=127.0.0.1 CONTROL_PASSWORD=dev SESSION_SECRET=dev COOKIE_SECURE=0 \
  TTYD_CREDENTIAL=a:b python3 -m app.main
# use it:
curl -x http://127.0.0.1:3128 https://example.org/    # appears in Approvals at http://127.0.0.1:8080
```

## Testing levels

| Level | What | Where | Runs in CI |
|---|---|---|---|
| Unit | Policy matching, hard deny, CIDR semantics, expiry, approvals, validation, presets, templating; grants, history, learning mode and rule usage; control (auth, password, setup checks, files, notifications, Web Push); the agent's CLI, hook and status server | `tests/unit` | ✅ |
| E2E | Every enforcement path, held connections, injection incl. SNI spoofing and upstream cert verification, DNS, API auth, UI auth/CSRF/origin, console websocket, Telegram/Matrix flows | `tests/e2e` | ✅ |
| Integration | Real images and networks, started with zero configuration: first-start secrets, structural hardening and egress probes from an independent container | `tests/integration/bypass.sh` | ✅ (`integration` job) |

## Coverage

`make coverage` runs the unit and e2e tests under coverage.py, including the gateway (mitmdump) and control
processes the e2e tests start, and fails when **any module** is below **95 % line coverage**
(`tools/coverage_gate.py`). CI runs it in the `test` job and uploads the HTML report as the `coverage` artifact.

Excluded: only process entry points that would replace the process or touch the real network: `main()` in
`gateway/run.py` (it `exec`s mitmdump; `build_args()` and `ensure_api_token()` are tested) and the
`__main__` block of `agent/status.py` (its `main()` is tested). Nothing else carries `# pragma: no cover`.

Every Python module in `gateway/`, `control/`, `agent/` and `tools/` is gated this way, locally by
`make coverage` and in CI. The current figures per module are in the `coverage` artifact of the latest CI run.

## Code style

- Python ≥ 3.12, `ruff format` (line length 120) and `ruff check` (incl. bandit-style `S` rules).
- Shell: `shellcheck`-clean, `set -uo pipefail` (`setup.sh` also uses `-e`).
- Frontend: no framework, no build step, CSP-compatible (no inline scripts).
- `pre-commit install` runs the same checks on commit.

## Making changes safely

- Enforcement logic lives in `gateway/egressgw/core.py` (`server_connect` is the single gate). Keep it small.
- Any change to topology, policy evaluation, injection or management exposure requires an ADR update and a
  threat-model review ([threat-model.md](threat-model.md)).
- Add an e2e test for every new protocol path or decision type.

## Releases

1. Update `VERSION`, `pyproject.toml`, the version badge in `README.md` and `CHANGELOG.md` (date the release
   section).
2. Commit, tag `vX.Y.Z`, push the tag.
3. CI builds and pushes the images (`linux/amd64`, `linux/arm64`) to GHCR as `X.Y.Z`, `X.Y` and `latest`,
   and creates the GitHub release with `compose.yaml`, `.env.example`, `gateway.yaml` and `bypass.sh`
   attached. Every push to `main` also publishes `:main` and `:sha-<commit>`.
4. Check the release page and pull the new images once (`TALLYGATE_VERSION=X.Y.Z docker compose pull`).

**Claude Code updates.** The agent image pins Claude Code (`ARG CLAUDE_VERSION` in `agent/Dockerfile`)
and has no auto-updater. Every Monday, `.github/workflows/claude-code.yml` compares it with the latest
version on npm and opens a PR that bumps it, then starts CI for that branch. Merge it and cut a patch
release, so `:X.Y` and `:latest` carry the new version. It can also be run by hand (*Actions → Claude Code
update → Run workflow*).
