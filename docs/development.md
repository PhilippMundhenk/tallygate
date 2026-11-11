# Development

## Repository layout

```
.
├── compose.yaml              # the stack: networks, hardening, wiring
├── setup.sh                  # host setup: .env secrets, password hash, state dirs
├── config/gateway.yaml       # static gateway config (injection, service ports)
├── gateway/                  # egress-gw container
│   ├── run.py                #   builds the mitmdump command line from config/env
│   ├── presets/              #   policy presets (baseline, open, lockdown)
│   └── egressgw/
│       ├── addon.py          #   mitmproxy script entry point (thin loader)
│       ├── core.py           #   hooks: server_connect, tls_clienthello, request, dns_request; approvals
│       ├── policy.py         #   pure policy engine (rules, hard deny, approvals → rules)
│       ├── store.py          #   SQLite event log, secrets store, header templating
│       └── api.py            #   management API (aiohttp, bearer token)
├── control/                  # control container
│   ├── hashpw.py             #   password hash helper
│   └── app/
│       ├── main.py           #   auth, CSRF, gateway relay, terminal proxy, agent status
│       ├── notify.py         #   Telegram + Matrix approval bots
│       └── static/           #   single-page UI (vanilla JS, no build step)
├── agent/                    # agent container
│   ├── Dockerfile            #   Debian + Claude Code + gh (signed repo) + ttyd (checksummed)
│   ├── entrypoint.sh         #   CA trust, placeholders, tmux/ttyd/Remote Control supervisor
│   └── status.py             #   status + isolation self-test endpoint
├── tests/
│   ├── unit/                 # policy engine
│   ├── e2e/                  # real gateway + control on localhost, mock upstreams and bot APIs
│   └── integration/bypass.sh # Docker-based isolation test against the running stack
└── docs/                     # this documentation
```

## Local development

```bash
python3 -m venv .venv && . .venv/bin/activate
make dev-setup
make lint test
```

The e2e suite (`tests/e2e`) needs no Docker and no root:

- The gateway runs as a real `mitmdump` process on random localhost ports, with DNS on an unprivileged
  port (`GW_DNS_PORT`) and test-only static name resolution (`GW_TEST_STATIC_HOSTS`) instead of
  `/etc/hosts`. `GW_TEST_FLOOR_REPLACE=1` lets the test config's `hard_deny_floor` replace the built-in
  list, because the upstreams run on loopback.
- Upstreams are local HTTP/HTTPS echo servers with a throwaway certificate.
- The control plane runs as a real process; Telegram and Matrix are mocked (`tests/e2e/mockbots.py`).
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
| Unit | Policy matching, hard deny, CIDR semantics, expiry, approvals, validation, presets, templating | `tests/unit` | ✅ |
| E2E | Every enforcement path, held connections, injection incl. SNI spoofing and upstream cert verification, DNS, API auth, UI auth/CSRF/origin, console websocket, Telegram/Matrix flows | `tests/e2e` | ✅ |
| Integration | Real images and networks: structural hardening and egress probes from an independent container | `tests/integration/bypass.sh` | ✅ (`integration` job) |

## Code style

- Python ≥ 3.12, `ruff format` (line length 120) and `ruff check` (incl. bandit-style `S` rules).
- Shell: `shellcheck`-clean, `set -uo pipefail`.
- Frontend: no framework, no build step, CSP-compatible (no inline scripts).
- `pre-commit install` runs the same checks on commit.

## Making changes safely

- Enforcement logic lives in `gateway/egressgw/core.py` (`server_connect` is the single gate). Keep it small.
- Any change to topology, policy evaluation, injection or management exposure requires an ADR update and a
  threat-model review ([threat-model.md](threat-model.md)).
- Add an e2e test for every new protocol path or decision type.

## Releases

1. Update `VERSION`, `pyproject.toml` and `CHANGELOG.md`.
2. Commit, tag `vX.Y.Z`, push the tag.
3. Create a GitHub release from the changelog section.
