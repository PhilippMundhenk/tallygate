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
│       ├── model.py          #   one model: the verdict per connection, the limits per request (ADR-0014)
│       ├── access.py         #   read-only view for the UI: each destination once
│       ├── policy.py         #   pure policy engine: one ordered rule list, built-in blocks, migration, approvals → rules
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
│       ├── agentschema.py    #   the agent's answers reduced to known keys and types before the UI sees them
│       ├── notify.py         #   Telegram + Matrix bots, Web Push, ntfy, Gotify, Pushover
│       ├── notifyconfig.py   #   notification settings saved in the UI (write-only secrets, ADR-0018)
│       ├── webpush.py        #   Web Push: VAPID, RFC 8291 encryption, subscriptions, action tokens
│       └── static/           #   single-page UI (vanilla JS, no build step)
├── agent/                    # agent container
│   ├── Dockerfile            #   Debian + Claude Code + gh (signed repo) + ttyd (checksummed)
│   ├── entrypoint.sh         #   CA trust, placeholders, tmux/ttyd/Remote Control supervisor
│   ├── rc-loop.sh            #   restarts Remote Control as the same environment and session
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
  `/etc/hosts`. With `GW_TEST_FLOOR_REPLACE=1` and `never` entries in the test config, the built-in blocks
  are not seeded, because the upstreams run on loopback.
- An empty `GW_INTERNAL_NETS` stops the gateway. The unit tests (`tests/unit/conftest.py`) and the e2e
  harness (`tests/e2e/conftest.py`) run gateways outside the compose stack, where there are no networks of a
  stack to lock, and set `GW_TEST_NO_INTERNAL_NETS=1` for that. It is for tests and for running the gateway
  by hand during development only: `compose.yaml` never sets it, and the gateway logs a warning when it is
  on. Tests of the locked ranges set `GW_INTERNAL_NETS` instead.
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
  GW_API_HOST=127.0.0.1 GW_API_TOKEN=dev-token-dev-token-dev-token GW_TEST_NO_INTERNAL_NETS=1 python3 run.py
#   (GW_TEST_NO_INTERNAL_NETS=1: no compose stack here, so no networks to lock; development only)
# terminal 2: control
cd control && GW_URL=http://127.0.0.1:8081 GW_API_TOKEN=dev-token-dev-token-dev-token \
  CONTROL_BIND_HOST=127.0.0.1 CONTROL_PASSWORD=dev SESSION_SECRET=dev-only-session-secret-0123456789 COOKIE_SECURE=0 \
  TTYD_CREDENTIAL=a:b python3 -m app.main
# use it:
curl -x http://127.0.0.1:3128 https://example.org/    # appears in Approvals at http://127.0.0.1:8080
```

## Testing levels

| Level | What | Where | Runs in CI |
|---|---|---|---|
| Unit | Policy matching, the ordered rule list (name and address rules, built-in blocks, locked ranges, migration), expiry, approvals, validation, presets, templating; grants, history, learning mode and rule usage; control (auth, password, setup checks, files, notifications, Web Push); the agent's CLI, hook and status server | `tests/unit` | ✅ |
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
- UI: build every page from the parts in [ux-concept.md](ux-concept.md) (button ranks, one verb per meaning,
  three help levels, the status vocabulary); `tests/unit/test_ui_conventions.py` checks the mechanical rules.
- `pre-commit install` runs the same checks on commit.

## Making changes safely

- Enforcement lives in two files. `gateway/egressgw/core.py` holds the mitmproxy hooks (`server_connect` is the
  single gate for connections) and does the I/O. `gateway/egressgw/model.py` decides what follows from an allowed
  connection: whether it is intercepted, and what each request may do. It has no I/O and no mitmproxy types;
  a new kind of limit is added there, not as another check in the hooks.
- Any change to topology, policy evaluation, injection or management exposure requires an ADR update and a
  threat-model review ([threat-model.md](threat-model.md)).
- Add an e2e test for every new protocol path or decision type.

## Dependencies

Python dependencies are pinned twice. `gateway/requirements.in`, `control/requirements.in` and
`requirements-dev.in` list the direct dependencies with exact versions. The `requirements*.txt` next to them
are **lock files**: every package, direct or not, with its version and the SHA-256 hashes of its files,
compiled with [uv](https://docs.astral.sh/uv/) (`--universal`: one file for every platform and for Python
3.13 and newer; the images run 3.15). The images, CI and `make dev-setup` install with
`pip install --require-hashes`, so pip refuses a package that is not in the lock file or whose file has
another hash.

- Change a dependency: edit the `.in` file, run `make lock` (needs `pip install uv`), commit both files.
  `requirements-dev.in` includes the other two, so `make lock` always recompiles all three, and
  `tests/unit/test_supply_chain.py` fails when the lock files disagree with the `.in` files or with each other.
- Dependabot does the same weekly (`package-ecosystem: uv` in `.github/dependabot.yml` recompiles
  `uv pip compile` files, hashes included). If one of its PRs leaves the three lock files at different
  versions, check out its branch, run `make lock` and push.
- Limits: source distributions are hash-checked, but the build tools pip fetches to build them are not
  (PyYAML has no wheel for Python 3.15 yet and is built from source in the images). Debian packages are
  verified by apt's signatures, not pinned by version.

The GitHub CLI apt keyring in `agent/Dockerfile` is pinned by its SHA-256 and by the exact list of its primary
key fingerprints. When GitHub rotates the key the agent image build stops and prints the new values: compare
the fingerprints with GitHub's announcement, then update both build arguments.

## Image scan

The `image-scan` job (Trivy) runs on `main` and on tags, against the images the `images` job has just pushed.
A **CRITICAL** vulnerability for which a fixed version exists fails the job: `main` turns red, and on a tag
the `release` job does not run, so there is no GitHub release and no pinned `compose.yaml` for that version.
HIGH findings are listed in the job log and do not fail it (base images carry too many that do not apply).

- The images are pushed and signed *before* the scan, also on a tag (`:X.Y.Z`, `:X.Y`, `:latest`): the gate
  stops the release, not the push. After a failed scan on a tag, fix, and release the next patch version.
- First fix: a newer base image digest, `make lock` for a Python package, a newer Claude Code. A finding
  that does not apply can be accepted in `.trivyignore`: the ID, and above it a comment with the image and
  package, the reason and when to look again. Remove the entry when the fix is in.
- Pull requests are not scanned (nothing is pushed for them), so a finding shows up on `main` after the
  merge, or with a new vulnerability database without any change at all.

## Releases

1. Update `VERSION`, `pyproject.toml`, the version badge in `README.md` and `CHANGELOG.md` (date the release
   section).
2. Commit, tag `vX.Y.Z`, push the tag.
3. CI builds and pushes the images (`linux/amd64`, `linux/arm64`) to GHCR as `X.Y.Z`, `X.Y` and `latest`,
   signs each pushed image digest with cosign (keyless, job `images`), and creates the GitHub release with
   `compose.yaml`, `compose.digests.yaml`, `.env.example`, `gateway.yaml` and `bypass.sh` attached. The
   attached `compose.yaml` is not the file from the checkout: `tools/pin_compose.py` writes the version into
   its image lines (`${TALLYGATE_VERSION:-X.Y.Z}`) and the digests of the `images` job into
   `compose.digests.yaml`. The script refuses a compose file whose image lines it does not recognise, which
   fails the release job: keep the three `image:` lines of `compose.yaml` in the form
   `ghcr.io/…/tallygate-<name>:${TALLYGATE_VERSION:-latest}`. Every push to `main` also publishes `:main`
   and `:sha-<commit>`, signed the same way.
4. Check the release page: download the attached `compose.yaml`, check that its images name the new version,
   pull them once (`docker compose pull`) and verify a signature
   ([operations.md](operations.md#verifying-the-images)).

**Claude Code updates.** The agent image installs Claude Code with `npm ci` from
`agent/claude-code/package.json` and `package-lock.json` (the version, and the sha512 integrity of the package
and its platform packages; npm refuses a tarball with another hash) and has no auto-updater. Every Monday,
`.github/workflows/claude-code.yml` compares the locked version with the latest on npm and opens a PR that
bumps both files (`npm install --package-lock-only`, nothing is installed in the workflow), then starts CI
for that branch. Merge it and cut a patch release, so `:X.Y` and `:latest` carry the new version. It can also
be run by hand (*Actions → Claude Code update → Run workflow*). The hashes are the ones the registry reports
when the PR is made; from then on every build must get exactly those bytes. `CLAUDE_VERSION` (build argument)
installs another version by version only, without a pinned hash.