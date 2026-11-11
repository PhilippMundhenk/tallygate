# Contributing

Thanks for helping! tallygate is security-sensitive, so changes are reviewed with that lens.

## Development setup

```bash
python3 -m venv .venv && . .venv/bin/activate
make dev-setup          # gateway + control deps, pytest, ruff, shellcheck
make lint test          # everything that CI runs except the Docker integration job
```

The e2e suite starts the real gateway (mitmdump) and control plane on localhost with throwaway
upstream servers and a mock Telegram/Matrix API — no Docker or root needed. Install
[`ttyd`](https://github.com/tsl0922/ttyd) to also run the web-console test.

The full stack test (`make up && make bypass-test`) needs Docker; CI runs it on every PR.

## Guidelines

- **Security properties are invariants.** If a change touches the network topology, policy evaluation,
  credential injection, or management-plane exposure, update [docs/threat-model.md](docs/threat-model.md)
  and add/adjust an ADR in [docs/adr/](docs/adr/).
- **Tests first for policy changes.** Every enforcement path has an e2e test; add one for new paths.
- **Keep the gateway small.** UI and integrations belong in `control/`, never in `egress-gw`.
- **No new runtime dependencies without discussion.** Pin versions; verify checksums for downloaded binaries.
- Style: `ruff format` + `ruff check`, `shellcheck` for shell. Conventional commit messages
  (`feat:`, `fix:`, `docs:`, `test:`, `chore:`) are appreciated.
- Add a line to `CHANGELOG.md` under *Unreleased*.

## Releasing

1. Update `VERSION`, `pyproject.toml` and `CHANGELOG.md`.
2. Tag `vX.Y.Z` and push; publish release notes from the changelog.

By contributing you agree that your contributions are licensed under the MIT License.
