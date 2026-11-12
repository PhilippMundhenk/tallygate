# tallygate developer & operator shortcuts. `make help` lists targets.
SHELL := /bin/bash
# build from this checkout: compose.build.yaml adds `build:` to the published image definitions
COMPOSE ?= docker compose -f compose.yaml -f compose.build.yaml
PY ?= python3

.PHONY: help
help:  ## show this help
	@grep -hE '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

# ---------------------------------------------------------------- development
.PHONY: dev-setup lint fmt test test-unit test-e2e coverage
dev-setup:  ## install dev dependencies into the current Python env
	$(PY) -m pip install -r requirements-dev.txt

lint:  ## ruff + shellcheck + vendored-file checksums
	ruff check .
	ruff format --check .
	shellcheck setup.sh agent/entrypoint.sh tests/integration/bypass.sh
	cd control/app/static/vendor && sha256sum --quiet -c SHA256SUMS

fmt:  ## auto-format
	ruff check --fix .
	ruff format .

test-unit:  ## policy engine unit tests
	$(PY) -m pytest tests/unit

test-e2e:  ## gateway/control/notification end-to-end tests (no Docker needed; ttyd optional)
	$(PY) -m pytest tests/e2e

test: test-unit test-e2e  ## all local tests

coverage:  ## all tests with line coverage (incl. the gateway/control processes); fails below 95 % per module
	rm -f .coverage .coverage.*
	$(PY) -m coverage run -m pytest -q tests/unit tests/e2e
	$(PY) -m coverage combine -q
	$(PY) -m coverage report
	$(PY) -m coverage html -q
	$(PY) -m coverage json -q -o coverage.json
	$(PY) tools/coverage_gate.py coverage.json --min 95

# ---------------------------------------------------------------- operations
.PHONY: setup build up down logs ps bypass-test password
setup:  ## optional: create .env (and host state dirs with DIR=/path)
	./setup.sh $(DIR)

build:  ## build all images
	$(COMPOSE) build

up:  ## build and start the stack
	$(COMPOSE) up -d --build

down:  ## stop the stack
	$(COMPOSE) down

logs:  ## follow logs
	$(COMPOSE) logs -f --tail=100

ps:  ## container status
	$(COMPOSE) ps

bypass-test:  ## authoritative isolation test against the running stack
	./tests/integration/bypass.sh

password:  ## change the web UI password (stored in the control volume)
	$(COMPOSE) exec control python -m app.passwd
